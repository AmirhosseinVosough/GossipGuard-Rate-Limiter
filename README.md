# GossipGuard

[![CI](https://github.com/AmirhosseinVosough/GossipGuard-Rate-Limiter/actions/workflows/ci.yml/badge.svg)](https://github.com/AmirhosseinVosough/GossipGuard-Rate-Limiter/actions/workflows/ci.yml)

A distributed rate limiter that enforces per-user limits across a cluster
without a central store, using conflict-free replicated counters synchronised by
a signed gossip protocol.

## The problem

You run an API behind a load balancer with three instances and want to enforce
100 requests per minute per user.

If each instance keeps its own counter, every user gets 300 per minute. The
balancer spreads their traffic and no single instance ever sees the whole
picture, so the configured limit is silently wrong by a factor of N.

The usual answer is a central store: every request does a round trip to Redis to
increment a counter. That works, and it costs you three things. Redis becomes a
single point of failure, so when it is down you either fail open and have no rate
limiting or fail closed and have an outage. You pay network latency on every
request. And Redis needs its own scaling and high availability story.

GossipGuard takes the other path. Each node counts locally, so the hot path is an
in-memory dictionary lookup with no network hop, and nodes periodically gossip
their counts to each other. The cluster converges on the true total within a
gossip round.

The trade is stated plainly in [Known limitations](#known-limitations): this is
eventually consistent, and a burst can exceed the limit during convergence. That
cost is measured below rather than hand-waved.

## Why merging is the hard part

Sending counts between nodes is trivial. The difficulty is what happens when two
nodes' data meets.

Suppose each node stored a single number, "count for user X", and gossiped it.
Node A says 5, node B says 7. Taking the maximum discards A's increments. Taking
the sum double counts forever, because every subsequent round re-adds what was
already counted. Both are wrong, and this is the lost update problem.

The solution is that **each node owns its own slot**:

```text
{ user_key: { node_id: CounterSlot(count, expires_at, updated_at) } }
```

Node A only ever writes `slots["node-a"]`. Node B only ever writes
`slots["node-b"]`. A user's total is the sum across all slots.

Merging is then conflict free. For each incoming slot, take it if absent, and
otherwise keep whichever carries the later `updated_at`, breaking ties on the
higher count. No node can overwrite another's data, because no two nodes ever
write the same key. Arrival order stops mattering and duplicate deliveries are
harmless, which is what a G-Counter CRDT buys you.

Expired slots are pruned on access and by a background janitor, so memory is
bounded by the number of distinct keys seen within one window.

## Security model

Inbound gossip passes two independent checks before anything is merged.

- **HMAC-SHA256** over a canonical, key-sorted JSON body, compared with
  `hmac.compare_digest` so verification cannot leak through timing.
- **Source address allowlist**, resolved from the configured peer URLs.

Then two freshness checks:

- **Clock window.** Envelopes more than `GOSSIP_MAX_SKEW_SECONDS` from now are
  refused.
- **Replay cache.** Every accepted signature is remembered for that window, so a
  captured envelope cannot be resent. The signature is verified before the cache
  is consulted, so an unauthenticated caller cannot fill it.

On the user-facing side: JWT bearer tokens with the algorithm pinned at decode,
bcrypt at cost factor 12, and role-based permissions. Authentication spends the
same time whether or not the account exists, so response latency does not reveal
which usernames are registered.

Client identity is taken from the socket address unless `TRUSTED_PROXIES` names
the caller, in which case `X-Forwarded-For` is walked from right to left past
known proxies. The header is attacker controlled, so believing it unconditionally
would let any client mint a fresh counter bucket per request.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full analysis, including the gaps.

## Quick start

```bash
docker compose up --build
```

Three nodes on ports 8000, 8001 and 8002. The dashboard is at
<http://localhost:8000>, demo credentials `admin` / `admin123`.

Confirm the mesh has formed:

```bash
TOKEN=$(curl -s -X POST localhost:8000/auth/token \
  -d "username=admin&password=admin123" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -H "Authorization: Bearer $TOKEN" localhost:8000/internal/gossip/debug
```

`last_sync` should name a peer within a second or two.

### Running without Docker

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[test]"
cp .env.example .env          # then set the two required secrets
uvicorn app.main:app --reload
```

Every node runs the same entrypoint. Node identity comes from the environment,
so a second node is `NODE_ID=node-b PEER_URLS=... uvicorn app.main:app --port 8001`.

## Known limitations

### Over-admission during convergence

**Measured at 3.00x the configured limit.**

Between gossip rounds a node knows only its own count plus the last snapshot it
received. A client spreading a burst across every node is admitted by each of
them independently.

Reproduce it:

```bash
docker compose up -d
python scripts/load_test.py
```

A burst of 150 concurrent requests from one identity, against a three node
cluster with a limit of 30:

| | Result |
|---|---|
| Admitted | 90 |
| Refused (429) | 60 |
| Allowed by policy | 30 |
| **Over-admission** | **3.00x** |

Each node admitted its full 30 before learning about the other two. The worst
case is the limit multiplied by the node count, and the measurement lands exactly
there.

The system does correct itself. Within about three seconds all nodes agree on the
total, and a second burst is refused entirely.

**The fix, not yet implemented:** give each node `limit / node_count` rather than
the full limit, and gossip unused headroom so a node under heavy load can borrow
what idle peers are not spending. That bounds the total correctly while still
handling uneven traffic.

### Other known gaps

One shared gossip secret with no rotation path, no TLS between peers, no account
lockout, and no request size limit on the sync endpoint. Each is recorded with
its severity and reasoning in [THREAT_MODEL.md](THREAT_MODEL.md).

## Configuration

| Variable | Purpose | Required |
| --- | --- | --- |
| `GOSSIP_SECRET_KEY` | Signs internal gossip payloads | Yes |
| `JWT_SECRET_KEY` | Signs JWT access tokens | Yes |
| `NODE_ID` | Unique node identifier | No |
| `PEER_URLS` | Comma-separated peer URLs | No |
| `TRUSTED_PROXIES` | Proxies whose `X-Forwarded-For` may be believed | No |
| `GOSSIP_INTERVAL_SECONDS` | How often to gossip, default 0.5 | No |
| `GOSSIP_MAX_SKEW_SECONDS` | Clock tolerance and replay window, default 60 | No |
| `RATE_LIMIT_WINDOW_SECONDS` | Counter window, default 60 | No |
| `ANONYMOUS_LIMIT` / `VIEWER_LIMIT` / `EDITOR_LIMIT` / `ADMIN_LIMIT` | Per-role limits | No |
| `ENABLE_DEMO_USERS` | Seeds demo accounts, off by default | No |

The process refuses to start without the two secrets rather than falling back to
a default. Demo accounts are disabled unless explicitly enabled and require
passwords supplied from the environment.

## Project structure

```text
app/
  api/routes/        endpoints, including the internal gossip API
  core/              settings, auth, signing, replay guard, client IP resolution
  middleware/        rate limiting
  models/            user, role and counter types
  repositories/      in-memory auth and counter storage
  services/          auth, rate limiting, gossip
frontend/            operator dashboard
scripts/             load test harness
tests/               pytest suite
```

## Testing

```bash
pytest
```

48 tests covering the merge rule, permission enforcement, JWT handling,
signature and replay rejection, proxy header trust, and the login timing
equalisation. Time-dependent logic takes an injectable clock, so expiry and
convergence are tested deterministically rather than with sleeps.

CI runs the suite on Python 3.11, 3.12 and 3.13.

## API

| Endpoint | Auth |
|---|---|
| `POST /auth/token` | none |
| `GET /auth/me` | JWT |
| `GET /protected/public` | none |
| `GET /protected/profile` | `READ_PROFILE` |
| `GET /protected/admin` | `MANAGE_USERS` |
| `GET /internal/gossip/state` | `VIEW_AUDIT_LOGS` |
| `GET /internal/gossip/debug` | `VIEW_AUDIT_LOGS` |
| `POST /internal/gossip/sync` | HMAC signature and peer address |
