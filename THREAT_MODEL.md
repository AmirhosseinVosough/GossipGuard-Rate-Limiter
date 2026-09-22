# Threat Model

This document describes what GossipGuard protects, what it does not, and the
reasoning behind each control. It reflects the code as it stands rather than an
aspirational design, so it names the gaps as plainly as the mitigations.

## System summary

Three or more FastAPI nodes each enforce per-user request limits. Every node
counts locally and periodically gossips its counts to a subset of peers, so the
cluster converges on a shared view without a central store. Counter state is held
in memory only. There is no database.

## Trust boundaries

```mermaid
graph LR
    A[Untrusted clients] -->|public HTTP| B[Node]
    C[Browser dashboard] -->|JWT bearer| B
    B <-->|signed gossip| D[Peer nodes]
    E[Operator] -->|environment variables| B
```

Three boundaries matter:

1. **Internet to node.** Anyone can reach `/auth/token`, `/protected/public`,
   and the dashboard. Everything crossing here is untrusted.
2. **Node to node.** The gossip mesh. Peers are semi trusted: authenticated by a
   shared secret, but any compromised node can write to every other node's state.
3. **Operator to node.** Secrets and peer lists arrive through environment
   variables. The operator is trusted.

## Assets

| Asset | Why it matters |
|---|---|
| Rate limit counters | The product. Corrupting them lets a client exceed limits or locks a legitimate client out. |
| `GOSSIP_SECRET_KEY` | Holding it lets an attacker write arbitrary counter state to every node. |
| `JWT_SECRET_KEY` | Holding it lets an attacker mint tokens for any user, including admins. |
| Password hashes | In memory only, but recovery would expose credentials reused elsewhere. |
| Counter snapshots | Contain client IPs and user IDs. Exposure is a privacy concern, not a compromise. |

## Attack surface

| Endpoint | Authentication | Rate limited |
|---|---|---|
| `POST /auth/token` | None | Yes, anonymous tier |
| `GET /auth/me` | JWT | Yes |
| `GET /protected/public` | None | Yes, anonymous tier |
| `GET /protected/profile` | JWT plus `READ_PROFILE` | Yes |
| `GET /protected/admin` | JWT plus `MANAGE_USERS` | Yes |
| `GET /internal/gossip/state` | JWT plus `VIEW_AUDIT_LOGS` | No |
| `GET /internal/gossip/debug` | JWT plus `VIEW_AUDIT_LOGS` | No |
| `POST /internal/gossip/sync` | HMAC signature plus source IP allowlist | No |
| `GET /`, `/dashboard`, `/static/*` | None | Yes for the routes, static files bypass |

Paths under `/internal/` are exempt from rate limiting by design
(`app/middleware/rate_limit_middleware.py:17`). Throttling gossip would let a
traffic spike starve the very messages needed to converge, turning a load event
into a partition.

## Threats

### T1. Forged gossip messages

An attacker who can POST to `/internal/gossip/sync` writes directly into counter
state. Raising a victim's count denies them service. Supplying a fresher
`updated_at` with a low count resets their usage and defeats the limit entirely,
because the merge takes the newer timestamp as authoritative
(`app/repositories/rate_limit_repository.py:74`).

**Controls.** HMAC-SHA256 over a canonical, key sorted JSON body, compared with
`hmac.compare_digest` so verification does not leak position through timing
(`app/core/signing.py`). Independently, the source address must resolve from a
configured peer URL (`app/api/routes/internal.py:112`). Both must pass.

**Residual risk.** One shared secret covers the whole cluster. Any compromised
node, or any leak of the environment variable, grants full write access to every
node's state. There is no per peer key and no rotation path.

### T2. Replay of captured gossip

Envelopes are accepted within one hour of their timestamp
(`app/api/routes/internal.py:29`), so a captured message can be resent inside
that window.

**Why the impact is low.** The merge only overwrites a slot when the incoming
`updated_at` is strictly newer, or equal with a higher count. Replaying an old
envelope loses to the current state and changes nothing. The merge is effectively
idempotent, which is a property of the CRDT design rather than a deliberate
anti replay control.

**Residual risk.** A replay captured and resent within milliseconds, before the
victim node advances its own slot, can still land. The effect is bounded by one
gossip interval of counter drift.

### T3. Rate limit evasion across nodes

Between gossip rounds a node knows only its own count plus the last snapshot it
received. A client spreading requests across all nodes is admitted by each of
them before any of them learn about the others.

**Control.** Gossip at 0.5 second intervals with randomised fanout bounds how
long the divergence lasts.

**Residual risk.** This is the headline limitation of the design. Worst case
admission approaches the configured limit multiplied by the node count during the
convergence window. The standard fix, not yet implemented, is for each node to
reserve `limit / node_count` locally and gossip to reclaim unused headroom.
Choosing eventual consistency over a central store is what buys the availability
and the absent network hop, and this is the price.

### T4. Credential attacks

**Controls.** bcrypt at cost factor 12 (`app/core/auth.py:13`) makes offline
cracking expensive. Login errors are identical for an unknown username and a
wrong password. `/auth/token` is rate limited at the anonymous tier, ten attempts
per minute per IP by default.

Authentication also spends the same time on both failure paths. A missing account
is compared against a throwaway hash (`app/services/auth_service.py:18`) so the
response takes one bcrypt comparison either way. Before this, a lookup miss
returned in microseconds while a real username cost roughly 350 milliseconds, a
difference large enough to enumerate valid accounts remotely and then aim a
password spray at only those.

**Residual risk.** There is no account lockout and no failed attempt logging. The
throttle is keyed on client IP, so an attempt spread thinly across many source
addresses is not slowed by it.

### T5. Token handling

**Controls.** The decode call pins the algorithm list
(`app/core/auth.py:35`), which blocks the `alg: none` and algorithm confusion
family. Tokens expire after thirty minutes by default.

**Residual risk.** There is no `jti` and no revocation list, so a stolen token
stays valid until it expires. Logging out clears the browser copy and nothing
server side. The dashboard keeps its token in `localStorage`
(`frontend/app.js:37`), which any successful script injection can read.

### T6. Injection in the dashboard

`renderPeers` interpolates peer URLs into `innerHTML` without escaping
(`frontend/app.js:63`). Peer URLs originate from operator controlled
configuration, not user input, so this is not currently exploitable.

**Residual risk.** The pattern is one configuration change away from being live.
If peers ever become settable through the API or by a non administrator, this
becomes stored XSS against every admin viewing the dashboard. Snapshot data is
rendered with `textContent` and is safe.

### T7. Resource exhaustion

Counter keys are derived from the client IP, optionally suffixed with a user ID
(`app/middleware/rate_limit_middleware.py:24`). An attacker rotating source
addresses creates a new map entry per address.

**Controls.** Every slot carries an expiry, pruning runs on each access, and a
janitor sweeps every sixty seconds (`app/services/gossip_service.py:79`). Memory
is therefore bounded by unique keys seen within one window rather than growing
without limit.

**Residual risk.** Within a window that bound can still be large. More
importantly, the full snapshot is serialised and sent to each chosen peer every
interval, so gossip bandwidth grows linearly with tracked keys and a key flooding
attack degrades the whole mesh, not just one node. `POST /internal/gossip/sync`
also has no body size limit, so a signed but oversized snapshot from a compromised
peer can exhaust memory during parsing.

### T8. Transport exposure

Gossip runs over plain HTTP. The signature protects integrity and authenticity
but not confidentiality, so snapshots containing client IPs and user IDs travel in
cleartext, and a network observer can map traffic patterns per user.

**Requirement.** Deploy the gossip mesh on a private network, or terminate TLS
between peers. The application does not enforce this.

### T9. Client identity behind a reverse proxy

When a node sits behind a load balancer, the socket address belongs to the proxy
rather than the client. Reading it directly would place every client into one
shared bucket, so a single noisy caller would throttle everyone.

The obvious fix, reading `X-Forwarded-For`, is worse than the problem if applied
naively. The header is attacker controlled, so a client that sets it freely mints
a new counter bucket on every request and the limiter stops working altogether.

**Controls.** The header is honoured only when the immediate peer is itself a
configured proxy. `TRUSTED_PROXIES` accepts addresses or CIDR ranges, and
`resolve_client_ip` (`app/core/client_ip.py`) walks the forwarded chain from right
to left, discarding trusted hops and returning the first address that is not one
of them. Anything a client prepended sits further left and is never reached.
Entries that fail to parse stop the walk rather than being skipped, so a malformed
chain falls back to the proxy address instead of trusting whatever follows it.

The setting defaults to empty, which means the header is ignored entirely and the
socket address is used. A node is therefore secure before it is configured, and
the operator opts in once the deployment actually has a proxy in front of it.

**Residual risk.** Correctness depends on the operator listing the right ranges.
Trusting too broad a range, for example the whole of `0.0.0.0/0`, restores the
spoofing problem. Only `X-Forwarded-For` is read; `Forwarded` and
`X-Real-IP` are ignored.

### T10. Stale peer address cache

`_resolve_peer_ips` is memoised with `lru_cache` and never expires
(`app/api/routes/internal.py:84`). A peer whose address changes is refused until
the process restarts. If resolution happens once while DNS is compromised, the
attacker's address is trusted for the lifetime of the process. This is primarily
an availability problem, since the signature check still has to pass.

## Deliberate design choices

These look like defects and are not.

- **Throttled requests still increment the counter.** `allow_request` records the
  hit before comparing it against the limit
  (`app/services/rate_limit_service.py:25`), so a client that keeps hammering after
  a 429 extends its own lockout. This is a penalty, not an accounting error.
- **`/internal/` bypasses rate limiting.** Explained above under attack surface.
- **Secrets have no defaults.** `Settings` raises at construction when either key
  is missing (`app/core/config.py:64`), so the process refuses to start rather
  than silently running with a guessable secret. Demo accounts are disabled unless
  explicitly enabled, and require passwords supplied from the environment.

## Out of scope

Host and container hardening, supply chain integrity of dependencies, denial of
service at the network layer, physical access, and insider threat from the
operator. Persistence is also out of scope because there is none: all state is in
memory and a restart clears every counter, which is itself a limit evasion vector
if nodes restart frequently.

## Summary of known gaps

| Gap | Severity | Status |
|---|---|---|
| Over admission during convergence | Medium | Known, fix identified, not implemented |
| Single shared gossip secret, no rotation | Medium | Accepted for current scope |
| Trusted proxy ranges must be configured correctly | Low | Handled, opt in via `TRUSTED_PROXIES` |
| No account lockout or failed attempt logging | Low | Not addressed |
| No token revocation | Low | Accepted, mitigated by short expiry |
| Token in `localStorage` | Low | Accepted for a demo dashboard |
| Unescaped peer URLs in the dashboard | Low | Latent, not currently reachable |
| No request size limit on gossip sync | Low | Not addressed |
| Peer address cache never expires | Low | Not addressed |
