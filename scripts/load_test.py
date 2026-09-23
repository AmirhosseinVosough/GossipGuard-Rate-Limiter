"""Measure how far a burst can overshoot the limit before the nodes converge.

Fires one concurrent burst from a single identity, spread round-robin across
every node, then watches the gossiped counters until all nodes agree on the
total. Run against the Compose cluster:

    docker compose up -d
    python scripts/load_test.py

The counters live for RATE_LIMIT_WINDOW_SECONDS after the last hit, so a second
run within that window starts warm. The script checks for that and refuses to
measure a dirty window rather than report a wrong number.
"""
from __future__ import annotations

import argparse
import asyncio
import sys
import time
from collections import Counter

import httpx

DEFAULT_NODES = "http://localhost:8000,http://localhost:8001,http://localhost:8002"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--nodes", default=DEFAULT_NODES, help="comma separated node URLs")
    parser.add_argument("--burst", type=int, default=150, help="requests in the burst")
    parser.add_argument("--username", default="viewer")
    parser.add_argument("--password", default="viewer123")
    parser.add_argument("--user-id", default="viewer-1", help="the burst user's id, which the counter is keyed by")
    parser.add_argument("--admin-username", default="admin")
    parser.add_argument("--admin-password", default="admin123")
    parser.add_argument("--converge-timeout", type=float, default=10.0, help="seconds to wait for nodes to agree")
    return parser.parse_args()


async def login(client: httpx.AsyncClient, node: str, username: str, password: str) -> str:
    response = await client.post(f"{node}/auth/token", data={"username": username, "password": password})
    if response.status_code != 200:
        sys.exit(f"login as {username!r} on {node} failed: {response.status_code} {response.text}")
    return response.json()["access_token"]


async def user_totals(client: httpx.AsyncClient, node: str, admin_token: str, user_id: str) -> dict[str, dict]:
    """Return {user_key: {slot_node: slot}} for every counter belonging to user_id on one node."""
    response = await client.get(
        f"{node}/internal/gossip/state", headers={"Authorization": f"Bearer {admin_token}"}
    )
    if response.status_code != 200:
        sys.exit(f"reading state from {node} failed: {response.status_code} {response.text}")
    snapshot = response.json()["snapshot"]
    return {key: slots for key, slots in snapshot.items() if key.endswith(f":{user_id}")}


def total(slots: dict) -> int:
    return sum(int(slot["count"]) for slot in slots.values())


async def burst(
    client: httpx.AsyncClient, nodes: list[str], token: str, size: int
) -> tuple[dict[str, Counter], set[int]]:
    """Fire size requests at once, round-robin across nodes. Returns status counts and the limits reported."""
    headers = {"Authorization": f"Bearer {token}"}

    async def one(node: str) -> tuple[str, httpx.Response]:
        return node, await client.get(f"{node}/protected/profile", headers=headers)

    results = await asyncio.gather(*(one(nodes[i % len(nodes)]) for i in range(size)))
    per_node: dict[str, Counter] = {node: Counter() for node in nodes}
    limits: set[int] = set()
    for node, response in results:
        per_node[node][response.status_code] += 1
        if response.status_code == 200:
            limits.add(int(response.headers["X-RateLimit-Limit"]))
        elif response.status_code == 429:
            limits.add(int(response.json()["limit"]))
    return per_node, limits


async def main() -> int:
    args = parse_args()
    nodes = [url.strip().rstrip("/") for url in args.nodes.split(",") if url.strip()]

    pool = httpx.Limits(max_connections=args.burst + 10, max_keepalive_connections=args.burst + 10)
    async with httpx.AsyncClient(timeout=10.0, limits=pool) as client:
        for node in nodes:
            try:
                await client.get(f"{node}/health")
            except httpx.HTTPError as exc:
                sys.exit(f"{node} is not reachable ({exc}). Is the cluster up?")

        token = await login(client, nodes[0], args.username, args.password)
        admin_token = await login(client, nodes[0], args.admin_username, args.admin_password)

        # A warm counter from an earlier run would make the burst look better
        # behaved than it is, so measure only from an empty window.
        for node in nodes:
            warm = await user_totals(client, node, admin_token, args.user_id)
            if warm:
                expires = max(float(s["expires_at"]) for slots in warm.values() for s in slots.values())
                wait = max(0, int(expires - time.time()) + 1)
                sys.exit(f"{node} still holds counts for {args.user_id!r} from an earlier run. "
                         f"Try again in {wait}s.")

        per_node, limits = await burst(client, nodes, token, args.burst)
        burst_ended = time.monotonic()

        # Converged means every node holds one counter for this user, and it
        # adds up to every request sent, refused ones included.
        converged_after = None
        views: dict[str, dict] = {}
        while time.monotonic() - burst_ended < args.converge_timeout:
            views = {node: await user_totals(client, node, admin_token, args.user_id) for node in nodes}
            if all(len(v) == 1 and total(next(iter(v.values()))) == args.burst for v in views.values()):
                converged_after = time.monotonic() - burst_ended
                break
            await asyncio.sleep(0.25)

        second, _ = await burst(client, nodes, token, len(nodes))

    admitted = sum(c[200] for c in per_node.values())
    refused = sum(c[429] for c in per_node.values())
    other = args.burst - admitted - refused
    if len(limits) != 1:
        sys.exit(f"nodes reported different limits for the same user: {sorted(limits)}")
    limit = limits.pop()

    print(f"\nBurst of {args.burst} concurrent requests as {args.username!r} across {len(nodes)} nodes\n")
    print(f"{'node':<28}{'admitted':>10}{'refused':>10}")
    for node, counts in per_node.items():
        print(f"{node:<28}{counts[200]:>10}{counts[429]:>10}")
    print(f"{'total':<28}{admitted:>10}{refused:>10}")
    print(f"\nAllowed by policy: {limit}")
    print(f"Over-admission:    {admitted / limit:.2f}x  (worst case {len(nodes)}.00x, one full limit per node)")
    if other:
        print(f"\n{other} requests got neither 200 nor 429: {dict(sum(per_node.values(), Counter()))}")

    return report(args, nodes, views, converged_after, second)


def report(args, nodes, views, converged_after, second) -> int:
    ok = True
    keys = {key for v in views.values() for key in v}
    if not keys:
        print(f"\nNo node holds a counter for user id {args.user_id!r}. "
              f"Check --user-id matches the account {args.username!r}.")
        return 1
    if converged_after is None:
        ok = False
        print(f"\nNodes did not agree within {args.converge_timeout}s.")
        if len(keys) > 1:
            print("They are counting this user under different keys, which means they see the client at "
                  f"different addresses: {sorted(keys)}. That is separate buckets, not slow convergence.")
        for node, v in views.items():
            print(f"  {node}: {({k: total(s) for k, s in v.items()})}")
    else:
        print(f"\nAll nodes agreed on a total of {args.burst} after {converged_after:.2f}s")

    second_admitted = sum(c[200] for c in second.values())
    print(f"Follow-up request to each node: {second_admitted} of {len(nodes)} admitted")
    if second_admitted:
        ok = False

    print(f"\nCounters stay warm for the rate limit window after the last hit; wait that long before rerunning.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
