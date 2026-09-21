from __future__ import annotations

import hashlib
import hmac
import json


def compute_signature(node_id: str, timestamp: float, version: int, snapshot: dict, secret_key: str) -> str:
    message = json.dumps(
        {
            "node_id": node_id,
            "timestamp": timestamp,
            "version": version,
            "snapshot": snapshot,
        },
        sort_keys=True,
    )
    return hmac.new(secret_key.encode(), message.encode(), hashlib.sha256).hexdigest()


def verify_signature(
    node_id: str,
    timestamp: float,
    version: int,
    snapshot: dict,
    signature: str,
    secret_key: str,
) -> bool:
    expected_signature = compute_signature(node_id, timestamp, version, snapshot, secret_key)
    return hmac.compare_digest(signature, expected_signature)
