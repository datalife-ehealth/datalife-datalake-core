"""Chained Merkle ledger helpers.

This module hashes canonical JSON leaves and links block hashes. It does not
run consensus, mining, or a peer network. Verification is local and deterministic.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def leaf_hash(record: Any) -> str:
    return sha256_hex(canonical_json(record))


def merkle_root(records: list[Any]) -> str:
    level = [leaf_hash(record) for record in records]
    if not level:
        return sha256_hex(b"")
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [sha256_hex((level[index] + level[index + 1]).encode("ascii")) for index in range(0, len(level), 2)]
    return level[0]


def block_hash(height: int, previous_hash: str, root: str, records: list[Any]) -> str:
    payload = {"height": height, "previous_hash": previous_hash, "merkle_root": root, "records": records}
    return sha256_hex(canonical_json(payload))


def seal(records: list[Any], previous_hash: str, height: int) -> dict[str, Any]:
    root = merkle_root(records)
    digest = block_hash(height, previous_hash, root, records)
    return {
        "height": height,
        "previous_hash": previous_hash,
        "merkle_root": root,
        "block_hash": digest,
        "records": records,
    }


def verify_chain(blocks: list[dict[str, Any]]) -> bool:
    previous = "0" * 64
    for index, block in enumerate(blocks):
        records = list(block.get("records") or [])
        root = merkle_root(records)
        digest = block_hash(index, previous, root, records)
        if block.get("height") != index or block.get("previous_hash") != previous:
            return False
        if block.get("merkle_root") != root or block.get("block_hash") != digest:
            return False
        previous = digest
    return True
