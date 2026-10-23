# CRITICAL: Every change to the cryptographic test vectors in this file or the resulting fixture
# requires manual cryptographic review. Do not modify or regenerate vectors to match code changes
# without explicit independent cryptographic review.
#
# This script uses ONLY the Python standard library and must NOT import from src/ or services.crypto.
"""Independent reference generator for cryptographic golden test vectors."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    """Serialize value to canonical JSON UTF-8 bytes using standard library json.

    - Keys sorted lexicographically
    - Compact separators (',', ':')
    - Non-ASCII characters preserved as UTF-8 (ensure_ascii=False)
    """
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Return lowercase hex SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def leaf_hash_hex(record: Any) -> str:
    """Compute SHA-256 leaf hash for a single record."""
    return sha256_hex(canonical_json_bytes(record))


def merkle_root_hex(records: list[Any]) -> str:
    """Compute Merkle root from a list of records.

    - Empty record list produces sha256(b"").
    - Odd leaf counts at any level duplicate the last hash.
    - Adjacent pairs are concatenated as ascii strings and hashed.
    """
    level = [leaf_hash_hex(record) for record in records]
    if not level:
        return sha256_hex(b"")
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            sha256_hex((level[i] + level[i + 1]).encode("ascii"))
            for i in range(0, len(level), 2)
        ]
    return level[0]


def block_payload_and_hash(
    height: int,
    previous_hash: str,
    merkle_root: str,
    records: list[Any],
) -> tuple[bytes, str]:
    """Compute canonical payload bytes and block hash for a block."""
    payload = {
        "height": height,
        "merkle_root": merkle_root,
        "previous_hash": previous_hash,
        "records": records,
    }
    raw_bytes = canonical_json_bytes(payload)
    return raw_bytes, sha256_hex(raw_bytes)


def build_fixture_data() -> dict[str, Any]:
    """Build the complete test vectors data structure with literal expected values."""

    # 1. Canonical JSON vectors
    canonical_inputs = [
        {
            "id": "empty_object",
            "description": "Empty object canonicalization",
            "input": {},
        },
        {
            "id": "key_order_variant_a",
            "description": "Key order test variant A (keys defined in alphabetical order)",
            "input": {"apple": "alpha", "middle": 42, "zebra": 100},
        },
        {
            "id": "key_order_variant_b",
            "description": "Key order test variant B (keys defined in scrambled order, must produce identical bytes to variant A)",
            "input": {"zebra": 100, "apple": "alpha", "middle": 42},
        },
        {
            "id": "nested_structures",
            "description": "Nested objects, arrays, boolean, and null primitives",
            "input": {
                "active": True,
                "count": 10,
                "data": None,
                "flags": [True, False, None],
                "nested": {"a": [1, 2, 3], "b": 2},
            },
        },
        {
            "id": "unicode_accents_and_scripts",
            "description": "Unicode characters (Latin accents, Greek, kanji, section symbol) preserved in UTF-8",
            "input": {
                "accents": "naïve café",
                "greek": "Ωμέγα",
                "kanji": "監査",
                "section": "§",
            },
        },
        {
            "id": "unicode_non_bmp",
            "description": "Unicode non-BMP characters (emoji and biology symbols) preserved in UTF-8",
            "input": {
                "emoji": "🔬",
                "label": "laboratory",
                "symbol": "🧬",
            },
        },
        {
            "id": "unicode_precomposed_e_acute",
            "description": "Precomposed e-acute (U+00E9); must differ in bytes and hash from decomposed variant",
            "input": {"label": "caf\u00e9"},
        },
        {
            "id": "unicode_decomposed_e_acute",
            "description": "Decomposed e + combining acute accent (U+0065 U+0301); must differ in bytes and hash from precomposed variant",
            "input": {"label": "cafe\u0301"},
        },
    ]

    canonical_json_vectors = []
    for item in canonical_inputs:
        raw_bytes = canonical_json_bytes(item["input"])
        digest = sha256_hex(raw_bytes)
        canonical_json_vectors.append({
            "id": item["id"],
            "description": item["description"],
            "input": item["input"],
            "expected_utf8_hex": raw_bytes.hex(),
            "expected_sha256": digest,
        })

    # 2. Merkle Root vectors
    merkle_inputs = [
        {
            "id": "empty_records",
            "description": "Empty record list produces sha256 of empty bytes",
            "records": [],
        },
        {
            "id": "single_leaf_record",
            "description": "Single record (odd leaf count: 1) where root equals the leaf hash",
            "records": [
                {"id": "synth-rec-1", "type": "AUDIT_EVENT", "value": 100},
            ],
        },
        {
            "id": "two_leaf_records",
            "description": "Two records (even leaf count: 2) combined via sha256(h0 + h1)",
            "records": [
                {"id": "synth-rec-1", "type": "AUDIT_EVENT", "value": 100},
                {"id": "synth-rec-2", "type": "AUDIT_EVENT", "value": 200},
            ],
        },
        {
            "id": "three_leaf_records",
            "description": "Three records (odd leaf count: 3) requiring duplication of the third leaf hash",
            "records": [
                {"id": "synth-rec-1", "type": "AUDIT_EVENT", "value": 100},
                {"id": "synth-rec-2", "type": "AUDIT_EVENT", "value": 200},
                {"id": "synth-rec-3", "type": "AUDIT_EVENT", "value": 300},
            ],
        },
        {
            "id": "four_leaf_records",
            "description": "Four records (even leaf count: 4) forming a balanced 2-level binary tree",
            "records": [
                {"id": "synth-rec-1", "type": "AUDIT_EVENT", "value": 100},
                {"id": "synth-rec-2", "type": "AUDIT_EVENT", "value": 200},
                {"id": "synth-rec-3", "type": "AUDIT_EVENT", "value": 300},
                {"id": "synth-rec-4", "type": "AUDIT_EVENT", "value": 400},
            ],
        },
    ]

    merkle_root_vectors = []
    for item in merkle_inputs:
        leaf_hashes = [leaf_hash_hex(rec) for rec in item["records"]]
        root = merkle_root_hex(item["records"])
        merkle_root_vectors.append({
            "id": item["id"],
            "description": item["description"],
            "leaf_count": len(item["records"]),
            "records": item["records"],
            "expected_leaf_hashes": leaf_hashes,
            "expected_merkle_root": root,
        })

    # 3. Two-block chain vector
    genesis_prev = "0" * 64
    b0_records = [
        {"action": "INIT_SYSTEM", "code": 100},
        {"action": "REGISTER_SCHEMA", "code": 101},
    ]
    b0_root = merkle_root_hex(b0_records)
    b0_payload_bytes, b0_hash = block_payload_and_hash(0, genesis_prev, b0_root, b0_records)

    b1_records = [
        {"action": "INGEST_RECORD", "code": 201},
        {"action": "VERIFY_POLICY", "code": 202},
        {"action": "ARCHIVE_RECORD", "code": 203},
    ]
    b1_root = merkle_root_hex(b1_records)
    b1_payload_bytes, b1_hash = block_payload_and_hash(1, b0_hash, b1_root, b1_records)

    chain_vectors = [
        {
            "id": "two_block_chain",
            "description": "Two-block sealed ledger chain demonstrating genesis Block 0 and linked Block 1",
            "blocks": [
                {
                    "height": 0,
                    "previous_hash": genesis_prev,
                    "records": b0_records,
                    "expected_merkle_root": b0_root,
                    "expected_canonical_payload_hex": b0_payload_bytes.hex(),
                    "expected_block_hash": b0_hash,
                },
                {
                    "height": 1,
                    "previous_hash": b0_hash,
                    "records": b1_records,
                    "expected_merkle_root": b1_root,
                    "expected_canonical_payload_hex": b1_payload_bytes.hex(),
                    "expected_block_hash": b1_hash,
                },
            ],
        }
    ]

    return {
        "version": 1,
        "description": (
            "Cryptographic golden test vectors for canonical JSON and Merkle hashes. "
            "Invented synthetic test data only. Every vector change requires manual cryptographic review."
        ),
        "canonical_json_vectors": canonical_json_vectors,
        "merkle_root_vectors": merkle_root_vectors,
        "chain_vectors": chain_vectors,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Independent reference generator for cryptographic golden test vectors."
    )
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Path where the fixture JSON file must be written (required; no default).",
    )
    args = parser.parse_args()

    output_path = args.output.resolve()
    data = build_fixture_data()

    # json.dumps with indent=2, ensure_ascii=True (so all non-ASCII are escaped as \\uXXXX),
    # sort_keys=False preserving fixed dict order.
    serialized = json.dumps(data, indent=2, ensure_ascii=True) + "\n"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(serialized)

    print(f"Successfully generated cryptographic golden vectors to: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
