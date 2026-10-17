"""Tests for cryptographic golden vectors.

Verifies canonical JSON serialization, leaf hashes, Merkle roots, and sealed
ledger blocks against committed literal golden vectors from tests/fixtures/crypto_vectors_v1.json.
Expected values must NEVER be regenerated at runtime.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from services.crypto import canonical_json, leaf_hash, merkle_root, seal, verify_chain

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "crypto_vectors_v1.json"


def _load_fixture() -> dict[str, Any]:
    with open(FIXTURE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


VECTORS = _load_fixture()


def test_fixture_version():
    """Assert fixture schema version is exactly 1."""
    assert VECTORS.get("version") == 1, (
        f"Unexpected fixture version: {VECTORS.get('version')}"
    )


@pytest.mark.parametrize(
    "vector",
    VECTORS["canonical_json_vectors"],
    ids=[v["id"] for v in VECTORS["canonical_json_vectors"]],
)
def test_canonical_json_bytes_matches_golden(vector: dict[str, Any]):
    """Assert canonical JSON byte serialization matches literal hex in fixture."""
    actual_hex = canonical_json(vector["input"]).hex()
    expected_hex = vector["expected_utf8_hex"]
    assert actual_hex == expected_hex, (
        f"Vector '{vector['id']}' canonical hex mismatch: "
        f"actual={actual_hex} expected={expected_hex}"
    )


@pytest.mark.parametrize(
    "vector",
    VECTORS["canonical_json_vectors"],
    ids=[v["id"] for v in VECTORS["canonical_json_vectors"]],
)
def test_leaf_hash_matches_golden(vector: dict[str, Any]):
    """Assert leaf SHA-256 hash matches literal expected digest."""
    actual_hash = leaf_hash(vector["input"])
    expected_hash = vector["expected_sha256"]
    assert actual_hash == expected_hash, (
        f"Vector '{vector['id']}' leaf hash mismatch: "
        f"actual={actual_hash} expected={expected_hash}"
    )


def test_key_ordering_variants_produce_identical_bytes_and_hash():
    """Verify that differently ordered dictionary keys produce identical canonical bytes and hash."""
    var_a = next(v for v in VECTORS["canonical_json_vectors"] if v["id"] == "key_order_variant_a")
    var_b = next(v for v in VECTORS["canonical_json_vectors"] if v["id"] == "key_order_variant_b")

    bytes_a = canonical_json(var_a["input"])
    bytes_b = canonical_json(var_b["input"])
    assert bytes_a == bytes_b, "Key ordering variant bytes differ"
    assert leaf_hash(var_a["input"]) == leaf_hash(var_b["input"]), "Key ordering variant hashes differ"
    assert bytes_a.hex() == var_a["expected_utf8_hex"]
    assert leaf_hash(var_a["input"]) == var_a["expected_sha256"]


def test_unicode_precomposed_and_decomposed_produce_distinct_hashes():
    """Verify precomposed and decomposed Unicode forms produce distinct bytes and hashes without normalization."""
    pre = next(v for v in VECTORS["canonical_json_vectors"] if v["id"] == "unicode_precomposed_e_acute")
    dec = next(v for v in VECTORS["canonical_json_vectors"] if v["id"] == "unicode_decomposed_e_acute")

    bytes_pre = canonical_json(pre["input"])
    bytes_dec = canonical_json(dec["input"])
    assert bytes_pre != bytes_dec, "Precomposed and decomposed bytes unexpectedly matched"
    assert leaf_hash(pre["input"]) != leaf_hash(dec["input"]), "Precomposed and decomposed hashes unexpectedly matched"
    assert bytes_pre.hex() == pre["expected_utf8_hex"]
    assert bytes_dec.hex() == dec["expected_utf8_hex"]


@pytest.mark.parametrize(
    "vector",
    VECTORS["merkle_root_vectors"],
    ids=[v["id"] for v in VECTORS["merkle_root_vectors"]],
)
def test_merkle_root_matches_golden(vector: dict[str, Any]):
    """Assert Merkle roots for empty, single, even, and odd counts match literal fixture roots."""
    actual_root = merkle_root(vector["records"])
    expected_root = vector["expected_merkle_root"]
    assert actual_root == expected_root, (
        f"Vector '{vector['id']}' Merkle root mismatch: "
        f"actual={actual_root} expected={expected_root}"
    )


@pytest.mark.parametrize(
    "vector",
    [v for v in VECTORS["merkle_root_vectors"] if v["leaf_count"] > 0],
    ids=[v["id"] for v in VECTORS["merkle_root_vectors"] if v["leaf_count"] > 0],
)
def test_merkle_leaf_hashes_match_golden(vector: dict[str, Any]):
    """Assert individual leaf hashes within Merkle record sets match literal fixture leaf hashes."""
    actual_hashes = [leaf_hash(r) for r in vector["records"]]
    expected_hashes = vector["expected_leaf_hashes"]
    assert actual_hashes == expected_hashes, (
        f"Vector '{vector['id']}' leaf hashes mismatch"
    )


@pytest.mark.parametrize(
    "vector",
    VECTORS["chain_vectors"],
    ids=[v["id"] for v in VECTORS["chain_vectors"]],
)
def test_chain_block_sealing_and_verification_matches_golden(vector: dict[str, Any]):
    """Assert sealed ledger blocks match golden roots, block hashes, and chain verifies."""
    cid = vector["id"]
    reconstructed_blocks = []
    for block in vector["blocks"]:
        h = block["height"]
        prev = block["previous_hash"]
        recs = block["records"]
        sealed = seal(recs, prev, h)
        assert sealed["merkle_root"] == block["expected_merkle_root"], (
            f"Chain '{cid}' block {h} root mismatch: "
            f"actual={sealed['merkle_root']} expected={block['expected_merkle_root']}"
        )
        assert sealed["block_hash"] == block["expected_block_hash"], (
            f"Chain '{cid}' block {h} hash mismatch: "
            f"actual={sealed['block_hash']} expected={block['expected_block_hash']}"
        )
        reconstructed_blocks.append(sealed)

    assert verify_chain(reconstructed_blocks) is True, (
        f"Chain '{cid}' verification failed"
    )
