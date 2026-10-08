from __future__ import annotations

import copy
import random
from typing import Any

import pytest

from services.crypto import merkle_root, seal, verify_chain


def _generate_deterministic_chain(depth: int, seed: int = 42) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    chain: list[dict[str, Any]] = []
    previous = "0" * 64
    for i in range(depth):
        event = {
            "height": i,
            "type": "OTP_ISSUED",
            "subject_key": f"subj-{rng.randint(1000, 9999)}",
            "physician_id": f"PHY-{rng.randint(100, 999)}",
            "payload_hash": f"{rng.getrandbits(256):064x}",
        }
        block = seal([event], previous, i)
        chain.append(block)
        previous = block["block_hash"]
    return chain


def test_merkle_root_is_deterministic_and_detects_mutation():
    records = [{"kind": "dicom", "object_key": "abc"}, {"kind": "xml", "object_key": "def"}]
    assert merkle_root(records) == merkle_root(list(records))
    first = seal(records, "0" * 64, 0)
    second = seal([{"type": "OTP_ISSUED", "subject_key": "subj-1"}], first["block_hash"], 1)
    assert verify_chain([first, second])
    first_tampered = copy.deepcopy(first)
    first_tampered["records"][0]["object_key"] = "tampered"
    assert verify_chain([first_tampered, second]) is False


def test_empty_ledger_verifies():
    assert verify_chain([])


@pytest.mark.parametrize("depth", [10, 100])
def test_untouched_deterministic_chain_verifies(depth: int):
    chain = _generate_deterministic_chain(depth, seed=depth)
    assert verify_chain(chain) is True


@pytest.mark.parametrize("depth", [10, 100])
def test_tamper_head_record_fails_verification(depth: int):
    chain = _generate_deterministic_chain(depth, seed=depth)
    tampered_chain = copy.deepcopy(chain)
    tampered_chain[0]["records"][0]["subject_key"] = "tampered-head-subject"
    assert verify_chain(tampered_chain) is False


@pytest.mark.parametrize("depth", [10, 100])
def test_tamper_tip_record_fails_verification(depth: int):
    chain = _generate_deterministic_chain(depth, seed=depth)
    tampered_chain = copy.deepcopy(chain)
    tampered_chain[-1]["records"][0]["subject_key"] = "tampered-tip-subject"
    assert verify_chain(tampered_chain) is False


@pytest.mark.parametrize("depth", [10, 100])
@pytest.mark.parametrize("hash_field", ["merkle_root", "block_hash", "previous_hash"])
@pytest.mark.parametrize("position", ["head", "tip"])
def test_tamper_stored_hash_fields_fails_verification(depth: int, hash_field: str, position: str):
    chain = _generate_deterministic_chain(depth, seed=depth)
    tampered_chain = copy.deepcopy(chain)
    target_idx = 0 if position == "head" else -1
    original_value = tampered_chain[target_idx][hash_field]
    # Alter the hash hex string
    altered_char = "f" if original_value[0] != "f" else "0"
    tampered_chain[target_idx][hash_field] = altered_char + original_value[1:]
    assert verify_chain(tampered_chain) is False
