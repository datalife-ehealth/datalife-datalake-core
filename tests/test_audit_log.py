"""Audit log regression tests for field hashing, immutability, and tamper detection."""

from __future__ import annotations

import copy

from fastapi.testclient import TestClient
import pytest

from api.routes.access import audit_log, reset_access_store
from main import app
from services.crypto import seal, verify_chain


@pytest.fixture(autouse=True)
def clean_state():
    """Reset shared audit log and grant store before and after each test."""
    reset_access_store()
    yield
    reset_access_store()


def _populate_chain_via_api(count: int = 3) -> None:
    client = TestClient(app)
    for i in range(count):
        response = client.post(
            "/api/v1/access/otp",
            json={
                "subject_key": f"subj-{i:04d}",
                "physician_id": "PHY-0001",
                "ttl_seconds": 900,
            },
        )
        assert response.status_code == 200


def test_audit_log_blocks_have_exact_seal_keys():
    """Every block returned by audit_log() has exactly the keys that seal() returns."""
    _populate_chain_via_api(3)
    blocks = audit_log()
    assert len(blocks) == 3

    expected_keys = set(seal([], "0" * 64, 0).keys())
    for block in blocks:
        assert set(block.keys()) == expected_keys


def test_mutating_returned_data_does_not_affect_internal_state():
    """Mutating returned audit data does not mutate internal ledger state."""
    client = TestClient(app)
    _populate_chain_via_api(3)

    original_snapshot = audit_log()
    mutated_copy = audit_log()
    assert mutated_copy == original_snapshot

    # 1. Change a nested record value
    mutated_copy[0]["records"][0]["subject_key"] = "tampered-subj"
    # 2. Replace merkle_root and block_hash on a returned block
    mutated_copy[1]["merkle_root"] = "0" * 64
    mutated_copy[1]["block_hash"] = "f" * 64
    # 3. Append to the returned list
    mutated_copy.append({"height": 99, "extra": "data"})

    # Fresh audit_log() must still equal the original snapshot
    fresh_blocks = audit_log()
    assert fresh_blocks == original_snapshot
    assert verify_chain(fresh_blocks) is True

    verify_resp = client.get("/api/v1/audit/verify")
    assert verify_resp.status_code == 200
    assert verify_resp.json() == {"ok": True, "height": 3}


def test_tampering_with_returned_copy_is_detected():
    """Tampering with a returned copy is detected at head and tip."""
    _populate_chain_via_api(3)
    chain = audit_log()
    assert verify_chain(chain) is True

    # Tamper with head (block 0)
    head_tampered = copy.deepcopy(chain)
    head_tampered[0]["records"][0]["subject_key"] = "tampered-head-key"
    assert verify_chain(head_tampered) is False

    # Tamper with tip (last block)
    tip_tampered = copy.deepcopy(chain)
    tip_tampered[-1]["records"][0]["subject_key"] = "tampered-tip-key"
    assert verify_chain(tip_tampered) is False
