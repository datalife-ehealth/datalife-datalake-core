"""Concurrency regression tests for access endpoints and audit ledger."""

from __future__ import annotations

import concurrent.futures
import threading
import time
from typing import Any

from fastapi.testclient import TestClient
import pytest

from api.routes.access import audit_log, reset_access_store
import api.routes.access as access_module
from main import app
from services.crypto import verify_chain


@pytest.fixture(autouse=True)
def clean_state():
    """Reset shared audit log and grant store before and after each test."""
    reset_access_store()
    yield
    reset_access_store()


def test_concurrent_otp_requests():
    """Verify bounded parallel OTP requests maintain token uniqueness and chain integrity.

    Note: This is a basic sanity check. Under CPython's GIL, this simple test can
    sometimes pass even without a lock because the race window in pure Python is small.
    test_concurrent_interleaved_audit_appends is the true regression test.
    """
    client = TestClient(app)
    num_workers = 25
    barrier = threading.Barrier(num_workers)

    def worker(worker_id: int) -> dict[str, Any]:
        barrier.wait()  # Synchronize workers to hit the endpoint at the exact same moment
        response = client.post(
            "/api/v1/access/otp",
            json={
                "subject_key": f"subj-{worker_id:04d}",
                "physician_id": "PHY-0001",
                "ttl_seconds": 900,
            },
        )
        return {"status_code": response.status_code, "json": response.json()}

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(worker, i) for i in range(num_workers)]
        results = [f.result() for f in futures]

    # 1. All requests succeeded
    for res in results:
        assert res["status_code"] == 200, f"Request failed: {res}"

    # 2. Assert no duplicate tokens
    tokens = [res["json"]["token"] for res in results]
    assert len(tokens) == num_workers
    assert len(set(tokens)) == num_workers, f"Duplicate tokens detected! {len(set(tokens))} unique out of {num_workers}"

    # 3. Assert contiguous unique heights and correct chain linkage
    audit_blocks = audit_log()
    assert len(audit_blocks) == num_workers

    heights = [b.get("height") for b in audit_blocks]
    assert heights == list(range(num_workers)), f"Corrupted/duplicate block heights: {heights}"

    previous = "0" * 64
    for i, block in enumerate(audit_blocks):
        assert block.get("previous_hash") == previous, (
            f"Broken chain link at index {i}: expected previous_hash={previous}, got {block.get('previous_hash')}"
        )
        previous = block.get("block_hash")

    # 4. Final verify_chain passes and verify endpoint returns ok=True
    assert verify_chain(audit_blocks) is True
    verify_resp = client.get("/api/v1/audit/verify")
    assert verify_resp.status_code == 200
    assert verify_resp.json() == {"ok": True, "height": num_workers}


def test_concurrent_interleaved_audit_appends(monkeypatch):
    """Ensure that under forced thread interleaving, unlocked code fails and locked code passes.

    Monkeypatches access_module.seal with a small sleep to hold threads inside the race window
    between reading the previous block/height and appending the sealed block to the audit log.
    Calls the real, unmodified _append() through the API without touching any internal locks.
    """
    reset_access_store()
    client = TestClient(app)
    num_workers = 10
    barrier = threading.Barrier(num_workers)

    orig_seal = access_module.seal

    def delayed_seal(*args: Any, **kwargs: Any) -> dict[str, Any]:
        time.sleep(0.005)
        return orig_seal(*args, **kwargs)

    monkeypatch.setattr(access_module, "seal", delayed_seal)

    def worker(worker_id: int) -> dict[str, Any]:
        barrier.wait()
        response = client.post(
            "/api/v1/access/otp",
            json={
                "subject_key": f"subj-{worker_id:04d}",
                "physician_id": "PHY-0001",
                "ttl_seconds": 900,
            },
        )
        return {"status_code": response.status_code, "json": response.json()}

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(worker, i) for i in range(num_workers)]
        results = [f.result() for f in futures]

    # 1. Assert all responses are 200
    for res in results:
        assert res["status_code"] == 200, f"Request failed: {res}"

    # 2. Assert tokens are unique
    tokens = [res["json"]["token"] for res in results]
    assert len(tokens) == num_workers
    assert len(set(tokens)) == num_workers, f"Duplicate tokens detected: {tokens}"

    # 3. Assert block heights are exactly list(range(num_workers))
    audit_blocks = audit_log()
    assert len(audit_blocks) == num_workers
    heights = [b.get("height") for b in audit_blocks]
    assert heights == list(range(num_workers)), f"Duplicate/corrupted block heights: {heights}"

    # 4. Assert each previous_hash equals the prior block's block_hash
    previous = "0" * 64
    for i, block in enumerate(audit_blocks):
        assert block.get("previous_hash") == previous, (
            f"Broken chain link at index {i}: expected previous_hash={previous}, got {block.get('previous_hash')}"
        )
        previous = block.get("block_hash")

    # 5. Assert verify_chain on the log is True
    assert verify_chain(audit_blocks) is True
