"""Synthetic Merkle benchmarks using pytest-benchmark.

These benchmarks measure:
1. merkle_root() computation across odd and even leaf counts (widths).
2. verify_chain() performance across documented chain depths (e.g. 10, 100, 1000 blocks).
3. verify_chain() tamper detection performance near the beginning and end of a chain.

Run with:
    pytest -m performance --benchmark-only
Or emit JSON results:
    pytest -m performance --benchmark-only --benchmark-json=benchmark_results.json
"""

from __future__ import annotations

import copy
import random
from typing import Any

import pytest

from services.crypto import leaf_hash, merkle_root, seal, verify_chain


def _generate_deterministic_records(count: int, seed: int = 42) -> list[dict[str, Any]]:
    rng = random.Random(seed)
    return [
        {
            "id": i,
            "type": "OTP_ISSUED",
            "subject_key": f"subj-{rng.randint(1000, 9999)}",
            "physician_id": f"PHY-{rng.randint(100, 999)}",
            "payload_hash": f"{rng.getrandbits(256):064x}",
        }
        for i in range(count)
    ]


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


@pytest.mark.performance
@pytest.mark.parametrize("leaf_count", [0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32])
def test_benchmark_merkle_root_width(benchmark, leaf_count: int):
    """Benchmark Merkle root calculation across representative even/odd leaf widths."""
    records = _generate_deterministic_records(leaf_count, seed=leaf_count + 100)
    result = benchmark(merkle_root, records)
    assert isinstance(result, str)
    assert len(result) == 64


@pytest.mark.performance
@pytest.mark.parametrize("depth", [10, 100, 1000])
def test_benchmark_verify_chain_depth(benchmark, depth: int):
    """Benchmark verify_chain() performance across documented chain depths."""
    chain = _generate_deterministic_chain(depth, seed=depth + 500)
    result = benchmark(verify_chain, chain)
    assert result is True


@pytest.mark.performance
@pytest.mark.parametrize("tamper_position", ["beginning", "end"])
@pytest.mark.parametrize("depth", [10, 100, 1000])
def test_benchmark_tamper_detection(benchmark, depth: int, tamper_position: str):
    """Benchmark verify_chain() tamper detection at beginning (block 0) vs end (last block)."""
    chain = _generate_deterministic_chain(depth, seed=depth + 1000)
    # Tamper with a deep copy outside the benchmark timer
    tampered_chain = copy.deepcopy(chain)
    target_idx = 0 if tamper_position == "beginning" else (depth - 1)
    tampered_chain[target_idx]["records"][0]["subject_key"] = "tampered-key"

    result = benchmark(verify_chain, tampered_chain)
    assert result is False
