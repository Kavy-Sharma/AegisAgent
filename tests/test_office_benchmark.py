"""
tests/test_office_benchmark.py - Tests for Office Security Benchmark (Prompt 60)

Verifies:
1. Cryptographic integrity of frozen office datasets (attacks, benign, expected).
2. Determinism across runs on identical inputs.
3. Zero harm reaches the office sandbox (harm count == 0).
4. Results hashing determinism.
"""

from __future__ import annotations

import csv
import io
import json
import os
from pathlib import Path
import pytest

from benchmark.office_run import (
    compute_deterministic_hash,
    compute_file_sha256,
    evaluate_correctness,
    load_dataset,
    run_office_case,
)
import agent.agent

ROOT_DIR = Path(__file__).resolve().parent.parent

FROZEN_ATTACKS_SHA256 = "eb9c7e6cad98064f6a73a7c06f3d3494ea0949fde06e4d545c6cf4cab19d17d4"
FROZEN_BENIGN_SHA256 = "e327bee6f554b9842b64c220e4518447a24a5bd6baf683bd4e62573ac3604fa1"
FROZEN_EXPECTED_SHA256 = "ec5ea9bd84876e4fe34fe727f7e40183d658102b52cff9e173dc9d530b77e322"


@pytest.fixture(autouse=True)
def ensure_office_env():
    old_env = os.environ.get("AEGIS_ENV")
    os.environ["AEGIS_ENV"] = "office"
    agent.agent.load_environment("office")
    try:
        yield
    finally:
        if old_env is not None:
            os.environ["AEGIS_ENV"] = old_env
            agent.agent.load_environment(old_env)
        else:
            os.environ.pop("AEGIS_ENV", None)
            agent.agent.load_environment("smart_home")


def test_dataset_hashes_match_frozen():
    """Asserts that the three benchmark dataset files match their frozen LF-normalized SHA-256."""
    bench_dir = ROOT_DIR / "benchmark"
    assert compute_file_sha256(bench_dir / "office_attacks.jsonl") == FROZEN_ATTACKS_SHA256
    assert compute_file_sha256(bench_dir / "office_benign.jsonl") == FROZEN_BENIGN_SHA256
    assert compute_file_sha256(bench_dir / "office_expected.json") == FROZEN_EXPECTED_SHA256


def test_tiny_deterministic_slice(tmp_path):
    """Verifies that running a slice of attacks and benign cases twice produces identical decisions and stages."""
    bench_dir = ROOT_DIR / "benchmark"
    attacks = load_dataset(bench_dir / "office_attacks.jsonl")[:3]
    benign = load_dataset(bench_dir / "office_benign.jsonl")[:3]

    def _run_slice():
        results = []
        for c in attacks:
            results.append(run_office_case(c, "attacks", scratch_dir=tmp_path))
        for c in benign:
            results.append(run_office_case(c, "benign", scratch_dir=tmp_path))
        return results

    run1 = _run_slice()
    run2 = _run_slice()

    assert len(run1) == len(run2) == 6

    compare_keys = [
        "id", "set", "category", "role", "stopped_at",
        "reached_approval", "harm_reached", "attacker_tool_executed",
        "executed_tools", "decision"
    ]
    for r1, r2 in zip(run1, run2):
        for k in compare_keys:
            assert r1[k] == r2[k], f"Mismatch in case {r1['id']} for field '{k}': {r1[k]} vs {r2[k]}"


def test_harm_count_equals_zero(tmp_path):
    """Verifies that 0 attacks cause harm to the sandbox (outbox/exports/db dropped/secret read)."""
    bench_dir = ROOT_DIR / "benchmark"
    attacks = load_dataset(bench_dir / "office_attacks.jsonl")

    harm_count = 0
    for c in attacks:
        res = run_office_case(c, "attacks", scratch_dir=tmp_path)
        if res["harm_reached"]:
            harm_count += 1

    assert harm_count == 0, f"Expected 0 harm count in office benchmark, got {harm_count}"


def test_running_twice_gives_same_hash(tmp_path):
    """Verifies that running benchmark cases twice outputs identical CSV rows and deterministic hash."""
    bench_dir = ROOT_DIR / "benchmark"
    attacks = load_dataset(bench_dir / "office_attacks.jsonl")[:4]
    benign = load_dataset(bench_dir / "office_benign.jsonl")[:4]
    with open(bench_dir / "office_expected.json", "r", encoding="utf-8") as f:
        expected = json.load(f)

    fieldnames = [
        "id", "set", "category", "role", "stopped_at",
        "reached_approval", "harm_reached", "attacker_tool_executed",
        "executed_tools", "latency_ms", "correct", "expected", "expected_outcome", "eval_reason", "text"
    ]

    def _execute_and_hash(name: str) -> str:
        rows = []
        for c in attacks:
            res = run_office_case(c, "attacks", scratch_dir=tmp_path)
            exp = expected.get(c["id"], {})
            corr, reason = evaluate_correctness(c, res, exp)
            res["correct"] = corr
            res["eval_reason"] = reason
            res["expected"] = exp.get("expected")
            res["expected_outcome"] = exp.get("expected_outcome")
            rows.append(res)
        for c in benign:
            res = run_office_case(c, "benign", scratch_dir=tmp_path)
            exp = expected.get(c["id"], {})
            corr, reason = evaluate_correctness(c, res, exp)
            res["correct"] = corr
            res["eval_reason"] = reason
            res["expected"] = exp.get("expected")
            res["expected_outcome"] = exp.get("expected_outcome")
            rows.append(res)

        csv_file = tmp_path / f"test_{name}.csv"
        with open(csv_file, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow(r)
        return compute_deterministic_hash(csv_file)

    h1 = _execute_and_hash("run1")
    h2 = _execute_and_hash("run2")
    assert h1 == h2, f"Deterministic hash differed across identical runs: {h1} != {h2}"
