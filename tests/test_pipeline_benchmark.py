"""
Tests for Full Pipeline Security Benchmark Runner (Phase 9B).
Verifies:
1. Determinism across runs on identical inputs.
2. Complete independence from expected outcome fields during execution.
3. Zero side effects on real hardware, real audit logs, and system state.
4. Cryptographic integrity of the frozen benign paraphrase dataset.
"""

import copy
import hashlib
import json
from pathlib import Path
import pytest

from benchmark.pipeline_run import compute_file_sha256, load_dataset, run_pipeline_case
import security.hardware
import security.logger

ROOT_DIR = Path(__file__).resolve().parent.parent
FROZEN_PARAPHRASE_SHA256 = "501c5e919519710f28a8161062c965c2ecc057cc828dfa7d3cb6c470675bed60"  # LF-normalised file hash


def test_tiny_slice_deterministic(tmp_path):
    attacks_file = ROOT_DIR / "benchmark" / "attacks.jsonl"
    benign_file = ROOT_DIR / "benchmark" / "benign_paraphrase.jsonl"

    attacks = load_dataset(attacks_file)[:3]
    benign = load_dataset(benign_file)[:3]

    def _run_all():
        results = []
        for c in attacks:
            results.append(run_pipeline_case(c, "attacks", scratch_dir=tmp_path))
        for c in benign:
            results.append(run_pipeline_case(c, "benign_paraphrase", scratch_dir=tmp_path))
        return results

    run1 = _run_all()
    run2 = _run_all()

    assert len(run1) == len(run2) == 6

    compare_keys = [
        "id",
        "set",
        "stopped_at",
        "reached_approval",
        "dangerous_action_reached_home",
        "attacker_tool_executed",
        "executed_tools",
        "decision",
    ]

    for r1, r2 in zip(run1, run2):
        for k in compare_keys:
            assert r1[k] == r2[k], f"Mismatch in case {r1['id']} for field '{k}': {r1[k]} vs {r2[k]}"


def test_results_independent_of_expected_fields(tmp_path):
    attacks_file = ROOT_DIR / "benchmark" / "attacks.jsonl"
    benign_file = ROOT_DIR / "benchmark" / "benign_paraphrase.jsonl"

    attacks = load_dataset(attacks_file)[:3]
    benign = load_dataset(benign_file)[:3]

    orig_cases = attacks + benign
    stripped_cases = []
    for c in orig_cases:
        c_copy = copy.deepcopy(c)
        c_copy.pop("expected", None)
        c_copy.pop("expected_outcome", None)
        stripped_cases.append(c_copy)

    compare_keys = [
        "id",
        "stopped_at",
        "reached_approval",
        "dangerous_action_reached_home",
        "attacker_tool_executed",
        "executed_tools",
        "decision",
    ]

    for orig, stripped in zip(orig_cases, stripped_cases):
        dataset_name = "attacks" if orig["id"].startswith("ATT") else "benign_paraphrase"
        r_orig = run_pipeline_case(orig, dataset_name, scratch_dir=tmp_path)
        r_stripped = run_pipeline_case(stripped, dataset_name, scratch_dir=tmp_path)

        for k in compare_keys:
            assert r_orig[k] == r_stripped[k], f"Field '{k}' differed when expected labels were stripped: {r_orig[k]} != {r_stripped[k]}"


def test_real_audit_log_and_hardware_untouched(tmp_path):
    real_audit_log = ROOT_DIR / "data" / "audit_log.jsonl"
    audit_exists_before = real_audit_log.exists()
    audit_sha_before = compute_file_sha256(real_audit_log) if audit_exists_before else None

    old_bridge = getattr(security.hardware, "_bridge_instance", None)

    attacks_file = ROOT_DIR / "benchmark" / "attacks.jsonl"
    benign_file = ROOT_DIR / "benchmark" / "benign_paraphrase.jsonl"
    sample = load_dataset(attacks_file)[:2] + load_dataset(benign_file)[:2]

    for c in sample:
        d_name = "attacks" if c["id"].startswith("ATT") else "benign_paraphrase"
        run_pipeline_case(c, d_name, scratch_dir=tmp_path)

    # 1. Audit log invariance
    if audit_exists_before:
        assert real_audit_log.exists(), "Real audit log was unexpectedly deleted"
        audit_sha_after = compute_file_sha256(real_audit_log)
        assert audit_sha_before == audit_sha_after, "Real audit log was modified during benchmark run!"
    else:
        assert not real_audit_log.exists(), "Real audit log was unexpectedly created in production location!"

    # 2. Hardware bridge invariance
    active_bridge = getattr(security.hardware, "_bridge_instance", None)
    assert active_bridge is old_bridge, "Hardware bridge instance was not properly restored!"


def test_benign_paraphrase_frozen_sha256():
    benign_file = ROOT_DIR / "benchmark" / "benign_paraphrase.jsonl"
    assert benign_file.exists(), "benchmark/benign_paraphrase.jsonl does not exist"

    sha = compute_file_sha256(benign_file)
    assert sha == FROZEN_PARAPHRASE_SHA256, (
        f"benchmark/benign_paraphrase.jsonl has been altered! Expected {FROZEN_PARAPHRASE_SHA256}, got {sha}"
    )

