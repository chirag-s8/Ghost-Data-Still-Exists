#!/usr/bin/env python3
"""main.py – Ghost Data Still Exists: Deletion-Audit Agent.

Usage:
    python code/main.py [--sample]

  --sample  : run against sample_deletion_requests.csv and compare with
              sample_output.csv for accuracy measurement.

Output:
    output.csv at the repository root (518 rows for full run).
    If --sample, also prints accuracy metrics to stderr.

Architecture:
    loader.py        – Load all dataset CSVs and the evidence manifest.
    identity.py      – Resolve current and historical identifiers for a subject.
    intent.py        – Classify whether request_text authorizes deletion.
    evidence_index.py– Parse all 94 evidence files into a unified record list.
    policy.py        – Map data categories to required actions.
    planner.py       – Build ordered findings + remediation + verification steps.
    investigator.py  – Per-case orchestration of the above components.
    validator.py     – Automated output schema checks.
"""
from __future__ import annotations

import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from typing import List

# Add code/ to path so imports work when run from root
_CODE_DIR = os.path.dirname(os.path.abspath(__file__))
if _CODE_DIR not in sys.path:
    sys.path.insert(0, _CODE_DIR)

from loader import (
    load_deletion_requests,
    load_sample_requests,
    load_user_identities,
    load_audit_log,
    load_deletion_rules,
    load_evidence_manifest,
    load_system_activity,
    load_sample_output,
)
from identity import IdentityResolver
from evidence_index import EvidenceIndex
from investigator import investigate


ROOT = os.path.dirname(_CODE_DIR)
DATASET = os.path.join(ROOT, "dataset")
OUTPUT_PATH = os.path.join(ROOT, "output.csv")


def write_output(results, path: str) -> None:
    """Write the output CSV to path, sorted by case_id."""
    sorted_results = sorted(results, key=lambda r: r.case_id)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for r in sorted_results:
            row = r.to_row()
            writer.writerow([row["case_id"], row["deletion_status"], row["steps_json"]])
    print(f"  Wrote {len(sorted_results)} rows to {path}", file=sys.stderr)


def compare_with_sample(results, sample_output: dict) -> None:
    """Compare results against sample_output.csv and print accuracy metrics."""
    total = 0
    status_correct = 0
    step_correct = 0
    field_total = 0
    field_correct = 0

    for r in results:
        cid = r.case_id
        if cid not in sample_output:
            continue
        total += 1
        expected = sample_output[cid]
        expected_status = expected["deletion_status"]
        predicted_status = r.deletion_status

        if predicted_status == expected_status:
            status_correct += 1

        # Compare steps
        try:
            exp_steps = json.loads(expected["steps_json"])
        except Exception:
            exp_steps = []
        pred_steps = [s.to_dict() for s in r.steps]

        # Step-level: check if step lists match (same length + same content)
        if len(exp_steps) == len(pred_steps):
            all_match = True
            for es, ps in zip(exp_steps, pred_steps):
                # Compare key fields (allow key-order independence)
                for key in ("phase", "system_id", "resource_id", "operation", "state"):
                    field_total += 1
                    if str(es.get(key, "")) == str(ps.get(key, "")):
                        field_correct += 1
                    else:
                        all_match = False
                # evidence_id: only compare if FINDING or COMPLETE VERIFICATION
                field_total += 1
                if es.get("phase") in ("FINDING",) or (predicted_status == "COMPLETE" and es.get("phase") == "VERIFICATION"):
                    if es.get("evidence_id", "") == ps.get("evidence_id", ""):
                        field_correct += 1
                    else:
                        all_match = False
                else:
                    # REMEDIATION and INCOMPLETE VERIFICATION: just check it's ""
                    if ps.get("evidence_id", "") == "":
                        field_correct += 1
                    else:
                        all_match = False
            if all_match:
                step_correct += 1
        else:
            # Different step counts — add field comparisons for expected fields
            for key in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                field_total += len(exp_steps)
            # Count partial credit
            for i, es in enumerate(exp_steps):
                ps = pred_steps[i] if i < len(pred_steps) else {}
                for key in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                    field_total += 1
                    if str(es.get(key, "")) == str(ps.get(key, "")):
                        field_correct += 1

        # Print mismatches
        if predicted_status != expected_status or len(exp_steps) != len(pred_steps):
            pred_step_count = len(pred_steps)
            exp_step_count = len(exp_steps)
            print(f"  MISMATCH {cid}: predicted={predicted_status}({pred_step_count}steps) "
                  f"expected={expected_status}({exp_step_count}steps)", file=sys.stderr)
            if len(pred_steps) <= 6 and len(exp_steps) <= 6:
                for j, (ps, es) in enumerate(zip(pred_steps[:6], exp_steps[:6])):
                    for key in ("phase", "system_id", "resource_id", "operation", "state", "evidence_id"):
                        pv = ps.get(key, "")
                        ev = es.get(key, "")
                        if pv != ev:
                            print(f"    step {j+1} {key}: pred={pv!r} exp={ev!r}", file=sys.stderr)

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"SAMPLE ACCURACY ({total} cases):", file=sys.stderr)
    print(f"  Status accuracy:  {status_correct}/{total} = {status_correct/total*100:.1f}%",
          file=sys.stderr)
    print(f"  Step-exact match: {step_correct}/{total} = {step_correct/total*100:.1f}%",
          file=sys.stderr)
    if field_total:
        print(f"  Field accuracy:   {field_correct}/{field_total} = {field_correct/field_total*100:.1f}%",
              file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)


def main(sample_mode: bool = False) -> int:
    t0 = time.time()
    print("Ghost Data Still Exists — Deletion Audit Agent", file=sys.stderr)
    print(f"  Dataset: {DATASET}", file=sys.stderr)

    # Load data
    print("  Loading identities and audit log...", file=sys.stderr)
    identities = load_user_identities(DATASET)
    audit_log = load_audit_log(DATASET)
    manifest = load_evidence_manifest(DATASET)

    print(f"  Loaded {len(identities)} identities, {len(audit_log)} audit events, "
          f"{len(manifest)} evidence files", file=sys.stderr)

    # Build identity resolver
    resolver = IdentityResolver(identities, audit_log)

    # Build evidence index
    print("  Building evidence index...", file=sys.stderr)
    ev_index = EvidenceIndex()
    ev_index.build(DATASET, manifest)

    # Load requests
    activities = load_system_activity(DATASET)
    activities.sort(key=lambda a: (a.event_time or EPOCH_SORT, a.activity_id))
    if sample_mode:
        requests = load_sample_requests(DATASET)
        sample_output = load_sample_output(DATASET)
        print(f"  Running on {len(requests)} SAMPLE requests", file=sys.stderr)
    else:
        requests = load_deletion_requests(DATASET)
        sample_output = load_sample_output(DATASET)
        print(f"  Running on {len(requests)} evaluation requests", file=sys.stderr)

    # Investigate each case
    results = []
    not_applicable_count = 0
    complete_count = 0
    incomplete_count = 0

    for i, req in enumerate(requests):
        result = investigate(req, resolver, ev_index, activities)
        results.append(result)
        if result.deletion_status == "NOT_APPLICABLE":
            not_applicable_count += 1
        elif result.deletion_status == "COMPLETE":
            complete_count += 1
        else:
            incomplete_count += 1
        if (i + 1) % 50 == 0:
            print(f"  Progress: {i+1}/{len(requests)}", file=sys.stderr)

    t1 = time.time()
    print(f"  Processed {len(results)} cases in {t1-t0:.1f}s", file=sys.stderr)
    print(f"  COMPLETE={complete_count}  INCOMPLETE={incomplete_count}  "
          f"NOT_APPLICABLE={not_applicable_count}", file=sys.stderr)

    # Write output
    write_output(results, OUTPUT_PATH)

    # Compare with sample if available
    if sample_mode:
        compare_with_sample(results, sample_output)
    else:
        # Also compare sample cases for accuracy reporting
        sample_results = [r for r in results if r.case_id in sample_output]
        if sample_results:
            print("\n  Sample case accuracy (within full run):", file=sys.stderr)
            compare_with_sample(sample_results, sample_output)

    # Run validator
    print("\n  Running output validator...", file=sys.stderr)
    from validator import validate_output
    ok, messages = validate_output(OUTPUT_PATH, os.path.join(DATASET, "deletion_requests.csv"))
    for m in messages:
        print(f"  {m}", file=sys.stderr)
    if ok:
        print("  ✓ Validation PASSED", file=sys.stderr)
    else:
        print("  ✗ Validation FAILED", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sample_mode = "--sample" in sys.argv
    sys.exit(main(sample_mode=sample_mode))
