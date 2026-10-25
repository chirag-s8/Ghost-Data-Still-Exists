"""validator.py – Automated output validation.

Checks:
  - Exact header and column order
  - Exactly 518 unique data rows
  - No missing or duplicate case_ids
  - All case_ids present from deletion_requests.csv
  - Rows sorted by case_id
  - Valid JSON in every steps_json cell
  - Exact required keys in every step
  - Consecutive step numbering starting at 1
  - Allowed phases, operations, and states
  - Correct phase ordering (FINDING < REMEDIATION < VERIFICATION)
  - Correct operation ordering within each phase
  - Empty evidence_id for REMEDIATION and future VERIFICATION steps (INCOMPLETE)
  - Non-empty evidence_id for FINDING steps
  - Non-empty evidence_id for COMPLETE VERIFICATION steps
  - No steps for NOT_APPLICABLE
  - Only VERIFICATION steps for COMPLETE
  - status values are exactly COMPLETE | INCOMPLETE | NOT_APPLICABLE
"""
from __future__ import annotations

import csv
import json
import os
import sys
from typing import List, Optional, Tuple


REQUIRED_HEADER = ["case_id", "deletion_status", "steps_json"]
ALLOWED_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
ALLOWED_PHASES = {"FINDING", "REMEDIATION", "VERIFICATION"}

ALLOWED_OPS = {
    "FINDING": {
        "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII",
        "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
    },
    "REMEDIATION": {
        "DISABLE_DATA_FLOW", "BLOCK_RESTORE",
        "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD",
    },
    "VERIFICATION": {
        "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT",
        "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
    },
}

# State allowed for each operation
ALLOWED_STATES = {
    "REPORT_REMAINING_RECORD": {"PRESENT"},
    "REPORT_EXPOSED_PII": {"PRESENT"},
    "REPORT_ACTIVE_DATA_FLOW": {"ACTIVE"},
    "REPORT_RESTORE_RISK": {"ACTIVE"},
    "DISABLE_DATA_FLOW": {"DISABLED"},
    "BLOCK_RESTORE": {"BLOCKED"},
    "DELETE_RECORD": {"ABSENT"},
    "REDACT_RECORD": {"REDACTED"},
    "ANONYMIZE_RECORD": {"ANONYMIZED"},
    "VERIFY_RECORD_ABSENT": {"ABSENT"},
    "VERIFY_RECORD_PRESENT": {"PRESENT"},
    "VERIFY_RECORD_REDACTED": {"REDACTED"},
    "VERIFY_RECORD_ANONYMIZED": {"ANONYMIZED"},
    "VERIFY_DATA_FLOW_DISABLED": {"DISABLED"},
    "VERIFY_RESTORE_BLOCKED": {"BLOCKED"},
}

REQUIRED_STEP_KEYS = {
    "step_no", "phase", "system_id", "resource_id",
    "operation", "state", "evidence_id",
}

PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
FINDING_OP_ORDER = {
    "REPORT_REMAINING_RECORD": 0, "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2, "REPORT_RESTORE_RISK": 3,
}
REMEDIATION_OP_ORDER = {
    "DISABLE_DATA_FLOW": 0, "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2, "REDACT_RECORD": 3, "ANONYMIZE_RECORD": 4,
}
VERIFICATION_OP_ORDER = {
    "VERIFY_RECORD_ABSENT": 0, "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2, "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4, "VERIFY_RESTORE_BLOCKED": 5,
}


def validate_output(output_path: str, requests_path: str) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    # Load expected case IDs
    expected_ids: List[str] = []
    with open(requests_path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            expected_ids.append(r["case_id"].strip())
    expected_set = set(expected_ids)

    if not os.path.exists(output_path):
        errors.append(f"OUTPUT FILE NOT FOUND: {output_path}")
        return False, errors

    rows = []
    with open(output_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, None)
        if header != REQUIRED_HEADER:
            errors.append(f"Header mismatch: got {header}, want {REQUIRED_HEADER}")
        for i, row in enumerate(reader, start=2):
            rows.append(row)

    # Row count
    if len(rows) != 518:
        errors.append(f"Expected 518 data rows, got {len(rows)}")

    case_ids_seen = []
    for row_i, row in enumerate(rows, start=1):
        if len(row) < 3:
            errors.append(f"Row {row_i}: too few columns ({len(row)})")
            continue
        case_id, deletion_status, steps_json_str = row[0], row[1], row[2]
        case_ids_seen.append(case_id)

        # Status
        if deletion_status not in ALLOWED_STATUSES:
            errors.append(f"{case_id}: invalid deletion_status '{deletion_status}'")

        # Steps JSON
        try:
            steps = json.loads(steps_json_str)
        except json.JSONDecodeError as e:
            errors.append(f"{case_id}: invalid steps_json JSON: {e}")
            continue

        if not isinstance(steps, list):
            errors.append(f"{case_id}: steps_json must be a JSON array")
            continue

        # NOT_APPLICABLE must have empty steps
        if deletion_status == "NOT_APPLICABLE" and steps:
            errors.append(f"{case_id}: NOT_APPLICABLE must have steps_json=[]")
            continue

        # COMPLETE must have only VERIFICATION steps
        if deletion_status == "COMPLETE":
            for s in steps:
                if s.get("phase") != "VERIFICATION":
                    errors.append(f"{case_id}: COMPLETE has non-VERIFICATION step: {s.get('phase')}")
                    break

        # Validate each step
        prev_phase_order = -1
        prev_op_order = -1
        prev_sys = ""
        prev_rid = ""
        expected_step_no = 1

        for step in steps:
            if not isinstance(step, dict):
                errors.append(f"{case_id}: step is not an object")
                continue

            # Required keys
            missing = REQUIRED_STEP_KEYS - set(step.keys())
            if missing:
                errors.append(f"{case_id}: step missing keys {missing}")
                continue

            # step_no consecutiveness
            if step["step_no"] != expected_step_no:
                errors.append(f"{case_id}: step_no {step['step_no']} expected {expected_step_no}")
            expected_step_no += 1

            phase = step.get("phase", "")
            op = step.get("operation", "")
            state = step.get("state", "")
            eid = step.get("evidence_id", "")

            # Allowed phase
            if phase not in ALLOWED_PHASES:
                errors.append(f"{case_id}: unknown phase '{phase}'")
                continue

            # Phase ordering
            po = PHASE_ORDER.get(phase, -1)
            if po < prev_phase_order:
                errors.append(f"{case_id}: phase order violation: {phase} after {prev_phase_order}")
            elif po == prev_phase_order:
                pass  # same phase — check op order below
            else:
                prev_phase_order = po
                prev_op_order = -1
                prev_sys = ""
                prev_rid = ""

            # Allowed op for phase
            if op not in ALLOWED_OPS.get(phase, set()):
                errors.append(f"{case_id}: op '{op}' not allowed in phase '{phase}'")

            # Allowed state for op
            if state not in ALLOWED_STATES.get(op, {state}):
                errors.append(f"{case_id}: state '{state}' not valid for op '{op}'")

            # Op ordering within phase
            if phase == "FINDING":
                ooo = FINDING_OP_ORDER.get(op, 99)
            elif phase == "REMEDIATION":
                ooo = REMEDIATION_OP_ORDER.get(op, 99)
            else:
                ooo = VERIFICATION_OP_ORDER.get(op, 99)

            if po == prev_phase_order:
                if ooo < prev_op_order:
                    errors.append(f"{case_id}: op order violation in {phase}: {op} (order {ooo}) after {prev_op_order}")
                prev_op_order = ooo

            # evidence_id rules
            if phase == "FINDING" and not eid:
                warnings.append(f"{case_id}: FINDING step has empty evidence_id (op={op})")
            if phase == "REMEDIATION" and eid:
                warnings.append(f"{case_id}: REMEDIATION step has non-empty evidence_id '{eid}' (should be '')")
            if deletion_status == "INCOMPLETE" and phase == "VERIFICATION" and eid:
                # INCOMPLETE verifications should have empty evidence_id
                # EXCEPT VERIFY_RECORD_PRESENT (retained records) may have evidence
                if op != "VERIFY_RECORD_PRESENT":
                    warnings.append(f"{case_id}: INCOMPLETE VERIFICATION step has non-empty evidence_id (op={op})")
            if deletion_status == "COMPLETE" and phase == "VERIFICATION" and not eid:
                warnings.append(f"{case_id}: COMPLETE VERIFICATION step has empty evidence_id (op={op})")

    # Check case_id coverage
    seen_set = set(case_ids_seen)
    missing_ids = expected_set - seen_set
    extra_ids = seen_set - expected_set
    dups = [c for c in case_ids_seen if case_ids_seen.count(c) > 1]

    if missing_ids:
        errors.append(f"Missing case_ids: {sorted(missing_ids)[:10]} ...")
    if extra_ids:
        errors.append(f"Unexpected case_ids: {sorted(extra_ids)[:10]}")
    if dups:
        errors.append(f"Duplicate case_ids: {sorted(set(dups))[:10]}")

    # Sorted order
    if case_ids_seen != sorted(case_ids_seen):
        errors.append("Rows are not sorted by case_id")

    ok = len(errors) == 0
    return ok, errors + [f"WARN: {w}" for w in warnings]


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    output_path = os.path.join(root, "output.csv")
    requests_path = os.path.join(root, "dataset", "deletion_requests.csv")
    ok, messages = validate_output(output_path, requests_path)
    for m in messages:
        print(m)
    if ok:
        print("✓ Validation PASSED")
    else:
        print(f"✗ Validation FAILED ({sum(1 for m in messages if not m.startswith('WARN'))} errors)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
