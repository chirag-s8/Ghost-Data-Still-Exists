"""planner.py – Build the ordered steps_json for a deletion case.

Step ordering rules (from problem_statement.md):
  Phase order: FINDING → REMEDIATION → VERIFICATION
  
  Within FINDING (op order per spec):
    1. REPORT_REMAINING_RECORD  (DELETE targets: present)
    2. REPORT_EXPOSED_PII       (REDACT/ANONYMIZE targets: identifiable)
    3. REPORT_ACTIVE_DATA_FLOW  (DATA_FLOW targets: active)
    4. REPORT_RESTORE_RISK      (BACKUP targets: active)
    Then sub-sort: system_id ASC, resource_id ASC

  Within REMEDIATION (op order per spec):
    1. DISABLE_DATA_FLOW
    2. BLOCK_RESTORE
    3. DELETE_RECORD
    4. REDACT_RECORD
    5. ANONYMIZE_RECORD
    Then sub-sort: system_id ASC, resource_id ASC

  Within VERIFICATION (op order per spec):
    1. VERIFY_RECORD_ABSENT
    2. VERIFY_RECORD_PRESENT
    3. VERIFY_RECORD_REDACTED
    4. VERIFY_RECORD_ANONYMIZED
    5. VERIFY_DATA_FLOW_DISABLED
    6. VERIFY_RESTORE_BLOCKED
    Then sub-sort: system_id ASC, resource_id ASC

Remediation dependency rule:
  DISABLE_DATA_FLOW and BLOCK_RESTORE must come before DELETE/REDACT/ANONYMIZE
  on the same or dependent records.

For COMPLETE cases:
  Only VERIFICATION steps with evidence_id = the best evidence file.

For INCOMPLETE cases:
  FINDING steps with real evidence_id
  REMEDIATION steps with evidence_id = ""
  VERIFICATION steps with evidence_id = ""
  EXCEPT: VERIFY_RECORD_PRESENT (retained records) uses the evidence_id that proves presence.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from evidence_index import EvidenceRecord
from policy import PolicyOutcome, get_policy, is_violation, is_already_compliant


# ---------------------------------------------------------------------------
# Step data model
# ---------------------------------------------------------------------------

@dataclass
class AuditStep:
    step_no: int
    phase: str          # FINDING | REMEDIATION | VERIFICATION
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str    # "" for proposed remediation/future verification

    def to_dict(self) -> dict:
        return {
            "step_no": self.step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


# ---------------------------------------------------------------------------
# Operation sort keys
# ---------------------------------------------------------------------------

_FINDING_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
}

_REMEDIATION_ORDER = {
    "DISABLE_DATA_FLOW": 0,
    "BLOCK_RESTORE": 1,
    "DELETE_RECORD": 2,
    "REDACT_RECORD": 3,
    "ANONYMIZE_RECORD": 4,
}

_VERIFICATION_ORDER = {
    "VERIFY_RECORD_ABSENT": 0,
    "VERIFY_RECORD_PRESENT": 1,
    "VERIFY_RECORD_REDACTED": 2,
    "VERIFY_RECORD_ANONYMIZED": 3,
    "VERIFY_DATA_FLOW_DISABLED": 4,
    "VERIFY_RESTORE_BLOCKED": 5,
}


def _sort_key(op: str, system_id: str, resource_id: str,
              phase_order: Dict[str, int]) -> Tuple:
    """Multi-key sort: op_order, system_id, resource_id."""
    return (phase_order.get(op, 99), system_id or "", resource_id or "")


# ---------------------------------------------------------------------------
# Core planner
# ---------------------------------------------------------------------------

@dataclass
class ResourceRecord:
    """A single resource with its latest observed state and evidence file."""
    system_id: str
    resource_id: str
    category: str
    state: str          # observed state at audit_at
    evidence_id: str    # file_id that established this state


def select_best_record_per_resource(records: List[EvidenceRecord]) -> Dict[Tuple[str, str], ResourceRecord]:
    """
    For each (system_id, resource_id) pair, select the record with the
    latest captured_at timestamp. This gives the most recent known state.
    """
    from datetime import datetime, timezone
    EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

    best: Dict[Tuple[str, str], Tuple[ResourceRecord, datetime]] = {}
    for rec in records:
        if not rec.resource_id or not rec.system_id:
            continue
        if not rec.category or rec.category in ("UNKNOWN", "JSON_OTHER", "PDF_TEXT"):
            continue
        key = (rec.system_id, rec.resource_id)
        ts = rec.captured_at or EPOCH
        if key not in best or ts > best[key][1]:
            best[key] = (
                ResourceRecord(
                    system_id=rec.system_id,
                    resource_id=rec.resource_id,
                    category=rec.category,
                    state=rec.state,
                    evidence_id=rec.file_id,
                ),
                ts,
            )
    return {k: v[0] for k, v in best.items()}


def build_steps(
    resource_map: Dict[Tuple[str, str], ResourceRecord],
    account_resource_id: Optional[str],
    security_audit_resource_id: Optional[str],
    best_evidence_id: str,
    is_complete: bool,
) -> List[AuditStep]:
    """
    Build the full ordered step list for a case.

    is_complete: if True, produce only VERIFICATION steps with real evidence_id.
                 if False, produce FINDING + REMEDIATION + VERIFICATION (empty evidence for latter two).
    """
    findings: List[Tuple] = []
    remediations: List[Tuple] = []
    verifications: List[Tuple] = []

    seen_verify: set = set()  # (system_id, resource_id, operation)

    for (sys_id, rid), rr in resource_map.items():
        policy = get_policy(rr.category)
        if not policy:
            continue

        if policy.required_action == "RETAIN":
            # SECURITY_AUDIT_LOG and LEGAL_HOLD_RECORD: always add a VERIFY_RECORD_PRESENT
            vk = (sys_id, rid, "VERIFY_RECORD_PRESENT")
            if vk not in seen_verify:
                seen_verify.add(vk)
                evidence_id = rr.evidence_id if is_complete else ""
                verifications.append((
                    _sort_key("VERIFY_RECORD_PRESENT", sys_id, rid, _VERIFICATION_ORDER),
                    sys_id, rid, "VERIFY_RECORD_PRESENT", "PRESENT", evidence_id
                ))
            continue

        violation = is_violation(rr.category, rr.state)
        compliant = is_already_compliant(rr.category, rr.state)

        if is_complete:
            # Only verification steps proving compliant state
            if compliant and policy.verify_op:
                vk = (sys_id, rid, policy.verify_op)
                if vk not in seen_verify:
                    seen_verify.add(vk)
                    verifications.append((
                        _sort_key(policy.verify_op, sys_id, rid, _VERIFICATION_ORDER),
                        sys_id, rid, policy.verify_op, policy.post_state, rr.evidence_id
                    ))
        else:
            # INCOMPLETE: findings + remediation + verification
            if violation and policy.finding_op:
                findings.append((
                    _sort_key(policy.finding_op, sys_id, rid, _FINDING_ORDER),
                    sys_id, rid, policy.finding_op, policy.finding_state, rr.evidence_id
                ))
                if policy.remediation_op:
                    remediations.append((
                        _sort_key(policy.remediation_op, sys_id, rid, _REMEDIATION_ORDER),
                        sys_id, rid, policy.remediation_op, policy.post_state, ""
                    ))
                if policy.verify_op:
                    vk = (sys_id, rid, policy.verify_op)
                    if vk not in seen_verify:
                        seen_verify.add(vk)
                        verifications.append((
                            _sort_key(policy.verify_op, sys_id, rid, _VERIFICATION_ORDER),
                            sys_id, rid, policy.verify_op, policy.post_state, ""
                        ))
            elif compliant and policy.verify_op:
                # Already compliant — still need verification to confirm
                vk = (sys_id, rid, policy.verify_op)
                if vk not in seen_verify:
                    seen_verify.add(vk)
                    verifications.append((
                        _sort_key(policy.verify_op, sys_id, rid, _VERIFICATION_ORDER),
                        sys_id, rid, policy.verify_op, policy.post_state, ""
                    ))

    # Add account_service VERIFY_RECORD_ABSENT if we know the account resource
    if account_resource_id:
        vk = ("account_service", account_resource_id, "VERIFY_RECORD_ABSENT")
        if vk not in seen_verify:
            seen_verify.add(vk)
            evidence_id = best_evidence_id if is_complete else ""
            verifications.append((
                _sort_key("VERIFY_RECORD_ABSENT", "account_service", account_resource_id,
                          _VERIFICATION_ORDER),
                "account_service", account_resource_id,
                "VERIFY_RECORD_ABSENT", "ABSENT", evidence_id
            ))

    # Sort each phase
    findings.sort(key=lambda x: x[0])
    remediations.sort(key=lambda x: x[0])
    verifications.sort(key=lambda x: x[0])

    # Renumber steps consecutively
    steps: List[AuditStep] = []
    for phase_list in (findings, remediations, verifications):
        for item in phase_list:
            _, sys_id, rid, op, state, eid = item
            phase = "FINDING" if op in _FINDING_ORDER else (
                "REMEDIATION" if op in _REMEDIATION_ORDER else "VERIFICATION")
            steps.append(AuditStep(
                step_no=len(steps) + 1,
                phase=phase,
                system_id=sys_id,
                resource_id=rid,
                operation=op,
                state=state,
                evidence_id=eid,
            ))

    return steps
