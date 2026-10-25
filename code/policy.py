"""policy.py – Apply deletion_rules.csv to determine required action per category.

Rules (from deletion_rules.csv):
  rule_01 USER_PROFILE               Always               DELETE
  rule_02 SECONDARY_IDENTIFIER       Always               DELETE
  rule_03 SEARCH_INDEX_ENTRY         Always               DELETE
  rule_04 CACHE_ENTRY                Always               DELETE
  rule_05 SUPPORT_MESSAGE            Conversation contains shared context  REDACT
  rule_06 SUPPORT_ATTACHMENT         Attachment belongs only to subject    DELETE
  rule_07 ANALYTICS_PROFILE          Still attributable to user            ANONYMIZE
  rule_08 PRODUCT_TELEMETRY          Still attributable to user            ANONYMIZE
  rule_09 USER_EXPORT                Always               DELETE
  rule_10 MARKETING_PROFILE          Always               DELETE
  rule_11 EMAIL_DELIVERY_LOG         Log contains user email               REDACT
  rule_12 SECURITY_AUDIT_LOG         Within retention period               RETAIN
  rule_13 LEGAL_HOLD_RECORD          Legal hold is active                  RETAIN
  rule_14 BACKUP_ARCHIVE             Restore access can be blocked         RETAIN  (block restore)
  rule_15 ACCOUNT_TOMBSTONE          Account deleted, only user_id needed  REDACT

Notes:
- SUPPORT_MESSAGE condition: "Conversation contains shared customer, agent, or order context
  that must be retained" → REDACT (not delete). We treat all support messages as REDACT
  since we cannot verify from evidence whether a conversation is purely solo.
  The sample output (cases 07, 10, 19, 26, etc.) confirms REDACT for support tickets.
- SUPPORT_ATTACHMENT: DELETE when it belongs only to the deletion subject.
- BACKUP_ARCHIVE: policy is RETAIN (keep the backup archive itself) but BLOCK RESTORE
  if restore access can be blocked. So the finding is REPORT_RESTORE_RISK and
  remediation is BLOCK_RESTORE.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

from loader import DeletionRule


# Map category → (required_action, finding_operation, remediation_operation,
#                  verification_operation, finding_state, post_state)
@dataclass
class PolicyOutcome:
    required_action: str    # DELETE | REDACT | ANONYMIZE | RETAIN | BLOCK_RESTORE
    finding_op: str
    remediation_op: Optional[str]
    verify_op: str
    finding_state: str      # PRESENT | IDENTIFIABLE | ACTIVE
    post_state: str         # ABSENT | REDACTED | ANONYMIZED | BLOCKED | PRESENT


# Canonical policy map built from deletion_rules.csv semantics
_POLICY: Dict[str, PolicyOutcome] = {
    "USER_PROFILE": PolicyOutcome(
        required_action="DELETE",
        finding_op="REPORT_REMAINING_RECORD",
        remediation_op="DELETE_RECORD",
        verify_op="VERIFY_RECORD_ABSENT",
        finding_state="PRESENT",
        post_state="ABSENT",
    ),
    "SECONDARY_IDENTIFIER": PolicyOutcome(
        required_action="DELETE",
        finding_op="REPORT_REMAINING_RECORD",
        remediation_op="DELETE_RECORD",
        verify_op="VERIFY_RECORD_ABSENT",
        finding_state="PRESENT",
        post_state="ABSENT",
    ),
    "SEARCH_INDEX_ENTRY": PolicyOutcome(
        required_action="DELETE",
        finding_op="REPORT_REMAINING_RECORD",
        remediation_op="DELETE_RECORD",
        verify_op="VERIFY_RECORD_ABSENT",
        finding_state="PRESENT",
        post_state="ABSENT",
    ),
    "CACHE_ENTRY": PolicyOutcome(
        required_action="DELETE",
        finding_op="REPORT_REMAINING_RECORD",
        remediation_op="DELETE_RECORD",
        verify_op="VERIFY_RECORD_ABSENT",
        finding_state="PRESENT",
        post_state="ABSENT",
    ),
    "SUPPORT_MESSAGE": PolicyOutcome(
        required_action="REDACT",
        finding_op="REPORT_EXPOSED_PII",
        remediation_op="REDACT_RECORD",
        verify_op="VERIFY_RECORD_REDACTED",
        finding_state="PRESENT",
        post_state="REDACTED",
    ),
    "SUPPORT_ATTACHMENT": PolicyOutcome(
        required_action="DELETE",
        finding_op="REPORT_REMAINING_RECORD",
        remediation_op="DELETE_RECORD",
        verify_op="VERIFY_RECORD_ABSENT",
        finding_state="PRESENT",
        post_state="ABSENT",
    ),
    "ANALYTICS_PROFILE": PolicyOutcome(
        required_action="ANONYMIZE",
        finding_op="REPORT_EXPOSED_PII",
        remediation_op="ANONYMIZE_RECORD",
        verify_op="VERIFY_RECORD_ANONYMIZED",
        finding_state="PRESENT",
        post_state="ANONYMIZED",
    ),
    "PRODUCT_TELEMETRY": PolicyOutcome(
        required_action="ANONYMIZE",
        finding_op="REPORT_EXPOSED_PII",
        remediation_op="ANONYMIZE_RECORD",
        verify_op="VERIFY_RECORD_ANONYMIZED",
        finding_state="PRESENT",
        post_state="ANONYMIZED",
    ),
    "USER_EXPORT": PolicyOutcome(
        required_action="DELETE",
        finding_op="REPORT_REMAINING_RECORD",
        remediation_op="DELETE_RECORD",
        verify_op="VERIFY_RECORD_ABSENT",
        finding_state="PRESENT",
        post_state="ABSENT",
    ),
    "MARKETING_PROFILE": PolicyOutcome(
        required_action="DELETE",
        finding_op="REPORT_REMAINING_RECORD",
        remediation_op="DELETE_RECORD",
        verify_op="VERIFY_RECORD_ABSENT",
        finding_state="PRESENT",
        post_state="ABSENT",
    ),
    "EMAIL_DELIVERY_LOG": PolicyOutcome(
        required_action="REDACT",
        finding_op="REPORT_EXPOSED_PII",
        remediation_op="REDACT_RECORD",
        verify_op="VERIFY_RECORD_REDACTED",
        finding_state="PRESENT",
        post_state="REDACTED",
    ),
    "SECURITY_AUDIT_LOG": PolicyOutcome(
        required_action="RETAIN",
        finding_op="",
        remediation_op=None,
        verify_op="VERIFY_RECORD_PRESENT",
        finding_state="PRESENT",
        post_state="PRESENT",
    ),
    "LEGAL_HOLD_RECORD": PolicyOutcome(
        required_action="RETAIN",
        finding_op="",
        remediation_op=None,
        verify_op="VERIFY_RECORD_PRESENT",
        finding_state="PRESENT",
        post_state="PRESENT",
    ),
    "BACKUP_ARCHIVE": PolicyOutcome(
        required_action="BLOCK_RESTORE",
        finding_op="REPORT_RESTORE_RISK",
        remediation_op="BLOCK_RESTORE",
        verify_op="VERIFY_RESTORE_BLOCKED",
        finding_state="ACTIVE",
        post_state="BLOCKED",
    ),
    "ACCOUNT_TOMBSTONE": PolicyOutcome(
        required_action="REDACT",
        finding_op="REPORT_EXPOSED_PII",
        remediation_op="REDACT_RECORD",
        verify_op="VERIFY_RECORD_REDACTED",
        finding_state="PRESENT",
        post_state="REDACTED",
    ),
    "DATA_FLOW": PolicyOutcome(
        required_action="DISABLE",
        finding_op="REPORT_ACTIVE_DATA_FLOW",
        remediation_op="DISABLE_DATA_FLOW",
        verify_op="VERIFY_DATA_FLOW_DISABLED",
        finding_state="ACTIVE",
        post_state="DISABLED",
    ),
}


def get_policy(category: str) -> Optional[PolicyOutcome]:
    return _POLICY.get(category)


# ---------------------------------------------------------------------------
# Violation detection
# A violation exists when a record's current state does not meet policy.
# ---------------------------------------------------------------------------

def is_violation(category: str, state: str) -> bool:
    """Return True if this record's state represents a policy violation."""
    policy = _POLICY.get(category)
    if not policy:
        return False

    action = policy.required_action
    if action == "DELETE":
        # Violation if record still exists (PRESENT or IDENTIFIABLE)
        return state in ("PRESENT", "IDENTIFIABLE")
    if action == "REDACT":
        # Violation if still has direct identifiers
        return state in ("PRESENT", "IDENTIFIABLE")
    if action == "ANONYMIZE":
        # Violation if still identifiable
        return state == "IDENTIFIABLE"
    if action == "RETAIN":
        # No violation — we just need to verify it's PRESENT
        return False
    if action == "BLOCK_RESTORE":
        # Violation if restore is still ACTIVE
        return state == "ACTIVE"
    if action == "DISABLE":
        # Violation if data flow still ACTIVE
        return state == "ACTIVE"
    return False


def is_already_compliant(category: str, state: str) -> bool:
    """Return True if this record already satisfies policy requirements."""
    policy = _POLICY.get(category)
    if not policy:
        return True
    action = policy.required_action
    if action == "DELETE":
        return state == "ABSENT"
    if action == "REDACT":
        return state == "REDACTED"
    if action == "ANONYMIZE":
        return state == "ANONYMIZED"
    if action == "RETAIN":
        return state == "PRESENT"
    if action == "BLOCK_RESTORE":
        return state == "BLOCKED"
    if action == "DISABLE":
        return state == "DISABLED"
    return True
