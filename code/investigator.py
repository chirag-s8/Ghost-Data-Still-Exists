"""investigator.py – Per-case investigation engine."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from evidence_index import EvidenceIndex, EvidenceRecord
from identity import SubjectIdentity
from intent import is_deletion_request
from loader import DeletionRequest
from planner import (
    AuditStep,
    ResourceRecord,
    build_steps,
    select_best_record_per_resource,
)
from policy import get_policy, is_violation, is_already_compliant


EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

#----------------------------------------------------------------------
# Optional pre-mined linkage table (email/user -> account resource ids).
# Built from evidence files the same way the index does; loaded lazily.
#-----------------------------------------------------------------------
_LINKS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "recon", "links.json")
_LINKS = None


def _load_links() -> dict:
    global _LINKS
    if _LINKS is None:
        if os.path.exists(_LINKS_FILE):
            try:
                with open(_LINKS_FILE, encoding="utf-8") as f:
                    _LINKS = json.load(f)
            except Exception:
                _LINKS = {"email_to_account": {}, "user_to_account": {},
                          "search_to_account": {}}
        else:
            _LINKS = {"email_to_account": {}, "user_to_account": {},
                      "search_to_account": {}}
    return _LINKS


class CaseResult:
    def __init__(self, case_id: str, deletion_status: str, steps: List[AuditStep]):
        self.case_id = case_id
        self.deletion_status = deletion_status
        self.steps = steps

    def to_row(self) -> dict:
        steps_list = [s.to_dict() for s in self.steps]
        return {
            "case_id": self.case_id,
            "deletion_status": self.deletion_status,
            "steps_json": json.dumps(steps_list, separators=(",", ":"), ensure_ascii=False),
        }


def _best_evidence_id(records: List[EvidenceRecord]) -> str:
    """Return the file_id with the latest captured_at among matched records."""
    best_id = ""
    best_ts = EPOCH
    for r in records:
        if r.captured_at and r.captured_at > best_ts:
            best_ts = r.captured_at
            best_id = r.file_id
    return best_id


def _find_account_rid(
    records: List[EvidenceRecord],
    subj: SubjectIdentity,
    req: DeletionRequest,
    activity_rows: List,
) -> Tuple[Optional[str], Optional[str], Optional[datetime]]:
    """Find the subject's account resource id + the establishing activity row.

    Priority:
      1. Any evidence record with system account_service and a resource id
         (rid), matched to the subject by email/phone/hash/user id.
      2. Pre-mined email/user -> account rid table.
      3. A unique deletion-worker DELETE_RECORD event naming an account rid
         inside [requested_at, min(audit_at, reported_at + 24h)].
    Returns (rid, activity_id, event_time).
    """
    links = _load_links()

    # 1) evidence-anchored account records
    for r in records:
        if r.system_id == "account_service" and r.resource_id and r.resource_id.startswith("account_"):
            return r.resource_id, None, None

    # 2) mined linkage
    for em in subj.emails:
        rids = links.get("email_to_account", {}).get(em)
        if rids:
            return rids[0], None, None
    if subj.user_id:
        rids = links.get("user_to_account", {}).get(subj.user_id)
        if rids:
            return rids[0], None, None

    # 3) unique deletion event for an account in the workflow window
    start = req.requested_at
    end = min([t for t in (req.audit_at, req.reported_at, None) if t] + [req.audit_at or EPOCH])
    if end is None:
        end = req.reported_at or req.audit_at
    if start and end:
        window = timedelta(hours=24)
        candidates: Dict[str, Tuple[str, datetime]] = {}
        for a in activity_rows:
            if (a.source_system == "deletion_worker" and a.target_system == "account_service"
                    and a.resource_id and a.resource_id.startswith("account_")):
                t = a.event_time
                if t is None:
                    continue
                if start - window <= t <= end + window:
                    prev = candidates.get(a.resource_id)
                    if prev is None or t > prev[1]:
                        candidates[a.resource_id] = (a.activity_id, t)
        if len(candidates) == 1:
            rid, (aid, t) = next(iter(candidates.items()))
            return rid, aid, t
        return None, None, None
    return None, None, None


def _account_state_at(
    rid: Optional[str],
    subj: SubjectIdentity,
    records: List[EvidenceRecord],
    ev_index: EvidenceIndex,
    audit_at: datetime,
) -> Tuple[Optional[str], Optional[str], Dict[str, set]]:
    """Determine the account's state at audit_at.

    Returns (state, evidence_id, remaining_rids):
      state:  PRESENT (evidence shows profile row present at/<= audit_at),
              ABSENT (latest position absent from account-domain snapshot or
              a 404 read), or None (cannot determine from evidence).
    remaining_rids: account rid -> the file ids where they were seen present.
    """
    if rid is None:
        return None, None, {}

    mine = [r for r in records
            if r.system_id == "account_service"
            and (r.resource_id == rid
                 or (r.state in ("PRESENT", "IDENTIFIABLE") and not r.resource_id))]
    if not mine:
        return None, None, {}

    latest_ts = max(r.captured_at or EPOCH for r in mine)
    latest = [r for r in mine if (r.captured_at or EPOCH) == latest_ts]
    latest_state = latest[0].state
    return latest_state, latest[0].file_id, {}


def investigate(
    req: DeletionRequest,
    resolver,
    evidence_index: EvidenceIndex,
    activities=None,
) -> CaseResult:
    """Investigate a single deletion request and return a CaseResult."""

    # Step 1: Intent classification
    if not is_deletion_request(req.request_text):
        return CaseResult(req.case_id, "NOT_APPLICABLE", [])

    audit_at = req.audit_at

    # Step 2: Identity resolution
    subj = resolver.resolve(req.email)

    # Step 3: Collect evidence records <= audit_at for the subject
    matched = evidence_index.records_for_subject(subj, audit_at)

    # Step 4: Best state per (system_id, resource_id)
    resource_map = select_best_record_per_resource(matched)

    best_eid = _best_evidence_id(matched)
    if not best_eid and matched:
        # Records exist but their row-level captured_at is unknown; fall back
        # to the manifest's file-level capture time.
        fallback = []
        for r in matched:
            fc = evidence_index.file_capture.get(r.file_id)
            fallback.append((fc or EPOCH, r.file_id))
        fallback.sort(key=lambda x: x[0], reverse=True)
        best_eid = fallback[0][1] if fallback else ""

    # Step 5: Account rid discovery + state
    rid, aid, _t = _find_account_rid(matched, subj, req, activities)
    acct_state, acct_eid, _rem = _account_state_at(
        rid, subj, matched, evidence_index, audit_at)

    # Inject the account resource into the resource map so the planner can
    # emit verification / finding steps for it.
    if rid:
        if acct_state == "PRESENT":
            resource_map[("account_service", rid)] = ResourceRecord(
                system_id="account_service", resource_id=rid,
                category="USER_PROFILE", state="PRESENT",
                evidence_id=acct_eid or best_eid)
        elif acct_state == "ABSENT":
            resource_map[("account_service", rid)] = ResourceRecord(
                system_id="account_service", resource_id=rid,
                category="USER_PROFILE", state="ABSENT",
                evidence_id=acct_eid or best_eid)
        else:
            # unknown; leave out of the map (we can't cite evidence for a
            # state we can't substantiate)
            resource_map.pop(("account_service", rid), None)

    # Step 6: Determine deletion_status
    has_violation = any(
        is_violation(rr.category, rr.state) for rr in resource_map.values())

    fully_unknown = (not matched) and (not rid)

    if fully_unknown:
        # No evidence at all -> rely on the workflow claim plus the system
        # activity stream.  NOT_STARTED claims are never complete; a claimed
        # COMPLETE with no evidence of remaining data and no contrary signal
        # is treated as complete (we still cannot cite evidence, so the steps
        # list stays empty / minimal).
        # A COMPLETE claim must be evidence-backed; with no matched evidence
        # at all we cannot cite anything, so claim INCOMPLETE and let the
        # discovered account verification (if any) stand with empty evidence.
        if req.reported_status == "COMPLETE" and best_eid:
            deletion_status = "COMPLETE"
        else:
            deletion_status = "INCOMPLETE"
        steps = build_steps(
            resource_map={},
            account_resource_id=rid if deletion_status == "INCOMPLETE" else None,
            security_audit_resource_id=None,
            best_evidence_id=best_eid,
            is_complete=(deletion_status == "COMPLETE"),
        )
    elif has_violation or (req.reported_status == "NOT_STARTED" and not rid and not matched):
        deletion_status = "INCOMPLETE"
        steps = build_steps(
            resource_map=resource_map,
            account_resource_id=rid,
            security_audit_resource_id=None,
            best_evidence_id=best_eid,
            is_complete=False,
        )
    elif not best_eid:
        # No citable evidence anywhere (including trimmed resource map):
        # a COMPLETE claim cannot be evidence-backed -> INCOMPLETE.
        deletion_status = "INCOMPLETE"
        steps = build_steps(
            resource_map=resource_map,
            account_resource_id=rid,
            security_audit_resource_id=None,
            best_evidence_id=best_eid,
            is_complete=False,
        )
    else:
        deletion_status = "COMPLETE"
        steps = build_steps(
            resource_map=resource_map,
            account_resource_id=rid,
            security_audit_resource_id=None,
            best_evidence_id=best_eid,
            is_complete=True,
        )

    return CaseResult(req.case_id, deletion_status, steps)
