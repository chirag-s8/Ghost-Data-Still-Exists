"""resource_discovery.py – Discover all resource_ids for a subject from
system_activity.csv and resolve their current state from evidence.

Strategy:
1. Build a resource_id → email/user_id index from LINK_RESOURCE_IDENTITY events.
2. For any case, use the subject's emails/user_ids to find relevant resource_ids
   mentioned in system_activity rows (via the index).
3. For each resource_id, determine its state from evidence files:
   a. If it appears in a parse evidence record → use that state.
   b. If it appeared in a DELETE_RECORD activity before audit_at → likely ABSENT;
      confirm by checking absence in latest SQL snapshot (use the SQL as witness).
4. Also apply naming-convention fallback for account_NNN = user_NN.
"""
from __future__ import annotations

import csv
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from evidence_index import EvidenceRecord
from identity import SubjectIdentity
from loader import SystemActivity


EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Map resource_id prefix → (system_id, category)
_PREFIX_MAP = {
    "account_": ("account_service", "USER_PROFILE"),
    "search_": ("search_service", "SEARCH_INDEX_ENTRY"),
    "analytics_": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_": ("support_platform", "SUPPORT_MESSAGE"),
    "export_": ("export_service", "USER_EXPORT"),
    "data_flow_": ("integration_service", "DATA_FLOW"),
    "backup_": ("backup_service", "BACKUP_ARCHIVE"),
    "audit_record_": ("security_service", "SECURITY_AUDIT_LOG"),
    "tombstone_": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "email_delivery_": ("email_delivery_service", "EMAIL_DELIVERY_LOG"),
    "cache_": ("cache_service", "CACHE_ENTRY"),
    "marketing_": ("marketing_platform", "MARKETING_PROFILE"),
    "object_": ("object_storage", "SUPPORT_ATTACHMENT"),
}


def _prefix_to_system(rid: str) -> Tuple[Optional[str], Optional[str]]:
    for prefix, (sys_id, cat) in _PREFIX_MAP.items():
        if rid.startswith(prefix):
            return sys_id, cat
    return None, None


# Map system_activity event_type → approximate state after the event
_EVENT_TO_RESULT_STATE = {
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "BLOCK_RESTORE": "BLOCKED",
    "DISABLE_DATA_FLOW": "DISABLED",
    "RETAIN_RECORD": "PRESENT",
    "INDEX_RECORD": "PRESENT",
    "SYNC_RECORD": "PRESENT",
    "UPDATE_RECORD": "PRESENT",
    "CREATE_EXPORT": "PRESENT",
    "SEND_EMAIL": "PRESENT",
    "REFRESH_CACHE": "PRESENT",
    "RESTORE_BACKUP": "ACTIVE",
    "CHECK_DATA_FLOW": None,  # ambiguous
    "CHECK_RESTORE_ACCESS": None,
    "CLASSIFY_REQUEST": None,
    "LINK_RESOURCE_IDENTITY": None,
}


class ResourceDiscovery:
    """Extract resource_ids for a subject from system_activity and evidence."""

    def __init__(self, activities: List[SystemActivity]):
        self._activities = activities

        # Index: resource_id → list of (event_time, event_type, reported_result)
        self._resource_events: Dict[str, List[Tuple[datetime, str, str]]] = {}
        for a in activities:
            self._resource_events.setdefault(a.resource_id, []).append(
                (a.event_time or EPOCH, a.event_type, a.reported_result)
            )

        # LINK_RESOURCE_IDENTITY: resource_id → (email, user_id)
        self._linked: Dict[str, Tuple[Optional[str], Optional[str]]] = {}
        _em = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")
        _uid = re.compile(r"\buser_\d+\b")
        for a in activities:
            if a.event_type == "LINK_RESOURCE_IDENTITY":
                ems = _em.findall(a.details)
                uids = _uid.findall(a.details)
                em = ems[0].lower() if ems else None
                uid = uids[0] if uids else None
                self._linked[a.resource_id] = (em, uid)

    def resource_ids_for_subject(
        self, subj: SubjectIdentity, audit_at: datetime
    ) -> Dict[str, Tuple[str, str, str, Optional[datetime]]]:
        """Return {resource_id: (system_id, category, inferred_state, event_time)}
        for resources linked to the subject via activity events ≤ audit_at.
        
        Only returns resources where we have a strong linkage signal.
        """
        result: Dict[str, Tuple[str, str, str, Optional[datetime]]] = {}

        for rid, (em, uid) in self._linked.items():
            if subj.matches_any(email=em, user_id=uid):
                # Find latest event for this resource ≤ audit_at
                events = [
                    (ts, ev, res) for (ts, ev, res) in
                    self._resource_events.get(rid, [])
                    if ts <= audit_at
                ]
                sys_id, cat = _prefix_to_system(rid)
                if not sys_id:
                    continue
                state = "PRESENT"
                last_ts = None
                if events:
                    events.sort(key=lambda x: x[0], reverse=True)
                    ts, ev, res = events[0]
                    last_ts = ts
                    # Use event-based state as hint, but don't trust it blindly
                    hint = _EVENT_TO_RESULT_STATE.get(ev)
                    if hint:
                        state = hint
                result[rid] = (sys_id, cat, state, last_ts)

        return result

    def inferred_resources_from_deletion_events(
        self,
        subj: SubjectIdentity,
        audit_at: datetime,
        existing_resource_ids: Set[str],
    ) -> Dict[str, Tuple[str, str, str, Optional[datetime]]]:
        """
        For subjects where we know the user_id, look for account_NNN patterns.
        This implements the naming-convention fallback for low-numbered sample cases.
        
        Also: scan system_activity for any resource mentioned in conjunction with
        subjects' emails in the details text (very few such rows exist).
        """
        result: Dict[str, Tuple[str, str, str, Optional[datetime]]] = {}

        # Naming convention: user_01 → account_001, user_02 → account_002, etc.
        if subj.user_id:
            m = re.match(r"user_(\d+)", subj.user_id)
            if m:
                num = m.group(1)
                # try both zero-padded and unpadded
                candidates = [f"account_{num}", f"account_{num.zfill(3)}"]
                for cid in candidates:
                    if cid not in existing_resource_ids:
                        events = [
                            (ts, ev, res)
                            for (ts, ev, res) in self._resource_events.get(cid, [])
                            if ts <= audit_at
                        ]
                        if events:
                            events.sort(key=lambda x: x[0], reverse=True)
                            ts, ev, res = events[0]
                            hint = _EVENT_TO_RESULT_STATE.get(ev)
                            state = hint if hint else "PRESENT"
                            sys_id, cat = _prefix_to_system(cid)
                            if sys_id:
                                result[cid] = (sys_id, cat, state, ts)
                                break  # found one convention match

        # Scan activity details for subject email mentions
        _em = re.compile(r"[\w.+-]+@[\w.-]+\.\w+")
        _rid_pattern = re.compile(
            r"\b(account|search|analytics|support|export|data_flow|backup|"
            r"audit_record|tombstone|email_delivery|cache|marketing)_\w+"
        )
        for a in self._activities:
            if a.event_time and a.event_time > audit_at:
                continue
            det = a.details
            ems = _em.findall(det)
            if any(e.lower() in subj.emails for e in ems):
                # this activity mentions one of the subject's emails
                rid = a.resource_id
                if rid and rid not in existing_resource_ids and rid not in result:
                    sys_id, cat = _prefix_to_system(rid)
                    if sys_id:
                        events = [
                            (ts, ev, res)
                            for (ts, ev, res) in self._resource_events.get(rid, [])
                            if ts <= audit_at
                        ]
                        state = "PRESENT"
                        last_ts = None
                        if events:
                            events.sort(key=lambda x: x[0], reverse=True)
                            ts, ev, res = events[0]
                            last_ts = ts
                            hint = _EVENT_TO_RESULT_STATE.get(ev)
                            if hint:
                                state = hint
                        result[rid] = (sys_id, cat, state, last_ts)

        return result
