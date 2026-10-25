"""loader.py – Load all dataset CSV files and the evidence manifest."""
from __future__ import annotations

import csv
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DeletionRequest:
    case_id: str
    email: str
    requested_at: Optional[datetime]
    reported_status: str          # COMPLETE | PARTIALLY_COMPLETE | NOT_STARTED
    reported_at: Optional[datetime]
    audit_at: Optional[datetime]
    request_text: str


@dataclass
class UserIdentity:
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    updated_at: Optional[datetime]


@dataclass
class AuditLogEntry:
    audit_id: str
    user_id: str
    event_time: Optional[datetime]
    field_name: str
    old_value: str
    new_value: str


@dataclass
class SystemActivity:
    activity_id: str
    event_time: Optional[datetime]
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


@dataclass
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str   # DELETE | REDACT | ANONYMIZE | RETAIN


@dataclass
class EvidenceFile:
    file_id: str
    file_path: str          # relative to dataset/
    origin: str
    captured_at: Optional[datetime]


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_deletion_requests(dataset_dir: str) -> List[DeletionRequest]:
    rows = []
    path = os.path.join(dataset_dir, "deletion_requests.csv")
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(DeletionRequest(
                case_id=r["case_id"].strip(),
                email=r["email"].strip(),
                requested_at=_iso(r.get("requested_at", "")),
                reported_status=r.get("reported_status", "").strip(),
                reported_at=_iso(r.get("reported_at", "")),
                audit_at=_iso(r.get("audit_at", "")),
                request_text=r.get("request_text", "").strip(),
            ))
    return rows


def load_sample_requests(dataset_dir: str) -> List[DeletionRequest]:
    rows = []
    path = os.path.join(dataset_dir, "sample_deletion_requests.csv")
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(DeletionRequest(
                case_id=r["case_id"].strip(),
                email=r["email"].strip(),
                requested_at=_iso(r.get("requested_at", "")),
                reported_status=r.get("reported_status", "").strip(),
                reported_at=_iso(r.get("reported_at", "")),
                audit_at=_iso(r.get("audit_at", "")),
                request_text=r.get("request_text", "").strip(),
            ))
    return rows


def load_user_identities(dataset_dir: str) -> List[UserIdentity]:
    rows = []
    path = os.path.join(dataset_dir, "user_identities.csv")
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(UserIdentity(
                user_id=r["user_id"].strip(),
                name=r.get("name", "").strip(),
                email=r.get("email", "").strip(),
                phone=r.get("phone", "").strip(),
                email_hash=r.get("email_hash", "").strip(),
                updated_at=_iso(r.get("updated_at", "")),
            ))
    return rows


def load_audit_log(dataset_dir: str) -> List[AuditLogEntry]:
    rows = []
    path = os.path.join(dataset_dir, "user_audit_log.csv")
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(AuditLogEntry(
                audit_id=r["audit_id"].strip(),
                user_id=r["user_id"].strip(),
                event_time=_iso(r.get("event_time", "")),
                field_name=r.get("field_name", "").strip(),
                old_value=r.get("old_value", "").strip(),
                new_value=r.get("new_value", "").strip(),
            ))
    return rows


def load_deletion_rules(dataset_dir: str) -> List[DeletionRule]:
    rows = []
    path = os.path.join(dataset_dir, "deletion_rules.csv")
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(DeletionRule(
                rule_id=r["rule_id"].strip(),
                data_category=r["data_category"].strip(),
                condition=r.get("condition", "").strip(),
                required_action=r["required_action"].strip(),
            ))
    return rows


def load_evidence_manifest(dataset_dir: str) -> Dict[str, EvidenceFile]:
    m: Dict[str, EvidenceFile] = {}
    path = os.path.join(dataset_dir, "evidence_files.csv")
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            fid = r["file_id"].strip()
            m[fid] = EvidenceFile(
                file_id=fid,
                file_path=r["file_path"].strip(),
                origin=r.get("origin", "").strip(),
                captured_at=_iso(r.get("captured_at", "")),
            )
    return m


def load_system_activity(dataset_dir: str) -> List[SystemActivity]:
    rows = []
    path = os.path.join(dataset_dir, "system_activity.csv")
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(SystemActivity(
                activity_id=r["activity_id"].strip(),
                event_time=_iso(r.get("event_time", "")),
                event_type=r.get("event_type", "").strip(),
                source_system=r.get("source_system", "").strip(),
                target_system=r.get("target_system", "").strip(),
                resource_id=r.get("resource_id", "").strip(),
                reported_result=r.get("reported_result", "").strip(),
                details=r.get("details", "").strip(),
            ))
    return rows


def load_sample_output(dataset_dir: str) -> Dict[str, dict]:
    """Returns {case_id: {deletion_status, steps_json_str}}."""
    import json
    result = {}
    path = os.path.join(dataset_dir, "sample_output.csv")
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            cid = r["case_id"].strip()
            result[cid] = {
                "deletion_status": r["deletion_status"].strip(),
                "steps_json": r["steps_json"].strip(),
            }
    return result
