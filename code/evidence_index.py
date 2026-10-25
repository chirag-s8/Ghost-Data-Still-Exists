"""evidence_index.py – Parse all evidence files into a unified EvidenceRecord list.

Each EvidenceRecord captures:
  - Which evidence file it came from (file_id, captured_at)
  - The system and resource (system_id, resource_id, category)
  - The observed state (ABSENT, PRESENT, IDENTIFIABLE, ANONYMIZED, REDACTED,
                        ACTIVE, DISABLED, BLOCKED)
  - Subject identifiers found in or associated with the record
    (user_id, email, phone, email_hash, lookup_key)

Parsers cover:
  - SQL inventory snapshots (sqlite3 :memory:)
  - service_resource_export JSON
  - customer_data_snapshot_bundle JSON
  - resource_lookup_trace logs
  - customer_account_handover txt
  - security_audit_ledger JSON
  - connector_configurations JSON
  - customer_analytics_report JSON
  - customer_export_jobs / customer_export_manifest JSON
  - Other JSON records (generic resource_id extraction)
  - PDF text (best-effort)
  - PNG images (NOT parseable without OCR; linkages hard-coded from recon)
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class EvidenceRecord:
    file_id: str
    captured_at: Optional[datetime]
    system_id: Optional[str]
    resource_id: Optional[str]
    category: Optional[str]
    state: str            # ABSENT | PRESENT | IDENTIFIABLE | ANONYMIZED | REDACTED | ACTIVE | DISABLED | BLOCKED
    user_id: Optional[str]
    email: Optional[str]
    phone: Optional[str]
    email_hash: Optional[str]
    lookup_key: Optional[str]  # the key used to look up this resource (email or user_id)
    source: str           # informational: which parser produced this


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None


def _clean(v) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s if s and s.lower() not in ("null", "none", "") else None


# ---------------------------------------------------------------------------
# SQL table → (system_id, category) mapping
# ---------------------------------------------------------------------------

_TABLE_MAP: Dict[str, Tuple[str, str]] = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_profiles_primary": ("account_service", "USER_PROFILE"),
    "customer_profiles_failover_replica": ("account_service", "USER_PROFILE"),
    "customer_profiles_read_replica": ("account_service", "USER_PROFILE"),
    "customer_profiles_reporting_replica": ("account_service", "USER_PROFILE"),
    "customer_profiles_regional_replica": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_search_documents_primary": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_documents_primary": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "customer_analytics_reports": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "support_tickets": ("support_platform", "SUPPORT_MESSAGE"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
    "connector_configurations": ("integration_service", "DATA_FLOW"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "backup_restore_policies": ("backup_service", "BACKUP_ARCHIVE"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
    "security_audit_events": ("security_service", "SECURITY_AUDIT_LOG"),
    "deleted_customer_references": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "marketing_profiles": ("marketing_platform", "MARKETING_PROFILE"),
}

# Full-store variant tables: customer_data_<topology> wraps records as escaped
# JSON with columns (resource_id, origin_system, collection_name, record_json,
# updated_at). We detect these by name pattern instead of exact equality.
_DATA_WRAPPING_RE = re.compile(
    r"^customer_data_(primary|failover_replica|read_replica|replica_.+|"
    r"reporting_replica|regional_replica)$")

# Store name → default category, used for json-wrapped customer_data_* stores
# whose collection_name is not a recognized table name.
_DS_CATEGORY_BY_STORE: Dict[str, str] = {
    "account_service": "USER_PROFILE",
    "search_service": "SEARCH_INDEX_ENTRY",
    "analytics_platform": "ANALYTICS_PROFILE",
    "support_platform": "SUPPORT_MESSAGE",
    "export_service": "USER_EXPORT",
    "integration_service": "DATA_FLOW",
    "backup_service": "BACKUP_ARCHIVE",
    "security_service": "SECURITY_AUDIT_LOG",
    "identity_service": "ACCOUNT_TOMBSTONE",
    "marketing_platform": "MARKETING_PROFILE",
    "email_delivery_service": "EMAIL_DELIVERY_LOG",
    "cache_service": "CACHE_ENTRY",
    "object_storage": "SUPPORT_ATTACHMENT",
}


def _map_table(tname: str) -> Optional[Tuple[str, str]]:
    key = tname.lower()
    if key in _TABLE_MAP:
        return _TABLE_MAP[key]
    # data-wrapping variant tables (record_json holder) are handled specially
    if _DATA_WRAPPING_RE.match(key):
        return ("MULTI", "MULTI")
    # prefix match
    for k, v in _TABLE_MAP.items():
        if key.startswith(k):
            return v
    return None


# ---------------------------------------------------------------------------
# State derivation helpers
# ---------------------------------------------------------------------------

def _profile_state(row: dict) -> str:
    st = _clean(row.get("account_status")) or ""
    if "DELETED" in st.upper() or "NOT_FOUND" in st.upper():
        return "ABSENT"
    return "PRESENT"


def _analytics_state(row: dict) -> str:
    if any(_clean(row.get(k)) for k in ("email", "phone", "email_hash", "customer_reference", "user_id")):
        return "IDENTIFIABLE"
    return "ANONYMIZED"


def _support_state(row: dict) -> str:
    if any(_clean(row.get(k)) for k in ("requester_email", "requester_phone", "requester_name")):
        return "IDENTIFIABLE"
    if _clean(row.get("customer_reference")) or _clean(row.get("user_id")):
        return "REDACTED"
    return "PRESENT"


def _flow_state(row: dict) -> str:
    en = str(row.get("enabled", "")).strip()
    return "ACTIVE" if en in ("1", "true", "True") else "DISABLED"


def _backup_state(row: dict) -> str:
    ra = str(row.get("restore_allowed", "")).strip()
    return "ACTIVE" if ra in ("1", "true", "True") else "BLOCKED"


def _tombstone_state(row: dict) -> str:
    if any(_clean(row.get(k)) for k in ("name", "email", "phone", "email_hash")):
        return "IDENTIFIABLE"
    return "REDACTED"


def _derive_state(category: str, row: dict) -> str:
    d = {
        "USER_PROFILE": _profile_state,
        "SEARCH_INDEX_ENTRY": lambda r: "PRESENT",
        "ANALYTICS_PROFILE": _analytics_state,
        "SUPPORT_MESSAGE": _support_state,
        "SUPPORT_ATTACHMENT": lambda r: "PRESENT",
        "USER_EXPORT": lambda r: "PRESENT",
        "MARKETING_PROFILE": lambda r: "PRESENT",
        "DATA_FLOW": _flow_state,
        "BACKUP_ARCHIVE": _backup_state,
        "SECURITY_AUDIT_LOG": lambda r: "PRESENT",
        "ACCOUNT_TOMBSTONE": _tombstone_state,
    }
    fn = d.get(category)
    return fn(row) if fn else "PRESENT"


def _row_identifiers(row: dict) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """(user_id, email, phone, email_hash)"""
    uid = _clean(row.get("customer_reference") or row.get("user_id") or row.get("subject_reference"))
    em = _clean(row.get("email") or row.get("owner_email") or row.get("customer_email") or row.get("requester_email"))
    ph = _clean(row.get("phone") or row.get("owner_phone") or row.get("requester_phone"))
    eh = _clean(row.get("email_hash"))
    return uid, (em.lower() if em else None), ph, (eh.lower() if eh else None)


# ---------------------------------------------------------------------------
# SQL parser
# ---------------------------------------------------------------------------

def _parse_sql(path: str, file_id: str, captured_at: Optional[datetime], out: List[EvidenceRecord]) -> None:
    with open(path, encoding="utf-8", errors="replace") as f:
        script = f.read()
    con = sqlite3.connect(":memory:")
    try:
        con.executescript(script)
    except Exception:
        # strip problematic pragmas and retry
        try:
            con2 = sqlite3.connect(":memory:")
            s2 = re.sub(r"PRAGMA[^;]+;", "", script)
            con2.executescript(s2)
            con.close()
            con = con2
        except Exception as e:
            con.close()
            print(f"  !! SQL parse failed {file_id}: {e}", file=sys.stderr)
            return
    cur = con.cursor()
    tables = [r[0] for r in cur.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    for t in tables:
        mapping = _map_table(t)
        if not mapping:
            continue
        system_id, category = mapping
        if system_id == "MULTI":
            # json-wrapped multi-collection store: dispatch per record via
            # (origin_system, collection_name)
            try:
                cur.execute(f'SELECT * FROM "{t}"')
                cols = [d[0] for d in cur.description]
                rows = cur.execute(f'SELECT * FROM "{t}"').fetchall()
            except Exception:
                continue
            for data_row in rows:
                row = dict(zip(cols, data_row))
                try:
                    inner = json.loads(row.get("record_json") or "{}")
                except Exception:
                    continue
                if not isinstance(inner, dict):
                    continue
                coll = (row.get("collection_name") or "").lower()
                osys = row.get("origin_system") or ""
                sub_map = _map_table(coll)
                if sub_map:
                    sys_id2, cat2 = sub_map
                elif osys:
                    cat2 = _DS_CATEGORY_BY_STORE.get(osys)
                    if not cat2:
                        continue
                    sys_id2 = osys
                    cat2 = cat2
                else:
                    continue
                uid, em, ph, eh = _row_identifiers(inner)
                out.append(EvidenceRecord(
                    file_id=file_id, captured_at=captured_at,
                    system_id=sys_id2, resource_id=_clean(inner.get("resource_id")) or _clean(row.get("resource_id")),
                    category=cat2, state=_derive_state(cat2, inner),
                    user_id=uid, email=em, phone=ph, email_hash=eh,
                    lookup_key=None, source=f"SQL:{t}:{coll}",
                ))
            continue
        try:
            cur.execute(f'SELECT * FROM "{t}" LIMIT 0')
            cols = [d[0] for d in cur.description]
            rows = cur.execute(f'SELECT * FROM "{t}"').fetchall()
        except Exception:
            continue
        for data_row in rows:
            row = dict(zip(cols, data_row))
            rid = _clean(row.get("resource_id"))
            if not rid:
                continue
            uid, em, ph, eh = _row_identifiers(row)
            out.append(EvidenceRecord(
                file_id=file_id, captured_at=captured_at,
                system_id=system_id, resource_id=rid,
                category=category, state=_derive_state(category, row),
                user_id=uid, email=em, phone=ph, email_hash=eh,
                lookup_key=None, source=f"SQL:{t}",
            ))
    con.close()


# ---------------------------------------------------------------------------
# JSON parsers
# ---------------------------------------------------------------------------

def _parse_service_resource_export(data: dict, file_id: str, captured_at: Optional[datetime],
                                    out: List[EvidenceRecord]) -> None:
    se = data.get("service_exports", {})
    for sysname, payload in se.items():
        # account_service
        for r in payload.get("profile_lookups", []):
            prof = r.get("profile")
            state = "ABSENT" if (r.get("status_code") == 404 or not prof) else "PRESENT"
            uid = _clean((prof or {}).get("customer_reference") or (prof or {}).get("subject_reference"))
            em = _clean((prof or {}).get("email"))
            lk = _clean(r.get("lookup_key") or r.get("correlation_key"))
            if lk in ("null", "None", ""):
                lk = None
            if em is None and lk and "@" in lk:
                em = lk
            if uid is None and lk and lk.startswith("user_"):
                uid = lk
            if em is None and not lk:
                em = None
            out.append(EvidenceRecord(
                file_id=file_id, captured_at=captured_at,
                system_id=sysname, resource_id=_clean(r.get("resource_id")),
                category="USER_PROFILE", state=state,
                user_id=uid, email=(em.lower() if em else None),
                phone=_clean((prof or {}).get("phone")),
                email_hash=_clean((prof or {}).get("email_hash")),
                lookup_key=lk, source="JSON:profile_lookups",
            ))
        # analytics_platform
        for r in payload.get("profiles", []):
            uid = _clean(r.get("customer_reference"))
            em = _clean(r.get("email"))
            ph = _clean(r.get("phone"))
            eh = _clean(r.get("email_hash"))
            ident = uid or em or ph or eh
            out.append(EvidenceRecord(
                file_id=file_id, captured_at=captured_at,
                system_id=sysname, resource_id=_clean(r.get("resource_id")),
                category="ANALYTICS_PROFILE",
                state="IDENTIFIABLE" if ident else "ANONYMIZED",
                user_id=uid, email=em.lower() if em else None,
                phone=ph, email_hash=eh.lower() if eh else None,
                lookup_key=None, source="JSON:analytics_profiles",
            ))
        # search_service
        for q in payload.get("index_queries", []):
            hits = q.get("hits", {})
            docs = hits.get("documents", [])
            doc = docs[0] if docs else {}
            state = "ABSENT" if hits.get("total", 0) == 0 else "PRESENT"
            em = _clean(doc.get("email"))
            out.append(EvidenceRecord(
                file_id=file_id, captured_at=captured_at,
                system_id=sysname, resource_id=_clean(q.get("resource_id")),
                category="SEARCH_INDEX_ENTRY", state=state,
                user_id=_clean(doc.get("customer_reference")),
                email=em.lower() if em else None,
                phone=None, email_hash=None,
                lookup_key=_clean(q.get("query")),
                source="JSON:search_index",
            ))
        # support_platform
        for r in payload.get("tickets", []):
            em = _clean(r.get("requester_email"))
            ph = _clean(r.get("requester_phone"))
            nm = _clean(r.get("requester_name"))
            uid = _clean(r.get("customer_reference"))
            ident = em or ph or nm
            out.append(EvidenceRecord(
                file_id=file_id, captured_at=captured_at,
                system_id=sysname, resource_id=_clean(r.get("resource_id")),
                category="SUPPORT_MESSAGE",
                state="IDENTIFIABLE" if ident else "REDACTED",
                user_id=uid, email=em.lower() if em else None,
                phone=ph, email_hash=None, lookup_key=None,
                source="JSON:support_tickets",
            ))
        # export_service
        for r in payload.get("exports", []):
            em = _clean(r.get("owner_email"))
            out.append(EvidenceRecord(
                file_id=file_id, captured_at=captured_at,
                system_id=sysname, resource_id=_clean(r.get("resource_id")),
                category="USER_EXPORT", state="PRESENT",
                user_id=_clean(r.get("customer_reference")),
                email=em.lower() if em else None,
                phone=_clean(r.get("owner_phone")), email_hash=None,
                lookup_key=None, source="JSON:exports",
            ))
        # integration_service
        for r in payload.get("connectors", []):
            enabled = r.get("enabled")
            em = _clean(r.get("customer_email"))
            uid = _clean(r.get("customer_reference"))
            out.append(EvidenceRecord(
                file_id=file_id, captured_at=captured_at,
                system_id=sysname, resource_id=_clean(r.get("resource_id")),
                category="DATA_FLOW",
                state="ACTIVE" if enabled else "DISABLED",
                user_id=uid, email=em.lower() if em else None,
                phone=None, email_hash=None, lookup_key=None,
                source="JSON:connectors",
            ))
        # backup_service
        for r in payload.get("restore_entries", []):
            ra = r.get("restore_allowed")
            em = _clean(r.get("customer_email"))
            uid = _clean(r.get("customer_reference"))
            out.append(EvidenceRecord(
                file_id=file_id, captured_at=captured_at,
                system_id=sysname, resource_id=_clean(r.get("resource_id")),
                category="BACKUP_ARCHIVE",
                state="ACTIVE" if ra else "BLOCKED",
                user_id=uid, email=em.lower() if em else None,
                phone=None, email_hash=None, lookup_key=None,
                source="JSON:backup",
            ))
        # security_service
        for r in payload.get("audit_records", []):
            out.append(EvidenceRecord(
                file_id=file_id, captured_at=captured_at,
                system_id=sysname, resource_id=_clean(r.get("resource_id")),
                category="SECURITY_AUDIT_LOG", state="PRESENT",
                user_id=_clean(r.get("subject_reference")),
                email=None, phone=None, email_hash=None, lookup_key=None,
                source="JSON:audit",
            ))


def _parse_snapshot_bundle(data: dict, file_id: str, captured_at: Optional[datetime],
                            out: List[EvidenceRecord]) -> None:
    _DS_CAT = {
        "account_service": "USER_PROFILE",
        "search_service": "SEARCH_INDEX_ENTRY",
        "analytics_platform": "ANALYTICS_PROFILE",
        "support_platform": "SUPPORT_MESSAGE",
        "export_service": "USER_EXPORT",
        "integration_service": "DATA_FLOW",
        "backup_service": "BACKUP_ARCHIVE",
        "security_service": "SECURITY_AUDIT_LOG",
        "identity_service": "ACCOUNT_TOMBSTONE",
        "marketing_service": "MARKETING_PROFILE",
    }
    for snap in data.get("snapshots", []):
        ds = snap.get("data_store", "")
        coll = (snap.get("collection") or "").lower()
        cap = _iso(snap.get("captured_at")) or captured_at
        # derive mapping
        mapping = _map_table(coll)
        if not mapping:
            cat = _DS_CAT.get(ds)
            if not cat:
                continue
            mapping = (ds, cat)
        system_id, category = mapping
        for r in snap.get("records", []):
            row = dict(r)
            # flatten nested document
            if isinstance(row.get("document"), dict):
                for k, v in row["document"].items():
                    row.setdefault(k, v)
            rid = _clean(row.get("resource_id"))
            if not rid:
                continue
            uid, em, ph, eh = _row_identifiers(row)
            out.append(EvidenceRecord(
                file_id=file_id, captured_at=cap,
                system_id=system_id, resource_id=rid,
                category=category, state=_derive_state(category, row),
                user_id=uid, email=em, phone=ph, email_hash=eh,
                lookup_key=None, source=f"BUNDLE:{coll}",
            ))


def _parse_security_audit_ledger(data: dict, file_id: str, captured_at: Optional[datetime],
                                   out: List[EvidenceRecord]) -> None:
    for r in data.get("records", []):
        rid = _clean(r.get("resource_id"))
        if not rid:
            continue
        sys_name = _clean(r.get("system")) or "security_service"
        result = (r.get("result") or "FOUND").upper()
        state = "ABSENT" if result == "NOT_FOUND" else "PRESENT"
        subj = _clean(r.get("subject_reference"))
        em = None
        uid = None
        if subj and "@" in subj:
            em = subj.lower()
        elif subj:
            uid = subj
        out.append(EvidenceRecord(
            file_id=file_id, captured_at=captured_at,
            system_id=sys_name, resource_id=rid,
            category=_clean(r.get("record_type")) or "SECURITY_AUDIT_LOG",
            state=state, user_id=uid, email=em,
            phone=None, email_hash=None, lookup_key=subj,
            source="JSON:audit_ledger",
        ))


def _parse_connector_configurations(data: dict, file_id: str, captured_at: Optional[datetime],
                                     out: List[EvidenceRecord]) -> None:
    for r in data.get("connectors", []):
        rid = _clean(r.get("connector_id") or r.get("resource_id"))
        if not rid:
            continue
        enabled = r.get("enabled")
        em = _clean(r.get("customer_email") or r.get("owner_email") or r.get("selector"))
        uid = _clean(r.get("customer_reference"))
        out.append(EvidenceRecord(
            file_id=file_id, captured_at=captured_at,
            system_id="integration_service", resource_id=rid,
            category="DATA_FLOW",
            state="ACTIVE" if enabled else "DISABLED",
            user_id=uid, email=em.lower() if em else None,
            phone=None, email_hash=None, lookup_key=None,
            source="JSON:connector_conf",
        ))


def _parse_export_jobs(data: dict, file_id: str, captured_at: Optional[datetime],
                       out: List[EvidenceRecord]) -> None:
    # handle list or dict with "jobs" key
    items = data if isinstance(data, list) else data.get("jobs", data.get("exports", []))
    if isinstance(items, dict):
        items = list(items.values())
    for r in items:
        if not isinstance(r, dict):
            continue
        rid = _clean(r.get("export_id") or r.get("resource_id"))
        if not rid:
            continue
        em = _clean(r.get("owner_email") or r.get("requester_email") or r.get("email"))
        uid = _clean(r.get("customer_reference") or r.get("user_id"))
        out.append(EvidenceRecord(
            file_id=file_id, captured_at=captured_at,
            system_id="export_service", resource_id=rid,
            category="USER_EXPORT", state="PRESENT",
            user_id=uid, email=em.lower() if em else None,
            phone=None, email_hash=None, lookup_key=None,
            source="JSON:export_jobs",
        ))


def _parse_analytics_report(data: dict, file_id: str, captured_at: Optional[datetime],
                              out: List[EvidenceRecord]) -> None:
    for r in data.get("profiles", data.get("records", [])):
        if not isinstance(r, dict):
            continue
        rid = _clean(r.get("resource_id") or r.get("profile_id"))
        if not rid:
            continue
        em = _clean(r.get("email"))
        uid = _clean(r.get("customer_reference") or r.get("user_id"))
        ph = _clean(r.get("phone"))
        eh = _clean(r.get("email_hash"))
        ident = uid or em or ph or eh
        out.append(EvidenceRecord(
            file_id=file_id, captured_at=captured_at,
            system_id="analytics_platform", resource_id=rid,
            category="ANALYTICS_PROFILE",
            state="IDENTIFIABLE" if ident else "ANONYMIZED",
            user_id=uid, email=em.lower() if em else None,
            phone=ph, email_hash=eh, lookup_key=None,
            source="JSON:analytics_report",
        ))


def _parse_snapshot_data_bundle(data: dict, file_id: str, captured_at: Optional[datetime],
                                  out: List[EvidenceRecord]) -> None:
    """Alternative format: list of {user_id, resources: [...]} or other structures."""
    # If it has a top-level "snapshots" key, that's handled by _parse_snapshot_bundle.
    # Here we handle a flat list of subjects or other structures.
    for key in ("subjects", "users", "records"):
        items = data.get(key)
        if items and isinstance(items, list):
            for subj in items:
                uid = _clean(subj.get("user_id") or subj.get("customer_reference"))
                em = _clean(subj.get("email"))
                for res in subj.get("resources", []):
                    rid = _clean(res.get("resource_id"))
                    if not rid:
                        continue
                    sys_id = _clean(res.get("system_id") or res.get("system"))
                    cat = _clean(res.get("category") or res.get("record_type")) or "UNKNOWN"
                    state = _clean(res.get("state") or res.get("status")) or "PRESENT"
                    out.append(EvidenceRecord(
                        file_id=file_id, captured_at=captured_at,
                        system_id=sys_id, resource_id=rid,
                        category=cat, state=state,
                        user_id=uid, email=em.lower() if em else None,
                        phone=None, email_hash=None, lookup_key=None,
                        source="JSON:bundle_subjects",
                    ))
            return


def _parse_generic_json(data: dict, file_id: str, captured_at: Optional[datetime],
                         out: List[EvidenceRecord]) -> None:
    """Fallback: extract any resource_id mentions with associated identifiers."""
    flat = json.dumps(data)
    for m in re.finditer(r'"resource_id"\s*:\s*"([^"]+)"', flat):
        rid = m.group(1)
        # try to get surrounding context for email/user
        ctx_start = max(0, m.start() - 200)
        ctx = flat[ctx_start:m.end() + 200]
        em_m = re.search(r'"email"\s*:\s*"([^"@]+@[^"]+)"', ctx)
        uid_m = re.search(r'"(?:customer_reference|user_id|subject_reference)"\s*:\s*"(user_\d+)"', ctx)
        em = em_m.group(1).lower() if em_m else None
        uid = uid_m.group(1) if uid_m else None
        out.append(EvidenceRecord(
            file_id=file_id, captured_at=captured_at,
            system_id=None, resource_id=rid,
            category="UNKNOWN", state="PRESENT",
            user_id=uid, email=em, phone=None, email_hash=None,
            lookup_key=None, source="JSON:generic",
        ))


def _parse_json_file(path: str, file_id: str, captured_at: Optional[datetime],
                     out: List[EvidenceRecord]) -> None:
    try:
        data = json.load(open(path, encoding="utf-8"))
    except Exception as e:
        print(f"  !! JSON parse {file_id}: {e}", file=sys.stderr)
        return
    if not isinstance(data, (dict, list)):
        return

    if isinstance(data, list):
        # Treat as export jobs list
        _parse_export_jobs(data, file_id, captured_at, out)
        return

    if "service_exports" in data:
        _parse_service_resource_export(data, file_id, captured_at, out)
    elif "snapshots" in data:
        _parse_snapshot_bundle(data, file_id, captured_at, out)
    elif "records" in data and data.get("origin", "").endswith("audit_service"):
        _parse_security_audit_ledger(data, file_id, captured_at, out)
    elif "records" in data:
        # Could be security_audit_ledger with different origin, or analytics, etc.
        sample = data["records"]
        if isinstance(sample, list) and sample and isinstance(sample[0], dict):
            if "subject_reference" in sample[0] or "record_type" in sample[0]:
                _parse_security_audit_ledger(data, file_id, captured_at, out)
            elif "audience_cohort" in sample[0] or "sessions" in json.dumps(sample[0]):
                _parse_analytics_report(data, file_id, captured_at, out)
            else:
                _parse_generic_json(data, file_id, captured_at, out)
        else:
            _parse_generic_json(data, file_id, captured_at, out)
    elif "connectors" in data:
        _parse_connector_configurations(data, file_id, captured_at, out)
    elif "jobs" in data or "exports" in data:
        _parse_export_jobs(data, file_id, captured_at, out)
    elif "profiles" in data:
        _parse_analytics_report(data, file_id, captured_at, out)
    elif any(k in data for k in ("subjects", "users")):
        _parse_snapshot_data_bundle(data, file_id, captured_at, out)
    else:
        _parse_generic_json(data, file_id, captured_at, out)


# ---------------------------------------------------------------------------
# Log parsers
# ---------------------------------------------------------------------------

def _parse_resource_lookup_trace(path: str, file_id: str, captured_at: Optional[datetime],
                                   out: List[EvidenceRecord]) -> None:
    """Parse resource_lookup_trace style logs with started+completed pairs."""
    # {trace_id: {lookup_key, service, ts}}
    started: Dict[str, dict] = {}
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip()
            # started line
            ts_m = re.match(r"(\S+)", line)
            rid_m = re.search(r"resource_id=(\S+)", line)
            trace_m = re.search(r"trace_id=(\S+)", line)
            svc_m = re.search(r"service=(\S+)", line)
            ev_m = re.search(r"event=(\S+)", line)
            if not rid_m:
                continue
            rid = rid_m.group(1)
            ev = ev_m.group(1) if ev_m else ""
            if "_started" in ev or ("lookup_key=" in line and "_completed" not in ev):
                lk_m = re.search(r"lookup_key=(\S+)", line)
                lk = lk_m.group(1) if lk_m else None
                if lk and lk.lower() == "null":
                    lk = None
                tid = trace_m.group(1) if trace_m else rid
                started[rid] = {
                    "lookup_key": lk,
                    "service": svc_m.group(1) if svc_m else None,
                    "ts": ts_m.group(1) if ts_m else None,
                }
            if "_completed" in ev:
                st_info = started.get(rid, {})
                svcname = st_info.get("service") or (svc_m.group(1) if svc_m else None)
                lk = st_info.get("lookup_key")

                category = None
                state = "UNKNOWN"
                uid = None
                em = None

                if "profile_lookup" in ev:
                    category = "USER_PROFILE"
                    hs_m = re.search(r"http_status=(\d+)", line)
                    rows_m = re.search(r"rows=(\d+)", line)
                    if (hs_m and hs_m.group(1) == "404") or (rows_m and rows_m.group(1) == "0"):
                        state = "ABSENT"
                    else:
                        state = "PRESENT"
                        # try to extract email/user from completed line
                        cr_m = re.search(r"customer_reference=([^\s,]+)", line)
                        em_m = re.search(r"email=([^\s,]+)", line)
                        if cr_m and cr_m.group(1) != "null":
                            uid = cr_m.group(1)
                        if em_m and em_m.group(1) != "null":
                            em = em_m.group(1).lower()

                elif "analytics_profile_read" in ev:
                    category = "ANALYTICS_PROFILE"
                    em_m = re.search(r"email=([^\s,]+)", line)
                    cr_m = re.search(r"customer_reference=([^\s,]+)", line)
                    ph_m = re.search(r"phone=([^\s,]+)", line)
                    eh_m = re.search(r"email_hash=([^\s,]+)", line)
                    has_ident = False
                    if em_m and em_m.group(1) not in ("null", "None"):
                        em = em_m.group(1).lower()
                        has_ident = True
                    if cr_m and cr_m.group(1) not in ("null", "None"):
                        uid = cr_m.group(1)
                        has_ident = True
                    state = "IDENTIFIABLE" if has_ident else "ANONYMIZED"

                elif "index_query" in ev:
                    category = "SEARCH_INDEX_ENTRY"
                    tot_m = re.search(r"total_hits=(\d+)", line)
                    state = "PRESENT" if (tot_m and int(tot_m.group(1)) > 0) else "ABSENT"
                    em_m = re.search(r"email=([^\s,]+)", line)
                    if em_m and em_m.group(1) not in ("null", "None"):
                        em = em_m.group(1).lower()

                elif "support_ticket_read" in ev:
                    category = "SUPPORT_MESSAGE"
                    em_m = re.search(r"requester_email=([^\s,]+)", line)
                    nm_m = re.search(r"requester_name=([^\s,]+)", line)
                    ph_m = re.search(r"requester_phone=([^\s,]+)", line)
                    cr_m = re.search(r"customer_reference=([^\s,]+)", line)
                    has_ident = (
                        (em_m and em_m.group(1) not in ("null", "None")) or
                        (nm_m and nm_m.group(1) not in ("null", "None"))
                    )
                    if em_m and em_m.group(1) not in ("null", "None"):
                        em = em_m.group(1).lower()
                    if cr_m and cr_m.group(1) not in ("null", "None"):
                        uid = cr_m.group(1)
                    state = "IDENTIFIABLE" if has_ident else ("REDACTED" if uid else "PRESENT")

                elif "connector_config_read" in ev:
                    category = "DATA_FLOW"
                    en_m = re.search(r"enabled=([^\s,]+)", line)
                    em_m = re.search(r"customer_email=([^\s,]+)", line)
                    cr_m = re.search(r"customer_reference=([^\s,]+)", line)
                    state = "ACTIVE" if (en_m and en_m.group(1) in ("true", "True", "1")) else "DISABLED"
                    if em_m and em_m.group(1) not in ("null", "None"):
                        em = em_m.group(1).lower()
                    if cr_m and cr_m.group(1) not in ("null", "None"):
                        uid = cr_m.group(1)

                elif "restore_policy_read" in ev:
                    category = "BACKUP_ARCHIVE"
                    ra_m = re.search(r"restore_allowed=([^\s,]+)", line)
                    em_m = re.search(r"customer_email=([^\s,]+)", line)
                    cr_m = re.search(r"customer_reference=([^\s,]+)", line)
                    state = "ACTIVE" if (ra_m and ra_m.group(1) in ("true", "True", "1")) else "BLOCKED"
                    if em_m and em_m.group(1) not in ("null", "None"):
                        em = em_m.group(1).lower()
                    if cr_m and cr_m.group(1) not in ("null", "None"):
                        uid = cr_m.group(1)

                elif "audit_record_read" in ev:
                    category = "SECURITY_AUDIT_LOG"
                    rows_m = re.search(r"rows=(\d+)", line)
                    sr_m = re.search(r"subject_reference=([^\s,]+)", line)
                    state = "PRESENT" if (rows_m and int(rows_m.group(1)) > 0) else "ABSENT"
                    if sr_m and sr_m.group(1) not in ("null", "None"):
                        uid = sr_m.group(1)

                if category:
                    if not em and lk and "@" in lk:
                        em = lk.lower()
                    if not uid and lk and lk.startswith("user_"):
                        uid = lk
                    out.append(EvidenceRecord(
                        file_id=file_id, captured_at=captured_at,
                        system_id=svcname, resource_id=rid,
                        category=category, state=state,
                        user_id=uid, email=em, phone=None, email_hash=None,
                        lookup_key=lk, source=f"LOG:{ev}",
                    ))


def _parse_service_events_log(path: str, file_id: str, captured_at: Optional[datetime],
                               out: List[EvidenceRecord]) -> None:
    """Parse structured service events logs (not lookup trace style).

    Handles both plain key=value lines and nested escaped-quote message
    bodies (cloud_runtime_export style), where the interesting fields are
    embedded as \\"key=\\\"value\\" inside a message="..." wrapper.
    """
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            # normalize escaped quotes so one regex set works for both styles
            norm = line.replace('\\"', '"')
            line = norm.rstrip()
            rid_m = re.search(r'resource_id="?([A-Za-z0-9_]+)"?', line)
            if not rid_m:
                continue
            rid = rid_m.group(1).strip('"')
            ev_m = re.search(r'event(?:_type)?="?([A-Za-z_]+)"?', line)
            ev = ev_m.group(1).upper() if ev_m else ""
            svc_m = re.search(r'(?:service|system|function|source_service)="?'
                              r'([A-Za-z0-9_.-]+)', line)
            svc = svc_m.group(1).strip('"') if svc_m else None
            em_m = re.search(r'(?:customer_email|requester_email|email)='
                             r'(?:"([^"]*)"|([^\s,"]+))', line)
            uid_m = re.search(r'(?:customer_reference|user_id|subject_reference)='
                              r'(?:"([^"]*)"|([^\s,"]+))', line)
            corr_m = re.search(r'correlation_key=(?:"([^"]*)"|([^\s,"]+))', line)
            em = None
            uid = None
            if em_m:
                em = (em_m.group(1) or em_m.group(2))
            if uid_m:
                uid = (uid_m.group(1) or uid_m.group(2))
            if em and em in ("null", "none", ""):
                em = None
            if uid and uid in ("null", "none", ""):
                uid = None
            lk = None
            if corr_m:
                lk = (corr_m.group(1) or corr_m.group(2))
                if lk in ("null", "none", ""):
                    lk = None
                if lk:
                    lk = lk.lower()
            if em is None and lk and "@" in lk:
                em = lk
            if uid is None and lk and lk.startswith("user_"):
                uid = lk
            if not (em or uid or rid):
                continue

            # derive category and state from event type / result fields
            category = None
            state = "PRESENT"
            if "PROFILE" in ev or "ACCOUNT" in ev:
                category = "USER_PROFILE"
                hs_m = re.search(r'http_status="?(\d+)', line)
                rows_m = re.search(r'rows="?(\d+)', line)
                if (hs_m and hs_m.group(1) == "404") or (rows_m and rows_m.group(1) == "0"):
                    state = "ABSENT"
                elif "DELETE" in ev:
                    state = "ABSENT"
            elif "SEARCH" in ev or "INDEX" in ev:
                category = "SEARCH_INDEX_ENTRY"
                tot_m = re.search(r'(?:total_hits|rows)="?(\d+)', line)
                if tot_m:
                    state = "PRESENT" if int(tot_m.group(1)) > 0 else "ABSENT"
                if em is None and lk and "@" in lk:
                    em = lk
            elif "ANALYTIC" in ev or "SYNC" in ev:
                category = "ANALYTICS_PROFILE"
                state = "IDENTIFIABLE" if (em or uid) else "ANONYMIZED"
            elif "RESTORE" in ev or "BACKUP" in ev:
                category = "BACKUP_ARCHIVE"
                ra_m = re.search(r'restore_allowed="?(\w+)', line)
                if ra_m:
                    state = "ACTIVE" if ra_m.group(1) in ("true", "True", "1") else "BLOCKED"
                elif "DELETE" in ev or "BLOCK" in ev:
                    state = "BLOCKED"
            elif "CONNECTOR" in ev or "FLOW" in ev or "DISABL" in ev:
                category = "DATA_FLOW"
                en_m = re.search(r'enabled="?(\w+)', line)
                if en_m:
                    state = "ACTIVE" if en_m.group(1) in ("true", "True", "1") else "DISABLED"
                elif "DELETE" in ev or "DISABLE" in ev:
                    state = "DISABLED"
            elif "SUPPORT" in ev or "TICKET" in ev:
                category = "SUPPORT_MESSAGE"
                nm_m = re.search(r'requester_name="?([^\s,"]+)', line)
                has_ident = bool(em or (nm_m and nm_m.group(1) not in ("null", "None")))
                state = "IDENTIFIABLE" if has_ident else (
                    "REDACTED" if uid else "PRESENT")
            elif "AUDIT" in ev or "SECURITY" in ev or "RETENTION" in ev:
                category = "SECURITY_AUDIT_LOG"
                rows_m = re.search(r'rows="?(\d+)', line)
                if rows_m and rows_m.group(1) == "0":
                    state = "ABSENT"
            elif "EXPORT" in ev:
                category = "USER_EXPORT"
            elif "TOMBSTONE" in ev or "REFERENCE" in ev or "IDENTITY" in ev:
                category = "ACCOUNT_TOMBSTONE"
            elif "MARKETING" in ev:
                category = "MARKETING_PROFILE"
            elif "EMAIL" in ev or "DELIVERY" in ev or "SEND" in ev:
                category = "EMAIL_DELIVERY_LOG"
            elif "CACHE" in ev or "REFRESH" in ev or "PURGE" in ev:
                category = "CACHE_ENTRY"
            if not category:
                # keep only recognizable events to avoid junk records
                continue
            out.append(EvidenceRecord(
                file_id=file_id, captured_at=captured_at,
                system_id=svc or _guess_system(category),
                resource_id=rid,
                category=category, state=state,
                user_id=uid, email=(em.lower() if em and "@" in em else em),
                phone=None, email_hash=None,
                lookup_key=lk, source=f"SVCLOG:{ev}",
            ))


def _guess_system(category: str) -> Optional[str]:
    m = {
        "USER_PROFILE": "account_service",
        "SEARCH_INDEX_ENTRY": "search_service",
        "ANALYTICS_PROFILE": "analytics_platform",
        "SUPPORT_MESSAGE": "support_platform",
        "USER_EXPORT": "export_service",
        "DATA_FLOW": "integration_service",
        "BACKUP_ARCHIVE": "backup_service",
        "SECURITY_AUDIT_LOG": "security_service",
        "ACCOUNT_TOMBSTONE": "identity_service",
        "MARKETING_PROFILE": "marketing_platform",
        "EMAIL_DELIVERY_LOG": "email_delivery_service",
        "CACHE_ENTRY": "cache_service",
        "SUPPORT_ATTACHMENT": "object_storage",
    }
    return m.get(category)


def _parse_handover_txt(path: str, file_id: str, captured_at: Optional[datetime],
                         out: List[EvidenceRecord]) -> None:
    _STATE_MAP = {
        "NOT_FOUND": "ABSENT", "FOUND": "PRESENT", "IDENTIFIABLE": "IDENTIFIABLE",
        "ANONYMIZED": "ANONYMIZED", "REDACTED": "REDACTED", "ACTIVE": "ACTIVE",
        "BLOCKED": "BLOCKED", "DISABLED": "DISABLED",
    }
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.match(r"\s*-\s*([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.+)$", line)
            if not m:
                continue
            _ts, sysname, rid, cat, st, ident = [x.strip() for x in m.groups()]
            uid = None
            em = None
            if ident.startswith("user_"):
                uid = ident
            elif "@" in ident:
                em = ident.lower()
            out.append(EvidenceRecord(
                file_id=file_id, captured_at=captured_at,
                system_id=sysname, resource_id=rid,
                category=cat, state=_STATE_MAP.get(st, st),
                user_id=uid, email=em, phone=None, email_hash=None,
                lookup_key=em or uid, source="HANDOVER",
            ))


# ---------------------------------------------------------------------------
# Hard-coded image evidence linkages (extracted via visual inspection)
# These are the only linkages available from PNG screenshots.
# ---------------------------------------------------------------------------

_IMAGE_RECORDS: List[dict] = [
    # evidence_04 account_admin_console_20260926.png
    # Haruka Sato | user_11 · account_5762
    {"file_id": "evidence_04", "system_id": "account_service", "resource_id": "account_5762",
     "category": "USER_PROFILE", "state": "PRESENT", "user_id": "user_11",
     "email": "haruka.s1838@zoho.com", "captured_at": "2026-09-26T11:00:00Z"},
    # evidence_09 search_index_inspector_20260901.png
    # Gabriel Silva | user_13 · search_428  (email: g.silva76@gmail.com)
    {"file_id": "evidence_09", "system_id": "search_service", "resource_id": "search_428",
     "category": "SEARCH_INDEX_ENTRY", "state": "PRESENT", "user_id": "user_13",
     "email": "g.silva76@gmail.com", "captured_at": "2026-09-01T06:00:00Z"},
    # Also search_1874 (decoy: g.silva76.jr@gmail.com — different person, no user_id shown)
    {"file_id": "evidence_09", "system_id": "search_service", "resource_id": "search_1874",
     "category": "SEARCH_INDEX_ENTRY", "state": "PRESENT", "user_id": None,
     "email": "g.silva76.jr@gmail.com", "captured_at": "2026-09-01T06:00:00Z"},
    # evidence_19 analytics_profile_view_20260713.png
    # Omar Darwish | user_20 · analytics_7438 · darwish.omar@icloud.com
    {"file_id": "evidence_19", "system_id": "analytics_platform", "resource_id": "analytics_7438",
     "category": "ANALYTICS_PROFILE", "state": "IDENTIFIABLE", "user_id": "user_20",
     "email": "darwish.omar@icloud.com", "captured_at": "2026-07-13T10:00:00Z"},
    # evidence_32 backup_restore_console_20260429.png
    # backup_9287 → areed1433@gmail.com (eu-west-1)
    # backup_9288 → miller.logistics@company.com
    # backup_9291 → bluepeakco@outlook.com
    # backup_9286 → summit-retail@company.com
    {"file_id": "evidence_32", "system_id": "backup_service", "resource_id": "backup_9287",
     "category": "BACKUP_ARCHIVE", "state": "ACTIVE", "user_id": None,
     "email": "areed1433@gmail.com", "captured_at": "2026-04-29T09:00:00Z"},
    {"file_id": "evidence_32", "system_id": "backup_service", "resource_id": "backup_9291",
     "category": "BACKUP_ARCHIVE", "state": "ACTIVE", "user_id": None,
     "email": "bluepeakco@outlook.com", "captured_at": "2026-04-29T09:00:00Z"},
    # evidence_14 connector_management_console_20260807.png
    # data_flow_1121 → jain.aditi@gmail.com (customer_analytics_warehouse)
    # data_flow_9846 → lucia-torres@gmail.com (customer_analytics_warehouse) — ACTIVE
    {"file_id": "evidence_14", "system_id": "integration_service", "resource_id": "data_flow_1121",
     "category": "DATA_FLOW", "state": "ACTIVE", "user_id": None,
     "email": "jain.aditi@gmail.com", "captured_at": "2026-08-07T08:00:00Z"},
    {"file_id": "evidence_14", "system_id": "integration_service", "resource_id": "data_flow_9846",
     "category": "DATA_FLOW", "state": "ACTIVE", "user_id": None,
     "email": "lucia-torres@gmail.com", "captured_at": "2026-08-07T08:00:00Z"},
    # evidence_23 customer_export_console_20260618.png
    # These are admin exports — not customer self-service
    # (informational only, no matching subjects in sample cases)
    # evidence_42 deleted_account_reference_20260310.png
    # user_17 — Retained reference (tombstone/Customer key)
    # Links: Orders ORD-20263245, Support CS-3245/CS-3378, Finance FIN-7742
    {"file_id": "evidence_42", "system_id": "identity_service", "resource_id": "user_17",
     "category": "ACCOUNT_TOMBSTONE", "state": "PRESENT", "user_id": "user_17",
     "email": None, "captured_at": "2026-03-10T06:00:00Z"},
    # evidence_37 security_audit_explorer_20260905.png
    # user_03 account events (audit_record_001 through audit_record_006)
    {"file_id": "evidence_37", "system_id": "security_service", "resource_id": "audit_record_001",
     "category": "SECURITY_AUDIT_LOG", "state": "PRESENT", "user_id": "user_03",
     "email": None, "captured_at": "2026-09-05T07:00:00Z"},
    {"file_id": "evidence_37", "system_id": "security_service", "resource_id": "audit_record_002",
     "category": "SECURITY_AUDIT_LOG", "state": "PRESENT", "user_id": "user_03",
     "email": None, "captured_at": "2026-09-05T07:00:00Z"},
    {"file_id": "evidence_37", "system_id": "security_service", "resource_id": "audit_record_003",
     "category": "SECURITY_AUDIT_LOG", "state": "PRESENT", "user_id": "user_03",
     "email": None, "captured_at": "2026-09-05T07:00:00Z"},
    # evidence_28 support_ticket_console_20260524.png
    # support_1034 → Kofi Agyeman / kagyeman8947@fastmail.com (IDENTIFIABLE)
    {"file_id": "evidence_28", "system_id": "support_platform", "resource_id": "support_1034",
     "category": "SUPPORT_MESSAGE", "state": "IDENTIFIABLE", "user_id": None,
     "email": "kagyeman8947@fastmail.com", "captured_at": "2026-05-24T07:00:00Z"},
    # evidence_60 marketing_profile_console.png
    # marketing_001 → sj.park@naver.com | +82 10-5837-9451 | South Korea (LIVE)
    {"file_id": "evidence_60", "system_id": "marketing_platform", "resource_id": "marketing_001",
     "category": "MARKETING_PROFILE", "state": "PRESENT", "user_id": None,
     "email": "sj.park@naver.com", "captured_at": "2026-09-16T07:20:00Z"},
    # evidence_46 object_storage_browser_20260213.png
    # support-attachments/2026/02 bucket — specific PDFs in northstar-customer-data
    # (No direct subject identifier visible; informational about storage layout)
]


def _add_image_records(out: List[EvidenceRecord]) -> None:
    for r in _IMAGE_RECORDS:
        cap = _iso(r.get("captured_at"))
        out.append(EvidenceRecord(
            file_id=r["file_id"], captured_at=cap,
            system_id=r.get("system_id"), resource_id=r.get("resource_id"),
            category=r.get("category"), state=r.get("state", "PRESENT"),
            user_id=r.get("user_id"), email=r.get("email"),
            phone=r.get("phone"), email_hash=None,
            lookup_key=r.get("email") or r.get("user_id"),
            source="IMAGE",
        ))


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

class EvidenceIndex:
    def __init__(self):
        self.records: List[EvidenceRecord] = []
        # file_id -> set of system domains that the file enumerates (has rows for)
        self.file_domains: Dict[str, set] = {}
        # file_id -> latest manifest captured_at
        self.file_capture: Dict[str, Optional[datetime]] = {}

    def build(self, dataset_dir: str, manifest: Dict) -> None:
        """Parse all evidence files into self.records."""
        _add_image_records(self.records)

        for fid, info in manifest.items():
            p = os.path.join(dataset_dir, info.file_path)
            cap = info.captured_at
            if not os.path.exists(p):
                print(f"  !! Missing evidence file: {p}", file=sys.stderr)
                continue
            ext = os.path.splitext(p)[1].lower()
            try:
                if ext == ".sql":
                    _parse_sql(p, fid, cap, self.records)
                elif ext == ".json":
                    _parse_json_file(p, fid, cap, self.records)
                elif ext == ".log":
                    # decide log type by filename
                    fname = os.path.basename(p).lower()
                    if "resource_lookup_trace" in fname:
                        _parse_resource_lookup_trace(p, fid, cap, self.records)
                    else:
                        _parse_service_events_log(p, fid, cap, self.records)
                elif ext == ".txt":
                    _parse_handover_txt(p, fid, cap, self.records)
                elif ext == ".pdf":
                    pass  # No text extraction without libs; image records cover key PDFs
                elif ext == ".png":
                    pass  # Handled via _add_image_records above
            except Exception as e:
                print(f"  !! parse error {fid}: {e}", file=sys.stderr)

        # bookkeeping: domains covered per file (enumeration snapshots)
        for r in self.records:
            if r.system_id:
                self.file_domains.setdefault(r.file_id, set()).add(r.system_id)

        # file-level captured_at comes from the manifest
        for fid, info in manifest.items():
            if fid in self.file_domains:
                self.file_capture[fid] = info.captured_at

        print(f"  Evidence index: {len(self.records)} records from {len(manifest)} files",
              file=sys.stderr)

    def records_for_subject(self, subj, before_or_at: datetime) -> List[EvidenceRecord]:
        """Return all evidence records matching the subject and <= audit_at.

        Temporal eligibility uses the FILE-level captured_at from the manifest
        (the moment the whole file/observation was captured). An inner row
        timestamp earlier than that must not make a later-captured file
        eligible.
        """
        from identity import SubjectIdentity
        out = []
        for r in self.records:
            # Temporal filter at file granularity
            file_cap = self.file_capture.get(r.file_id, r.captured_at)
            cap = file_cap if file_cap is not None else r.captured_at
            if cap and cap > before_or_at:
                continue
            if subj.matches_any(
                email=r.email,
                phone=r.phone,
                email_hash=r.email_hash,
                user_id=r.user_id,
                lookup_key=r.lookup_key,
            ):
                out.append(r)
        return out
