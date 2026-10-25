#!/usr/bin/env python3
"""Reconnaissance: build a unified evidence record index and dump linkage
for two sample cases (case_03 = l.fontaine46, case_25 = s.yoon04) to discover
exactly how each expected resource is linked to the subject.

Pure stdlib. Parses SQL (via sqlite3), JSON, logs, and handover txt.
"""
import csv
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET = os.path.join(ROOT, "dataset")
EVIDENCE = os.path.join(DATASET, "evidence")


def iso(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Load identity helpers
# ---------------------------------------------------------------------------
def load_identities():
    rows = []
    with open(os.path.join(DATASET, "user_identities.csv"), newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


def load_audit_log():
    rows = []
    with open(os.path.join(DATASET, "user_audit_log.csv"), newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


def load_evidence_manifest():
    m = {}
    with open(os.path.join(DATASET, "evidence_files.csv"), newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            m[r["file_id"]] = r
    return m


def resolve_subject(email, identities, audit_log):
    """Return dict: user_id, emails set, phones set, email_hashes set, names set."""
    email_lc = email.strip().lower()
    by_email = {}
    for r in identities:
        by_email.setdefault(r["email"].strip().lower(), []).append(r)
    matches = list(by_email.get(email_lc, []))
    user_id = matches[0]["user_id"] if matches else None
    # historical emails/phones via audit log (only if we resolved a user_id)
    emails = {email_lc}
    phones = set()
    hashes = set()
    names = set()
    if matches:
        for r in matches:
            emails.add(r["email"].strip().lower())
            if r["phone"]:
                phones.add(r["phone"].strip())
            if r["email_hash"]:
                hashes.add(r["email_hash"].strip().lower())
            if r["name"]:
                names.add(r["name"].strip().lower())
    if user_id:
        for a in audit_log:
            if a["user_id"] == user_id:
                if a["field_name"] == "email":
                    if a["old_value"]:
                        emails.add(a["old_value"].strip().lower())
                    if a["new_value"]:
                        emails.add(a["new_value"].strip().lower())
                elif a["field_name"] == "phone":
                    if a["old_value"]:
                        phones.add(a["old_value"].strip())
                    if a["new_value"]:
                        phones.add(a["new_value"].strip())
                elif a["field_name"] == "email_hash":
                    if a["old_value"]:
                        hashes.add(a["old_value"].strip().lower())
                    if a["new_value"]:
                        hashes.add(a["new_value"].strip().lower())
    emails.discard("")
    phones.discard("")
    hashes.discard("")
    return {
        "user_id": user_id,
        "emails": emails,
        "phones": phones,
        "hashes": hashes,
        "names": names,
    }


# ---------------------------------------------------------------------------
# Evidence parsing into a unified record list
# Each record: dict(file_id, captured_at(str), system_id, resource_id, category,
#                   state, user_id, email, phone, email_hash, lookup_key, source)
# 'state' is a normalized label: PRESENT/ABSENT/REDACTED/ANONYMIZED/ACTIVE/DISABLED/BLOCKED/PRESENT_REDACTED/IDENTIFIABLE/UNKNOWN
# ---------------------------------------------------------------------------

# table -> (system_id, category, state-derivation)
def derive_state_for_table(category, row):
    """Infer a normalized state from a SQL/JSON row dict for inventory-style tables."""
    if category == "USER_PROFILE":
        st = (row.get("account_status") or "").upper()
        if st in ("DELETED", "ACCOUNT_DELETED"):
            return "ABSENT"
        if "PENDING" in st or st in ("ACTIVE", ""):
            # present (exists) unless explicitly deleted
            return "PRESENT"
        return "PRESENT"
    if category == "SEARCH_INDEX_ENTRY":
        return "PRESENT"
    if category == "ANALYTICS_PROFILE":
        # anonymized if no direct identifier
        if (row.get("email") or row.get("phone") or row.get("email_hash") or row.get("customer_reference") or row.get("user_id")):
            return "IDENTIFIABLE"
        return "ANONYMIZED"
    if category == "SUPPORT_MESSAGE":
        if (row.get("requester_email") or row.get("requester_phone") or row.get("requester_name")):
            return "IDENTIFIABLE"
        if row.get("customer_reference") or row.get("user_id"):
            return "REDACTED"
        return "PRESENT"
    if category == "SUPPORT_ATTACHMENT":
        return "PRESENT"
    if category == "USER_EXPORT":
        return "PRESENT"
    if category == "MARKETING_PROFILE":
        return "PRESENT"
    if category == "DATA_FLOW":
        enabled = str(row.get("enabled")).strip()
        if enabled in ("1", "true", "True"):
            return "ACTIVE"
        return "DISABLED"
    if category == "BACKUP_ARCHIVE":
        ra = str(row.get("restore_allowed")).strip()
        if ra in ("1", "true", "True"):
            return "ACTIVE"  # restore risk
        return "BLOCKED"
    if category == "SECURITY_AUDIT_LOG":
        return "PRESENT"
    if category == "ACCOUNT_TOMBSTONE":
        if (row.get("name") or row.get("email") or row.get("phone") or row.get("email_hash")):
            return "IDENTIFIABLE"
        return "REDACTED"
    return "PRESENT"


# Mapping from SQL table name -> (system_id, category)
TABLE_MAP = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_profiles_primary": ("account_service", "USER_PROFILE"),
    "customer_profiles_failover_replica": ("account_service", "USER_PROFILE"),
    "customer_profiles_read_replica": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_search_documents_primary": ("search_service", "SEARCH_INDEX_ENTRY"),
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
}


def parse_sql_file(path, file_id, captured_at, out):
    """Execute SQL in sqlite3 :memory: and extract all mapped tables."""
    with open(path, encoding="utf-8") as f:
        script = f.read()
    con = sqlite3.connect(":memory:")
    try:
        con.executescript(script)
    except Exception as e:
        # try stripping problematic pragmas
        try:
            con2 = sqlite3.connect(":memory:")
            s2 = re.sub(r"PRAGMA[^;]+;", "", script)
            con2.executescript(s2)
            con.close()
            con = con2
        except Exception as e2:
            con.close()
            print(f"  !! SQL parse failed {file_id}: {e2}", file=sys.stderr)
            return
    cur = con.cursor()
    tables = [r[0] for r in cur.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
    for t in tables:
        key = t.lower()
        mapping = None
        for k, v in TABLE_MAP.items():
            if key == k or key.startswith(k):
                mapping = v
                break
        if not mapping:
            continue
        system_id, category = mapping
        try:
            cols = [d[0] for d in cur.execute(f'SELECT * FROM "{t}" LIMIT 1').description]
            data = cur.execute(f'SELECT * FROM "{t}"').fetchall()
        except Exception:
            continue
        for d in data:
            row = dict(zip(cols, d))
            ident_user = row.get("customer_reference") or row.get("user_id") or row.get("subject_reference")
            rec = {
                "file_id": file_id, "captured_at": captured_at,
                "system_id": system_id, "resource_id": row.get("resource_id"),
                "category": category, "state": derive_state_for_table(category, row),
                "user_id": ident_user, "email": (row.get("email") or row.get("owner_email") or row.get("customer_email") or row.get("requester_email")),
                "phone": row.get("phone") or row.get("owner_phone") or row.get("requester_phone"),
                "email_hash": row.get("email_hash"),
                "lookup_key": None, "source": f"SQL:{t}",
            }
            out.append(rec)
    con.close()


def parse_service_resource_export(path, file_id, captured_at, out):
    data = json.load(open(path, encoding="utf-8"))
    se = data.get("service_exports", {})
    # account_service -> profile_lookups
    for sysname, payload in se.items():
        kind = None
        if sysname == "account_service":
            for r in payload.get("profile_lookups", []):
                prof = r.get("profile")
                state = "ABSENT" if r.get("status_code") == 404 or not prof else "PRESENT"
                out.append({"file_id": file_id, "captured_at": captured_at, "system_id": sysname,
                            "resource_id": r.get("resource_id"), "category": "USER_PROFILE",
                            "state": state, "user_id": (prof or {}).get("customer_reference"),
                            "email": (prof or {}).get("email"), "phone": (prof or {}).get("phone"),
                            "email_hash": (prof or {}).get("email_hash"), "lookup_key": None, "source": "JSON:profile_lookups"})
        elif sysname == "analytics_platform":
            for r in payload.get("profiles", []):
                ident = r.get("email") or r.get("phone") or r.get("email_hash") or r.get("customer_reference")
                out.append({"file_id": file_id, "captured_at": captured_at, "system_id": sysname,
                            "resource_id": r.get("resource_id"), "category": "ANALYTICS_PROFILE",
                            "state": "IDENTIFIABLE" if ident else "ANONYMIZED",
                            "user_id": r.get("customer_reference"), "email": r.get("email"),
                            "phone": r.get("phone"), "email_hash": r.get("email_hash"),
                            "lookup_key": None, "source": "JSON:analytics_profiles"})
        elif sysname == "search_service":
            for q in payload.get("index_queries", []):
                hits = q.get("hits", {})
                docs = hits.get("documents", [])
                doc = docs[0] if docs else {}
                out.append({"file_id": file_id, "captured_at": captured_at, "system_id": sysname,
                            "resource_id": q.get("resource_id"), "category": "SEARCH_INDEX_ENTRY",
                            "state": "ABSENT" if hits.get("total", 0) == 0 else "PRESENT",
                            "user_id": doc.get("customer_reference"), "email": doc.get("email"),
                            "phone": doc.get("phone"), "email_hash": doc.get("email_hash"),
                            "lookup_key": q.get("query"), "source": "JSON:search_index"})
        elif sysname == "support_platform":
            for r in payload.get("tickets", []):
                ident = r.get("requester_email") or r.get("requester_phone") or r.get("requester_name")
                out.append({"file_id": file_id, "captured_at": captured_at, "system_id": sysname,
                            "resource_id": r.get("resource_id"), "category": "SUPPORT_MESSAGE",
                            "state": "IDENTIFIABLE" if ident else "REDACTED",
                            "user_id": r.get("customer_reference"), "email": r.get("requester_email"),
                            "phone": r.get("requester_phone"), "email_hash": None,
                            "lookup_key": None, "source": "JSON:support_tickets"})
        elif sysname == "export_service":
            for r in payload.get("exports", []):
                out.append({"file_id": file_id, "captured_at": captured_at, "system_id": sysname,
                            "resource_id": r.get("resource_id"), "category": "USER_EXPORT",
                            "state": "PRESENT", "user_id": r.get("customer_reference"),
                            "email": r.get("owner_email"), "phone": r.get("owner_phone"),
                            "email_hash": None, "lookup_key": None, "source": "JSON:exports"})
        elif sysname == "integration_service":
            for r in payload.get("connectors", []):
                enabled = r.get("enabled")
                out.append({"file_id": file_id, "captured_at": captured_at, "system_id": sysname,
                            "resource_id": r.get("resource_id"), "category": "DATA_FLOW",
                            "state": "ACTIVE" if enabled else "DISABLED",
                            "user_id": r.get("customer_reference"), "email": r.get("customer_email"),
                            "phone": None, "email_hash": None, "lookup_key": None, "source": "JSON:connectors"})
        elif sysname == "backup_service":
            for r in payload.get("restore_entries", []):
                ra = r.get("restore_allowed")
                out.append({"file_id": file_id, "captured_at": captured_at, "system_id": sysname,
                            "resource_id": r.get("resource_id"), "category": "BACKUP_ARCHIVE",
                            "state": "ACTIVE" if ra else "BLOCKED",
                            "user_id": r.get("customer_reference"), "email": r.get("customer_email"),
                            "phone": None, "email_hash": None, "lookup_key": None, "source": "JSON:backup"})
        elif sysname == "security_service":
            for r in payload.get("audit_records", []):
                out.append({"file_id": file_id, "captured_at": captured_at, "system_id": sysname,
                            "resource_id": r.get("resource_id"), "category": "SECURITY_AUDIT_LOG",
                            "state": "PRESENT", "user_id": r.get("subject_reference"),
                            "email": None, "phone": None, "email_hash": None,
                            "lookup_key": None, "source": "JSON:audit"})


def parse_snapshot_bundle(path, file_id, captured_at, out):
    data = json.load(open(path, encoding="utf-8"))
    for snap in data.get("snapshots", []):
        ds = snap.get("data_store")
        coll = snap.get("collection", "")
        cap = snap.get("captured_at") or captured_at
        mapping = None
        for k, v in TABLE_MAP.items():
            if coll.lower().startswith(k) or coll.lower() == k:
                mapping = v
                break
        if not mapping:
            # try by data_store
            dsmap = {"account_service": "USER_PROFILE", "search_service": "SEARCH_INDEX_ENTRY",
                     "analytics_platform": "ANALYTICS_PROFILE", "support_platform": "SUPPORT_MESSAGE",
                     "export_service": "USER_EXPORT", "integration_service": "DATA_FLOW",
                     "backup_service": "BACKUP_ARCHIVE", "security_service": "SECURITY_AUDIT_LOG",
                     "identity_service": "ACCOUNT_TOMBSTONE"}
            cat = dsmap.get(ds)
            if not cat:
                continue
            mapping = (ds, cat)
        system_id, category = mapping
        for r in snap.get("records", []):
            row = dict(r)
            # flatten nested 'document'
            if "document" in row and isinstance(row["document"], dict):
                for k2, v2 in row["document"].items():
                    row.setdefault(k2, v2)
            ident_user = row.get("customer_reference") or row.get("user_id") or row.get("subject_reference")
            rec = {"file_id": file_id, "captured_at": cap, "system_id": system_id,
                   "resource_id": row.get("resource_id"), "category": category,
                   "state": derive_state_for_table(category, row),
                   "user_id": ident_user, "email": row.get("email"),
                   "phone": row.get("phone"), "email_hash": row.get("email_hash"),
                   "lookup_key": None, "source": f"JSONBUNDLE:{coll}"}
            out.append(rec)


def parse_log_file(path, file_id, captured_at, out):
    """Parse resource_lookup_trace and service_events style logs."""
    text = open(path, encoding="utf-8", errors="replace").read()
    # resource_lookup_trace lines: event=profile_lookup_completed resource_id=X rows=0 http_status=404 ; lookup_key=Y on started line
    # We pair started+completed by trace_id.
    started = {}
    for line in text.splitlines():
        m = re.search(r"trace_id=(\S+)", line)
        rid = re.search(r"resource_id=(\S+)", line)
        ts = re.match(r"(\S+)\s", line)
        tstamp = ts.group(1) if ts else None
        svc = re.search(r"service=(\S+)", line)
        if "lookup_key=" in line and rid:
            lk = re.search(r"lookup_key=(\S+)", line)
            started[rid.group(1)] = {
                "lookup_key": (lk.group(1) if lk else None),
                "service": svc.group(1) if svc else None,
                "ts": tstamp,
            }
        ev = re.search(r"event=(\S+)", line)
        if ev and rid and "_completed" in ev.group(1):
            st = started.get(rid.group(1), {})
            svcname = st.get("service") or (svc.group(1) if svc else None)
            # determine state
            state = "UNKNOWN"
            category = None
            evname = ev.group(1)
            if "profile_lookup" in evname:
                category = "USER_PROFILE"
                hs = re.search(r"http_status=(\d+)", line)
                rowsm = re.search(r"rows=(\d+)", line)
                if hs and hs.group(1) == "404":
                    state = "ABSENT"
                elif rowsm and rowsm.group(1) == "0":
                    state = "ABSENT"
                else:
                    state = "PRESENT"
            elif "analytics_profile_read" in evname:
                category = "ANALYTICS_PROFILE"
                em = re.search(r"email=(\S+)", line)
                cr = re.search(r"customer_reference=(\S+)", line)
                ph = re.search(r"phone=(\S+)", line)
                eh = re.search(r"email_hash=(\S+)", line)
                if em or cr or ph or eh:
                    if em and em.group(1) != "null":
                        state = "IDENTIFIABLE"
                    else:
                        state = "IDENTIFIABLE"
                else:
                    state = "ANONYMIZED"
            elif "index_query" in evname:
                category = "SEARCH_INDEX_ENTRY"
                tot = re.search(r"total_hits=(\d+)", line)
                state = "PRESENT" if (tot and int(tot.group(1)) > 0) else "ABSENT"
            elif "support_ticket_read" in evname:
                category = "SUPPORT_MESSAGE"
                em = re.search(r"requester_email=(\S+)", line)
                nm = re.search(r"requester_name=(\S+)", line)
                ph = re.search(r"requester_phone=(\S+)", line)
                cr = re.search(r"customer_reference=(\S+)", line)
                if (em and em.group(1) != "null") or (nm and nm.group(1) != "null") or (ph and nm and ph.group(1) != "null"):
                    state = "IDENTIFIABLE"
                elif cr and cr.group(1) != "null":
                    state = "REDACTED"
                else:
                    state = "PRESENT"
            elif "connector_config_read" in evname:
                category = "DATA_FLOW"
                en = re.search(r"enabled=(\S+)", line)
                state = "ACTIVE" if (en and en.group(1) in ("true", "True", "1")) else "DISABLED"
            elif "restore_policy_read" in evname:
                category = "BACKUP_ARCHIVE"
                ra = re.search(r"restore_allowed=(\S+)", line)
                state = "ACTIVE" if (ra and ra.group(1) in ("true", "True", "1")) else "BLOCKED"
            elif "audit_record_read" in evname:
                category = "SECURITY_AUDIT_LOG"
                rowsm = re.search(r"rows=(\d+)", line)
                state = "PRESENT" if (rowsm and int(rowsm.group(1)) > 0) else "ABSENT"
            if category:
                lk = st.get("lookup_key")
                # extract identifiers from completed line too
                em = re.search(r"email=([^\s]+)", line)
                cr = re.search(r"customer_reference=([^\s]+)", line)
                sr = re.search(r"subject_reference=([^\s]+)", line)
                rec_user = None
                if cr and cr.group(1) != "null":
                    rec_user = cr.group(1)
                if sr and sr.group(1) != "null":
                    rec_user = sr.group(1)
                rec_email = em.group(1) if (em and em.group(1) != "null") else None
                out.append({"file_id": file_id, "captured_at": captured_at, "system_id": svcname,
                            "resource_id": rid.group(1), "category": category, "state": state,
                            "user_id": rec_user, "email": rec_email, "phone": None, "email_hash": None,
                            "lookup_key": lk, "source": f"LOG:{evname}"})


def parse_handover_txt(path, file_id, captured_at, out):
    text = open(path, encoding="utf-8", errors="replace").read()
    # lines: - TS | system_id | resource_id | CATEGORY | STATE | identifier
    for line in text.splitlines():
        m = re.match(r"\s*-\s*([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|([^|]+)\|(.+)$", line)
        if not m:
            continue
        ts, sysname, rid, cat, st, ident = [x.strip() for x in m.groups()]
        ident = ident.strip()
        user_id = None; email = None; phone = None
        if ident.startswith("user_"):
            user_id = ident
        elif "@" in ident:
            email = ident.lower()
        # normalize state
        state_map = {"NOT_FOUND": "ABSENT", "FOUND": "PRESENT", "IDENTIFIABLE": "IDENTIFIABLE",
                     "ANONYMIZED": "ANONYMIZED", "REDACTED": "REDACTED", "ACTIVE": "ACTIVE",
                     "BLOCKED": "BLOCKED", "DISABLED": "DISABLED"}
        out.append({"file_id": file_id, "captured_at": captured_at, "system_id": sysname,
                    "resource_id": rid, "category": cat, "state": state_map.get(st, st),
                    "user_id": user_id, "email": email, "phone": phone, "email_hash": None,
                    "lookup_key": email or user_id, "source": "HANDOVER"})


def parse_pdf_text(path, file_id, captured_at, out):
    """Best-effort: extract text from PDF content streams (no library)."""
    try:
        raw = open(path, "rb").read()
    except Exception:
        return
    # Extract text inside parentheses in BT...ET blocks (very basic)
    text_chunks = re.findall(rb"\((?:[^()\\]|\\.)*\)", raw)
    decoded = []
    for c in text_chunks:
        try:
            decoded.append(c.decode("latin-1"))
        except Exception:
            pass
    full = " ".join(decoded)
    # we just stash raw text for inspection; not structured enough generally
    if decoded:
        out.append({"file_id": file_id, "captured_at": captured_at, "system_id": None,
                    "resource_id": None, "category": "PDF_TEXT", "state": "PRESENT",
                    "user_id": None, "email": None, "phone": None, "email_hash": None,
                    "lookup_key": None, "source": "PDF_TEXT", "_text": full[:2000]})


def build_index(manifest):
    out = []
    for fid, info in manifest.items():
        p = os.path.join(DATASET, info["file_path"])
        cap = info["captured_at"]
        if not os.path.exists(p):
            continue
        ext = os.path.splitext(p)[1].lower()
        try:
            if ext == ".sql":
                parse_sql_file(p, fid, cap, out)
            elif ext == ".json":
                # decide bundle vs service export vs others by content
                try:
                    data = json.load(open(p, encoding="utf-8"))
                except Exception:
                    continue
                if "service_exports" in data:
                    parse_service_resource_export(p, fid, cap, out)
                elif "snapshots" in data:
                    parse_snapshot_bundle(p, fid, cap, out)
                elif isinstance(data, dict):
                    # other JSON records: flatten and look for resource_ids
                    flat = json.dumps(data)
                    for m in re.finditer(r'"resource_id"\s*:\s*"([^"]+)"', flat):
                        out.append({"file_id": fid, "captured_at": cap, "system_id": None,
                                    "resource_id": m.group(1), "category": "JSON_OTHER",
                                    "state": "PRESENT", "user_id": None, "email": None,
                                    "phone": None, "email_hash": None, "lookup_key": None,
                                    "source": "JSON_OTHER", "_text": flat[:1500]})
            elif ext == ".log":
                parse_log_file(p, fid, cap, out)
            elif ext == ".txt":
                parse_handover_txt(p, fid, cap, out)
            elif ext == ".pdf":
                parse_pdf_text(p, fid, cap, out)
            elif ext == ".png":
                # cannot OCR without libs
                pass
        except Exception as e:
            print(f"  !! parse {fid}: {e}", file=sys.stderr)
    return out


def match_record(rec, subj):
    """Does this evidence record belong to the subject?"""
    rid_email = (rec.get("email") or "").lower() if rec.get("email") else None
    if rid_email and rid_email in subj["emails"]:
        return True
    if rec.get("email_hash") and rec.get("email_hash").lower() in subj["hashes"]:
        return True
    if rec.get("phone") and rec.get("phone") in subj["phones"]:
        return True
    if rec.get("user_id") and rec.get("user_id") == subj["user_id"]:
        return True
    lk = rec.get("lookup_key")
    if lk:
        if lk.startswith("user_"):
            if lk == subj["user_id"]:
                return True
        elif "@" in lk:
            if lk.lower() in subj["emails"]:
                return True
    return False


def main():
    identities = load_identities()
    audit_log = load_audit_log()
    manifest = load_evidence_manifest()
    print(f"Identities: {len(identities)} | audit_log: {len(audit_log)} | evidence files: {len(manifest)}")
    idx = build_index(manifest)
    print(f"Total parsed evidence records: {len(idx)}")
    # breakdown by source
    from collections import Counter
    c = Counter(r["source"].split(":")[0] for r in idx)
    print("By source type:", dict(c))
    c2 = Counter(r["category"] for r in idx if r["category"])
    print("By category:", dict(c2))

    for case_email in ["l.fontaine46@yahoo.com", "s.yoon04@gmail.com"]:
        print("\n" + "=" * 80)
        subj = resolve_subject(case_email, identities, audit_log)
        print(f"Subject {case_email}:")
        print(f"  user_id={subj['user_id']}")
        print(f"  emails={subj['emails']}")
        print(f"  phones={subj['phones']}")
        print(f"  hashes={subj['hashes']}")
        # find matching records
        matched = [r for r in idx if match_record(r, subj)]
        print(f"  matched evidence records: {len(matched)}")
        # dedupe by (resource_id) keep latest captured_at
        seen = {}
        for r in matched:
            key = r["resource_id"]
            if not key:
                continue
            seen.setdefault(key, []).append(r)
        print(f"  distinct resources linked: {len(seen)}")
        for rid in sorted(seen.keys()):
            recs = sorted(seen[rid], key=lambda x: x["captured_at"] or "")
            print(f"    {rid}: ", end="")
            for r in recs:
                print(f"[{r['file_id']}@{r['captured_at'][:10]} {r['system_id']} {r['category']} {r['state']} lk={r['lookup_key']}]", end=" ")
            print()


if __name__ == "__main__":
    main()
