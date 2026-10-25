"""mine_links.py – Build email/user -> account resource id linkage from all evidence.

Sources:
  1. resource_lookup_trace logs: profile_lookup_started lines bind
     resource_id (account rid) to lookup_key (email); trace pairs bind
     customer_reference (user_id) to the rid.
  2. cloud runtime logs: correlation_key=<email> + resource_id=<account rid>
  3. SQL profile tables: user references on account records
  4. Search SQL: source_resource_id links search_XXX -> account_YYY
  5. service_resource_export JSON: profile lookups with customer emails

Output: recon/links.json with:
  {
    "email_to_account": {email_lc: [rid,...]},
    "user_to_account": {user_id: [rid,...]},
    "search_to_account": {search_rid: account_rid}
  }
"""
import os
import re
import json
import sqlite3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVID = os.path.join(ROOT, "dataset", "evidence")

email_to_account = {}
user_to_account = {}
search_to_account = {}
trace_lookup = {}  # trace_id -> (lookup_key, resource_id)


def add_email(rid, em):
    if em:
        email_to_account.setdefault(em.lower(), set()).add(rid)


def add_user(rid, uid):
    if uid and re.match(r"^user_\d+$", uid):
        user_to_account.setdefault(uid, set()).add(rid)


# ---- 1. resource_lookup_trace + other logs ------------------------------------
logdir = os.path.join(EVID, "logs")
for fn in sorted(os.listdir(logdir)):
    if not fn.endswith(".log"):
        continue
    path = os.path.join(logdir, fn)
    is_trace = "resource_lookup_trace" in fn
    for line in open(path, encoding="utf-8", errors="replace"):
        norm = line.replace('\\"', '"')
        rid_m = re.search(r'resource_id="?=?([^"\[\],\s]+)', norm)
        if not rid_m:
            continue
        rid = rid_m.group(1)
        if is_trace or "resource_lookup_trace" in fn or "trace_id=" in norm:
            tr_m = re.search(r"trace_id=(\S+)", norm)
            ev_m = re.search(r"event=([\w_]+)", norm)
            lk_m = re.search(r'lookup_key="?([^"\s,]+)', norm)
            if rid.startswith("account_"):
                # started line binds rid to lookup_key (email); completed line
                # may bind customer_reference / customer_email.
                cr_m = re.search(r'customer_reference="?([A-Za-z0-9_]+)', norm)
                em_m = re.search(r'customer_email="?([\w.+\-]+@[\w.\-]+\.\w+)', norm)
                if (cr_m and cr_m.group(1) not in ("null", "None")):
                    add_user(rid, cr_m.group(1))
                if em_m:
                    add_email(rid, em_m.group(1))
            if tr_m and ev_m:
                tid = tr_m.group(1)
                ev = ev_m.group(1)
                lk = lk_m.group(1).strip('"') if lk_m else None
                if lk in ("null", "None"):
                    lk = None
                if ev.endswith("_started"):
                    trace_lookup[tid] = (lk, rid)
                elif ev.endswith("_completed"):
                    info = trace_lookup.get(tid)
                    if info:
                        lk0, rid0 = info
                        if rid0 == rid and rid.startswith("account_"):
                            if lk0 and "@" in lk0:
                                add_email(rid, lk0)
                            elif lk0 and lk0.startswith("user_"):
                                add_user(rid, lk0)
        # cloud runtime logs: correlation_key + account rid on same line
        if "correlation_key=" in norm:
            accs = re.findall(r'resource_id="?=?\\?"?(account_\d+)', norm)
            em_raw = re.search(r'correlation_key="?=?([\w.+\-]+)', norm)
            em = em_raw.group(1).split("\\")[0].strip('"').lower() if em_raw else None
            if accs and em and "@" in em:
                for a in accs:
                    add_email(a, em)

# ---- 2. SQL profile tables and search source links -----------------------------
d = os.path.join(EVID, "databases")
for fn in sorted(os.listdir(d)):
    if not fn.endswith(".sql"):
        continue
    p = os.path.join(d, fn)
    try:
        con = sqlite3.connect(":memory:")
        con.executescript(open(p, encoding="utf-8").read())
    except Exception:
        continue
    try:
        tables = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    except Exception:
        continue
    for (t,) in tables:
        try:
            cols = [c[1] for c in con.execute(f'PRAGMA table_info("{t}")')]
        except Exception:
            continue
        json_row = "record_json" in cols
        for raw in con.execute(f'SELECT * FROM "{t}"'):
            rec = dict(zip(cols, raw))
            if json_row:
                try:
                    inner = json.loads(rec.get("record_json") or "{}")
                except Exception:
                    continue
                rid = inner.get("resource_id") or rec.get("resource_id")
                uid = inner.get("subject_reference") or inner.get("user_id")
                em = inner.get("email")
                src = inner.get("source_resource_id")
                st = inner.get("account_status")
            else:
                rid = rec.get("resource_id")
                uid = (rec.get("subject_reference") or rec.get("user_id")
                       or rec.get("customer_reference"))
                em = rec.get("email")
                src = rec.get("source_resource_id")
                st = rec.get("account_status")
            if not rid:
                continue
            if rid.startswith("account_"):
                if uid:
                    add_user(rid, uid)
                if em and not (st and "DELETED" in st.upper()):
                    add_email(rid, em)
            if rid.startswith("search_") and src and src.startswith("account_"):
                search_to_account[rid] = src
    con.close()

# ---- 3. service_resource_export JSON: profile lookups with emails --------------
recdir = os.path.join(EVID, "records")
for fn in sorted(os.listdir(recdir)):
    if not fn.endswith(".json"):
        continue
    p = os.path.join(recdir, fn)
    try:
        d = json.load(open(p, encoding="utf-8"))
    except Exception:
        continue
    if not isinstance(d, dict):
        continue
    se = d.get("service_exports")
    if not isinstance(se, dict):
        continue
    for sysname, payload in se.items():
        if not isinstance(payload, dict):
            continue
        for r in payload.get("profile_lookups", []):
            rid = r.get("resource_id")
            lr = r.get("lookup_key") or r.get("correlation_key")
            prof = r.get("profile") or {}
            em = prof.get("email") or lr
            if isinstance(em, str) and "@" in em and rid and rid.startswith("account_"):
                add_email(rid, em)
            if rid and rid.startswith("account_") and prof.get("subject_reference"):
                add_user(rid, prof["subject_reference"])

out = {
    "email_to_account": {k: sorted(v) for k, v in email_to_account.items()},
    "user_to_account": {k: sorted(v) for k, v in user_to_account.items()},
    "search_to_account": search_to_account,
}
dst = os.path.join(os.path.dirname(os.path.abspath(__file__)), "links.json")
with open(dst, "w", encoding="utf-8") as f:
    json.dump(out, f, indent=1, ensure_ascii=False)
print("email_to_account entries:", len(email_to_account))
print("user_to_account entries:", len(user_to_account))
print("search_to_account entries:", len(search_to_account))
print("wrote", dst)
