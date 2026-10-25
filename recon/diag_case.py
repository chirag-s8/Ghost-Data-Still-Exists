"""diag_case.py – Debug helper. Prints, for chosen sample cases:
  - Identity resolution result
  - All evidence records matched for the subject (with states/files)
  - Golden output steps
Run: python recon/diag_case.py case_01 case_12 ...
"""
import sys, os, csv, json
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "code"))

from loader import load_user_identities, load_audit_log, load_sample_requests, load_sample_output, load_evidence_manifest
from identity import IdentityResolver
from evidence_index import EvidenceIndex

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET = os.path.join(ROOT, "dataset")

loader_names = ["load_user_identities", "load_audit_log", "load_sample_requests"]
identities = load_user_identities(DATASET)
audit_log = load_audit_log(DATASET)
reqs = {r.case_id: r for r in load_sample_requests(DATASET)}
gold = load_sample_output(DATASET)
ev = EvidenceIndex(); ev.build(DATASET, load_evidence_manifest(DATASET))

cases = sys.argv[1:] or ["case_01"]
for cid in cases:
    q = reqs.get(cid)
    if not q:
        print("unknown case", cid); continue
    subj = resolve = None
    from identity import IdentityResolver
    resolver = IdentityResolver(identities, audit_log)
    subj = resolver.resolve(q.email)
    print("=" * 70)
    print(cid, q.email, "reported:", q.reported_status, "audit_at:", q.audit_at)
    print("  text:", q.request_text[:200])
    print("  subject user:", subj.user_id, "emails:", sorted(subj.emails), "hashes:", sorted(subj.email_hashes))
    recs = ev.records_for_subject(subj, q.audit_at)
    for r in recs:
        print(f"   rec {r.file_id} {r.source} sys={r.system_id} rid={r.resource_id} "
              f"cat={r.category} state={r.state} user={r.user_id} email={r.email} hash={bool(r.email_hash)}")
    g = gold.get(cid)
    if g:
        print("  GOLDEN:", g["deletion_status"])
        for s in json.loads(g["steps_json"]):
            print("    ", json.dumps(s))
