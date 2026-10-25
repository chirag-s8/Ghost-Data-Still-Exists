"""Compute evaluation metrics for the deletion-audit agent.

Usage: python recon/eval_metrics.py
Reports (on the 32 public sample cases):
  - case-level deletion_status accuracy
  - step-level accuracy (step count + content per step, positionally aligned)
  - field-level accuracy (per field over positionally aligned steps)
  - sequence accuracy (ordered 5-tuples phase/system/resource/op/state)
Then runs three participant-authored custom cases and prints their outputs.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "code"))

from loader import (  # noqa: E402
    load_audit_log,
    load_deletion_rules,
    load_evidence_manifest,
    load_sample_output,
    load_sample_requests,
    load_system_activity,
    load_user_identities,
)
from evidence_index import EvidenceIndex  # noqa: E402
from identity import IdentityResolver  # noqa: E402
from investigator import investigate  # noqa: E402
from intent import is_deletion_request  # noqa: E402


def run():
    DATASET = os.path.join(ROOT, "dataset")
    manifest = load_evidence_manifest(DATASET)
    idx = EvidenceIndex()
    idx.build(DATASET, manifest)
    resolver = IdentityResolver(
        load_user_identities(DATASET), load_audit_log(DATASET))
    acts = sorted(load_system_activity(DATASET),
                  key=lambda a: (a.event_time, a.activity_id))
    gold = load_sample_output(DATASET)

    status_ok = step_exact = seq_ok = tot = 0
    field_ok = field_tot = 0
    step_ok_positions = step_tot_positions = 0

    for q in load_sample_requests(DATASET):
        g = gold.get(q.case_id)
        if not g:
            continue
        tot += 1
        res = investigate(q, resolver, idx, acts)
        if res.deletion_status == g["deletion_status"]:
            status_ok += 1
        exp = json.loads(g["steps_json"])
        pred = [s.to_dict() for s in res.steps]
        n = min(len(exp), len(pred))
        # positional field comparison
        trip_full = True
        for i in range(n):
            if exp[i] == pred[i]:
                step_ok_positions += 1
            step_tot_positions += 1
            for k in ("phase", "system_id", "resource_id", "operation",
                      "state", "evidence_id"):
                if str(exp[i].get(k, "")) == str(pred[i].get(k, "")):
                    field_ok += 1
                else:
                    trip_full = False
                field_tot += 1
        if n == len(exp) == len(pred) and trip_full:
            step_exact += 1
        seq_full = n == len(exp) == len(pred)
        for i in range(n):
            e5 = tuple(str(exp[i].get(k, "")) for k in
                       ("phase", "system_id", "resource_id", "operation", "state"))
            p5 = tuple(str(pred[i].get(k, "")) for k in
                       ("phase", "system_id", "resource_id", "operation", "state"))
            if e5 != p5:
                seq_full = False
        if seq_full:
            seq_ok += 1

    print(f"SAMPLE METRICS ({tot} cases)")
    print(f"  status accuracy : {status_ok}/{tot}")
    print(f"  step-exact cases: {step_exact}/{tot}")
    print(f"  field accuracy  : {field_ok}/{field_tot}")
    print(f"  sequence accuracy: {seq_ok}/{tot}")

    # ------------------------------------------------------------------
    # Three participant-authored custom evaluation cases
    # ------------------------------------------------------------------
    print("\nCUSTOM CASES")

    # Cases are built against real resolved subjects so identity resolution
    # is exercised; request_text drives the intended branch.

    class FakeReq:
        def __init__(self, case_id, email, text):
            from datetime import datetime, timezone
            self.case_id = case_id
            self.email = email
            self.requested_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
            self.reported_at = datetime(2026, 2, 1, tzinfo=timezone.utc)
            self.audit_at = datetime(2026, 3, 1, tzinfo=timezone.utc)
            self.reported_status = "COMPLETE"
            self.request_text = text

    customs = [
        ("custom_01", "amina.elmasri@gmail.com",
         "How do I download a copy of my order history? I want to check "
         "what I bought last year.", "NOT_APPLICABLE (export request)"),
        ("custom_02", "rafael.r9464@outlook.com",
         "Please erase my personal data permanently, I do not want "
         "anything remaining that identifies me.", "deletion (erasure)"),
        ("custom_03", "jonas.berg@outlook.com",
         "Delete my account and all my data, I no longer use this shop.",
         "deletion (account closure)"),
    ]
    for cid, email, text, note in customs:
        req = FakeReq(cid, email, text)
        na = not is_deletion_request(text)
        res = investigate(req, resolver, idx, acts)
        steps = res.steps
        print(f"  {cid} [{note}] requested={email[:24]} "
              f"intent-delete={not na}")
        print(f"    -> status={res.deletion_status} steps={len(steps)}")
        for s in steps[:8]:
            d = s.to_dict()
            print(f"       {d['step_no']:>2} {d['phase']:<11} "
                  f"{d['system_id']:<19} {d['resource_id']:<22} "
                  f"{d['operation']:<26} {d['state']:<11} "
                  f"ev={d['evidence_id'] or '-'}")


if __name__ == "__main__":
    run()
