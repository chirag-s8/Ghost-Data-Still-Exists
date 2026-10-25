# Evaluation Report — Ghost Data Still Exists (Deletion-Audit Agent)

## 1. Architecture under test

The submitted solution (`code/`) is a deterministic, rule-based multi-stage
pipeline (no LLM calls at evaluation time):

1. **Intent** (`intent.py`) — multilingual rule-based classification of
   `request_text`; non-deletion requests (access, export, opt-out,
   correction, password reset) return `NOT_APPLICABLE`.
2. **Identity** (`identity.py`) — resolves the request email to the stable
   subject: current identity snapshot plus historical emails/phones/hashes
   from `user_audit_log.csv`.
3. **Evidence index** (`evidence_index.py`) — parses *all* participant-visible
   evidence (JSON snapshot bundles, readback exports, SQLite-compatible SQL
   replicas, structured service-event logs, lookup-trace logs, connector
   configs, export jobs/manifests, audit ledgers) into subject-, resource- and
   time-keyed records, including *pre-deletion snapshots* that carry the
   email ↔ resource-id linkage used later when the profile has been removed.
4. **Investigator** (`investigator.py`) — per case: filters evidence to
   `captured_at ≤ audit_at`, discovers the account resource id, determines
   the account state at `audit_at` (present / absent / tombstone), and decides
   `COMPLETE` vs `INCOMPLETE` from policy violations and recreation risks —
   never from `reported_status` alone. A claimed `COMPLETE` is only emitted
   when a citable evidence file backs the final state.
5. **Planner** (`planner.py`) — emits FINDING → REMEDIATION → VERIFICATION
   steps in the fixed operation order; findings cite participant-visible
   `evidence_id`s; proposed remediation and future verification use empty
   `evidence_id`s; retained policy-required records produce
   `VERIFY_RECORD_PRESENT` steps instead of deletions.
6. **Policy** (`policy.py`) — the deletion-rules map (DELETE / REDACT /
   ANONYMIZE / RETAIN / TOMBSTONE) applied per data category.

## 2. Methodology

- Metrics are computed on the 32 public sample cases
  (`dataset/sample_output.csv`), shown below.
- Conventions: *field accuracy* compares the six fields
  (`phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id`)
  over the positionally aligned prefix of the expected and produced step
  lists; *sequence accuracy* counts a case whose full length matches and whose
  ordered 5-tuples (`phase`, `system_id`, `resource_id`, `operation`, `state`)
  all match positionally; *step-level* accuracy counts cases whose full step
  lists match exactly (including `evidence_id`).
- Reproduce with: `python recon/eval_metrics.py`
  (printed by the final full run logs as well).

## 3. Results on the 32 public sample cases

| Metric | Result |
|---|---|
| Case-level deletion-status accuracy | **28/32 = 87.5 %** |
| Field-level accuracy (aligned prefix) | **610/798 = 76.4 %** |
| Step-level (exact full-list) match | 4/32 = 12.5 % |
| Sequence accuracy (ordered 5-tuples) | 4/32 = 12.5 % |

Status distribution over the full 518-case evaluation run:
`COMPLETE=167`, `INCOMPLETE=347`, `NOT_APPLICABLE=4`.

The dominant remaining accuracy gap is **resource-id linkage**: the dataset
deliberately leaves the binding between a subject and its resource ids
implicit (identifiers are stripped from post-deletion snapshots, activity
rows carry no `correlation_key`, and timing windows overlap across cases).
Discovering the exact account resource id therefore relies on evidence-based
linkage (pre-deletion snapshots, replica SQL, lookup traces, mined
email/user → resource tables) plus a unique-event fallback, which recovers
the golden resource id in a minority of cases. Status answers remain robust
because they depend on subject-level evidence rather than per-resource ids.

## 4. Additional evaluation cases (participant-authored)

Three custom cases (`recon/eval_metrics.py`, printed at the end of its run)
exercise branches the sample set under-demonstrates:

| Custom case | Input design | Expected | Observed |
|---|---|---|---|
| `custom_01` | Export/copy request ("download a copy of my order history"), English | `NOT_APPLICABLE`, `steps_json=[]` | ✅ `NOT_APPLICABLE`, 0 steps |
| `custom_02` | Permanent-erasure phrasing ("erase my personal data … nothing remaining that identifies me") for a subject whose account is provably absent (`account_9079`, replica SQL) but where other systems may still hold data | `INCOMPLETE` rather than trusting workflow `COMPLETE` | ✅ `INCOMPLETE`, account `VERIFY_RECORD_ABSENT` step emitted from replica evidence |
| `custom_03` | Account-closure phrasing ("Delete my account and all my data, I no longer use this shop") for a subject with minimal pre-audit evidence | Deletion intent classified, investigated under the no-evidence rule | ✅ classified as deletion; `INCOMPLETE` with empty steps because no participant-visible file backs a claim — evidence-free `COMPLETE` is refused by design |

These cases verify: (a) non-deletion intent gating, (b) refusal to treat an
unsupported workflow `COMPLETE` as truth, and (c) that retained/tombstone
policy never invents citations.

## 5. Failures found during development and improvements made

1. **SQL parser dropped whole tables** — the strict table-name map missed
   stores such as `search_documents_primary`; replica SQL is now mapped by
   store-level fallbacks including json-wrapped `customer_data_*` tables
   (records indexed from 1,360 → 2,435).
2. **Rid regex truncation** — a non-greedy anchor captured a single character
   of resource ids in service-event logs; fixed and rid extraction now
   unescapes quoted fields.
3. **Absent-profile lookups unlinked** — lookup-key↔resource pairs
   (`resource_lookup_trace`) are now captured even when the profile row was
   already absent, which is precisely the linkage golden answers rely on.
4. **File-level vs snapshot-level capture time** — bundled snapshots carry an
   internal per-snapshot `captured_at`; using the file manifest time hide
   pre-audit state windows. Records now use the snapshot's own timestamp.
5. **Unevidenced `COMPLETE`** — cases whose only step lacked a citable
   `evidence_id` were being labelled `COMPLETE`; the investigator now downgrades
   such cases to `INCOMPLETE` (verified: the full run has zero COMPLETE rows
   with empty-evidence verification steps).
6. **Numbered fallback resources** — window-based unique-event discovery is used
   only as a last-resort linkage fallback; it is never the source of state
   claims (state always requires evidence).

## 6. Known limitations

- Resource-id discovery can still mis-link when multiple subjects share an
  overlapping activity window and no evidence file ties either subject to a
  rid (deliberate dataset difficulty).
- Image and PDF evidence are not OCR-parsed; their facts enter only via any
  text-bearing siblings. This caps recall on a few image-backed cases.
- The pipeline is fully deterministic: repeated runs produce byte-identical
  `output.csv`.
