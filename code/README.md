# Ghost Data Still Exists - deletion audit agent

Deterministic, evidence-grounded audit agent for the HackerRank Orchestrate (October 2026) challenge.
It decides for every request whether the deletion is `COMPLETE`, `INCOMPLETE` or `NOT_APPLICABLE` and emits the
ordered findings / remediation / verification steps. **No LLM or network call is made**: a full run is offline,
reproducible and costs zero tokens (see `evaluation/usage_report.md`).

## Setup and run

```bash
# Python 3.10+, standard library only. Optional OCR/PDF tools for the screenshots and PDFs:
#   pdftotext (poppler-utils) and tesseract. If they are missing those files are skipped, not fatal.
python3 code/main.py                       # reads dataset/, writes ./output.csv (518 rows)
python3 code/evaluation/validate_output.py # schema / ordering / evidence-time checks on output.csv
python3 code/evaluation/evaluate.py -v     # accuracy against dataset/sample_output.csv
python3 code/evaluation/evaluate.py --requests code/evaluation/custom_requests.csv \
        --labels code/evaluation/custom_labels.csv     # extra cases created for this project
```

A clean run takes about 25 s (almost all of it OCR of 11 screenshots and parsing 94 evidence files).

## Architecture (`code/ghostaudit/`)

| Module | Job |
| --- | --- |
| `intent.py` | Multilingual (EN/ES/FR/PT/KO/JA) rules: is deletion really requested? Declines, access, correction, export, marketing opt-out -> `NOT_APPLICABLE`. |
| `identity.py` | Current + historical e-mails, e-mail hashes (sha256) and phones from `user_identities.csv` + `user_audit_log.csv`. |
| `evidence.py` | Parses every evidence file into uniform observations (resource, system, time, identifiers, state attributes): SQL snapshots executed in SQLite (primary and replicas), JSON bundles/exports, five log dialects, text handovers, PDFs (`pdftotext`) and screenshots (`tesseract`). Also records which systems a snapshot enumerates. |
| `linker.py` | Links resources to a data subject: (1) explicit identifier match inside the case window, (2) catalog link events and display references (statement numbers, file names), (3) activity anchoring for records that carry no identifier (account deletion events, policy actions), using a time window calibrated on the explicitly linked cases and elimination across all known requests. |
| `engine.py` | Reconstructs each record's state at `audit_at` (latest evidence captured at or before the cutoff; replica drift = present if any copy has it), applies `deletion_rules.csv` per category, decides the status and builds steps in the contract order. |
| `pipeline.py` | Orchestration and deterministic CSV writer. |

Key rules implemented (all from `problem_statement.md` / `AGENTS.md`):

* evidence captured after `audit_at` is invisible - it can neither change the answer nor be cited;
* reported statuses and activity results are only claims - state comes from evidence;
* `COMPLETE` needs every verification to cite evidence; `INCOMPLETE` cites evidence for findings only;
* security audit records / legal holds are verified present, tombstones must be redacted but kept,
  attachments owned only by the subject are deleted, analytics/telemetry anonymised, support messages redacted,
  data flows disabled and restores blocked before records are touched.

## Known limits

Some links cannot be proven from the supplied data (e.g. two accounts deleted at nearly the same time for two
subjects with no identifier on either). Those are resolved by a deterministic tie-break and counted at the end
of `main.py`'s output. See `evaluation/evaluation_report.md` for the measured impact.
