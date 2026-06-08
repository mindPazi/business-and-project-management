# GenAI-Assisted Redaction -- working demo

Runnable counterpart of the four-pillar framework. Takes a sensitive business
document, classifies its risk, redacts it, and produces a tamper-evident audit
record. Runs in about one second so it can be executed live.

## Run

```bash
python redact_pdf.py build                      # txt -> sample_incident_report.pdf
python redact_pdf.py redact sample_incident_report.pdf
```

A *true* redaction: PyMuPDF deletes the underlying text and draws a black bar
over its box, so the sensitive bytes leave the file. The run prints a
`Byte-level check: CLEAN` line proving no sensitive text remains -- the control
the Post Office case lacked. Add `--no-label` for plain bars without the
category tag, or `--audience {internal,external,public}` to change the risk
score. Requires PyMuPDF (`pip install pymupdf`).

## What it produces (in `output/`)

| File | Pillar | Shows |
|------|--------|-------|
| `redacted_document.pdf` | II | the document with PII / financial data removed (black bars) |
| `audit_log.json` | III | hash-chained record, 4 field groups, publication BLOCKED |
| console report | II / IV | risk score, mandated human controls, byte-level leak check |

## How it maps to the paper

- **Detection** = the GenAI tool *proposes* (it never publishes).
- **Risk score** = Sensitivity x Exposure x Audience -> tier, with the public-release floor.
- **Tier** selects the mandated human control and release authority (control matrix).
- **Audit log** is complete (no record, no token), immutable (hash chain), traceable
  (every item bound to a category and offset); `publication_status` stays BLOCKED
  until a human clears the review gate.

## Talking point: the tool misses things on purpose

Plain names without a title (e.g. "David Aldridge", "Mr Okafor" on its own line)
are *not* caught by the detector. That is the automation-bias argument made
concrete: the reviewer must see the original beside the output and catch what the
tool misses, which is why no tier allows automatic release.
