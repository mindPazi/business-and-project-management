"""
GenAI-Assisted Document Redaction -- runnable demo for the governance framework.

PDF in -> redacted PDF out, on top of the four-pillar pipeline:

  1. DETECT sensitive items            (Pillar II: the GenAI tool *proposes*)
  2. SCORE risk = Sensitivity x Exposure x Audience -> tier
  3. REDACT for real: delete the underlying text, draw a black bar over its box
  4. EMIT a hash-chained audit log     (Pillar III: complete, immutable, traceable)
  5. REPORT risk, mandated human controls, and a byte-level leak check

The redaction is a *true* redaction: PyMuPDF removes the sensitive bytes from the
file, not merely covers them. The run re-opens the output and confirms nothing is
still extractable -- the control the Post Office case lacked.

Self-contained: standard library plus PyMuPDF (pip install pymupdf).

Usage:
    python redact_pdf.py build                       # txt -> sample_incident_report.pdf
    python redact_pdf.py redact sample_incident_report.pdf
    python redact_pdf.py redact sample_incident_report.pdf --audience public --no-label
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import fitz  # PyMuPDF

MODEL_TAG = "redaction-demo/regex-detector-v1"


# ----------------------------------------------------------------------------
# Detection (Pillar II: the GenAI tool proposes candidates)
# ----------------------------------------------------------------------------
# Each detector carries a data category and a sensitivity weight on the paper's
# scale: 1 = routine, 2 = personal data, 3 = special / financial.

@dataclass(frozen=True)
class Detector:
    category: str
    sensitivity: int
    pattern: re.Pattern
    is_subject_identifier: bool = False  # counts toward "exposure" (data subjects)


DETECTORS: List[Detector] = [
    Detector("IBAN", 3, re.compile(r"\bGB\d{2}\s?[A-Z]{4}(?:\s?\d{4}){3}\s?\d{2}\b")),
    Detector("SORT_CODE", 3, re.compile(r"\b\d{2}-\d{2}-\d{2}\b")),
    Detector("ACCOUNT_NO", 3, re.compile(r"\baccount\s+number\s+\d{8}\b", re.IGNORECASE)),
    Detector("NI_NUMBER", 3, re.compile(r"\b[A-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b")),
    Detector("MONEY", 3, re.compile(r"\bGBP\s?[\d,]+\.\d{2}\b")),
    Detector("EMAIL", 2, re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
    Detector("PHONE", 2, re.compile(r"\+44\s?\d{4}\s?\d{6}\b")),
    Detector("POSTCODE", 2, re.compile(r"\b[A-Z]{2}\d\s?\d[A-Z]{2}\b")),
    Detector("DOB", 2, re.compile(r"\b\d{2}/\d{2}/\d{4}\b")),
    Detector("PERSON", 2, re.compile(
        r"\b(?:Mr|Mrs|Ms|Dr)\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b"), is_subject_identifier=True),
]


@dataclass
class Finding:
    category: str
    sensitivity: int
    text: str
    start: int
    end: int
    is_subject_identifier: bool


def detect(document: str) -> List[Finding]:
    """Scan the document and return non-overlapping findings, left to right."""
    findings: List[Finding] = []
    for det in DETECTORS:
        for m in det.pattern.finditer(document):
            findings.append(Finding(
                category=det.category, sensitivity=det.sensitivity,
                text=m.group(0), start=m.start(), end=m.end(),
                is_subject_identifier=det.is_subject_identifier,
            ))
    findings.sort(key=lambda f: (f.start, -(f.end - f.start)))
    pruned: List[Finding] = []
    cursor = -1
    for f in findings:
        if f.start >= cursor:  # drop overlaps, keep the longest at a given start
            pruned.append(f)
            cursor = f.end
    return pruned


# ----------------------------------------------------------------------------
# Risk scoring (Pillar II: Sensitivity x Exposure x Audience)
# ----------------------------------------------------------------------------

AUDIENCE_SCORE = {"internal": 1, "external": 2, "public": 3}


@dataclass
class RiskAssessment:
    sensitivity: int
    exposure: int
    audience: int
    score: int
    tier: str
    floored: bool


def assess_risk(findings: List[Finding], audience: str) -> RiskAssessment:
    sensitivity = max((f.sensitivity for f in findings), default=1)
    subjects = {f.text for f in findings if f.is_subject_identifier}
    exposure = 1 if len(subjects) <= 1 else (2 if len(subjects) < 100 else 3)
    audience_score = AUDIENCE_SCORE[audience]
    score = sensitivity * exposure * audience_score
    tier = "standard" if score <= 4 else ("high" if score <= 12 else "very high")

    # Override: any public document is floored at "high" (irreversible release).
    floored = False
    if audience_score == 3 and tier == "standard":
        tier, floored = "high", True
    return RiskAssessment(sensitivity, exposure, audience_score, score, tier, floored)


# Control matrix from the paper (Table: Risk-Tier to Control).
TIER_CONTROLS = {
    "standard": {
        "human_control": "Owner reviews every proposal and attests completeness",
        "release_authority": "Document owner"},
    "high": {
        "human_control": "Independent reviewer (not the author) plus compliance check",
        "release_authority": "DPO, on Legal's recommendation"},
    "very high": {
        "human_control": "Independent review plus dual approval; no single-person release",
        "release_authority": "DPO + senior management"},
}


# ----------------------------------------------------------------------------
# Audit log (Pillar III: complete, immutable via hash chain, traceable)
# ----------------------------------------------------------------------------

def build_audit_record(doc_path: Path, document: str, redacted: str,
                       findings: List[Finding], risk: RiskAssessment,
                       prev_hash: str) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    subjects = sorted({f.text for f in findings if f.is_subject_identifier})
    record = {
        "document_identity": {
            "document_id": doc_path.stem.upper(),
            "type": "incident_memorandum",
            "version_hash": hashlib.sha256(document.encode()).hexdigest()[:16],
            "owner": "Helen Brooks (Compliance)",
            "intended_audience": {1: "internal", 2: "external", 3: "public"}[risk.audience],
            "classification_tier": risk.tier,
        },
        "detection": {
            "model": MODEL_TAG,
            "categories_detected": sorted({f.category for f in findings}),
            "items": [{"category": f.category, "offset": f.start} for f in findings],
            "scan_timestamp": now,
        },
        "decision": {
            "reviewer": "PENDING -- human-in-the-loop gate not yet cleared",
            "redaction_profile": "pdf-true-redaction",
            "data_subjects_affected": subjects,
            "completeness_attestation": False,
            "escalation_flag": risk.tier == "very high",
        },
        "disposition": {
            "approver": None,
            "approval": None,
            "approval_token": None,
            "publication_status": "BLOCKED -- no valid token",
            "redacted_version_hash": hashlib.sha256(redacted.encode()).hexdigest()[:16],
        },
        "risk_assessment": {
            "sensitivity": risk.sensitivity, "exposure": risk.exposure,
            "audience": risk.audience, "score": risk.score,
            "tier_floored_to_high": risk.floored,
            "required_human_control": TIER_CONTROLS[risk.tier]["human_control"],
            "release_authority": TIER_CONTROLS[risk.tier]["release_authority"],
        },
        "prev_hash": prev_hash,
    }
    record["entry_hash"] = hashlib.sha256(
        (prev_hash + json.dumps(record, sort_keys=True)).encode()).hexdigest()
    return record


# ----------------------------------------------------------------------------
# Build a presentable input PDF from the plain-text sample
# ----------------------------------------------------------------------------
# Styling reuses the paper's palette so the artefact looks like a real memo:
# slate letterhead, sectioned body, metadata block, footer and a DRAFT watermark.

SLATE = (0.200, 0.255, 0.333)   # #334155, the paper's accentdark
LIGHT = (0.863, 0.890, 0.918)   # #DCE3EA, accentlight
GRAY = (0.42, 0.45, 0.50)
HAIR = (0.80, 0.82, 0.85)
MARGIN = 56.0


def _wrap(text: str, font: str, size: float, width: float) -> List[str]:
    """Greedy word-wrap to a pixel width, so the y cursor stays exact."""
    lines, cur = [], ""
    for word in text.split():
        trial = f"{cur} {word}".strip()
        if fitz.get_text_length(trial, fontname=font, fontsize=size) <= width:
            cur = trial
        else:
            if cur:
                lines.append(cur)
            cur = word
    if cur:
        lines.append(cur)
    return lines


def build_input_pdf(txt_path: Path, pdf_path: Path) -> None:
    text = txt_path.read_text(encoding="utf-8")
    blocks = [b.strip() for b in text.split("\n\n") if b.strip()]
    head = blocks[0].split("\n")            # title, subtitle, reference
    meta = blocks[1].split("\n")            # prepared by, reviewed by
    body = blocks[2:]                       # alternating heading / paragraph

    doc = fitz.open()
    page = doc.new_page()
    W, H = page.rect.width, page.rect.height
    right = W - MARGIN

    # -- Letterhead band --
    page.draw_rect(fitz.Rect(0, 0, W, 60), color=SLATE, fill=SLATE)
    page.draw_rect(fitz.Rect(0, 60, W, 63.5), color=LIGHT, fill=LIGHT)
    page.insert_text((MARGIN, 38), "NORTHGATE RETAIL NETWORK",
                     fontname="hebo", fontsize=13, color=(1, 1, 1))
    conf = "CONFIDENTIAL"
    page.insert_text((right - fitz.get_text_length(conf, "hebo", 10), 37),
                     conf, fontname="hebo", fontsize=10, color=LIGHT)

    # -- Diagonal DRAFT watermark, drawn before the body so text sits on top --
    page.insert_text((130, 560), "DRAFT", fontname="hebo", fontsize=140,
                     color=(0.93, 0.94, 0.96),
                     morph=(fitz.Point(297, 470), fitz.Matrix(50)))

    # -- Title block --
    y = 96
    page.insert_text((MARGIN, y), head[0], fontname="hebo", fontsize=21, color=SLATE)
    y += 22
    if len(head) > 1:
        page.insert_text((MARGIN, y), head[1], fontname="heit", fontsize=12.5, color=GRAY)
        y += 16
    if len(head) > 2:
        page.insert_text((MARGIN, y), head[2], fontname="helv", fontsize=9.5, color=GRAY)
        y += 10
    y += 8
    page.draw_line((MARGIN, y), (right, y), color=SLATE, width=1.1)
    y += 22

    # -- Metadata block (labels small-caps slate, values wrapped) --
    for line in meta:
        label, _, value = line.partition(":")
        page.insert_text((MARGIN, y), label.upper(), fontname="hebo",
                         fontsize=7.5, color=SLATE)
        y += 12
        for wl in _wrap(value.strip(), "helv", 9.5, right - MARGIN):
            page.insert_text((MARGIN, y), wl, fontname="helv", fontsize=9.5, color=(0, 0, 0))
            y += 13
        y += 4
    y += 6
    page.draw_line((MARGIN, y), (right, y), color=HAIR, width=0.6)
    y += 20

    # -- Body: headings get an accent tick, paragraphs are wrapped --
    for blk in body:
        is_heading = blk.isupper() and len(blk.split()) <= 3
        if is_heading:
            y += 6
            page.draw_rect(fitz.Rect(MARGIN, y - 8, MARGIN + 16, y - 5),
                           color=SLATE, fill=SLATE)
            page.insert_text((MARGIN + 24, y), blk.title(),
                             fontname="hebo", fontsize=11.5, color=SLATE)
            y += 16
        else:
            for wl in _wrap(blk, "helv", 9.7, right - MARGIN):
                page.insert_text((MARGIN, y), wl, fontname="helv", fontsize=9.7, color=(0.12, 0.12, 0.14))
                y += 14.5
            y += 8

    # -- Footer --
    fy = H - 44
    page.draw_line((MARGIN, fy), (right, fy), color=HAIR, width=0.6)
    page.insert_text((MARGIN, fy + 14),
                     "Northgate Retail Network  |  Confidential  |  Pending classified review",
                     fontname="helv", fontsize=8, color=GRAY)
    pno = "Page 1 of 1"
    page.insert_text((right - fitz.get_text_length(pno, "helv", 8), fy + 14),
                     pno, fontname="helv", fontsize=8, color=GRAY)

    doc.save(pdf_path)
    doc.close()
    print(f"  built input PDF -> {pdf_path}")


# ----------------------------------------------------------------------------
# Redact a PDF: detect, score, true-redact, audit, report
# ----------------------------------------------------------------------------

def redact_pdf(in_pdf: Path, audience: str, out_dir: Path, label: bool) -> None:
    doc = fitz.open(in_pdf)

    full_text = "\n".join(page.get_text() for page in doc)
    findings = detect(full_text)
    risk = assess_risk(findings, audience)

    category_of: Dict[str, str] = {f.text: f.category for f in findings}
    terms = sorted(category_of, key=len, reverse=True)
    boxes_drawn = 0
    for page in doc:
        for term in terms:
            for rect in page.search_for(term):
                tag = category_of[term] if label else ""
                page.add_redact_annot(rect, text=tag, fontname="helv", fontsize=6,
                                      fill=(0, 0, 0), text_color=(1, 1, 1), cross_out=False)
                boxes_drawn += 1
        page.apply_redactions()  # this is what actually deletes the text

    out_dir.mkdir(parents=True, exist_ok=True)
    out_pdf = out_dir / "redacted_document.pdf"
    doc.save(out_pdf, garbage=4, deflate=True)

    redacted_text = "\n".join(page.get_text() for page in doc)
    leaks = [f.text for f in findings if f.text in redacted_text]
    doc.close()

    record = build_audit_record(in_pdf, full_text, redacted_text, findings, risk, "0" * 64)
    (out_dir / "audit_log.json").write_text(json.dumps([record], indent=2), encoding="utf-8")

    _report(in_pdf, out_pdf, risk, findings, boxes_drawn, leaks, out_dir)


def _report(in_pdf, out_pdf, risk, findings, boxes, leaks, out_dir) -> None:
    cats = ", ".join(sorted({f.category for f in findings}))
    line = "=" * 64
    print(line)
    print("  GenAI-Assisted Redaction (PDF) -- run report")
    print(line)
    print(f"  Source            : {in_pdf.name}")
    print(f"  Items detected    : {len(findings)} ({cats})")
    print(f"  Black bars drawn  : {boxes}")
    print()
    print("  RISK (Pillar II)  : Sensitivity x Exposure x Audience")
    print(f"                      {risk.sensitivity} x {risk.exposure} x {risk.audience}"
          f" = {risk.score}  ->  tier: {risk.tier.upper()}"
          + ("  [floored: public release]" if risk.floored else ""))
    print(f"  Human control     : {TIER_CONTROLS[risk.tier]['human_control']}")
    print(f"  Release authority : {TIER_CONTROLS[risk.tier]['release_authority']}")
    print()
    status = ("CLEAN -- no sensitive text remains in the file" if not leaks
              else f"LEAK -- {len(leaks)} item(s) still extractable: {leaks}")
    print(f"  Byte-level check  : {status}")
    print("  Audit (Pillar III): hash-chained record written, publication BLOCKED")
    print()
    print("  Outputs:")
    print(f"    - {out_pdf}")
    print(f"    - {out_dir / 'audit_log.json'}")
    print(line)


def parse_args():
    p = argparse.ArgumentParser(description="PDF -> redacted PDF governance demo")
    sub = p.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="render the sample .txt into an input PDF")
    b.add_argument("--txt", type=Path, default=Path("sample_incident_report.txt"))
    b.add_argument("--pdf", type=Path, default=Path("sample_incident_report.pdf"))

    r = sub.add_parser("redact", help="redact a PDF and emit the audit log")
    r.add_argument("pdf", type=Path, help="input PDF")
    r.add_argument("--audience", choices=list(AUDIENCE_SCORE), default="public")
    r.add_argument("--out", type=Path, default=Path("output"))
    r.add_argument("--no-label", dest="label", action="store_false",
                   help="draw plain black bars without a category tag")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.cmd == "build":
        build_input_pdf(args.txt, args.pdf)
    else:
        redact_pdf(args.pdf, args.audience, args.out, args.label)
