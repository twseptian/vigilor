"""services/pdf_report.py — Generate a formatted PDF pentest report using reportlab."""
from __future__ import annotations

import html
import os
from datetime import datetime
from typing import Any


def _esc(text: str | None) -> str:
    """Escape special XML/HTML chars so reportlab Paragraph doesn't choke."""
    if not text:
        return ""
    return html.escape(str(text), quote=False)

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, Image, PageBreak, PageTemplate,
    Paragraph, Spacer, Table, TableStyle,
)
from reportlab.platypus.flowables import KeepTogether

# ── Severity palette ──────────────────────────────────────────────────────────

_SEV_COLOR = {
    "Critical":      colors.HexColor("#dc2626"),
    "High":          colors.HexColor("#ea580c"),
    "Medium":        colors.HexColor("#d97706"),
    "Low":           colors.HexColor("#2563eb"),
    "Informational": colors.HexColor("#6b7280"),
}
_SEV_BG = {
    "Critical":      colors.HexColor("#fef2f2"),
    "High":          colors.HexColor("#fff7ed"),
    "Medium":        colors.HexColor("#fffbeb"),
    "Low":           colors.HexColor("#eff6ff"),
    "Informational": colors.HexColor("#f9fafb"),
}

# ── Styles ────────────────────────────────────────────────────────────────────

def _build_styles():
    base = getSampleStyleSheet()

    def ps(name, **kw) -> ParagraphStyle:
        return ParagraphStyle(name, **kw)

    return {
        "title": ps("title",
            fontName="Helvetica-Bold", fontSize=28, textColor=colors.HexColor("#111827"),
            alignment=TA_CENTER, spaceAfter=6),
        "subtitle": ps("subtitle",
            fontName="Helvetica", fontSize=13, textColor=colors.HexColor("#6b7280"),
            alignment=TA_CENTER, spaceAfter=4),
        "cover_meta": ps("cover_meta",
            fontName="Helvetica", fontSize=10, textColor=colors.HexColor("#374151"),
            alignment=TA_CENTER, spaceAfter=3),
        "h1": ps("h1",
            fontName="Helvetica-Bold", fontSize=15, textColor=colors.HexColor("#111827"),
            spaceBefore=18, spaceAfter=6, borderPad=0),
        "h2": ps("h2",
            fontName="Helvetica-Bold", fontSize=12, textColor=colors.HexColor("#1e40af"),
            spaceBefore=12, spaceAfter=4),
        "h3": ps("h3",
            fontName="Helvetica-BoldOblique", fontSize=10, textColor=colors.HexColor("#374151"),
            spaceBefore=8, spaceAfter=3),
        "body": ps("body",
            fontName="Helvetica", fontSize=9, leading=14,
            textColor=colors.HexColor("#374151"), alignment=TA_JUSTIFY, spaceAfter=4),
        "mono": ps("mono",
            fontName="Courier", fontSize=8, leading=12,
            textColor=colors.HexColor("#1f2937"), backColor=colors.HexColor("#f1f5f9"),
            leftIndent=6, rightIndent=6, spaceBefore=4, spaceAfter=4),
        "label": ps("label",
            fontName="Helvetica-Bold", fontSize=8, textColor=colors.HexColor("#6b7280"),
            spaceAfter=2),
        "toc": ps("toc",
            fontName="Helvetica", fontSize=10, textColor=colors.HexColor("#1d4ed8"),
            leading=18, leftIndent=12),
        "footer": ps("footer",
            fontName="Helvetica", fontSize=8, textColor=colors.HexColor("#9ca3af"),
            alignment=TA_CENTER),
    }


# ── Page template ─────────────────────────────────────────────────────────────

def _build_doc(file_path: str, target_url: str) -> BaseDocTemplate:
    W, H = A4
    doc = BaseDocTemplate(
        file_path,
        pagesize=A4,
        leftMargin=2.0 * cm,
        rightMargin=2.0 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2.0 * cm,
    )

    def _header_footer(canvas, doc, is_cover=False):
        canvas.saveState()
        if not is_cover:
            # Header bar
            canvas.setFillColor(colors.HexColor("#1e40af"))
            canvas.rect(0, H - 1.5 * cm, W, 1.5 * cm, fill=1, stroke=0)
            canvas.setFont("Helvetica-Bold", 9)
            canvas.setFillColor(colors.white)
            canvas.drawString(2.0 * cm, H - 0.95 * cm, "VIGILOR Report")
            canvas.setFont("Helvetica", 8)
            canvas.drawRightString(W - 2.0 * cm, H - 0.95 * cm, target_url[:80])
            # Footer
            canvas.setFillColor(colors.HexColor("#e5e7eb"))
            canvas.rect(0, 0, W, 1.2 * cm, fill=1, stroke=0)
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(colors.HexColor("#6b7280"))
            canvas.drawString(2.0 * cm, 0.45 * cm, "CONFIDENTIAL — For authorized personnel only")
            canvas.drawRightString(W - 2.0 * cm, 0.45 * cm, f"Page {doc.page}")
        canvas.restoreState()

    cover_frame = Frame(0, 0, W, H, leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    content_frame = Frame(
        2.0 * cm, 1.5 * cm,
        W - 4.0 * cm, H - 4.0 * cm,
        leftPadding=0, rightPadding=0,
    )

    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[cover_frame],
                     onPage=lambda c, d: _header_footer(c, d, is_cover=True)),
        PageTemplate(id="Content", frames=[content_frame],
                     onPage=lambda c, d: _header_footer(c, d, is_cover=False)),
    ])
    return doc


# ── Helpers ───────────────────────────────────────────────────────────────────

def _hr(color="#e5e7eb", thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness,
                      color=colors.HexColor(color), spaceAfter=6, spaceBefore=6)


def _sev_badge_table(severity: str, S) -> Table:
    color = _SEV_COLOR.get(severity, colors.gray)
    bg = _SEV_BG.get(severity, colors.white)
    cell = Paragraph(f"<b>{severity}</b>",
                     ParagraphStyle("b", fontName="Helvetica-Bold", fontSize=9,
                                    textColor=color, alignment=TA_CENTER))
    t = Table([[cell]], colWidths=[2.5 * cm], rowHeights=[0.55 * cm])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("BOX", (0, 0), (-1, -1), 0.8, color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("ROUNDEDCORNERS", [3, 3, 3, 3]),
    ]))
    return t


def _two_col_table(rows: list[tuple[str, str]], S) -> Table:
    """Key-value info table."""
    data = [[Paragraph(f"<b>{k}</b>", S["label"]), Paragraph(v or "—", S["body"])]
            for k, v in rows]
    t = Table(data, colWidths=[3.5 * cm, None])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("BOX", (0, 0), (-1, -1), 0.3, colors.HexColor("#e5e7eb")),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, colors.HexColor("#e5e7eb")),
    ]))
    return t


# ── Main generator ────────────────────────────────────────────────────────────

def generate_pdf(
    scan: Any,
    findings: list[dict],
    out_dir: str,
) -> str:
    """
    Generate a PDF pentest report.

    Parameters
    ----------
    scan      : Scan ORM object (has .target_url, .target_description, .scan_mode, etc.)
    findings  : list of dicts built from Finding ORM objects
    out_dir   : directory where the .pdf file will be written

    Returns the absolute path to the generated .pdf file.
    """
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = os.path.join(out_dir, f"pentest_report_{ts}.pdf")

    S = _build_styles()
    doc = _build_doc(file_path, scan.target_url)
    story = []

    # Report vocabulary adapts to scan type (web pentest vs source code review).
    is_src = bool(getattr(scan, "source_repo_url", None))
    repo_or_url = getattr(scan, "source_repo_url", None) or scan.target_url
    _t1, _t2 = (("SOURCE CODE SECURITY", "REVIEW REPORT") if is_src
                else ("WEB VULNERABILITY ASSESSMENT", "PENETRATION TEST REPORT"))
    _assess = ("Static &amp; AI-Assisted Source Code Review" if is_src
               else "Web Vulnerability Assessment &amp; Penetration Test")
    _target_lbl = "Repository" if is_src else "Target"

    # ── Cover page ────────────────────────────────────────────────────────────
    story.append(Spacer(1, 3.5 * cm))
    story.append(Paragraph(_t1, S["title"]))
    story.append(Paragraph(_t2, S["title"]))
    story.append(Spacer(1, 0.5 * cm))
    story.append(_hr("#1e40af", 1.5))
    story.append(Spacer(1, 0.3 * cm))
    story.append(Paragraph(_esc(repo_or_url), S["subtitle"]))
    if scan.target_description:
        story.append(Paragraph(_esc(scan.target_description), S["cover_meta"]))
    story.append(Spacer(1, 1.0 * cm))

    # Cover meta box
    gen_date = datetime.now().strftime("%B %d, %Y")
    sev_counts = {}
    for f in findings:
        sev_counts[f.get("severity", "Informational")] = sev_counts.get(f.get("severity", "Informational"), 0) + 1

    cover_rows = [
        ["Report Date", gen_date],
        ["Assessment Type", _assess],
        [_target_lbl, _esc(repo_or_url)],
        ["Scan Type", "Source Code Review" if is_src
                      else ("Full Scan" if scan.scan_mode == "full" else "Static Analysis")],
        ["Total Findings", str(len(findings))],
        ["Critical / High", f"{sev_counts.get('Critical', 0)} / {sev_counts.get('High', 0)}"],
        ["Medium / Low", f"{sev_counts.get('Medium', 0)} / {sev_counts.get('Low', 0)}"],
    ]
    cover_data = [[Paragraph(f"<b>{r[0]}</b>", S["label"]), Paragraph(r[1], S["body"])]
                  for r in cover_rows]
    cover_t = Table(cover_data, colWidths=[4.5 * cm, 10 * cm])
    cover_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("BACKGROUND", (1, 0), (1, -1), colors.white),
        ("ROWBACKGROUNDS", (1, 0), (1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("LINEBELOW", (0, 0), (-1, -2), 0.3, colors.HexColor("#e5e7eb")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(cover_t)
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph(
        "CONFIDENTIAL — This report contains sensitive security information. "
        "Distribution is restricted to authorized personnel only.",
        ParagraphStyle("disc", fontName="Helvetica-Oblique", fontSize=8,
                       textColor=colors.HexColor("#9ca3af"), alignment=TA_CENTER)))
    story.append(PageBreak())

    # Switch to Content template
    from reportlab.platypus.doctemplate import NextPageTemplate
    story.append(NextPageTemplate("Content"))

    # ── Executive Summary ─────────────────────────────────────────────────────
    story.append(Paragraph("1. Executive Summary", S["h1"]))
    story.append(_hr())

    total = len(findings)
    crit = sev_counts.get("Critical", 0)
    high = sev_counts.get("High", 0)
    med  = sev_counts.get("Medium", 0)
    low  = sev_counts.get("Low", 0)
    info = sev_counts.get("Informational", 0)

    summary_text = (
        (f"A source code security review was performed on the repository <b>{_esc(repo_or_url)}</b>. "
         if is_src else
         f"A web application vulnerability assessment was conducted against <b>{_esc(scan.target_url)}</b>. ")
        + f"The assessment identified a total of <b>{total} findings</b> across all severity levels. "
        f"Of these, <b>{crit} Critical</b> and <b>{high} High</b> severity vulnerabilities require "
        f"immediate remediation. Additionally, <b>{med} Medium</b>, <b>{low} Low</b>, and "
        f"<b>{info} Informational</b> findings were identified."
    )
    story.append(Paragraph(summary_text, S["body"]))
    story.append(Spacer(1, 0.4 * cm))

    # Severity summary table
    sev_order = ["Critical", "High", "Medium", "Low", "Informational"]
    sev_header = [Paragraph("<b>Severity</b>", S["label"]),
                  Paragraph("<b>Count</b>", S["label"]),
                  Paragraph("<b>Risk Level</b>", S["label"])]
    risk_desc = {
        "Critical": "Immediate action required — active exploitation likely",
        "High": "High priority — significant impact if exploited",
        "Medium": "Medium priority — moderate impact, remediate soon",
        "Low": "Low priority — limited impact",
        "Informational": "No immediate risk — best practice recommendation",
    }
    sev_data = [sev_header]
    for sev in sev_order:
        cnt = sev_counts.get(sev, 0)
        c = _SEV_COLOR.get(sev, colors.gray)
        sev_data.append([
            Paragraph(f"<b>{sev}</b>", ParagraphStyle("sv", fontName="Helvetica-Bold",
                      fontSize=9, textColor=c)),
            Paragraph(str(cnt), S["body"]),
            Paragraph(risk_desc[sev], S["body"]),
        ])
    sev_t = Table(sev_data, colWidths=[3 * cm, 2 * cm, None])
    sev_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e40af")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e5e7eb")),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(sev_t)
    story.append(Spacer(1, 0.5 * cm))

    # ── Findings Summary Table ────────────────────────────────────────────────
    story.append(Paragraph("2. Findings Summary", S["h1"]))
    story.append(_hr())

    if findings:
        fsum_header = [
            Paragraph("<b>#</b>", S["label"]),
            Paragraph("<b>Title</b>", S["label"]),
            Paragraph("<b>Severity</b>", S["label"]),
            Paragraph("<b>CVSS</b>", S["label"]),
            Paragraph("<b>Location</b>", S["label"]),
        ]
        fsum_data = [fsum_header]
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "Informational")
            c = _SEV_COLOR.get(sev, colors.gray)
            bg = _SEV_BG.get(sev, colors.white)
            score = f.get("cvss_score")
            score_str = f"{score:.1f}" if score is not None else "—"
            loc = _esc(f.get("location", "") or "")
            if len(loc) > 55:
                loc = loc[:52] + "..."
            fsum_data.append([
                Paragraph(str(i), S["body"]),
                Paragraph(_esc(f.get("title", "")), S["body"]),
                Paragraph(f"<b>{_esc(sev)}</b>", ParagraphStyle("sv2", fontName="Helvetica-Bold",
                          fontSize=8, textColor=c, backColor=bg)),
                Paragraph(score_str, S["body"]),
                Paragraph(loc, ParagraphStyle("loc", fontName="Courier", fontSize=7,
                          textColor=colors.HexColor("#6b7280"))),
            ])
        fsum_t = Table(fsum_data, colWidths=[0.8 * cm, 5.5 * cm, 2.5 * cm, 1.5 * cm, None])
        fsum_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e40af")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("INNERGRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#e5e7eb")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(fsum_t)
    else:
        story.append(Paragraph("No findings recorded for this scan.", S["body"]))

    story.append(PageBreak())

    # ── Detailed Findings ─────────────────────────────────────────────────────
    story.append(Paragraph("3. Detailed Findings", S["h1"]))
    story.append(_hr())

    for idx, f in enumerate(findings, 1):
        sev = f.get("severity", "Informational")
        sev_color = _SEV_COLOR.get(sev, colors.gray)
        sev_bg = _SEV_BG.get(sev, colors.white)
        score = f.get("cvss_score")
        title = f.get("title", f"Finding {idx}")

        # Section header
        header_para = Paragraph(
            f"<b>3.{idx}  {_esc(title)}</b>",
            ParagraphStyle("fh", fontName="Helvetica-Bold", fontSize=11,
                           textColor=colors.HexColor("#111827"), spaceBefore=14, spaceAfter=4)
        )

        # Meta table
        meta_rows = [
            ("Severity", _esc(sev)),
            ("CVSS Score", f"{score:.1f}" if score is not None else "—"),
            ("CVSS Vector", _esc(f.get("cvss_vector") or "—")),
            ("Location", _esc(f.get("location") or "—")),
            ("OWASP Category", _esc(f"{f.get('owasp_id', '')} {f.get('owasp_name', '')}".strip() or "—")),
            ("Status", _esc(f.get("status", "Open"))),
        ]
        meta_data = [
            [Paragraph(f"<b>{k}</b>", ParagraphStyle("mk", fontName="Helvetica-Bold",
             fontSize=8, textColor=colors.HexColor("#6b7280"))),
             Paragraph(v or "—", ParagraphStyle("mv",
             fontName="Helvetica-Bold" if k == "Severity" else "Helvetica",
             fontSize=9,
             textColor=sev_color if k == "Severity" else colors.HexColor("#374151")))]
            for k, v in meta_rows
        ]
        meta_t = Table(meta_data, colWidths=[3.2 * cm, None])
        meta_t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("LINEBELOW", (0, 0), (-1, -2), 0.3, colors.HexColor("#e5e7eb")),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))

        finding_story = [header_para, _hr(color="#e5e7eb"), meta_t, Spacer(1, 0.3 * cm)]

        def _section(label: str, text: str | None):
            if not text:
                return []
            safe = _esc(text).replace("\n", "<br/>")
            return [
                Paragraph(label, S["h3"]),
                Paragraph(safe, S["body"]),
                Spacer(1, 0.2 * cm),
            ]

        finding_story += _section("Description", f.get("description"))
        finding_story += _section("Proof of Concept", f.get("proof_of_concept"))
        finding_story += _section("Implications", f.get("implications"))
        finding_story += _section("Recommendations", f.get("recommendations"))

        # Screenshots
        _DATA_BASE = os.environ.get("DATA_BASE", "/app/data")
        for label, path_key in [("Before — Normal State", "screenshot_before"),
                                 ("After — Exploit Result", "screenshot_after")]:
            rel_path = f.get(path_key)
            if rel_path:
                abs_path = os.path.join(_DATA_BASE, rel_path)
                if os.path.isfile(abs_path):
                    try:
                        finding_story.append(Paragraph(label, S["h3"]))
                        img = Image(abs_path, width=14 * cm, height=8 * cm, kind="proportional")
                        finding_story.append(img)
                        finding_story.append(Spacer(1, 0.2 * cm))
                    except Exception:
                        pass

        story.append(KeepTogether(finding_story[:4]))  # keep header + meta together
        story.extend(finding_story[4:])
        story.append(_hr("#e5e7eb"))

    # ── Conclusion ────────────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(Paragraph("4. Conclusion &amp; Recommendations", S["h1"]))
    story.append(_hr())
    story.append(Paragraph(
        (f"The source code review of <b>{_esc(repo_or_url)}</b> revealed <b>{total} vulnerabilities</b>. "
         if is_src else
         f"The penetration test of <b>{_esc(scan.target_url)}</b> revealed <b>{total} vulnerabilities</b>. ")
        + "It is strongly recommended to address all Critical and High severity findings immediately, "
        f"followed by Medium severity issues. Low and Informational findings should be tracked "
        f"and remediated as part of ongoing security hygiene. "
        f"A re-assessment should be conducted after remediation to verify that all identified "
        f"vulnerabilities have been addressed effectively.",
        S["body"]))
    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(
        f"Report generated: {datetime.now().strftime('%B %d, %Y at %H:%M')} | "
        f"Tool: VIGILOR",
        ParagraphStyle("gen", fontName="Helvetica-Oblique", fontSize=8,
                       textColor=colors.HexColor("#9ca3af"))))

    # ── Build ─────────────────────────────────────────────────────────────────
    doc.build(story)
    return file_path
