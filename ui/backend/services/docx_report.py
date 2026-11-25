"""
services/docx_report.py — Professional WVAPT report generator.

Fixes v2:
  - Cover: copied verbatim from template via deep-copy XML (preserves logo/colours)
  - Findings ordered: Critical → High → Medium → Low → Informational
  - Each finding starts on a new page (explicit page break before Heading 2)
  - PoC text: justified alignment, monospace sections preserved
  - All body text paragraphs set to justify
"""
from __future__ import annotations

import copy
import os
import re
import textwrap
from datetime import datetime, timezone
from typing import Any

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_LINE_SPACING
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

# ── Template path ─────────────────────────────────────────────────────────────

TEMPLATE_PATH = os.environ.get(
    "REPORT_TEMPLATE_PATH",
    "/app/data/report_template.docx",
)

# ── Brand ─────────────────────────────────────────────────────────────────────

BRAND       = "VIGILOR"
BRAND_TAG   = "Autonomous Security Assessment"


def _is_source_review(scan: Any) -> bool:
    return bool(getattr(scan, "source_repo_url", None))


def _report_kind(scan: Any) -> dict[str, str]:
    """Report vocabulary that adapts to the scan type so a source-code review reads
    as a code review, not a live web pentest."""
    if _is_source_review(scan):
        return {
            "title":      "Source Code Security Review",
            "subject":    "Source Code Review",
            "ref":        "SCR",
            "target_lbl": "Repository",
            "loc_lbl":    "Vulnerable Code Location",
            "assess":     "static and AI-assisted source code review",
        }
    return {
        "title":      "Web Application Security Assessment",
        "subject":    "Penetration Test",
        "ref":        "WVAPT",
        "target_lbl": "Target",
        "loc_lbl":    "Affected Hosts/Services",
        "assess":     "web application vulnerability assessment and penetration test",
    }


# ── Colour constants ──────────────────────────────────────────────────────────
# Refined, elegant palette — deep indigo + slate accents, professional severity chips.
NAVY       = "1E2A4A"   # deep indigo (headings / banners)
ACCENT     = "3B5BA5"   # accent blue
LIGHT_BLUE = "EAF0FA"   # soft panel fill
SLATE      = "5A6478"
WHITE      = "FFFFFF"
BLACK      = "1A1A1A"

SEV_COLORS: dict[str, str] = {
    "Critical":      "7A1220",   # deep crimson
    "High":          "C0392B",   # refined red
    "Medium":        "D97706",   # amber
    "Low":           "2563EB",   # blue
    "Informational": "64748B",   # slate
}
SEV_TEXT_COLORS: dict[str, str] = {
    "Critical":      "FFFFFF",
    "High":          "FFFFFF",
    "Medium":        "FFFFFF",
    "Low":           "FFFFFF",
    "Informational": "FFFFFF",
}
SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

STATUS_DESCRIPTIONS = {
    "Open":               "The vulnerability has been identified and validated. No remediation has been performed.",
    "Resolved":           "The issue has been fully remediated with evidence of fix verified.",
    "Partially Resolved": "Some remediation measures have been implemented but the vulnerability has not been fully addressed.",
    "Risk Accepted":      "Management has acknowledged the risk and has chosen to accept it without remediation.",
    "Closed":             "Management has evaluated and determined that the risk does not apply or is no longer valid.",
    "NA":                 "Not applicable. The risk finding has a scope or context that does not affect the target system.",
}

# ── XML helpers ───────────────────────────────────────────────────────────────

def _set_cell_bg(cell: Any, hex_color: str) -> None:
    tc = cell._element
    tcPr = tc.find(qn("w:tcPr"))
    if tcPr is None:
        tcPr = OxmlElement("w:tcPr")
        tc.insert(0, tcPr)
    shd = tcPr.find(qn("w:shd"))
    if shd is None:
        shd = OxmlElement("w:shd")
        tcPr.append(shd)
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color.upper())


def _cell_text(cell: Any, text: str, bold: bool = False,
               font_color: str | None = None,
               align: WD_ALIGN_PARAGRAPH | None = None,
               font_size: int = 10,
               justify: bool = False) -> None:
    para = cell.paragraphs[0]
    para.clear()
    pPr = para._element.find(qn("w:pPr"))
    if pPr is None:
        pPr = OxmlElement("w:pPr")
        para._element.insert(0, pPr)
    jc = pPr.find(qn("w:jc"))
    if jc is None:
        jc = OxmlElement("w:jc")
        pPr.append(jc)
    if justify:
        jc.set(qn("w:val"), "both")
    elif align == WD_ALIGN_PARAGRAPH.CENTER:
        jc.set(qn("w:val"), "center")
    elif align == WD_ALIGN_PARAGRAPH.RIGHT:
        jc.set(qn("w:val"), "right")
    else:
        jc.set(qn("w:val"), "left")
    run = para.add_run(text)
    run.bold = bold
    run.font.size = Pt(font_size)
    if font_color:
        run.font.color.rgb = RGBColor.from_string(font_color)


def _para_justify(para: Any) -> None:
    """Set paragraph alignment to justify (both)."""
    pPr = para._element.find(qn("w:pPr"))
    if pPr is None:
        pPr = OxmlElement("w:pPr")
        para._element.insert(0, pPr)
    jc = pPr.find(qn("w:jc"))
    if jc is None:
        jc = OxmlElement("w:jc")
        pPr.append(jc)
    jc.set(qn("w:val"), "both")


def _extract_context_from_poc(poc_text: str | None) -> str:
    """Extract a short context label from PoC (e.g. vulnerable parameter value, payload hint)."""
    if not poc_text:
        return "N/A"
    for line in poc_text.splitlines():
        s = line.strip()
        if s.lower().startswith("- vulnerable parameter:") or s.lower().startswith("vulnerable parameter:"):
            val = s.split(":", 1)[-1].strip()
            if val:
                return val[:80]
        if s.lower().startswith("- technology:") or s.lower().startswith("technology:"):
            val = s.split(":", 1)[-1].strip()
            if val:
                return val[:80]
    return "N/A"


def _add_underlined_heading(doc: Document, text: str) -> Any:
    """Add a bold + underlined sub-heading matching example-report style.

    Matches the example: spB=25400 EMU (2pt), spA=0 so these labels sit tight
    against their body text without an explicit blank paragraph between them.
    """
    para = doc.add_paragraph(style="Normal")
    run = para.add_run(text)
    run.bold = True
    run.underline = True
    run.font.size = Pt(10)
    # 2pt space before, 0pt space after (matches example-report.docx)
    para.paragraph_format.space_before = Pt(2)
    para.paragraph_format.space_after = Pt(0)
    return para


def _add_grey_shading(para: Any) -> None:
    """Apply light-grey background shading to a paragraph (for code blocks)."""
    pPr = para._element.find(qn("w:pPr"))
    if pPr is None:
        pPr = OxmlElement("w:pPr")
        para._element.insert(0, pPr)
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), "F2F2F2")
    pPr.append(shd)


def _add_para_break(doc: Document) -> None:
    """Insert an explicit page break paragraph."""
    p = doc.add_paragraph()
    run = p.add_run()
    br = OxmlElement("w:br")
    br.set(qn("w:type"), "page")
    run._element.append(br)


def _insert_page_break_before(doc: Document, heading_para: Any) -> None:
    """Insert a page break paragraph immediately before the given paragraph."""
    p = OxmlElement("w:p")
    r = OxmlElement("w:r")
    br = OxmlElement("w:br")
    br.set(qn("w:type"), "page")
    r.append(br)
    p.append(r)
    heading_para._element.addprevious(p)


def _add_header_row(table: Any, headers: list[str],
                    bg: str = NAVY, text_color: str = WHITE,
                    font_size: int = 10) -> Any:
    row = table.add_row()
    for i, h in enumerate(headers):
        cell = row.cells[i]
        _set_cell_bg(cell, bg)
        _cell_text(cell, h, bold=True, font_color=text_color, font_size=font_size)
    return row


def _add_data_row(table: Any, values: list[str],
                  col_bgs: list[str | None] | None = None,
                  font_size: int = 10) -> Any:
    row = table.add_row()
    for i, v in enumerate(values):
        cell = row.cells[i]
        bg = (col_bgs[i] if col_bgs else None)
        if bg:
            _set_cell_bg(cell, bg)
        _cell_text(cell, v, font_size=font_size)
    return row


def _make_table(doc: Document, cols: int,
                col_widths: list[float] | None = None) -> Any:
    table = doc.add_table(rows=0, cols=cols)
    table.style = "Table Grid"
    if col_widths:
        for i, w in enumerate(col_widths):
            for cell in table.column_cells(i):
                cell.width = Cm(w)
    return table


def _add_justified_paragraph(doc: Document, text: str,
                               style: str = "Normal",
                               font_size: int = 10) -> Any:
    """Add a paragraph with justified text."""
    para = doc.add_paragraph(style=style)
    run = para.add_run(text)
    run.font.size = Pt(font_size)
    _para_justify(para)
    return para


_HTTP_CODE_RE = re.compile(
    r'^(curl[\s\-]|GET |POST |PUT |DELETE |PATCH |HEAD |OPTIONS |HTTP/[12][\. ]|'
    r'Host:|Content-Type:|Content-Length:|Authorization:|Accept:|User-Agent:|'
    r'Cookie:|Set-Cookie:|Location:|X-[A-Za-z\-]+:|'
    r'[A-Z][a-z\-]+:\s|'           # generic header: Value
    r'<\?xml|<!DOCTYPE|<html|{\s*$|\[|\$\s|> |---)',
    re.IGNORECASE,
)


def _add_poc_paragraphs(doc: Document, poc_text: str) -> None:
    """Render PoC prose with clean professional formatting.

    - Strips markdown code fences (``` / ```language) and stray backticks.
    - HTTP requests/responses and code blocks → Courier New 9pt, grey background.
    - Prose lines → justified Normal 10pt.
    - Blank lines are collapsed (no extra blank paragraphs).
    - Bold markdown (**text**) is rendered as DOCX bold runs.
    """
    if not poc_text or not poc_text.strip():
        para = doc.add_paragraph("No proof of concept recorded.", style="Normal")
        _para_justify(para)
        return

    # Strip markdown code fences: ```language\n...\n``` and bare ```
    text = re.sub(r'```[a-zA-Z]*\r?\n?', '', poc_text)
    text = text.replace('`', '')

    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Skip blank lines — no extra paragraphs
        if not stripped:
            i += 1
            continue

        is_code = (
            line.startswith("    ") or
            line.startswith("\t") or
            bool(_HTTP_CODE_RE.match(stripped))
        )

        if is_code:
            code_lines: list[str] = []
            while i < len(lines):
                l = lines[i]
                s = l.strip()
                if not s:
                    # Include internal blank lines only if next line is still code
                    j = i + 1
                    while j < len(lines) and not lines[j].strip():
                        j += 1
                    if j < len(lines) and (
                        lines[j].startswith("    ") or
                        lines[j].startswith("\t") or
                        bool(_HTTP_CODE_RE.match(lines[j].strip()))
                    ):
                        code_lines.append("")
                        i += 1
                        continue
                    break
                if (l.startswith("    ") or l.startswith("\t") or
                        bool(_HTTP_CODE_RE.match(s))):
                    code_lines.append(l.rstrip())
                    i += 1
                else:
                    break
            # Trim trailing blank lines
            while code_lines and not code_lines[-1].strip():
                code_lines.pop()
            if code_lines:
                para = doc.add_paragraph(style="Normal")
                para.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT
                run = para.add_run("\n".join(code_lines))
                run.font.name = "Courier New"
                run.font.size = Pt(9)
                _add_grey_shading(para)
        else:
            # Prose line — render **bold** markdown spans inline
            para = doc.add_paragraph(style="Normal")
            _para_justify(para)
            parts = re.split(r'\*\*(.+?)\*\*', stripped)
            for k, part in enumerate(parts):
                if not part:
                    continue
                run = para.add_run(part)
                run.font.size = Pt(10)
                run.bold = (k % 2 == 1)  # odd splits are inside **...**
            i += 1


# ── Clear body ────────────────────────────────────────────────────────────────

def _clear_body(doc: Document) -> None:
    body = doc.element.body
    to_remove = [child for child in body if child.tag != qn("w:sectPr")]
    for child in to_remove:
        body.remove(child)


# ── Cover page (copied from template) ────────────────────────────────────────

def _add_cover(doc: Document, scan: Any, template_doc: Document) -> None:
    """
    Deep-copy cover paragraphs from the template and replace placeholder text
    with actual scan data. Preserves all template formatting including logo images.
    """
    from urllib.parse import urlparse
    parsed = urlparse(scan.target_url)
    host_display = parsed.netloc or parsed.path

    # Find cover end index (first non-empty Heading 1 in template)
    cover_end_idx = 0
    for i, para in enumerate(template_doc.paragraphs):
        if para.style.name.startswith("Heading 1") and para.text.strip():
            cover_end_idx = i
            break

    # Collect body-level XML elements that correspond to cover paragraphs
    body = template_doc.element.body
    para_elements = []
    para_count = 0
    for child in body:
        if child.tag == qn("w:p"):
            if para_count >= cover_end_idx:
                break
            para_elements.append(child)
            para_count += 1
        # Also include tables if any appear in cover (unlikely but safe)
        elif child.tag == qn("w:tbl") and para_count < cover_end_idx:
            para_elements.append(child)

    # Deep-copy and inject into output doc body (before w:sectPr — it must stay last)
    out_body = doc.element.body
    sect_pr = out_body.find(qn("w:sectPr"))
    for elem in para_elements:
        new_elem = copy.deepcopy(elem)
        # Replace text content: "UOL –" and "ORCHARD" are in separate w:t runs,
        # so replace each part individually instead of the combined string.
        _replace_text_in_element(new_elem, "UOL Group Limited", host_display)
        _replace_text_in_element(new_elem, "UOL –", host_display)   # first run of title
        _replace_text_in_element(new_elem, "ORCHARD", "")            # second run of title
        _replace_text_in_element(new_elem, "UOL", host_display)      # any remaining occurrences
        # Version stays 1.0
        _replace_text_in_element(new_elem, "0.1", "1.0")
        if sect_pr is not None:
            sect_pr.addprevious(new_elem)
        else:
            out_body.append(new_elem)
    # No _add_para_break here — the copied cover already contains
    # a page-break paragraph (template para 13) + section-break (para 14)


def _replace_text_in_element(elem: Any, old: str, new: str) -> None:
    """Replace text in all w:t elements within an XML element tree."""
    ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    for t in elem.iter(f"{{{ns}}}t"):
        if t.text and old in t.text:
            t.text = t.text.replace(old, new)


# ── Version control ───────────────────────────────────────────────────────────

def _add_version_control(doc: Document, scan: Any) -> None:
    doc.add_heading("Version Control", level=1)
    doc.add_paragraph()
    table = _make_table(doc, 5, [2.0, 3.5, 5.5, 4.0, 4.0])
    _add_header_row(table, ["Version", "Date", "Description", "Amended By", "Reviewed By"])
    now_str = datetime.now(timezone.utc).strftime("%d %B %Y")
    _add_data_row(table, ["1.0", now_str, "Initial Draft Report",
                          BRAND, "Security Reviewer"])
    doc.add_paragraph()
    _add_para_break(doc)


# ── Disclaimer ────────────────────────────────────────────────────────────────

def _add_disclaimer(doc: Document) -> None:
    doc.add_heading("Disclaimer", level=1)
    texts = [
        "A security test is considered a snapshot in time. The findings and recommendations "
        "reflect the information gathered during the security testing period only.",
        "A time-bound assessment approach does not allow for a full evaluation of all security "
        "controls. The security posture of the tested systems may change after the assessment.",
        "Recommendations and references enclosed are not meant to be comprehensive or exhaustive "
        "in nature. The client should evaluate all findings and recommendations in the context of "
        "their specific environment.",
        "References provided neither indicate endorsement nor support for the approaches to meet "
        "the recommendations but are provided for informational purposes.",
    ]
    for t in texts:
        _add_justified_paragraph(doc, t)
    doc.add_paragraph()
    _add_para_break(doc)


# ── Executive Summary ─────────────────────────────────────────────────────────

def _add_executive_summary(doc: Document, scan: Any, findings: list[Any]) -> None:
    from urllib.parse import urlparse
    _ekind = _report_kind(scan)
    parsed = urlparse(scan.target_url)
    host_display = parsed.netloc or parsed.path

    doc.add_heading("Executive Summary", level=1)

    _add_justified_paragraph(doc,
        f"An automated web vulnerability assessment and penetration test was conducted against "
        f"{scan.target_url}. The purpose of this assessment is to identify potential weaknesses "
        f"or vulnerabilities exposed to the public or authenticated users, and to provide "
        f"actionable remediation recommendations."
    )

    # Testing details table
    doc.add_paragraph("Table 1: Details of the security testing.", style="Caption")
    table = _make_table(doc, 2, [5.0, 14.0])
    _add_header_row(table, ["Testing Details", "Description"])
    completed_at = getattr(scan, "completed_at", None)
    started_at   = getattr(scan, "started_at", None)
    period = "—"
    if started_at and completed_at:
        fmt = "%d %B %Y"
        s = started_at.strftime(fmt) if hasattr(started_at, "strftime") else str(started_at)
        e = completed_at.strftime(fmt) if hasattr(completed_at, "strftime") else str(completed_at)
        period = f"{s} to {e}"
    rows_data = [
        ("Type",               "Web Vulnerability Assessment and Penetration Testing"),
        ("System Name",        host_display),
        ("Testing Period",     period),
        ("System Environment", "Production / Staging"),
        ("Approach",           "Black-box automated assessment with active exploitation"),
        ("Scan Mode",          "Full Scan" if getattr(scan, "scan_mode", "full") == "full"
                               else "Static Analysis Only"),
    ]
    for label, val in rows_data:
        row = table.add_row()
        _set_cell_bg(row.cells[0], LIGHT_BLUE)
        _cell_text(row.cells[0], label, bold=False)
        _cell_text(row.cells[1], val)
    doc.add_paragraph()

    _add_justified_paragraph(doc,
        f"The classification of the {len(findings)} finding(s) identified are summarized in the "
        f"table below, according to severity ratings."
    )

    # Severity summary table
    doc.add_paragraph("Table 2: Findings across work component and severity rating.",
                      style="Caption")
    sev_table = _make_table(doc, 6, [5.0, 2.5, 2.5, 2.5, 2.5, 2.5])
    hrow = sev_table.add_row()
    _set_cell_bg(hrow.cells[0], NAVY)
    _cell_text(hrow.cells[0], "Component", bold=True, font_color=WHITE)
    for i, sev in enumerate(SEV_ORDER):
        _set_cell_bg(hrow.cells[i + 1], SEV_COLORS[sev])
        _cell_text(hrow.cells[i + 1], sev, bold=True,
                   font_color=SEV_TEXT_COLORS[sev],
                   align=WD_ALIGN_PARAGRAPH.CENTER)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEV_ORDER}
    drow = sev_table.add_row()
    _cell_text(drow.cells[0], scan.target_url, font_size=9)
    for i, sev in enumerate(SEV_ORDER):
        if counts[sev] > 0:
            _set_cell_bg(drow.cells[i + 1], SEV_COLORS[sev])
            _cell_text(drow.cells[i + 1], str(counts[sev]),
                       font_color=SEV_TEXT_COLORS[sev],
                       align=WD_ALIGN_PARAGRAPH.CENTER)
        else:
            _cell_text(drow.cells[i + 1], str(counts[sev]),
                       align=WD_ALIGN_PARAGRAPH.CENTER)
    doc.add_paragraph()

    # Scope
    doc.add_heading("Scope", level=2)
    _add_justified_paragraph(doc,
        "The security testing focused on identifying vulnerabilities within the target application."
    )
    doc.add_paragraph("Table 3: List of URLs in scope of the security testing.",
                      style="Caption")
    scope_table = _make_table(doc, 3, [1.5, 10.0, 7.5])
    _add_header_row(scope_table, ["SN.", "URL", "Remarks"])
    scope_urls = [scan.target_url]
    scope_extra = getattr(scan, "scope_include", None)
    if scope_extra:
        import json
        try:
            extra = json.loads(scope_extra) if isinstance(scope_extra, str) else scope_extra
            scope_urls += [u for u in extra if u and u != scan.target_url]
        except Exception:
            pass
    for i, url in enumerate(scope_urls, 1):
        _add_data_row(scope_table, [str(i), url, "In scope"])
    doc.add_paragraph()

    doc.add_paragraph("Table 4: List of test accounts.", style="Caption")
    acc_table = _make_table(doc, 5, [1.5, 3.5, 3.5, 3.5, 7.0])
    _add_header_row(acc_table, ["SN.", "Role", "User ID", "Password", "Remarks"])
    _add_data_row(acc_table, ["", "N/A", "N/A", "N/A", "N/A"])
    doc.add_paragraph()

    # Limitations
    doc.add_heading("Limitations", level=2)
    _add_justified_paragraph(doc,
        "The following functions were excluded or limited during the security testing period."
    )
    doc.add_paragraph("Table 5: List of functions omitted in the security testing.",
                      style="Caption")
    lim_table = _make_table(doc, 3, [1.5, 6.0, 11.5])
    _add_header_row(lim_table, ["SN.", "Functionality", "Remarks"])
    _add_data_row(lim_table, ["", "N/A", "No limitations noted."])
    doc.add_paragraph()

    # List of findings
    doc.add_heading("List of Findings", level=2)
    doc.add_paragraph("Table 6: List of severity findings.", style="Caption")
    ft = _make_table(doc, 5, [1.5, 7.0, 3.0, 2.5, 3.0])
    _add_header_row(ft, ["SN.", "Findings", "Severity Rating", "CVSS Score", "Finding Status"])
    for i, f in enumerate(findings, 1):
        row = ft.add_row()
        _cell_text(row.cells[0], str(i), align=WD_ALIGN_PARAGRAPH.CENTER)
        ref = f.finding_ref or f"{_ekind['ref']}-{i}"
        _cell_text(row.cells[1], f"{ref}: {f.title}", font_size=9)
        sev = f.severity if f.severity in SEV_COLORS else "Informational"
        _set_cell_bg(row.cells[2], SEV_COLORS[sev])
        _cell_text(row.cells[2], sev, font_color=SEV_TEXT_COLORS[sev],
                   align=WD_ALIGN_PARAGRAPH.CENTER)
        score = (f.cvss4_score if f.cvss4_score is not None
                 else (f.cvss_score if f.cvss_score is not None else 0.0))
        _cell_text(row.cells[3], f"{score:.1f}", align=WD_ALIGN_PARAGRAPH.CENTER)
        _cell_text(row.cells[4], f.status or "Open")
    doc.add_paragraph()

    # Finding status description
    doc.add_heading("Finding Status Description", level=2)
    doc.add_paragraph("Table 7: List of finding status and its meaning.", style="Caption")
    st = _make_table(doc, 2, [4.0, 15.0])
    _add_header_row(st, ["Finding Status", "Description"])
    for status_name, desc in STATUS_DESCRIPTIONS.items():
        row = st.add_row()
        _set_cell_bg(row.cells[0], LIGHT_BLUE)
        _cell_text(row.cells[0], status_name, bold=True)
        _cell_text(row.cells[1], desc, justify=True)
    doc.add_paragraph()
    _add_para_break(doc)


# ── Per-finding section ───────────────────────────────────────────────────────

def _code_from_finding(f: Any) -> str:
    """Return the vulnerable source snippet. _persist_findings stores it as raw
    evidence (raw_request); fall back to parsing the description for the static
    'Matched snippet : <code>' marker."""
    snippet = (getattr(f, "raw_request", "") or "").strip()
    if snippet:
        return snippet
    for line in (getattr(f, "description", "") or "").splitlines():
        s = line.strip()
        if s.lower().startswith("matched snippet"):
            return s.split(":", 1)[1].strip() if ":" in s else s
    return ""


def _add_code_block(doc: Document, code: str, location: str) -> None:
    """Render a vulnerable-code box: file:line caption + monospaced snippet."""
    tbl = _make_table(doc, 1, [18.0])
    cap = tbl.add_row()
    _set_cell_bg(cap.cells[0], NAVY)
    _cell_text(cap.cells[0], location or "source location", bold=True,
               font_color=WHITE, font_size=9)
    body = tbl.add_row()
    _set_cell_bg(body.cells[0], "F5F7FA")
    para = body.cells[0].paragraphs[0]
    run = para.add_run(code or "(snippet unavailable — see location above)")
    run.font.name = "Consolas"; run.font.size = Pt(9)
    run.font.color.rgb = RGBColor.from_string("7A1220")


def _add_finding_section(doc: Document, idx: int, f: Any,
                          first: bool = False, kind: dict | None = None) -> None:
    """Render one finding section matching example-report.docx layout.

    Section order (matches example):
      Heading 2 → CVSS table → blank → Observations → Proof of Concepts →
      Affected Hosts/Services → table → blank → Implications →
      Recommendations → References → Remarks → management tables
    """
    if not first:
        _add_para_break(doc)

    kind = kind or _report_kind(None)
    is_src = kind.get("ref") == "SCR"
    ref = f.finding_ref or f"{kind['ref']}-{idx}"
    doc.add_heading(f"{ref}: {f.title}", level=2)
    # NO blank paragraph between heading and CVSS table (matches example)

    sev = f.severity if f.severity in SEV_COLORS else "Informational"
    score = (f.cvss4_score if f.cvss4_score is not None
             else (f.cvss_score if f.cvss_score is not None else None))
    vector = f.cvss4_vector or f.cvss_vector or "N/A"
    score_str = f"{score:.1f}" if score is not None else "N/A"

    # CVSS table — directly after heading
    cvss_table = _make_table(doc, 3, [4.0, 6.0, 9.0])
    hrow = cvss_table.add_row()
    _cell_text(hrow.cells[0], "Severity Level", bold=True)
    _set_cell_bg(hrow.cells[1], SEV_COLORS[sev])
    _cell_text(hrow.cells[1], sev, bold=True,
               font_color=SEV_TEXT_COLORS[sev],
               align=WD_ALIGN_PARAGRAPH.CENTER)
    _set_cell_bg(hrow.cells[2], SEV_COLORS[sev])
    _cell_text(hrow.cells[2], score_str, bold=True,
               font_color=SEV_TEXT_COLORS[sev],
               align=WD_ALIGN_PARAGRAPH.CENTER)
    drow = cvss_table.add_row()
    _cell_text(drow.cells[0], "CVSS Vector and Score", bold=True)
    _cell_text(drow.cells[1], vector, font_size=9)
    _cell_text(drow.cells[2], score_str, align=WD_ALIGN_PARAGRAPH.CENTER)
    doc.add_paragraph()  # single blank after CVSS table

    # Observations
    doc.add_heading("Observations", level=3)
    _add_justified_paragraph(doc, f.description or "See proof of concept below.")

    # Proof of Concept (before Affected Hosts — matches example order)
    doc.add_heading("Proof of Concept", level=3)
    _add_poc_paragraphs(doc, f.proof_of_concept)

    # Location — source review shows the vulnerable code (file:line + snippet);
    # a web pentest shows the affected host/parameter.
    if is_src:
        doc.add_heading(kind["loc_lbl"], level=3)
        _add_code_block(doc, _code_from_finding(f), f.location or "source location")
        srow_t = _make_table(doc, 2, [4.0, 15.0])
        s1 = srow_t.add_row()
        _cell_text(s1.cells[0], "Status", bold=True)
        _cell_text(s1.cells[1], f.status or "Open")
        doc.add_paragraph()
    else:
        doc.add_heading("Affected Hosts/Services", level=3)
        location_str = f.location or scan_target_fallback(f) or "See target URL"
        loc_parts = location_str.split("?", 1)
        host_part  = loc_parts[0]
        param_part = loc_parts[1] if len(loc_parts) > 1 else "N/A"
        context_part = _extract_context_from_poc(f.proof_of_concept)
        aff_table = _make_table(doc, 5, [1.0, 5.5, 4.0, 4.0, 4.5])
        _add_header_row(aff_table,
                        ["SN.", "Affected Host/Service", "Affected Parameter", "Context", "Status"])
        arow = aff_table.add_row()
        _cell_text(arow.cells[0], "1", align=WD_ALIGN_PARAGRAPH.CENTER)
        _cell_text(arow.cells[1], host_part, font_size=9)
        _cell_text(arow.cells[2], param_part, font_size=9)
        _cell_text(arow.cells[3], context_part, font_size=9)
        _cell_text(arow.cells[4], f.status or "Open")
        doc.add_paragraph()  # single blank after affected-hosts table

    # Implications — bold+underline label with spB=2pt, tight against body
    _add_underlined_heading(doc, "Implications")
    _add_justified_paragraph(doc, f.implications or "Not specified.")

    # Recommendations
    _add_underlined_heading(doc, "Recommendations")
    _add_justified_paragraph(doc, f.recommendations or "Not specified.")

    # References — numbered list as List Paragraph (matches example)
    _add_underlined_heading(doc, "References")
    for idx_r, ref_line in enumerate(_build_references(f), 1):
        try:
            para = doc.add_paragraph(style="List Paragraph")
        except Exception:
            para = doc.add_paragraph(style="Normal")
        run = para.add_run(f"{idx_r}. {ref_line}")
        run.font.size = Pt(10)

    # Remarks — management tables
    doc.add_heading("Remarks", level=3)
    doc.add_paragraph()
    mgmt = _make_table(doc, 2, [3.5, 15.5])
    mh = mgmt.add_row()
    _set_cell_bg(mh.cells[0], NAVY)
    _set_cell_bg(mh.cells[1], NAVY)
    _cell_text(mh.cells[0], "Management Comments (To be filled in by client)",
               bold=True, font_color=WHITE)
    _cell_text(mh.cells[1], "", bold=True, font_color=WHITE)
    ml = mgmt.add_row()
    _set_cell_bg(ml.cells[0], LIGHT_BLUE)
    _set_cell_bg(ml.cells[1], LIGHT_BLUE)
    _cell_text(ml.cells[0], "Date", bold=True)
    _cell_text(ml.cells[1], "Comment", bold=True)
    mgmt.add_row()
    doc.add_paragraph()

    post = _make_table(doc, 2, [3.5, 15.5])
    ph = post.add_row()
    _set_cell_bg(ph.cells[0], NAVY)
    _set_cell_bg(ph.cells[1], NAVY)
    _cell_text(ph.cells[0], "Post Review Observations (To be filled in by Reviewer)",
               bold=True, font_color=WHITE)
    _cell_text(ph.cells[1], "", bold=True, font_color=WHITE)
    pl = post.add_row()
    _set_cell_bg(pl.cells[0], LIGHT_BLUE)
    _set_cell_bg(pl.cells[1], LIGHT_BLUE)
    _cell_text(pl.cells[0], "Date", bold=True)
    _cell_text(pl.cells[1], "Comment", bold=True)
    post.add_row()
    doc.add_paragraph()


def scan_target_fallback(f: Any) -> str:
    return ""


def _build_references(f: Any) -> list[str]:
    refs = []
    owasp_cat  = f.owasp_category or ""
    owasp_name = f.owasp_name or ""
    cve        = f.cve or ""
    refs_raw   = f.references or ""

    if owasp_cat and owasp_name:
        slug = owasp_cat.replace(":", "_").replace(" ", "_").replace(".", "_")
        refs.append(
            f"{owasp_cat} – {owasp_name} – "
            f"https://owasp.org/Top10/{slug}/"
        )
    if cve:
        refs.append(f"{cve} – https://nvd.nist.gov/vuln/detail/{cve}")
    for line in refs_raw.splitlines():
        line = line.strip()
        if line and line not in refs:
            refs.append(line)
    if not refs:
        refs = ["https://owasp.org/www-project-top-ten/"]
    return refs


# ── Security Test Findings ────────────────────────────────────────────────────

def _sort_findings(findings: list[Any]) -> list[Any]:
    """Sort findings Critical → High → Medium → Low → Informational, then by numeric ref."""
    order = {s: i for i, s in enumerate(SEV_ORDER)}

    def _sort_key(f: Any):
        sev_idx = order.get(f.severity, 99)
        ref = getattr(f, "finding_ref", "") or ""
        m = re.search(r"(\d+)$", ref)
        ref_num = int(m.group(1)) if m else 9999
        return (sev_idx, ref_num)

    return sorted(findings, key=_sort_key)


def _add_findings_section(doc: Document, scan: Any, findings: list[Any]) -> None:
    kind = _report_kind(scan)
    doc.add_heading("Detailed Findings", level=1)
    doc.add_paragraph()

    if not findings:
        _add_justified_paragraph(doc,
            "No findings were identified during this assessment.")
        return

    for i, f in enumerate(findings, 1):
        _add_finding_section(doc, i, f, first=(i == 1), kind=kind)

    _add_para_break(doc)


# ── Attack Path & Chaining Analysis ───────────────────────────────────────────

def _add_attack_workflow(doc: Document, scan: Any, workflow: dict[str, Any] | None) -> None:
    """Render the attack chain analysis derived from the scan's findings.

    Skipped entirely when no workflow was generated (e.g. scans with no findings).
    """
    if not workflow:
        return
    chains = workflow.get("chains") or []
    summary = (workflow.get("summary") or "").strip()
    if not chains and not summary:
        return

    _add_para_break(doc)
    doc.add_heading("Attack Path and Chaining Analysis", level=1)
    _add_justified_paragraph(
        doc,
        "This section describes how the individual findings listed above combine into "
        "end-to-end attack paths. Each chain is derived from confirmed findings only; the "
        "finding references in every step point back to the corresponding entry in the "
        "Security Test Findings section. Chains are ordered by severity.",
    )
    doc.add_paragraph()

    if summary:
        _add_underlined_heading(doc, "Attack Narrative")
        _add_justified_paragraph(doc, summary)
        doc.add_paragraph()

    if not chains:
        _add_justified_paragraph(
            doc,
            "No multi-step attack chain could be derived from the confirmed findings. "
            "The identified issues appear to be independent exposures.",
        )
        doc.add_paragraph()
        return

    # ── Overview table ───────────────────────────────────────────────────────
    doc.add_heading("Attack Chain Overview", level=2)
    doc.add_paragraph("Table 8: Identified attack chains.", style="Caption")
    ct = _make_table(doc, 5, [1.2, 7.5, 3.0, 4.0, 3.3])
    _add_header_row(ct, ["SN.", "Attack Chain", "Severity", "Findings Involved", "Evidence"])
    for i, chain in enumerate(chains, 1):
        row = ct.add_row()
        _cell_text(row.cells[0], str(i), align=WD_ALIGN_PARAGRAPH.CENTER)
        _cell_text(row.cells[1], str(chain.get("name", "")), font_size=9)
        sev = chain.get("severity") if chain.get("severity") in SEV_COLORS else "Informational"
        _set_cell_bg(row.cells[2], SEV_COLORS[sev])
        _cell_text(row.cells[2], sev, font_color=SEV_TEXT_COLORS[sev],
                   align=WD_ALIGN_PARAGRAPH.CENTER)
        _cell_text(row.cells[3], " → ".join(chain.get("finding_refs") or []), font_size=9)
        evidence = "PoC-backed" if chain.get("evidence_backed") else "Partial evidence"
        _cell_text(row.cells[4], f"{evidence} ({chain.get('confidence', 0)}%)",
                   font_size=9, align=WD_ALIGN_PARAGRAPH.CENTER)
    doc.add_paragraph()

    # ── Per-chain detail ─────────────────────────────────────────────────────
    for i, chain in enumerate(chains, 1):
        doc.add_heading(f"Chain {i}: {chain.get('name', '')}", level=2)

        meta = _make_table(doc, 2, [4.5, 14.5])
        for label, value in (
            ("Severity", str(chain.get("severity", "—"))),
            ("Confidence", f"{chain.get('confidence', 0)}% "
                           f"({'PoC-backed' if chain.get('evidence_backed') else 'partial evidence'})"),
            ("Findings Involved", " → ".join(chain.get("finding_refs") or []) or "—"),
            ("End State", str(chain.get("terminal", "—"))),
            ("Derivation", "Rule-based correlation" if chain.get("source") == "heuristic"
                           else "AI-assisted correlation (grounded in listed findings)"),
        ):
            row = meta.add_row()
            _set_cell_bg(row.cells[0], LIGHT_BLUE)
            _cell_text(row.cells[0], label, bold=True, font_size=9)
            _cell_text(row.cells[1], value, font_size=9)
        doc.add_paragraph()

        steps = chain.get("steps") or []
        if steps:
            _add_underlined_heading(doc, "Attack Steps")
            st = _make_table(doc, 4, [1.5, 3.5, 3.0, 11.0])
            _add_header_row(st, ["Step", "Phase", "Finding", "Action"])
            for step in steps:
                row = st.add_row()
                _cell_text(row.cells[0], str(step.get("order", "")),
                           align=WD_ALIGN_PARAGRAPH.CENTER, font_size=9)
                _cell_text(row.cells[1], str(step.get("stage_label", "")), font_size=9)
                _cell_text(row.cells[2], str(step.get("finding_ref", "")), font_size=9)
                action = str(step.get("action", ""))
                location = str(step.get("location") or "")
                if location:
                    action = f"{action} (target: {location})"
                _cell_text(row.cells[3], action, font_size=9, justify=True)
            doc.add_paragraph()

        impact = (chain.get("impact") or "").strip()
        if impact:
            _add_underlined_heading(doc, "Impact")
            _add_justified_paragraph(doc, impact)
            doc.add_paragraph()

    # ── Diagram source ───────────────────────────────────────────────────────
    mermaid = (workflow.get("mermaid") or "").strip()
    if mermaid:
        doc.add_heading("Attack Path Diagram (Mermaid Source)", level=2)
        _add_justified_paragraph(
            doc,
            "The attack path graph below is provided in Mermaid flowchart syntax and can be "
            "rendered with any Mermaid-compatible viewer.",
        )
        for line in mermaid.splitlines():
            para = doc.add_paragraph(style="Normal")
            run = para.add_run(line if line.strip() else " ")
            run.font.name = "Courier New"
            run.font.size = Pt(8)
            para.paragraph_format.space_before = Pt(0)
            para.paragraph_format.space_after = Pt(0)
            _add_grey_shading(para)
        doc.add_paragraph()


# ── Methodology ───────────────────────────────────────────────────────────────

def _add_bullet(doc: Document, text: str, indent_level: int = 0) -> Any:
    """Add a bullet-point paragraph using List Bullet style."""
    try:
        para = doc.add_paragraph(style="List Paragraph")
    except Exception:
        para = doc.add_paragraph(style="Normal")
    run = para.add_run(text)
    run.font.size = Pt(10)
    if indent_level > 0:
        para.paragraph_format.left_indent = Cm(1.27 * (indent_level + 1))
    return para


def _add_owasp_item(doc: Document, code: str, title: str, description: str) -> None:
    """Add one OWASP item: underlined heading + justified description."""
    _add_underlined_heading(doc, f"{code}. {title}")
    para = doc.add_paragraph(style="Normal")
    run = para.add_run(description)
    run.font.size = Pt(10)
    _para_justify(para)
    para.paragraph_format.space_before = Pt(0)
    para.paragraph_format.space_after = Pt(4)


def _add_methodology(doc: Document) -> None:
    doc.add_heading("Appendix 1 \u2013 Methodology", level=1)

    # Intro paragraphs
    _add_justified_paragraph(doc,
        f"{BRAND}'s assessment methodology is based on OWASP Top 10 (2021) standards, "
        "combining deterministic static analysis with AI-assisted reasoning. It is "
        "designed to adapt to the application environment and security requirements."
    )
    _add_justified_paragraph(doc,
        "Our methodology can be summarised as a five-step approach consisting of following phases:"
    )

    # ── Phase 1: Planning and Preparation ────────────────────────────────────
    doc.add_heading("Planning and Preparation", level=2)
    for bullet in [
        "Conduct project kick-off meeting.",
        "Confirm project scope and objectives.",
        "Identify parties involved and key contact persons.",
        "Establish project timelines and duration.",
    ]:
        _add_bullet(doc, bullet)

    # ── Phase 2: Information Gathering, Mapping, and Profiling ───────────────
    doc.add_heading("Information Gathering, Mapping, and Profiling", level=2)
    for bullet in [
        "Determine the Web Application(s) to be reviewed.",
        "Gather information on the Web Application and its operating environment.",
        (
            "Identify the criteria to review the application against, such as Application "
            "development guidelines, Security policies/requirements, regulatory mandates, among others."
        ),
        "Design test procedures that will determine compliance with identified review criteria.",
    ]:
        _add_bullet(doc, bullet)

    # ── Phase 3: Execution and Testing ───────────────────────────────────────
    doc.add_heading("Execution and Testing", level=2)
    _add_bullet(doc,
        "Using a hybrid approach that involves automated web application vulnerability scan(s), "
        "manual validation of the automated scan(s) results and manual penetration test to uncover "
        "vulnerabilities in the following categories:"
    )

    owasp_items = [
        ("A1",  "Broken Access Control",
         "Restrictions on what authenticated users are allowed to do are often not properly enforced. "
         "Attackers can exploit these flaws to access unauthorised functionality and/or data, such as "
         "access other users\u2019 accounts, view sensitive files, modify other users\u2019 data, "
         "change access rights, etc."),
        ("A2",  "Cryptographic Failures",
         "Many web applications and APIs do not properly protect sensitive data, such as financial, "
         "healthcare, and PII. Attackers may steal or modify such weakly protected data to conduct "
         "credit card fraud, identity theft, or other crimes. Sensitive data may be compromised without "
         "extra protection, such as encryption at rest or in transit, and requires special precautions "
         "when exchanged with the browser."),
        ("A3",  "Injection",
         "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is "
         "sent to an interpreter as part of a command or query. The attacker\u2019s hostile data can "
         "trick the interpreter into executing unintended commands or accessing data without proper "
         "authorisation."),
        ("A4",  "Insecure Design",
         "Focuses on risks related to design and architectural flaws, with a call for more use of "
         "threat modelling, secure design patterns, and reference architectures. An insecure design "
         "cannot be fixed by a perfect implementation as by definition, needed security controls were "
         "never created to defend against specific attacks. One of the factors that contribute to "
         "insecure design is the lack of business risk profiling inherent in the software or system "
         "being developed, and thus the failure to determine what level of security design is required."),
        ("A5",  "Security Misconfiguration",
         "Security misconfiguration is the most seen issue. This is commonly a result of insecure "
         "default configurations, incomplete or ad hoc configurations, open cloud storage, "
         "misconfigured HTTP headers, and verbose error messages containing sensitive information. Not "
         "only must all operating systems, frameworks, libraries, and applications be securely "
         "configured, but they must be patched and upgraded in a timely fashion."),
        ("A6",  "Vulnerable and Outdated Components",
         "Components, such as libraries, frameworks, and other software modules, run with the same "
         "privileges as the application. If a vulnerable component is exploited, such an attack can "
         "facilitate serious data loss or server takeover. Applications and APIs using components with "
         "known vulnerabilities may undermine application defences and enable various attacks and impacts."),
        ("A7",  "Identification and Authentication Failures",
         "Application functions related to authentication and session management are often implemented "
         "incorrectly, allowing attackers to compromise passwords, keys, or session tokens, or to "
         "exploit other implementation flaws to assume other users\u2019 identities temporarily or "
         "permanently."),
        ("A8",  "Software and Data Integrity Failures",
         "Software and data integrity failures relate to code and infrastructure that does not protect "
         "against integrity violations. An example of this is where an application relies upon plugins, "
         "libraries, or modules from untrusted sources, repositories, and content delivery networks "
         "(CDNs). An insecure CI/CD pipeline can introduce the potential for unauthorised access, "
         "malicious code, or system compromise. Lastly, many applications now include auto-update "
         "functionality, where updates are downloaded without sufficient integrity verification and "
         "applied to the previously trusted application. Attackers could potentially upload their own "
         "updates to be distributed and run on all installations. Another example is where objects or "
         "data are encoded or serialised into a structure that an attacker can see and modify is "
         "vulnerable to insecure deserialisation."),
        ("A9",  "Security Logging and Monitoring Failures",
         "Insufficient logging and monitoring, coupled with missing or ineffective integration with "
         "incident response, allows attackers to further attack systems, maintain persistence, pivot to "
         "more systems, and tamper, extract, or destroy data. Most breach studies show time to detect "
         "a breach is over 200 days, typically detected by external parties rather than internal "
         "processes or monitoring."),
        ("A10", "Server-Side Request Forgery (SSRF)",
         "SSRF flaws occur whenever a web application is fetching a remote resource without validating "
         "the user-supplied URL. It allows an attacker to coerce the application to send a crafted "
         "request to an unexpected destination, even when protected by a firewall, VPN, or another "
         "type of network access control list (ACL)."),
    ]
    for code, title, desc in owasp_items:
        _add_owasp_item(doc, code, title, desc)

    # ── Phase 4: Analysis and Reporting ──────────────────────────────────────
    doc.add_heading("Analysis and Reporting", level=2)
    _add_bullet(doc,
        "Summarise and analyse all security weaknesses identified in a report that includes:"
    )
    for sub in [
        "Summary of applications reviewed and the corresponding security weaknesses identified.",
        "A detailed account of all security weaknesses found.",
        "Suggestions and techniques to resolve vulnerabilities found.",
    ]:
        _add_bullet(doc, sub, indent_level=1)

    # ── Phase 5: Follow-up (Optional) ─────────────────────────────────────────
    doc.add_heading("Follow-up (Optional)", level=2)
    for bullet in [
        "Obtain remediation plan/documentation.",
        "Determine post review schedule and timelines.",
        "Conduct security review to validate the effectiveness of remediation efforts.",
        "Summarise and report findings.",
    ]:
        _add_bullet(doc, bullet)

    # Closing paragraph
    doc.add_paragraph()
    _add_justified_paragraph(doc,
        "The penetration test aimed to cover the breadth and depth of the application. This ensured "
        "all the visible links found within the application were followed and scanned. However, this "
        "is a best effort attempt based on the time allocated for this project and there would still "
        "be a possibility that certain links were missed due to their covert nature."
    )
    _add_para_break(doc)


# ── Severity classification ───────────────────────────────────────────────────

def _add_severity_classification(doc: Document) -> None:
    doc.add_heading("Severity Classification & Rating", level=1)
    _add_justified_paragraph(doc,
        "Analysis of the criticality severity of findings was performed based on the "
        "Common Vulnerability Scoring System (CVSS) v3.1 / v4.0."
    )
    _add_justified_paragraph(doc,
        "The final rating scale is categorised into 5 severity levels according to CVSS scoring:"
    )
    table = _make_table(doc, 3, [3.0, 3.0, 13.0])
    _add_header_row(table, ["Rating", "CVSS Score", "Description"])
    sev_info = [
        ("Informational", "0.0",      "No exploitable vulnerability. Informational findings for awareness."),
        ("Low",           "0.1–3.9",  "Vulnerabilities are non-exploitable or require significant conditions to exploit."),
        ("Medium",        "4.0–6.9",  "Vulnerabilities exist but are not easily exploitable or require user interaction."),
        ("High",          "7.0–8.9",  "Exploitation is more difficult but could cause elevated impact if successful."),
        ("Critical",      "9.0–10.0", "Exploitation is straightforward and usually results in full system compromise."),
    ]
    for sev, score_range, desc in sev_info:
        row = table.add_row()
        bg = SEV_COLORS.get(sev, "D9D9D9")
        tc = SEV_TEXT_COLORS.get(sev, "000000")
        for cell in row.cells:
            _set_cell_bg(cell, bg)
        _cell_text(row.cells[0], sev, bold=True, font_color=tc)
        _cell_text(row.cells[1], score_range, font_color=tc,
                   align=WD_ALIGN_PARAGRAPH.CENTER)
        _cell_text(row.cells[2], desc, font_color=tc, justify=True)
    doc.add_paragraph()


# ── Main entry ────────────────────────────────────────────────────────────────

def _shade_para(para: Any, hex_fill: str) -> None:
    """Full-width paragraph shading — used for the cover banner + accent rules."""
    pPr = para._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear"); shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_fill.upper())
    pPr.append(shd)


def _add_page_field(paragraph: Any) -> None:
    run = paragraph.add_run()
    f1 = OxmlElement("w:fldChar"); f1.set(qn("w:fldCharType"), "begin")
    it = OxmlElement("w:instrText"); it.set(qn("xml:space"), "preserve"); it.text = "PAGE"
    f2 = OxmlElement("w:fldChar"); f2.set(qn("w:fldCharType"), "end")
    run._r.append(f1); run._r.append(it); run._r.append(f2)
    run.font.size = Pt(8); run.font.color.rgb = RGBColor.from_string(SLATE)


def _setup_base_document() -> Document:
    """Fresh, template-free document with a clean base style and generous margins."""
    doc = Document()
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(10.5)
    normal.font.color.rgb = RGBColor.from_string(BLACK)
    for section in doc.sections:
        section.left_margin = Cm(2.2); section.right_margin = Cm(2.2)
        section.top_margin = Cm(1.9); section.bottom_margin = Cm(1.7)
    return doc


def _setup_header_footer(doc: Document, scan: Any) -> None:
    kind = _report_kind(scan)
    sec = doc.sections[0]
    hp = sec.header.paragraphs[0]; hp.text = ""; hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    hr = hp.add_run(f"{BRAND}  ·  {kind['subject']}")
    hr.font.size = Pt(8); hr.font.color.rgb = RGBColor.from_string(SLATE)
    fp = sec.footer.paragraphs[0]; fp.text = ""; fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    fr = fp.add_run(f"{BRAND}   ·   Confidential   ·   Page ")
    fr.font.size = Pt(8); fr.font.color.rgb = RGBColor.from_string(SLATE)
    _add_page_field(fp)


def _add_cover_v2(doc: Document, scan: Any, findings: list[Any]) -> None:
    """Elegant, template-free cover page."""
    kind = _report_kind(scan)

    band = doc.add_paragraph(); _shade_para(band, NAVY)
    br = band.add_run(f"  {BRAND.upper()}")
    br.bold = True; br.font.size = Pt(13); br.font.color.rgb = RGBColor.from_string(WHITE)
    tagp = doc.add_paragraph()
    tg = tagp.add_run(BRAND_TAG); tg.font.size = Pt(9)
    tg.font.color.rgb = RGBColor.from_string(SLATE)

    for _ in range(6):
        doc.add_paragraph()

    tp = doc.add_paragraph()
    tr = tp.add_run(kind["title"])
    tr.bold = True; tr.font.size = Pt(30); tr.font.color.rgb = RGBColor.from_string(NAVY)
    rule = doc.add_paragraph(); _shade_para(rule, ACCENT)
    rr = rule.add_run(" "); rr.font.size = Pt(2)

    doc.add_paragraph()
    target = getattr(scan, "source_repo_url", None) or getattr(scan, "target_url", "") or "N/A"
    sp = doc.add_paragraph()
    lbl = sp.add_run(f"{kind['target_lbl']}:  ")
    lbl.bold = True; lbl.font.size = Pt(12); lbl.font.color.rgb = RGBColor.from_string(SLATE)
    val = sp.add_run(str(target))
    val.font.size = Pt(12); val.font.color.rgb = RGBColor.from_string(ACCENT)

    for _ in range(8):
        doc.add_paragraph()

    # Meta panel
    total = len(findings)
    crit_high = sum(1 for f in findings if getattr(f, "severity", "") in ("Critical", "High"))
    meta = _make_table(doc, 2, [5.0, 12.0])
    for k, v in [
        ("Report Type", kind["title"]),
        ("Assessment", kind["assess"].capitalize()),
        ("Date of Issue", datetime.now(timezone.utc).strftime("%d %B %Y")),
        ("Total Findings", f"{total}  ({crit_high} Critical/High)"),
        ("Classification", "CONFIDENTIAL"),
    ]:
        row = meta.add_row()
        _set_cell_bg(row.cells[0], LIGHT_BLUE)
        _cell_text(row.cells[0], k, bold=True, font_color=NAVY, font_size=10)
        _cell_text(row.cells[1], v, font_size=10)

    doc.add_page_break()


def generate_docx_report(
    scan: Any,
    findings: list[Any],
    out_dir: str,
    workflow: dict[str, Any] | None = None,
) -> str:
    """Build a professional .docx report (template-free, VIGILOR brand).
    Adapts wording/sections for a web pentest vs a source-code review."""

    doc = _setup_base_document()
    _setup_header_footer(doc, scan)

    sorted_findings = _sort_findings(findings)

    _add_cover_v2(doc, scan, sorted_findings)
    _add_version_control(doc, scan)
    _add_disclaimer(doc)
    _add_executive_summary(doc, scan, sorted_findings)
    _add_findings_section(doc, scan, sorted_findings)
    _add_attack_workflow(doc, scan, workflow)
    _add_methodology(doc)
    _add_severity_classification(doc)

    os.makedirs(out_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename  = f"pentest_report_{timestamp}.docx"
    file_path = os.path.join(out_dir, filename)
    doc.save(file_path)
    return file_path
