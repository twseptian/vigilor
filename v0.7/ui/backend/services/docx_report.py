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

# ── Colour constants ──────────────────────────────────────────────────────────

NAVY       = "242852"
LIGHT_BLUE = "D3E5F6"
WHITE      = "FFFFFF"
BLACK      = "000000"

SEV_COLORS: dict[str, str] = {
    "Critical":      "000000",
    "High":          "FF0000",
    "Medium":        "FFC000",
    "Low":           "92D050",
    "Informational": "D9D9D9",
}
SEV_TEXT_COLORS: dict[str, str] = {
    "Critical":      "FFFFFF",
    "High":          "FFFFFF",
    "Medium":        "000000",
    "Low":           "000000",
    "Informational": "000000",
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


def _add_poc_paragraphs(doc: Document, poc_text: str) -> None:
    """
    Render PoC text: code/request blocks in monospace Courier,
    everything else in justified Normal text at 10pt.
    """
    if not poc_text or not poc_text.strip():
        para = doc.add_paragraph("No proof of concept recorded.", style="Normal")
        _para_justify(para)
        return

    # Split by lines and detect code blocks (indented or curl/HTTP sections)
    lines = poc_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]

        # Detect section headers (ALL CAPS or ends with newline-separated block)
        stripped = line.strip()

        # Blank line → small spacing
        if not stripped:
            doc.add_paragraph("", style="Normal")
            i += 1
            continue

        # Code-like line: starts with spaces/tab, curl, HTTP, <, {, [, $, or >, or ---
        is_code = (
            line.startswith("    ") or
            line.startswith("\t") or
            re.match(r'^(curl |GET |POST |PUT |DELETE |HTTP/|<|{|\[|\$|> |---)', stripped)
        )

        if is_code:
            # Collect contiguous code block
            code_lines = []
            while i < len(lines) and (
                not lines[i].strip() or
                lines[i].startswith("    ") or
                lines[i].startswith("\t") or
                re.match(r'^(curl |GET |POST |PUT |DELETE |HTTP/|<|{|\[|\$|> |---)', lines[i].strip())
            ):
                code_lines.append(lines[i])
                i += 1
            # Remove trailing blank lines from code block
            while code_lines and not code_lines[-1].strip():
                code_lines.pop()
            code_text = "\n".join(code_lines)
            para = doc.add_paragraph(style="Normal")
            run = para.add_run(code_text)
            run.font.name = "Courier New"
            run.font.size = Pt(9)
            # Light grey background hint via shading
            pPr = para._element.find(qn("w:pPr"))
            if pPr is None:
                pPr = OxmlElement("w:pPr")
                para._element.insert(0, pPr)
            shd = OxmlElement("w:shd")
            shd.set(qn("w:val"), "clear")
            shd.set(qn("w:color"), "auto")
            shd.set(qn("w:fill"), "F2F2F2")
            pPr.append(shd)
        else:
            # Normal justified paragraph
            para = doc.add_paragraph(style="Normal")
            run = para.add_run(stripped)
            run.font.size = Pt(10)
            _para_justify(para)
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
                          "Agentic Web Pentest", "Security Reviewer"])
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
        ref = f.finding_ref or f"WVAPT-{i}"
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

def _add_finding_section(doc: Document, idx: int, f: Any,
                          first: bool = False) -> None:
    # Page break before every finding except the first
    if not first:
        _add_para_break(doc)

    ref = f.finding_ref or f"WVAPT-{idx}"
    doc.add_heading(f"{ref}: {f.title}", level=2)
    doc.add_paragraph()

    sev = f.severity if f.severity in SEV_COLORS else "Informational"
    score = (f.cvss4_score if f.cvss4_score is not None
             else (f.cvss_score if f.cvss_score is not None else None))
    vector = f.cvss4_vector or f.cvss_vector or "N/A"
    score_str = f"{score:.1f}" if score is not None else "N/A"

    # CVSS table
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
    doc.add_paragraph()

    # Observations
    doc.add_heading("Observations", level=3)
    _add_justified_paragraph(doc, f.description or "See proof of concept below.")

    # Proof of Concepts
    doc.add_heading("Proof of Concepts", level=3)
    _add_poc_paragraphs(doc, f.proof_of_concept)

    doc.add_paragraph()

    # Affected Hosts/Services
    doc.add_heading("Affected Hosts/Services", level=3)
    doc.add_paragraph()
    aff_table = _make_table(doc, 4, [1.5, 6.0, 5.0, 6.0])
    _add_header_row(aff_table,
                    ["SN.", "Affected Host/Service", "Affected Parameter", "Status"])
    location_str = f.location or scan_target_fallback(f) or "See target URL"
    loc_parts = location_str.split("?", 1)
    host_part  = loc_parts[0]
    param_part = loc_parts[1] if len(loc_parts) > 1 else "N/A"
    arow = aff_table.add_row()
    _cell_text(arow.cells[0], "1", align=WD_ALIGN_PARAGRAPH.CENTER)
    _cell_text(arow.cells[1], host_part, font_size=9)
    _cell_text(arow.cells[2], param_part, font_size=9)
    _cell_text(arow.cells[3], f.status or "Open")
    doc.add_paragraph()

    # Implications
    p_impl = doc.add_paragraph(style="Normal")
    p_impl.add_run("Implications").bold = True
    _add_justified_paragraph(doc, f.implications or "Not specified.")

    # Recommendations
    p_rec = doc.add_paragraph(style="Normal")
    p_rec.add_run("Recommendations").bold = True
    _add_justified_paragraph(doc, f.recommendations or "Not specified.")

    # References
    p_ref = doc.add_paragraph(style="Normal")
    p_ref.add_run("References").bold = True
    ref_lines = _build_references(f)
    for ref_line in ref_lines:
        try:
            doc.add_paragraph(ref_line, style="List Paragraph")
        except Exception:
            doc.add_paragraph(f"\u2022 {ref_line}", style="Normal")

    # Remarks — management comments table
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
    doc.add_heading("Security Test Findings", level=1)
    doc.add_paragraph()

    if not findings:
        _add_justified_paragraph(doc,
            "No findings were identified during this assessment.")
        return

    sorted_findings = _sort_findings(findings)
    for i, f in enumerate(sorted_findings, 1):
        _add_finding_section(doc, i, f, first=(i == 1))

    _add_para_break(doc)


# ── Methodology ───────────────────────────────────────────────────────────────

def _add_methodology(doc: Document) -> None:
    doc.add_heading("Methodology (WVAPT)", level=1)
    _add_justified_paragraph(doc,
        "The Web Vulnerability Assessment and Penetration Testing (WVAPT) is based on "
        "OWASP Testing Guide and OWASP Top 10 (2021) standards."
    )
    _add_justified_paragraph(doc,
        "The methodology follows a five-step approach:"
    )
    steps = [
        ("Planning and Preparation",
         "Confirm project scope, objectives, involved parties, and timelines."),
        ("Information Gathering, Mapping, and Profiling",
         "Enumerate the web application, gather technology fingerprints, and identify the attack surface."),
        ("Execution and Testing",
         "Apply automated and manual techniques to test for OWASP Top 10 vulnerability classes "
         "including injection, broken access control, cryptographic failures, and more."),
        ("Analysis and Reporting",
         "Summarise and analyse all security weaknesses identified, providing detailed findings "
         "and remediation guidance."),
        ("Follow-up (Optional)",
         "Validate remediation effectiveness and confirm closure of findings."),
    ]
    for title, desc in steps:
        try:
            p = doc.add_paragraph(style="List Paragraph")
        except Exception:
            p = doc.add_paragraph()
        p.add_run(title).bold = True
        _add_justified_paragraph(doc, desc)

    doc.add_paragraph()
    _add_justified_paragraph(doc,
        "The OWASP Top 10 2021 vulnerability classes covered in this assessment include:"
    )
    owasp_items = [
        "A01:2021 – Broken Access Control",
        "A02:2021 – Cryptographic Failures",
        "A03:2021 – Injection",
        "A04:2021 – Insecure Design",
        "A05:2021 – Security Misconfiguration",
        "A06:2021 – Vulnerable and Outdated Components",
        "A07:2021 – Identification and Authentication Failures",
        "A08:2021 – Software and Data Integrity Failures",
        "A09:2021 – Security Logging and Monitoring Failures",
        "A10:2021 – Server-Side Request Forgery (SSRF)",
    ]
    for item in owasp_items:
        try:
            doc.add_paragraph(item, style="List Paragraph")
        except Exception:
            doc.add_paragraph(f"\u2022 {item}", style="Normal")
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

def generate_docx_report(scan: Any, findings: list[Any], out_dir: str) -> str:
    """Build a full WVAPT .docx report. Returns absolute path of saved file."""

    if not os.path.exists(TEMPLATE_PATH):
        raise RuntimeError(
            f"Report template not found at {TEMPLATE_PATH}. "
            "Ensure report_template.docx is present in /app/data/."
        )

    # Load template to extract styles AND cover page elements
    template_doc = Document(TEMPLATE_PATH)

    # Create output document using template (inherits styles, margins, header/footer)
    doc = Document(TEMPLATE_PATH)
    _clear_body(doc)

    _add_cover(doc, scan, template_doc)
    _add_version_control(doc, scan)
    _add_disclaimer(doc)
    _add_executive_summary(doc, scan, findings)
    _add_findings_section(doc, scan, findings)
    _add_methodology(doc)
    _add_severity_classification(doc)

    os.makedirs(out_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename  = f"pentest_report_{timestamp}.docx"
    file_path = os.path.join(out_dir, filename)
    doc.save(file_path)
    return file_path
