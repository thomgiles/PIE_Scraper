#!/usr/bin/env python3
"""
Build a lay-facing Word report from a PII Regex Output Comparison text report.

The report is designed for non-technical readers. It focuses on:
  1. people/person-signature counts in each dataset,
  2. extra person records seen in the exposed dataset but not the exfiltrated dataset,
  3. person records in the exfiltrated dataset but not the exposed dataset,
  4. differences by evidence type, and
  5. overall term conservation.

Example:
    python PII_regex/reports/build_report.py \
      --report PII_regex/reports/report.txt \
      --left-display "Exfiltrated-DWD" \
      --right-display "Exposed-BFS" \
      --output-docx pii_lay_summary_v1.0.docx \
      --overwrite

Python dependencies:
    pip install python-docx matplotlib pillow
"""

from __future__ import annotations

__version__ = "1.0-method-notes"

import argparse
import csv
import math
import re
import shutil
import tempfile
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any, Iterable

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Circle
from docx import Document
from docx.enum.section import WD_ORIENT
from docx.enum.table import WD_ALIGN_VERTICAL, WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Inches, Pt, RGBColor


UON_BLUE = "10263B"
UON_BLUE_2 = "1D3D5C"
UON_LIGHT_BLUE = "E7EEF6"
UON_TEAL = "007C89"
UON_GREEN = "5C8727"
UON_GOLD = "F6BE00"
UON_RED = "B00020"
UON_GREY = "5B6770"
UON_PALE = "F5F7FA"
BLACK = "17212B"
WHITE = "FFFFFF"


@dataclass
class ConservationMetrics:
    left_unique: int = 0
    right_unique: int = 0
    shared: int = 0
    left_only: int = 0
    right_only: int = 0
    left_conserved_pct: float = 0.0
    right_conserved_pct: float = 0.0
    jaccard_pct: float = 0.0
    left_rows: int | None = None
    right_rows: int | None = None


@dataclass
class RowConservationMetrics:
    left_rows: int = 0
    right_rows: int = 0
    left_matched_rows: int = 0
    right_matched_rows: int = 0
    left_matched_pct: float = 0.0
    right_matched_pct: float = 0.0


@dataclass
class ParsedReport:
    title: str
    left_dataset: str
    right_dataset: str
    left_folder: str
    right_folder: str
    person_table: str
    definitions: str
    evidence_terms: ConservationMetrics
    evidence_by_type: list[dict[str, Any]]
    cluster_rows: RowConservationMetrics
    cluster_terms: ConservationMetrics
    known_universe: int
    known_matrix: dict[str, int]
    known_groups: list[dict[str, Any]]
    unknown_rows: RowConservationMetrics
    unknown_terms: ConservationMetrics


def parse_int(value: str) -> int:
    value = value.strip().replace(",", "")
    if value == "":
        return 0
    return int(float(value))


def parse_pct(value: str) -> float:
    value = value.strip().replace("%", "").replace(",", "")
    if value.lower() in {"", "n/a", "na", "not available", "-", "--"}:
        return math.nan
    return float(value)


def split_sections(text: str) -> tuple[str, dict[str, str]]:
    lines = text.splitlines()
    title = lines[0].strip() if lines else "PII Regex Output Comparison"
    sections: dict[str, str] = {}
    current_name: str | None = None
    current_lines: list[str] = []

    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        next_line = lines[i + 1].strip() if i + 1 < len(lines) else ""
        if line.strip() and re.fullmatch(r"[-=]{3,}", next_line):
            if current_name is not None:
                sections[current_name] = "\n".join(current_lines).strip("\n")
            current_name = line.strip()
            current_lines = []
            i += 2
            continue
        if current_name is not None:
            current_lines.append(line)
        i += 1

    if current_name is not None:
        sections[current_name] = "\n".join(current_lines).strip("\n")

    return title, sections


def parse_metadata(text: str) -> dict[str, str]:
    metadata = {
        "Left dataset": "Left dataset",
        "Left folder": "",
        "Right dataset": "Right dataset",
        "Right folder": "",
        "Person table": "",
    }
    for line in text.splitlines():
        match = re.match(r"^(Left dataset|Left folder|Right dataset|Right folder|Person table):\s*(.*)$", line.strip())
        if match:
            metadata[match.group(1)] = match.group(2).strip()
    return metadata


def parse_conservation(section_text: str, left_label: str, right_label: str) -> ConservationMetrics:
    metrics = ConservationMetrics()
    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith(f"{left_label} unique terms:"):
            metrics.left_unique = parse_int(line.split(":", 1)[1])
        elif line.startswith(f"{right_label} unique terms:"):
            metrics.right_unique = parse_int(line.split(":", 1)[1])
        elif line.startswith("Shared terms:"):
            metrics.shared = parse_int(line.split(":", 1)[1])
        elif line.startswith(f"{left_label}-only terms:"):
            metrics.left_only = parse_int(line.split(":", 1)[1])
        elif line.startswith(f"{right_label}-only terms:"):
            metrics.right_only = parse_int(line.split(":", 1)[1])
        elif line.startswith(f"{left_label} conserved in {right_label}:"):
            metrics.left_conserved_pct = parse_pct(line.split(":", 1)[1])
        elif line.startswith(f"{right_label} conserved in {left_label}:"):
            metrics.right_conserved_pct = parse_pct(line.split(":", 1)[1])
        elif line.startswith("Jaccard overlap:"):
            metrics.jaccard_pct = parse_pct(line.split(":", 1)[1])
        elif line.startswith(f"{left_label} atomic evidence rows scanned into comparison:"):
            metrics.left_rows = parse_int(line.split(":", 1)[1])
        elif line.startswith(f"{right_label} atomic evidence rows scanned into comparison:"):
            metrics.right_rows = parse_int(line.split(":", 1)[1])

    return metrics


def parse_evidence_by_type(section_text: str, left_label: str, right_label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in section_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("evidence_type"):
            continue
        parts = re.split(r"\s{2,}", stripped)
        if len(parts) != 6:
            continue
        left_count = parse_int(parts[1])
        right_count = parse_int(parts[2])
        shared = parse_int(parts[3])
        rows.append(
            {
                "evidence_type": parts[0],
                "left_count": left_count,
                "right_count": right_count,
                "shared_count": shared,
                "left_only": max(left_count - shared, 0),
                "right_only": max(right_count - shared, 0),
                "delta_right_minus_left": right_count - left_count,
                "left_conserved_pct": parse_pct(parts[4]),
                "right_conserved_pct": parse_pct(parts[5]),
            }
        )
    return rows


def parse_row_conservation(section_text: str, left_label: str, right_label: str, row_word: str, term_word: str) -> RowConservationMetrics:
    metrics = RowConservationMetrics()
    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if line.startswith(f"{left_label} {row_word}:"):
            metrics.left_rows = parse_int(line.split(":", 1)[1])
        elif line.startswith(f"{right_label} {row_word}:"):
            metrics.right_rows = parse_int(line.split(":", 1)[1])
        else:
            compact_row_word = row_word.removesuffix(" rows") + "s"
            left_matched_prefixes = (
                f"{left_label} {row_word} with at least one {term_word} seen in {right_label}:",
                f"{left_label} {compact_row_word} with at least one {term_word} seen in {right_label}:",
            )
            right_matched_prefixes = (
                f"{right_label} {row_word} with at least one {term_word} seen in {left_label}:",
                f"{right_label} {compact_row_word} with at least one {term_word} seen in {left_label}:",
            )

            if line.startswith(left_matched_prefixes):
                match = re.search(r":\s*([\d,]+)\s*\(([\d.]+)%\)", line)
                if match:
                    metrics.left_matched_rows = parse_int(match.group(1))
                    metrics.left_matched_pct = parse_pct(match.group(2))
            elif line.startswith(right_matched_prefixes):
                match = re.search(r":\s*([\d,]+)\s*\(([\d.]+)%\)", line)
                if match:
                    metrics.right_matched_rows = parse_int(match.group(1))
                    metrics.right_matched_pct = parse_pct(match.group(2))
    return metrics


def parse_known_matrix(section_text: str, left_label: str, right_label: str) -> tuple[int, dict[str, int]]:
    universe = 0
    matrix = {
        "both_in": 0,
        "left_only": 0,
        "right_only": 0,
        "both_out": 0,
    }

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if line.startswith("Person-table universe:"):
            universe = parse_int(line.split(":", 1)[1])
            continue
        match = re.match(rf"^{re.escape(left_label)}\s+in\s+([\d,]+)\s+([\d,]+)$", line)
        if match:
            matrix["both_in"] = parse_int(match.group(1))
            matrix["left_only"] = parse_int(match.group(2))
            continue
        match = re.match(rf"^{re.escape(left_label)}\s+out\s+([\d,]+)\s+([\d,]+)$", line)
        if match:
            matrix["right_only"] = parse_int(match.group(1))
            matrix["both_out"] = parse_int(match.group(2))
            continue
    return universe, matrix


def parse_known_groups(section_text: str) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    for raw_line in section_text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("group"):
            continue
        match = re.match(r"^(.*?)\s+([\d,]+)\s+([\d.]+%)\s+(\S+)$", stripped)
        if not match:
            continue
        groups.append(
            {
                "group": match.group(1).strip(),
                "count": parse_int(match.group(2)),
                "person_table_pct": parse_pct(match.group(3)),
                "detail_file": match.group(4).strip(),
            }
        )
    return groups


def parse_report(path: Path) -> ParsedReport:
    text = path.read_text(encoding="utf-8-sig")
    title, sections = split_sections(text)
    metadata = parse_metadata(text)

    left_label = metadata["Left dataset"]
    right_label = metadata["Right dataset"]

    return ParsedReport(
        title=title,
        left_dataset=left_label,
        right_dataset=right_label,
        left_folder=metadata["Left folder"],
        right_folder=metadata["Right folder"],
        person_table=metadata["Person table"],
        definitions=sections.get("Definitions", ""),
        evidence_terms=parse_conservation(sections.get("Evidence Term Conservation", ""), left_label, right_label),
        evidence_by_type=parse_evidence_by_type(sections.get("Evidence Conservation By Type", ""), left_label, right_label),
        cluster_rows=parse_row_conservation(
            sections.get("Person Cluster Conservation", ""),
            left_label,
            right_label,
            row_word="cluster rows",
            term_word="identity term",
        ),
        cluster_terms=parse_conservation(sections.get("Person Cluster Identity Term Conservation", ""), left_label, right_label),
        known_universe=parse_known_matrix(sections.get("Known Person Matrix", ""), left_label, right_label)[0],
        known_matrix=parse_known_matrix(sections.get("Known Person Matrix", ""), left_label, right_label)[1],
        known_groups=parse_known_groups(sections.get("Known Person Group Counts", "")),
        unknown_rows=parse_row_conservation(
            sections.get("Unknown Person Comparison", ""),
            left_label,
            right_label,
            row_word="unknown rows",
            term_word="signature term",
        ),
        unknown_terms=parse_conservation(sections.get("Unknown Person Signature Term Conservation", ""), left_label, right_label),
    )


def fmt_n(value: Any) -> str:
    if value is None or value == "":
        return ""
    try:
        if isinstance(value, float) and math.isnan(value):
            return ""
        return f"{int(round(float(value))):,}"
    except Exception:
        return str(value)


def fmt_pct(value: Any) -> str:
    if value is None or value == "":
        return "n/a"
    try:
        if isinstance(value, float) and math.isnan(value):
            return "n/a"
        return f"{float(value):.2f}%"
    except Exception:
        return str(value)


def shade_cell(cell, fill: str, color: str | None = None, bold: bool = False) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), fill)
    tc_pr.append(shd)
    for paragraph in cell.paragraphs:
        for run in paragraph.runs:
            if color:
                run.font.color.rgb = RGBColor.from_string(color)
            run.bold = bold


def set_cell_text(cell, text: str, bold: bool = False, color: str | None = None, size: float | None = None) -> None:
    cell.text = ""
    p = cell.paragraphs[0]
    run = p.add_run(str(text))
    run.bold = bold
    if color:
        run.font.color.rgb = RGBColor.from_string(color)
    if size:
        run.font.size = Pt(size)
    cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER


def set_table_borders(table) -> None:
    tbl = table._tbl
    tbl_pr = tbl.tblPr
    borders = tbl_pr.first_child_found_in("w:tblBorders")
    if borders is None:
        borders = OxmlElement("w:tblBorders")
        tbl_pr.append(borders)
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        tag = f"w:{edge}"
        element = borders.find(qn(tag))
        if element is None:
            element = OxmlElement(tag)
            borders.append(element)
        element.set(qn("w:val"), "single")
        element.set(qn("w:sz"), "4")
        element.set(qn("w:space"), "0")
        element.set(qn("w:color"), "D8E1EA")


def add_table(document: Document, headers: list[str], rows: list[list[str]], font_size: float = 8.5) -> None:
    table = document.add_table(rows=1, cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = "Table Grid"
    header_cells = table.rows[0].cells
    for i, h in enumerate(headers):
        set_cell_text(header_cells[i], h, bold=True, color=WHITE, size=font_size)
        shade_cell(header_cells[i], UON_BLUE, WHITE, bold=True)

    tr_pr = table.rows[0]._tr.get_or_add_trPr()
    tbl_header = OxmlElement("w:tblHeader")
    tbl_header.set(qn("w:val"), "true")
    tr_pr.append(tbl_header)

    for r_idx, row in enumerate(rows):
        cells = table.add_row().cells
        for c_idx, value in enumerate(row):
            set_cell_text(cells[c_idx], value, size=font_size)
            if r_idx % 2 == 0:
                shade_cell(cells[c_idx], UON_PALE)
    set_table_borders(table)


def add_caption(document: Document, text: str) -> None:
    p = document.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = p.add_run(text)
    r.italic = True
    r.font.size = Pt(9)
    r.font.color.rgb = RGBColor.from_string(UON_GREY)


def add_callout(document: Document, text: str) -> None:
    table = document.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = table.cell(0, 0)
    set_cell_text(cell, text, bold=False, color=BLACK, size=10.5)
    shade_cell(cell, UON_LIGHT_BLUE)
    set_table_borders(table)


def add_warning_callout(document: Document, title: str, body: str) -> None:
    table = document.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = table.cell(0, 0)
    cell.text = ""
    shade_cell(cell, "FFF4CC")
    p = cell.paragraphs[0]
    r = p.add_run(title)
    r.bold = True
    r.font.color.rgb = RGBColor.from_string(UON_RED)
    r.font.size = Pt(10.5)
    p2 = cell.add_paragraph()
    r2 = p2.add_run(body)
    r2.font.color.rgb = RGBColor.from_string(BLACK)
    r2.font.size = Pt(10.0)
    set_table_borders(table)


def set_document_styles(document: Document) -> None:
    styles = document.styles
    normal = styles["Normal"]
    normal.font.name = "Arial"
    normal.font.size = Pt(10.5)
    normal.font.color.rgb = RGBColor.from_string(BLACK)

    for style_name, size, colour in [
        ("Title", 22, UON_BLUE),
        ("Heading 1", 16, UON_BLUE),
        ("Heading 2", 13, UON_BLUE_2),
        ("Heading 3", 11.5, UON_BLUE_2),
    ]:
        style = styles[style_name]
        style.font.name = "Arial"
        style.font.size = Pt(size)
        style.font.color.rgb = RGBColor.from_string(colour)
        style.font.bold = True


def add_header_footer(document: Document, title: str) -> None:
    section = document.sections[0]
    header = section.header
    header_p = header.paragraphs[0]
    header_p.text = ""
    header_p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    run = header_p.add_run("University of Nottingham | Digital Research Service")
    run.font.size = Pt(8)
    run.font.color.rgb = RGBColor.from_string(UON_BLUE)

    footer = section.footer
    footer_p = footer.paragraphs[0]
    footer_p.text = ""
    footer_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = footer_p.add_run(title)
    run.font.size = Pt(8)
    run.font.color.rgb = RGBColor.from_string(UON_GREY)


def term_conservation_rows(report: ParsedReport) -> list[dict[str, Any]]:
    return [
        {
            "comparison": "Evidence terms",
            "left_unique": report.evidence_terms.left_unique,
            "right_unique": report.evidence_terms.right_unique,
            "shared": report.evidence_terms.shared,
            "left_only": report.evidence_terms.left_only,
            "right_only": report.evidence_terms.right_only,
            "left_conserved_pct": report.evidence_terms.left_conserved_pct,
            "right_conserved_pct": report.evidence_terms.right_conserved_pct,
            "jaccard_pct": report.evidence_terms.jaccard_pct,
        },
        {
            "comparison": "Cluster identity terms",
            "left_unique": report.cluster_terms.left_unique,
            "right_unique": report.cluster_terms.right_unique,
            "shared": report.cluster_terms.shared,
            "left_only": report.cluster_terms.left_only,
            "right_only": report.cluster_terms.right_only,
            "left_conserved_pct": report.cluster_terms.left_conserved_pct,
            "right_conserved_pct": report.cluster_terms.right_conserved_pct,
            "jaccard_pct": report.cluster_terms.jaccard_pct,
        },
        {
            "comparison": "Unknown signature terms",
            "left_unique": report.unknown_terms.left_unique,
            "right_unique": report.unknown_terms.right_unique,
            "shared": report.unknown_terms.shared,
            "left_only": report.unknown_terms.left_only,
            "right_only": report.unknown_terms.right_only,
            "left_conserved_pct": report.unknown_terms.left_conserved_pct,
            "right_conserved_pct": report.unknown_terms.right_conserved_pct,
            "jaccard_pct": report.unknown_terms.jaccard_pct,
        },
    ]


def people_counts(report: ParsedReport) -> dict[str, dict[str, int]]:
    known = {
        "both": report.known_matrix["both_in"],
        "left_only": report.known_matrix["left_only"],
        "right_only": report.known_matrix["right_only"],
    }
    known["left_total"] = known["both"] + known["left_only"]
    known["right_total"] = known["both"] + known["right_only"]

    unknown_both = min(report.unknown_rows.left_matched_rows, report.unknown_rows.right_matched_rows)
    unknown = {
        "both": unknown_both,
        "left_only": max(report.unknown_rows.left_rows - report.unknown_rows.left_matched_rows, 0),
        "right_only": max(report.unknown_rows.right_rows - report.unknown_rows.right_matched_rows, 0),
        "left_total": report.unknown_rows.left_rows,
        "right_total": report.unknown_rows.right_rows,
    }
    return {"known": known, "unknown": unknown}


def evidence_interpretation(row: dict[str, Any], left_name: str, right_name: str) -> str:
    left_only = row["left_only"]
    right_only = row["right_only"]
    if left_only == 0 and right_only == 0:
        return "No difference in distinct terms."
    if left_only == 0 and right_only > 0:
        return f"{right_only:,} term(s) appear only in {right_name}."
    if right_only == 0 and left_only > 0:
        return f"{left_only:,} term(s) appear only in {left_name}."
    if right_only > left_only:
        return f"More additional terms appear only in {right_name}."
    if left_only > right_only:
        return f"More additional terms appear only in {left_name}."
    return "Both datasets contain different dataset-specific terms."


def make_venn(path: Path, title: str, left_name: str, right_name: str, left_only: int, both: int, right_only: int) -> None:
    plt.rcParams["font.family"] = "DejaVu Sans"
    fig, ax = plt.subplots(figsize=(7.3, 3.9), dpi=220)
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5.2)
    ax.axis("off")

    left_circle = Circle((4.1, 2.55), 1.85, facecolor="#10263B", edgecolor="#10263B", alpha=0.20, lw=2.5)
    right_circle = Circle((5.9, 2.55), 1.85, facecolor="#007C89", edgecolor="#007C89", alpha=0.20, lw=2.5)
    ax.add_patch(left_circle)
    ax.add_patch(right_circle)

    ax.text(5.0, 4.95, title, ha="center", va="top", fontsize=14, fontweight="bold", color="#10263B")
    ax.text(3.25, 4.36, left_name, ha="center", va="center", fontsize=10.5, fontweight="bold", color="#10263B")
    ax.text(6.75, 4.36, right_name, ha="center", va="center", fontsize=10.5, fontweight="bold", color="#007C89")

    ax.text(3.10, 2.62, f"{left_only:,}", ha="center", va="center", fontsize=18, fontweight="bold", color="#10263B")
    ax.text(3.10, 2.18, f"only in\n{left_name}", ha="center", va="center", fontsize=8.7, color="#10263B")

    ax.text(5.00, 2.62, f"{both:,}", ha="center", va="center", fontsize=19, fontweight="bold", color="#5C8727")
    ax.text(5.00, 2.18, "in both", ha="center", va="center", fontsize=9, color="#5C8727")

    ax.text(6.90, 2.62, f"{right_only:,}", ha="center", va="center", fontsize=18, fontweight="bold", color="#007C89")
    ax.text(6.90, 2.18, f"only in\n{right_name}", ha="center", va="center", fontsize=8.7, color="#007C89")

    ax.text(5.0, 0.35, "Diagram is not area-scaled; counts are the authoritative values.", ha="center", va="center", fontsize=8, color="#5B6770")
    fig.tight_layout(pad=0.4)
    fig.savefig(path, bbox_inches="tight", pad_inches=0.02, facecolor="white")
    plt.close(fig)


def draw_venn_panel(ax, title: str, left_name: str, right_name: str, left_only: int, both: int, right_only: int) -> None:
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 5.2)
    ax.axis("off")

    left_circle = Circle((4.05, 2.45), 1.78, facecolor="#10263B", edgecolor="#10263B", alpha=0.20, lw=2.1)
    right_circle = Circle((5.95, 2.45), 1.78, facecolor="#007C89", edgecolor="#007C89", alpha=0.20, lw=2.1)
    ax.add_patch(left_circle)
    ax.add_patch(right_circle)

    ax.text(5.0, 5.05, title, ha="center", va="top", fontsize=12, fontweight="bold", color="#10263B")
    ax.text(3.10, 4.25, left_name, ha="center", va="center", fontsize=7.4, fontweight="bold", color="#10263B")
    ax.text(6.90, 4.25, right_name, ha="center", va="center", fontsize=7.4, fontweight="bold", color="#007C89")

    ax.text(3.05, 2.60, f"{left_only:,}", ha="center", va="center", fontsize=13.5, fontweight="bold", color="#10263B")
    ax.text(3.05, 2.13, f"only in\n{left_name}", ha="center", va="center", fontsize=6.6, color="#10263B")

    ax.text(5.00, 2.60, f"{both:,}", ha="center", va="center", fontsize=14.5, fontweight="bold", color="#5C8727")
    ax.text(5.00, 2.13, "in both", ha="center", va="center", fontsize=7.3, color="#5C8727")

    ax.text(6.95, 2.60, f"{right_only:,}", ha="center", va="center", fontsize=13.5, fontweight="bold", color="#007C89")
    ax.text(6.95, 2.13, f"only in\n{right_name}", ha="center", va="center", fontsize=6.6, color="#007C89")


def make_venn_pair(path: Path, left_name: str, right_name: str, known: dict[str, int], unknown: dict[str, int]) -> None:
    plt.rcParams["font.family"] = "DejaVu Sans"
    fig, axes = plt.subplots(1, 2, figsize=(10.8, 3.1), dpi=240)
    draw_venn_panel(axes[0], "Known people", left_name, right_name, known["left_only"], known["both"], known["right_only"])
    draw_venn_panel(axes[1], "Unknown person signatures", left_name, right_name, unknown["left_only"], unknown["both"], unknown["right_only"])
    fig.text(0.5, 0.035, "Diagrams are not area-scaled; printed counts are the authoritative values.", ha="center", va="bottom", fontsize=15.0, color="#5B6770")
    fig.tight_layout(rect=(0.01, 0.12, 0.99, 0.99), pad=0.08, w_pad=0.28)
    fig.savefig(path, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def make_term_conservation_bar(path: Path, rows: list[dict[str, Any]], left_name: str, right_name: str) -> None:
    plt.rcParams["font.family"] = "DejaVu Sans"
    labels = [r["comparison"] for r in rows]
    y = list(range(len(labels)))
    left_vals = [r["left_conserved_pct"] for r in rows]
    right_vals = [r["right_conserved_pct"] for r in rows]

    fig, ax = plt.subplots(figsize=(7.3, 3.2), dpi=220)
    height = 0.34
    ax.barh([v - height / 2 for v in y], left_vals, height=height, label=f"{left_name} -> {right_name}", color="#10263B")
    ax.barh([v + height / 2 for v in y], right_vals, height=height, label=f"{right_name} -> {left_name}", color="#007C89")
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=9.5)
    ax.set_xlim(0, 100)
    ax.set_xlabel("Conserved terms (%)")
    ax.set_title("Term conservation", fontsize=14, fontweight="bold", color="#10263B")
    ax.grid(axis="x", alpha=0.25)
    ax.spines[["top", "right", "left"]].set_visible(False)
    
    # Exact percentages are shown in the table beneath the chart.
    # Keeping labels out of the plot avoids clipping at 100%.
    fig.tight_layout(pad=1.1)
    fig.savefig(path, bbox_inches="tight", facecolor="white")
    plt.close(fig)


def add_title_block(document: Document, title: str, subtitle: str) -> None:
    table = document.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = table.cell(0, 0)
    shade_cell(cell, UON_BLUE)
    p = cell.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.LEFT
    r = p.add_run(title)
    r.bold = True
    r.font.size = Pt(19)
    r.font.color.rgb = RGBColor.from_string(WHITE)
    p2 = cell.add_paragraph()
    r2 = p2.add_run(subtitle)
    r2.font.size = Pt(10.5)
    r2.font.color.rgb = RGBColor.from_string(WHITE)
    document.add_paragraph()


def build_docx(
    report: ParsedReport,
    output_docx: Path,
    source_report: Path,
    left_name: str,
    right_name: str,
    title: str,
    keep_figures: bool = False,
) -> Path:
    counts = people_counts(report)
    known = counts["known"]
    unknown = counts["unknown"]
    total_left = known["left_total"] + unknown["left_total"]
    total_right = known["right_total"] + unknown["right_total"]
    extra_right = known["right_only"] + unknown["right_only"]
    extra_left = known["left_only"] + unknown["left_only"]

    if keep_figures:
        fig_dir = output_docx.with_suffix("").parent / f"{output_docx.stem}_figures"
        fig_dir.mkdir(parents=True, exist_ok=True)
        temp_context = None
    else:
        temp_context = tempfile.TemporaryDirectory()
        fig_dir = Path(temp_context.name)

    people_venn_pair = fig_dir / "people_and_signature_venn_pair.png"
    term_bar = fig_dir / "term_conservation_bar.png"
    make_venn_pair(people_venn_pair, left_name, right_name, known, unknown)
    term_rows = term_conservation_rows(report)
    make_term_conservation_bar(term_bar, term_rows, left_name, right_name)

    document = Document()
    set_document_styles(document)

    section = document.sections[0]
    section.top_margin = Cm(1.6)
    section.bottom_margin = Cm(1.5)
    section.left_margin = Cm(1.6)
    section.right_margin = Cm(1.6)
    add_header_footer(document, title)

    subtitle = f"{left_name} compared with {right_name}"
    add_title_block(document, title, subtitle)

    document.add_heading("Plain English summary", level=1)
    add_table(
        document,
        ["Question", "Answer"],
        [
            [f"How many person-level records are in {left_name}?", fmt_n(total_left)],
            ["Known people in that total", fmt_n(known["left_total"])],
            ["Unknown person-signature records in that total", fmt_n(unknown["left_total"])],
            [f"How many additional records appear only in {right_name}?", f"{fmt_n(extra_right)} ({fmt_n(known['right_only'])} known; {fmt_n(unknown['right_only'])} unknown signatures)"],
            [f"How many records appear only in {left_name}?", f"{fmt_n(extra_left)} ({fmt_n(known['left_only'])} known; {fmt_n(unknown['left_only'])} unknown signatures)"],
        ],
        font_size=9.2,
    )

    add_warning_callout(
        document,
        "Important reporting caveat",
        "The known-person count is the stronger reporting figure because it is matched to the supplied person table. Unknown person-signature records are inferred clusters, not confirmed named people. They are useful for triage and follow-up review, but should not be used as the reportable number of affected individuals."
    )

    document.add_page_break()

    document.add_heading("Methods", level=1)
    document.add_heading("How it works", level=2)
    document.add_paragraph(
        "The scanner is evidence-led. It does not start by deciding who a person is. It extracts text from files, finds individual evidence terms such as names, emails, dates of birth, identifiers and document numbers, then groups terms that occur together in the same meaningful unit, such as one table row or one structured record."
    )
    document.add_paragraph(
        "Those grouped terms are then clustered using identity anchors. A cluster may be linked to the supplied known-person table, in which case it is treated as a known-person finding. If it cannot be linked to the known-person table, it is treated as an unknown person-signature record."
    )
    document.add_paragraph(
        "The comparison does not rescan the original source files. It compares the outputs from two completed scanner runs. For term conservation, the comparison uses normalised evidence terms, so the same value can be counted as conserved even when it came from a different file path, row number or source context."
    )

    document.add_heading("Limitations and reporting use", level=2)
    limitation_intro = document.add_paragraph()
    limitation_intro.add_run("This report supports triage and review. It is not a definitive legal or forensic determination. ").bold = True
    limitation_intro.add_run(
        "The outputs depend on source-data quality, text extraction, OCR if used, table and structured-record boundary inference, regex rule coverage, clustering assumptions, repeated or common identifiers, incomplete records and the quality of the supplied known-person table."
    )
    for note in [
        "Known-person results are matched to the supplied reference table and are therefore the most suitable basis for reporting, subject to validation of material findings.",
        "Unknown person-signature records are higher-risk for interpretation. One real person may appear as multiple unknown signatures, and several people may be collapsed if they share weak or repeated identifiers.",
        "Unknown counts should be treated as a triage signal or possible additional exposure, not as a count of reportable affected individuals.",
        "Evidence counts and term-conservation values describe detected terms, not necessarily separate people."
    ]:
        document.add_paragraph(note, style="List Bullet")

    document.add_heading("What was compared", level=2)
    add_table(
        document,
        ["Role in this report", "Dataset label from source report"],
        [
            [left_name, report.left_dataset],
            [right_name, report.right_dataset],
            ["Known person reference table", "Person table supplied to the comparison"],
        ],
        font_size=8.8,
    )

    document.add_page_break()

    document.add_heading("1. People and person-signature records", level=1)
    p = document.add_paragraph(
        "This section answers the main operational question: which people or person-signature records appear in one dataset, both datasets, or only the other dataset."
    )

    add_table(
        document,
        ["Group", f"In {left_name}", f"Also in {right_name}", f"Only in {left_name}", f"Only in {right_name}"],
        [
            ["Known people", fmt_n(known["left_total"]), fmt_n(known["both"]), fmt_n(known["left_only"]), fmt_n(known["right_only"])],
            ["Unknown person signatures", fmt_n(unknown["left_total"]), fmt_n(unknown["both"]), fmt_n(unknown["left_only"]), fmt_n(unknown["right_only"])],
            ["Combined person-level total", fmt_n(total_left), fmt_n(known["both"] + unknown["both"]), fmt_n(extra_left), fmt_n(extra_right)],
        ],
        font_size=8.5,
    )

    document.add_paragraph()
    document.add_picture(str(people_venn_pair), width=Inches(7.1))
    add_caption(document, f"Known people and unknown person-signature records found in {left_name}, {right_name}, or both.")
    add_warning_callout(
        document,
        "Do not report unknown signatures as people",
        "The unknown-signature Venn diagram shows inferred person-like clusters that were not matched to the known-person table. It helps identify where further review may be needed, but the counts should not be used as a definitive number of additional affected individuals."
    )

    document.add_page_break()

    document.add_heading("2. Evidence-type differences", level=1)
    document.add_paragraph(
        "Each evidence type is a category of detected information, such as names, passport numbers, phone numbers or institutional email addresses. The table shows where the datasets differ."
    )
    add_warning_callout(
        document,
        "Evidence detection is rule-based",
        "Evidence detection is based on regular expression matching, table-header interpretation, structured-record parsing and value normalisation. These rules are designed to find likely personal-data evidence and support review, but they are not perfect. Some values may be missed if the source text is poorly extracted, the file structure is unusual, OCR is incomplete, or the relevant pattern is not covered by the rules. Some values may also be over-detected where text looks like a personal-data value but is not genuinely linked to an individual."
    )

    evidence_rows = sorted(report.evidence_by_type, key=lambda r: (abs(r["delta_right_minus_left"]), r["right_only"] + r["left_only"]), reverse=True)
    def evidence_difference_label(row: dict[str, Any]) -> str:
        delta = row["delta_right_minus_left"]
        if delta > 0:
            return f"+{delta:,} in {right_name}"
        if delta < 0:
            return f"+{abs(delta):,} in {left_name}"
        return "No difference"

    add_table(
        document,
        [
            "Evidence type",
            left_name,
            right_name,
            "Shared",
            f"Only {left_name}",
            f"Only {right_name}",
            "Difference",
        ],
        [
            [
                row["evidence_type"],
                fmt_n(row["left_count"]),
                fmt_n(row["right_count"]),
                fmt_n(row["shared_count"]),
                fmt_n(row["left_only"]),
                fmt_n(row["right_only"]),
                evidence_difference_label(row),
            ]
            for row in evidence_rows
        ],
        font_size=7.9,
    )


    most_right = max(evidence_rows, key=lambda r: r["right_only"] if r["right_only"] is not None else 0) if evidence_rows else None
    most_left = max(evidence_rows, key=lambda r: r["left_only"] if r["left_only"] is not None else 0) if evidence_rows else None
    evidence_note = document.add_paragraph()
    evidence_note.add_run("How to read this table: ").bold = True
    evidence_note.add_run(
        f"the shared column shows distinct evidence values seen in both datasets. The 'only' columns show values detected in one dataset but not the other. These are evidence terms, not people; for example, one person can contribute several terms and the same term can appear in several files."
    )
    if most_right and most_right["right_only"] > 0:
        document.add_paragraph(
            f"The largest {right_name}-only difference is {most_right['evidence_type']} ({fmt_n(most_right['right_only'])} distinct term(s) only in {right_name}).",
            style="List Bullet",
        )
    if most_left and most_left["left_only"] > 0:
        document.add_paragraph(
            f"The largest {left_name}-only difference is {most_left['evidence_type']} ({fmt_n(most_left['left_only'])} distinct term(s) only in {left_name}).",
            style="List Bullet",
        )

    document.add_page_break()

    document.add_heading("3. Term conservation", level=1)
    document.add_paragraph(
        "Term conservation shows how much of the information detected in one dataset can also be found in the other. A higher percentage means the datasets are more similar for that comparison level."
    )
    document.add_paragraph(
        "Evidence terms are the distinct normalised values detected by the scanner, grouped as evidence_type=value. This view ignores file path, row number and context so that the same detected value can be compared across the two scanner outputs.",
        style="List Bullet",
    )
    document.add_paragraph(
        "Cluster identity terms are the identity values used, or available, for merging linked evidence into inferred person clusters. These include configured identity anchors and fallbacks used for singleton-like clusters.",
        style="List Bullet",
    )
    document.add_paragraph(
        "Unknown signature terms are the comparison keys for inferred person-signature records that did not match the known-person table. They are useful for assessing overlap between unknown-signature outputs, but they should not be interpreted as confirmed individuals.",
        style="List Bullet",
    )
    document.add_picture(str(term_bar), width=Inches(6.6))
    add_caption(document, f"Percentage of terms conserved in the other dataset. Dark blue shows {left_name} to {right_name}; teal shows {right_name} to {left_name}.")

    add_table(
        document,
        [
            "Comparison",
            f"{left_name} unique",
            f"{right_name} unique",
            "Shared",
            f"Only in {left_name}",
            f"Only in {right_name}",
            "Jaccard overlap",
        ],
        [
            [
                row["comparison"],
                fmt_n(row["left_unique"]),
                fmt_n(row["right_unique"]),
                fmt_n(row["shared"]),
                fmt_n(row["left_only"]),
                fmt_n(row["right_only"]),
                fmt_pct(row["jaccard_pct"]),
            ]
            for row in term_rows
        ],
        font_size=8.0,
    )


    main_term = term_rows[0] if term_rows else None
    if main_term:
        term_note = document.add_paragraph()
        term_note.add_run("How to read this section: ").bold = True
        term_note.add_run(
            f"the bars show the percentage of terms from one dataset that are also present in the other. The table gives the exact numbers. Jaccard overlap is stricter: it compares the shared terms with all distinct terms found across both datasets."
        )
        document.add_paragraph(
            f"For evidence terms, {fmt_pct(main_term['left_conserved_pct'])} of terms from {left_name} were also seen in {right_name}, and {fmt_pct(main_term['right_conserved_pct'])} of terms from {right_name} were also seen in {left_name}.",
            style="List Bullet",
        )
        document.add_paragraph(
            "High conservation means the two outputs contain very similar detected values. It does not prove that the original files were identical, and it does not by itself identify affected people.",
            style="List Bullet",
        )

    document.add_page_break()

    document.add_heading("Notes for interpretation", level=1)
    notes = [
        f"'{left_name} only' and '{right_name} only' mean records or terms found in one comparison output but not observed in the other output. It should not be read as proof that the source system never held that information.",
        "The strongest figures in the report are the known-person counts, because they are linked back to the supplied person table. Even these should be validated against the supporting detail files before formal reporting.",
        "Unknown person-signature counts are for triage only and should not be used as reportable counts of affected individuals.",
        "An unknown signature is an inferred person-like cluster. One real person can generate more than one signature if evidence is fragmented, and more than one real person can be collapsed if weak or repeated identifiers are shared.",
        "Because the unknown group is inferred rather than confirmed, it is best interpreted as a possible pool for further review, not as a confirmed number of additional people.",
        "Evidence-type rows count distinct detected values in each category. They do not count people, files, or incidents. A single person can contribute several evidence values across several categories.",
        "Differences by evidence type help show what kinds of information appear more often in one dataset than the other, but they do not explain by themselves why those differences occurred.",
        "Term conservation measures overlap in normalised detected values. It deliberately ignores file path, row number and source context, so it is useful for broad comparison but not for proving exact file-level equivalence.",
        "High conservation means the two outputs contain very similar detected values. It does not mean the original files were identical, nor does it by itself establish who was affected.",
        "The Venn diagrams are not area-scaled; the printed counts are the authoritative values.",
        f"A practical reading order is: first confirm the known people in {left_name}; then review known people found only in {right_name}; then use unknown signatures as a follow-up triage list; and finally use evidence-type and term-conservation sections to understand the overall pattern of similarity and difference.",
    ]
    for note in notes:
        document.add_paragraph(note, style="List Bullet")

    output_docx.parent.mkdir(parents=True, exist_ok=True)
    document.save(output_docx)

    if temp_context is not None:
        temp_context.cleanup()
    return output_docx


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create a lay-facing Word report from a PII Regex Output Comparison text report.")
    parser.add_argument("--report", required=True, type=Path, help="Path to the plain-text PII Regex Output Comparison report.")
    parser.add_argument("--output-docx", type=Path, default=None, help="Output .docx path. Defaults to <report_stem>_lay_summary.docx.")
    parser.add_argument("--left-display", default=None, help="Reader-facing name for the left dataset, e.g. Exfiltrated-DWD. Defaults to the left dataset label in the report.")
    parser.add_argument("--right-display", default=None, help="Reader-facing name for the right dataset, e.g. Exposed-BFS. Defaults to the right dataset label in the report.")
    parser.add_argument("--title", default="Data exposure comparison summary", help="Document title.")
    parser.add_argument("--keep-figures", action="store_true", help="Keep generated PNG figures beside the DOCX for review/reuse.")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite an existing DOCX output file.")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    report_path = args.report.expanduser().resolve()
    if not report_path.exists():
        parser.error(f"Report file does not exist: {report_path}")

    output_docx = args.output_docx
    if output_docx is None:
        output_docx = report_path.with_name(f"{report_path.stem}_lay_summary.docx")
    output_docx = output_docx.expanduser().resolve()

    if output_docx.exists() and not args.overwrite:
        parser.error(f"Output file already exists: {output_docx}. Use --overwrite to replace it.")

    report = parse_report(report_path)
    left_name = args.left_display or report.left_dataset
    right_name = args.right_display or report.right_dataset

    build_docx(
        report=report,
        output_docx=output_docx,
        source_report=report_path,
        left_name=left_name,
        right_name=right_name,
        title=args.title,
        keep_figures=args.keep_figures,
    )
    print(f"Wrote Word report: {output_docx}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
