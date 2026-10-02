#!/usr/bin/env python3
"""Render the workflow diagrams used by the Quarto DOCX."""

from pathlib import Path
from textwrap import wrap

from PIL import Image, ImageDraw, ImageFont


SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = SCRIPT_DIR / "PII_REGEX_WORKFLOW_WRITEUP_files"
FONT = "/System/Library/Fonts/Supplemental/Arial.ttf"
FONT_BOLD = "/System/Library/Fonts/Supplemental/Arial Bold.ttf"

WIDTH = 1600
MARGIN = 90
NODE_HEIGHT = 112
LAYER_GAP = 105
UON_BLUE = "#10263B"
UON_BLUE_2 = "#1D3D5C"
UON_TEAL = "#007C89"
UON_LIGHT_BLUE = "#E7EEF6"
UON_PALE = "#F5F7FA"
BLACK = "#17212B"
WHITE = "#FFFFFF"


def font(size=30, bold=False):
    return ImageFont.truetype(FONT_BOLD if bold else FONT, size)


def node_positions(layers):
    positions = {}
    for layer_index, layer in enumerate(layers):
        y = MARGIN + layer_index * (NODE_HEIGHT + LAYER_GAP)
        count = len(layer)
        available = WIDTH - 2 * MARGIN
        slot = available / count
        node_width = min(400, slot - 44)
        for index, node_id in enumerate(layer):
            centre_x = MARGIN + slot * (index + 0.5)
            positions[node_id] = (
                int(centre_x - node_width / 2),
                y,
                int(centre_x + node_width / 2),
                y + NODE_HEIGHT,
            )
    return positions


def draw_arrow(draw, start, end):
    draw.line([start, end], fill=UON_BLUE_2, width=5)
    x, y = end
    draw.polygon([(x, y), (x - 12, y - 20), (x + 12, y - 20)], fill=UON_BLUE_2)


def draw_label(draw, box, text, fill, bold=False):
    draw.rounded_rectangle(box, radius=10, fill=fill, outline=UON_BLUE, width=3)
    box_width = box[2] - box[0]
    lines = wrap(text, width=16 if box_width < 300 else 25)
    line_font = font(24 if box_width < 300 else 28, bold)
    line_height = 30 if box_width < 300 else 34
    total_height = len(lines) * line_height
    y = box[1] + (NODE_HEIGHT - total_height) / 2
    colour = WHITE if fill in {UON_BLUE, UON_BLUE_2, UON_TEAL} else BLACK
    for line in lines:
        bounds = draw.textbbox((0, 0), line, font=line_font)
        x = box[0] + (box[2] - box[0] - (bounds[2] - bounds[0])) / 2
        draw.text((x, y), line, fill=colour, font=line_font)
        y += line_height


def render(name, title, layers, labels, edges, decisions=()):
    height = 2 * MARGIN + len(layers) * NODE_HEIGHT + (len(layers) - 1) * LAYER_GAP + 90
    image = Image.new("RGB", (WIDTH, height), WHITE)
    draw = ImageDraw.Draw(image)
    positions = node_positions(layers)

    title_font = font(42, True)
    title_box = draw.textbbox((0, 0), title, font=title_font)
    draw.text(((WIDTH - (title_box[2] - title_box[0])) / 2, 22), title, fill=UON_BLUE, font=title_font)

    for source, target in edges:
        source_box = positions[source]
        target_box = positions[target]
        draw_arrow(
            draw,
            ((source_box[0] + source_box[2]) // 2, source_box[3]),
            ((target_box[0] + target_box[2]) // 2, target_box[1]),
        )

    for node_id, box in positions.items():
        fill = UON_TEAL if node_id in decisions else (UON_BLUE if node_id == layers[0][0] else UON_LIGHT_BLUE)
        draw_label(draw, box, labels[node_id], fill, bold=node_id in decisions or node_id == layers[0][0])

    image.save(OUTPUT_DIR / name, dpi=(220, 220), optimize=True)


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    render(
        "diagram_01.png",
        "Linear direct CSV evidence pipeline",
        [
            ["start"],
            ["discovery"],
            ["table", "structured", "plain"],
            ["detect"],
            ["csv"],
            ["clustering"],
            ["reidentify"],
            ["exports"],
        ],
        {
            "start": "Start scanner",
            "discovery": "Stages 1-3: preprocessing and optional profiling",
            "table": "Label table rows",
            "structured": "Infer structured records",
            "plain": "Extract plain text",
            "detect": "Stage 4: run evidence detection",
            "csv": "Write 4.Regex_Scanning CSVs",
            "clustering": "Stage 5: cluster overlapping evidence",
            "reidentify": "Stage 6: search using known-person information",
            "exports": "Stage 7: write reports and metadata",
        },
        [
            ("start", "discovery"),
            ("discovery", "table"), ("discovery", "structured"), ("discovery", "plain"),
            ("table", "detect"), ("structured", "detect"), ("plain", "detect"),
            ("detect", "csv"), ("csv", "clustering"),
            ("clustering", "reidentify"), ("reidentify", "exports"),
        ],
    )

    render(
        "diagram_02.png",
        "Person clustering workflow",
        [
            ["linked"],
            ["filter"],
            ["keys"],
            ["clusters"],
        ],
        {
            "linked": "4.Regex_Scanning/linked_evidence.csv",
            "filter": "Apply max_per_cluster filtering",
            "keys": "Build strong and compound merge keys",
            "clusters": "Write 5.Clustering/clusters.csv",
        },
        [
            ("linked", "filter"),
            ("filter", "keys"),
            ("keys", "clusters"),
        ],
        decisions=("filter",),
    )

    render(
        "diagram_03.png",
        "Known and unknown person outputs",
        [
            ["clusters"],
            ["person_table"],
            ["match"],
            ["known", "unknown"],
        ],
        {
            "clusters": "Clusters, linked evidence, and direct raw evidence",
            "person_table": "Optional --person-tables",
            "match": "Match normalized anchors",
            "known": "Known-person CSVs and risk matrices",
            "unknown": "clusters_not_in_list outputs",
        },
        [
            ("clusters", "person_table"),
            ("person_table", "match"),
            ("match", "known"),
            ("match", "unknown"),
        ],
        decisions=("person_table", "match"),
    )

    render(
        "diagram_04.png",
        "Runtime rule-loading order",
        [
            ["args"],
            ["suffix"],
            ["identity", "regex", "table"],
            ["runtime"],
        ],
        {
            "args": "CLI args",
            "suffix": "Configure email suffix and wildcard aliases",
            "identity": "Load person_identity_anchors.json",
            "regex": "Load regex_searching rules",
            "table": "Load table_column_rules",
            "runtime": "Compiled runtime configuration",
        },
        [
            ("args", "suffix"),
            ("suffix", "identity"),
            ("suffix", "regex"),
            ("suffix", "table"),
            ("identity", "runtime"),
            ("regex", "runtime"),
            ("table", "runtime"),
        ],
    )

    render(
        "diagram_05.png",
        "Loaded rule-derived configuration",
        [
            ["rules"],
            ["patterns", "headers", "anchors"],
            ["counts", "limits", "matrices"],
        ],
        {
            "rules": "Regex, table-column, and identity JSON",
            "patterns": "Compiled regex patterns and triggers",
            "headers": "Compiled header matchers",
            "anchors": "Strong and compound anchor sets",
            "counts": "Evidence summary columns",
            "limits": "Cluster exclusion limits",
            "matrices": "Risk-matrix has_* columns",
        },
        [
            ("rules", "patterns"),
            ("rules", "headers"),
            ("rules", "anchors"),
            ("patterns", "counts"),
            ("patterns", "limits"),
            ("anchors", "limits"),
            ("patterns", "matrices"),
        ],
    )

    render(
        "diagram_06.png",
        "Structured and plain-text extraction routing",
        [
            ["file"],
            ["signature"],
            ["route"],
            ["structured", "text", "table"],
            ["records", "fallback", "rows"],
            ["scantext"],
        ],
        {
            "file": "File path",
            "signature": "Detect content signature",
            "route": "Route by detected extension",
            "structured": "Parse JSON, JSONL, XML, or YAML",
            "text": "Decode text or markup",
            "table": "Read delimited or spreadsheet table",
            "records": "Label structured records",
            "fallback": "Use text fallback",
            "rows": "Label table rows",
            "scantext": "Extracted scan text",
        },
        [
            ("file", "signature"), ("signature", "route"),
            ("route", "structured"), ("route", "text"), ("route", "table"),
            ("structured", "records"), ("structured", "fallback"),
            ("text", "fallback"), ("table", "rows"),
            ("records", "scantext"), ("fallback", "scantext"), ("rows", "scantext"),
        ],
        decisions=("route",),
    )

    render(
        "diagram_07.png",
        "Document and image extraction routing",
        [
            ["route"],
            ["docx", "pdf", "rtf", "email", "image"],
            ["document", "ocr", "disabled"],
            ["scantext", "status"],
        ],
        {
            "route": "Route by detected extension",
            "docx": "DOCX: python-docx",
            "pdf": "PDF: pypdf",
            "rtf": "RTF: striprtf",
            "email": "EML or MSG parser",
            "image": "Image file",
            "document": "Extract document text",
            "ocr": "OCR enabled: pytesseract",
            "disabled": "OCR disabled",
            "scantext": "Extracted scan text",
            "status": "No OCR text status",
        },
        [
            ("route", "docx"), ("route", "pdf"), ("route", "rtf"),
            ("route", "email"), ("route", "image"),
            ("docx", "document"), ("pdf", "document"), ("rtf", "document"),
            ("email", "document"), ("image", "ocr"), ("image", "disabled"),
            ("document", "scantext"), ("ocr", "scantext"), ("disabled", "status"),
        ],
        decisions=("route", "image"),
    )

    render(
        "diagram_08.png",
        "Table handling pipeline",
        [
            ["source"],
            ["orientation", "headers"],
            ["rows"],
            ["scan"],
        ],
        {
            "source": "Delimited, spreadsheet, or table-like text",
            "orientation": "Detect normal, transposed, headerless, or ambiguous orientation",
            "headers": "Resolve headers with table-local separators",
            "rows": "Build labelled row text and safe inferred columns",
            "scan": "Route relevant rules or raw fallback",
        },
        [
            ("source", "orientation"),
            ("source", "headers"),
            ("orientation", "rows"),
            ("headers", "rows"),
            ("rows", "scan"),
        ],
        decisions=("orientation",),
    )

    render(
        "diagram_09.png",
        "Person clustering and anchor merging",
        [
            ["linked"],
            ["eligible"],
            ["strong", "compound"],
            ["union"],
            ["clusters"],
        ],
        {
            "linked": "4.Regex_Scanning/linked_evidence.csv",
            "eligible": "cluster_eligible yes?",
            "strong": "Strong identity keys",
            "compound": "Compound identity keys",
            "union": "Union linked rows sharing keys",
            "clusters": "5.Clustering/clusters.csv",
        },
        [
            ("linked", "eligible"),
            ("eligible", "strong"),
            ("eligible", "compound"),
            ("strong", "union"),
            ("compound", "union"),
            ("union", "clusters"),
        ],
        decisions=("eligible",),
    )

    render(
        "diagram_10.png",
        "Known-person table loading and anchor extraction",
        [
            ["csv"],
            ["preserve", "resolve"],
            ["regex", "email", "name"],
            ["anchors"],
        ],
        {
            "csv": "Person-list CSV",
            "preserve": "Preserve original columns",
            "resolve": "Resolve headers with table-column rules",
            "regex": "Validate labelled cell values",
            "email": "Extract email-looking cells",
            "name": "Combine first and last names",
            "anchors": "Known-person anchors",
        },
        [
            ("csv", "preserve"),
            ("csv", "resolve"),
            ("resolve", "regex"),
            ("preserve", "email"),
            ("resolve", "name"),
            ("regex", "anchors"),
            ("email", "anchors"),
            ("name", "anchors"),
        ],
    )

    render(
        "diagram_11.png",
        "Rule inputs to runtime configuration",
        [
            ["sources"],
            ["regex", "table", "identity"],
            ["runtime"],
        ],
        {
            "sources": "rules/",
            "regex": "regex_searching/**/*.json",
            "table": "table_column_rules/**/*.json",
            "identity": "person_identity_anchors.json",
            "runtime": "Evidence types, matchers, anchors, summaries",
        },
        [
            ("sources", "regex"),
            ("sources", "table"),
            ("sources", "identity"),
            ("regex", "runtime"),
            ("table", "runtime"),
            ("identity", "runtime"),
        ],
    )

    render(
        "diagram_12.png",
        "Dataset scan outputs",
        [
            ["scan"],
            ["atomic", "summary", "linked"],
            ["clusters"],
        ],
        {
            "scan": "Stage 4 discovery and regex searching",
            "atomic": "4.Regex_Scanning/pii_regex_evidence/*.csv",
            "summary": "file_summary, entity_summary, regex_summary",
            "linked": "4.Regex_Scanning/linked_evidence.csv",
            "clusters": "5.Clustering/clusters.csv and cluster_members.csv",
        },
        [
            ("scan", "atomic"),
            ("scan", "summary"),
            ("scan", "linked"),
            ("linked", "clusters"),
        ],
    )

    render(
        "diagram_13.png",
        "Known and unknown person outputs",
        [
            ["inputs"],
            ["match"],
            ["known", "unknown", "evidence"],
        ],
        {
            "inputs": "Clusters, linked evidence, raw evidence, and person tables",
            "match": "Stage 6: reidentification and exposure scoring",
            "known": "6.Reidentification known-person outputs",
            "unknown": "6.Reidentification no-list outputs",
            "evidence": "Optional per-person evidence folders",
        },
        [
            ("inputs", "match"),
            ("match", "known"),
            ("match", "unknown"),
            ("match", "evidence"),
        ],
        decisions=("match",),
    )


if __name__ == "__main__":
    main()
