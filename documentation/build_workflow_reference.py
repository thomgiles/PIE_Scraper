#!/usr/bin/env python3
"""Build a style-only Word reference and finalize rendered DOCX typography."""

import argparse
from pathlib import Path
from tempfile import NamedTemporaryFile
from xml.etree import ElementTree as ET
from zipfile import ZIP_DEFLATED, ZipFile


SCRIPT_DIR = Path(__file__).resolve().parent
SOURCE_DOCX = SCRIPT_DIR / "PIE_Scraper.docx"
OUTPUT_DOCX = SCRIPT_DIR / "templates/PIE_Scraper_styles.docx"

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W = f"{{{W_NS}}}"
ET.register_namespace("w", W_NS)
REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
REL = f"{{{REL_NS}}}"
ET.register_namespace("", REL_NS)

UON_BLUE = "10263B"
UON_BLUE_2 = "1D3D5C"
UON_LIGHT_BLUE = "E7EEF6"
UON_TEAL = "007C89"
UON_PALE = "F5F7FA"
BLACK = "17212B"
WHITE = "FFFFFF"
BORDER = "D8E1EA"


def child(parent, tag):
    element = parent.find(W + tag)
    if element is None:
        element = ET.SubElement(parent, W + tag)
    return element


def set_run_style(style, font, size, colour, bold=False, theme=None):
    r_pr = child(style, "rPr")
    fonts = child(r_pr, "rFonts")
    for key in ("ascii", "hAnsi", "eastAsia", "cs"):
        fonts.set(W + key, font)
    if theme:
        for key in ("asciiTheme", "hAnsiTheme"):
            fonts.set(W + key, theme)
    else:
        for key in ("asciiTheme", "hAnsiTheme"):
            fonts.attrib.pop(W + key, None)

    half_points = str(round(size * 2))
    child(r_pr, "sz").set(W + "val", half_points)
    child(r_pr, "szCs").set(W + "val", half_points)
    child(r_pr, "color").set(W + "val", colour)
    existing_bold = r_pr.find(W + "b")
    if bold and existing_bold is None:
        ET.SubElement(r_pr, W + "b")
    elif not bold and existing_bold is not None:
        r_pr.remove(existing_bold)


def style_by_id(styles, style_id):
    for style in styles.findall(W + "style"):
        if style.get(W + "styleId") == style_id:
            return style
    raise KeyError(f"Word style not found: {style_id}")


def set_shading(properties, fill):
    shading = child(properties, "shd")
    shading.set(W + "val", "clear")
    shading.set(W + "fill", fill)


def set_table_borders(tbl_pr):
    borders = child(tbl_pr, "tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        border = child(borders, edge)
        border.set(W + "val", "single")
        border.set(W + "sz", "4")
        border.set(W + "space", "0")
        border.set(W + "color", BORDER)


def table_condition(table_style, condition):
    for item in table_style.findall(W + "tblStylePr"):
        if item.get(W + "type") == condition:
            return item
    item = ET.SubElement(table_style, W + "tblStylePr")
    item.set(W + "type", condition)
    return item


def update_styles(styles_xml):
    root = ET.fromstring(styles_xml)

    defaults = child(child(root, "docDefaults"), "rPrDefault")
    set_run_style(defaults, "Aptos", 11, BLACK, theme="minorHAnsi")

    for style_id in ("Normal", "BodyText", "BodyTextChar"):
        set_run_style(style_by_id(root, style_id), "Aptos", 11, BLACK, theme="minorHAnsi")

    heading_styles = {
        "Title": (22, UON_BLUE),
        "Heading1": (16, UON_BLUE),
        "Heading2": (13, UON_BLUE_2),
        "Heading3": (11.5, UON_BLUE_2),
    }
    for style_id, (size, colour) in heading_styles.items():
        set_run_style(style_by_id(root, style_id), "Aptos Display", size, colour, bold=True, theme="majorHAnsi")

    set_run_style(style_by_id(root, "SourceCode"), "Consolas", 9, BLACK)
    source_code_p_pr = child(style_by_id(root, "SourceCode"), "pPr")
    set_shading(source_code_p_pr, UON_LIGHT_BLUE)
    set_run_style(style_by_id(root, "VerbatimChar"), "Consolas", 9, UON_BLUE_2)
    set_run_style(style_by_id(root, "Hyperlink"), "Aptos", 11, UON_TEAL, theme="minorHAnsi")

    table_style = style_by_id(root, "Table")
    set_run_style(table_style, "Aptos", 10, BLACK, theme="minorHAnsi")
    set_table_borders(child(table_style, "tblPr"))

    first_row = table_condition(table_style, "firstRow")
    set_run_style(first_row, "Aptos", 10, WHITE, bold=True, theme="minorHAnsi")
    set_shading(child(first_row, "tcPr"), UON_BLUE)

    banded_row = table_condition(table_style, "band1Horz")
    set_shading(child(banded_row, "tcPr"), UON_PALE)

    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def set_run_format(run, font, size, colour, bold=None):
    r_pr = child(run, "rPr")
    fonts = child(r_pr, "rFonts")
    for key in ("ascii", "hAnsi", "eastAsia", "cs"):
        fonts.set(W + key, font)
    for key in ("asciiTheme", "hAnsiTheme"):
        fonts.attrib.pop(W + key, None)

    half_points = str(round(size * 2))
    child(r_pr, "sz").set(W + "val", half_points)
    child(r_pr, "szCs").set(W + "val", half_points)
    child(r_pr, "color").set(W + "val", colour)

    if bold is not None:
        bold_element = r_pr.find(W + "b")
        if bold and bold_element is None:
            ET.SubElement(r_pr, W + "b")
        elif not bold and bold_element is not None:
            r_pr.remove(bold_element)


def finalize_document_xml(document_xml):
    root = ET.fromstring(document_xml)

    for paragraph in root.iter(W + "p"):
        p_style = paragraph.find(f"./{W}pPr/{W}pStyle")
        is_source_code = p_style is not None and p_style.get(W + "val") == "SourceCode"
        for run in paragraph.iter(W + "r"):
            r_style = run.find(f"./{W}rPr/{W}rStyle")
            is_inline_code = r_style is not None and r_style.get(W + "val") == "VerbatimChar"
            if is_source_code or is_inline_code:
                set_run_format(run, "Consolas", 9, BLACK)

    for table in root.iter(W + "tbl"):
        rows = table.findall(f"./{W}tr")
        for row_index, row in enumerate(rows):
            for run in row.iter(W + "r"):
                set_run_format(
                    run,
                    "Aptos",
                    10,
                    WHITE if row_index == 0 else BLACK,
                    bold=True if row_index == 0 else None,
                )

    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def minimal_document_xml(document_xml):
    """Remove report content while retaining page and section configuration."""
    root = ET.fromstring(document_xml)
    body = root.find(W + "body")
    if body is None:
        raise ValueError("Word document has no body element.")

    section_properties = body.find(W + "sectPr")
    for element in list(body):
        body.remove(element)

    ET.SubElement(body, W + "p")
    body.append(section_properties if section_properties is not None else ET.Element(W + "sectPr"))
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def minimal_document_relationships_xml(relationships_xml):
    """Drop relationships to body-only image content removed from the template."""
    root = ET.fromstring(relationships_xml)
    for relationship in list(root):
        if relationship.get("Type", "").endswith("/image"):
            root.remove(relationship)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def rewrite_docx(source_path, output_path, transforms, excluded_prefixes=()):
    with ZipFile(source_path, "r") as source:
        with NamedTemporaryFile(suffix=".docx", dir=output_path.parent, delete=False) as temporary:
            temporary_path = Path(temporary.name)
        try:
            with ZipFile(temporary_path, "w", ZIP_DEFLATED) as target:
                for item in source.infolist():
                    if any(item.filename.startswith(prefix) for prefix in excluded_prefixes):
                        continue
                    data = source.read(item.filename)
                    transform = transforms.get(item.filename)
                    if transform is not None:
                        data = transform(data)
                    target.writestr(item, data)
            temporary_path.replace(output_path)
        finally:
            temporary_path.unlink(missing_ok=True)


def build_reference():
    if not SOURCE_DOCX.exists():
        raise FileNotFoundError(f"Render the workflow DOCX first: {SOURCE_DOCX}")

    rewrite_docx(
        SOURCE_DOCX,
        OUTPUT_DOCX,
        {
            "word/document.xml": minimal_document_xml,
            "word/_rels/document.xml.rels": minimal_document_relationships_xml,
            "word/styles.xml": update_styles,
        },
        excluded_prefixes=("word/media/",),
    )

    print(f"Wrote style-only Word reference: {OUTPUT_DOCX}")


def finalize_rendered_document():
    if not SOURCE_DOCX.exists():
        raise FileNotFoundError(f"Render the workflow DOCX first: {SOURCE_DOCX}")
    rewrite_docx(SOURCE_DOCX, SOURCE_DOCX, {"word/document.xml": finalize_document_xml})
    print(f"Finalized Word typography: {SOURCE_DOCX}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--finalize", action="store_true", help="Apply direct table and code typography to the rendered DOCX.")
    options = parser.parse_args()
    if options.finalize:
        finalize_rendered_document()
    else:
        build_reference()
