#!/usr/bin/env python3
"""Build overlap reports for known-list and no-list email evidence.

Point this at an existing PiiScraper output directory. It recursively finds:

- ``*_pii_value_risk_matrix.csv`` files, treated as known person-list outputs;
- ``clusters_not_in_list.csv``, treated as unknown/no-list output.

It writes:

- ``email_overlap_matrix.csv``: pairwise overlap counts between lists and unknowns;
- ``email_overlap_summary.csv``: totals, unique counts, and unknown overlap by list;
- ``email_overlap_by_unknown_file.csv``: no-list email counts by source file path;
- ``email_overlap_person_links.csv``: one row per known person/list row with
  institutional and personal emails kept together;
- ``email_overlap_membership.csv``: optional row-level email membership detail.

The membership file contains actual email values. Use ``--no-membership`` when
you only want non-disclosive counts.
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path


EMAIL_PATTERN = r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}"
EMAIL_RE = re.compile(rf"(?i)\b{EMAIL_PATTERN}\b")
EMAIL_TYPES = ("institutional", "personal")


def safe_name(path: Path) -> str:
    name = path.name
    suffix = "_pii_value_risk_matrix.csv"
    if name.endswith(suffix):
        name = name[: -len(suffix)]
    return name or path.stem


def split_values(value: str) -> list[str]:
    if not value:
        return []
    parts = [part.strip() for part in str(value).split("|")]
    values = []
    for part in parts:
        if not part or part.startswith("...(+"):
            continue
        values.extend(match.group(0).lower() for match in EMAIL_RE.finditer(part))
    return values


def known_matrix_email_fields(fields: set[str]) -> tuple[list[str], list[str], list[str]]:
    institutional_fields = [
        field for field in fields
        if field.lower() in {"has_institutional_email", "institutional_email", "institutional email"}
    ]
    personal_fields = [
        field for field in fields
        if field.lower() in {"has_personal_email", "personal_email", "personal email"}
    ]
    generic_fields = [
        field for field in fields
        if field.lower() in {"has_email", "email", "emails", "email_address", "email address"}
    ]
    return institutional_fields, personal_fields, generic_fields


def row_known_emails(row: dict[str, str], fields: set[str]) -> dict[str, set[str]]:
    emails = {email_type: set() for email_type in EMAIL_TYPES}
    institutional_fields, personal_fields, generic_fields = known_matrix_email_fields(fields)
    for field in institutional_fields:
        emails["institutional"].update(split_values(row.get(field, "")))
    for field in personal_fields:
        emails["personal"].update(split_values(row.get(field, "")))
    for field in generic_fields:
        # Generic email columns are counted as personal only when there is no
        # split email output. This avoids double-counting split runs.
        if not institutional_fields and not personal_fields:
            emails["personal"].update(split_values(row.get(field, "")))
    return emails


def emails_from_known_matrix(path: Path) -> dict[str, set[str]]:
    emails = {email_type: set() for email_type in EMAIL_TYPES}
    with path.open("r", newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        for row in reader:
            row_emails = row_known_emails(row, fields)
            for email_type in EMAIL_TYPES:
                emails[email_type].update(row_emails[email_type])
    return emails


def person_link_rows_from_known_matrix(path: Path, source_name: str, unknown: dict[str, set[str]], redact_values: bool) -> list[dict[str, str]]:
    rows = []
    with path.open("r", newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        for row in reader:
            row_emails = row_known_emails(row, fields)
            institutional = row_emails["institutional"]
            personal = row_emails["personal"]
            if not institutional and not personal:
                continue
            rows.append({
                "source": source_name,
                "person_key": row.get("person_key", ""),
                "person_table_row_number": row.get("person_table_row_number", ""),
                "overall_risk_level": row.get("overall_risk_level", ""),
                "institutional_email_count": len(institutional),
                "personal_email_count": len(personal),
                "has_both_institutional_and_personal": "yes" if institutional and personal else "no",
                "institutional_emails": "" if redact_values else " | ".join(sorted(institutional)),
                "personal_emails": "" if redact_values else " | ".join(sorted(personal)),
                "institutional_emails_in_unknown_no_list": len(institutional & unknown["institutional"]),
                "personal_emails_in_unknown_no_list": len(personal & unknown["personal"]),
            })
    return rows


def labelled_emails(text: str) -> dict[str, set[str]]:
    """Extract labelled email values from scanner-style text fields."""
    result = {email_type: set() for email_type in EMAIL_TYPES}
    if not text:
        return result

    # Prefer explicit scanner labels when they are present. Work token by token
    # so ``Institutional Email=...`` is not also interpreted as generic
    # ``Email=...``.
    for token in [part.strip() for part in text.split("|") if part.strip()]:
        token_lower = token.lower()
        token_emails = {match.group(0).lower() for match in EMAIL_RE.finditer(token)}
        if not token_emails:
            continue
        if "institutional email" in token_lower:
            result["institutional"].update(token_emails)
        elif "personal email" in token_lower:
            result["personal"].update(token_emails)
        elif re.search(r"(?i)(^|[^a-z])email\s*=", token):
            result["personal"].update(token_emails)

    # Fallback for fields such as cluster_merge_keys where the type may be part
    # of a prefix rather than a clean ``Evidence Type=value`` token.
    lower = text.lower()
    for email in (match.group(0).lower() for match in EMAIL_RE.finditer(text)):
        if email in result["institutional"] or email in result["personal"]:
            continue
        start = max(0, lower.find(email) - 80)
        context = lower[start: lower.find(email) + len(email)]
        if "institutional email" in context:
            result["institutional"].add(email)
        elif "personal email" in context:
            result["personal"].add(email)
        elif email not in result["institutional"] and email not in result["personal"]:
            result["personal"].add(email)

    return result


def emails_from_unknown_clusters(path: Path) -> tuple[dict[str, set[str]], dict[str, dict[str, set[str]]]]:
    emails = {email_type: set() for email_type in EMAIL_TYPES}
    by_file = defaultdict(lambda: {email_type: set() for email_type in EMAIL_TYPES})
    useful_fields = (
        "cluster_anchor_values",
        "cluster_merge_keys",
        "evidence_values",
        "source_rows",
    )

    with path.open("r", newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            row_emails = {email_type: set() for email_type in EMAIL_TYPES}
            for field in useful_fields:
                extracted = labelled_emails(row.get(field, ""))
                for email_type in EMAIL_TYPES:
                    row_emails[email_type].update(extracted[email_type])
            for email_type in EMAIL_TYPES:
                emails[email_type].update(row_emails[email_type])
            for file_path in [
                part.strip()
                for part in row.get("file_paths", "").split("|")
                if part.strip() and not part.strip().startswith("...(+")
            ]:
                for email_type in EMAIL_TYPES:
                    by_file[file_path][email_type].update(row_emails[email_type])
    return emails, by_file


def find_known_matrices(root: Path) -> list[Path]:
    return sorted(
        path for path in root.rglob("*_pii_value_risk_matrix.csv")
        if path.is_file() and not path.name.startswith("clusters_not_in_list")
    )


def find_unknown_clusters(root: Path) -> Path | None:
    candidates = sorted(path for path in root.rglob("clusters_not_in_list.csv") if path.is_file())
    if candidates:
        return candidates[0]
    return None


def write_matrix(output_path: Path, sources: dict[str, dict[str, set[str]]]) -> None:
    rows = []
    names = sorted(sources)
    for email_type in EMAIL_TYPES:
        for left in names:
            row = {"email_type": email_type, "source": left}
            for right in names:
                row[right] = len(sources[left][email_type] & sources[right][email_type])
            rows.append(row)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["email_type", "source"] + names)
        writer.writeheader()
        writer.writerows(rows)


def write_summary(output_path: Path, known_sources: dict[str, dict[str, set[str]]], unknown: dict[str, set[str]]) -> None:
    all_known = {email_type: set() for email_type in EMAIL_TYPES}
    for source in known_sources.values():
        for email_type in EMAIL_TYPES:
            all_known[email_type].update(source[email_type])

    rows = []
    for name, source in sorted(known_sources.items()):
        other_known = {
            email_type: set().union(*[
                other[email_type] for other_name, other in known_sources.items() if other_name != name
            ]) if len(known_sources) > 1 else set()
            for email_type in EMAIL_TYPES
        }
        for email_type in EMAIL_TYPES:
            values = source[email_type]
            rows.append({
                "source": name,
                "email_type": email_type,
                "total_unique_emails": len(values),
                "unique_to_this_list": len(values - other_known[email_type]),
                "also_in_other_known_lists": len(values & other_known[email_type]),
                "also_in_unknown_no_list": len(values & unknown[email_type]),
            })

    for email_type in EMAIL_TYPES:
        rows.append({
            "source": "UNKNOWN_NOT_IN_LIST",
            "email_type": email_type,
            "total_unique_emails": len(unknown[email_type]),
            "unique_to_this_list": len(unknown[email_type] - all_known[email_type]),
            "also_in_other_known_lists": "",
            "also_in_unknown_no_list": "",
        })

    with output_path.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "source",
            "email_type",
            "total_unique_emails",
            "unique_to_this_list",
            "also_in_other_known_lists",
            "also_in_unknown_no_list",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_unknown_by_file(output_path: Path, by_file: dict[str, dict[str, set[str]]], known_sources: dict[str, dict[str, set[str]]]) -> None:
    all_known = {email_type: set() for email_type in EMAIL_TYPES}
    for source in known_sources.values():
        for email_type in EMAIL_TYPES:
            all_known[email_type].update(source[email_type])

    rows = []
    for file_path, typed in sorted(by_file.items()):
        for email_type in EMAIL_TYPES:
            values = typed[email_type]
            if not values:
                continue
            rows.append({
                "file_path": file_path,
                "email_type": email_type,
                "unknown_unique_emails": len(values),
                "unknown_emails_also_in_known_lists": len(values & all_known[email_type]),
                "unknown_emails_not_in_known_lists": len(values - all_known[email_type]),
            })
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "file_path",
            "email_type",
            "unknown_unique_emails",
            "unknown_emails_also_in_known_lists",
            "unknown_emails_not_in_known_lists",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_membership(output_path: Path, known_sources: dict[str, dict[str, set[str]]], unknown: dict[str, set[str]]) -> None:
    rows = []
    for email_type in EMAIL_TYPES:
        all_values = set(unknown[email_type])
        for source in known_sources.values():
            all_values.update(source[email_type])
        for email in sorted(all_values):
            in_lists = [name for name, source in sorted(known_sources.items()) if email in source[email_type]]
            rows.append({
                "email": email,
                "email_type": email_type,
                "known_list_count": len(in_lists),
                "known_lists": "|".join(in_lists),
                "in_unknown_not_in_list": "yes" if email in unknown[email_type] else "no",
                "classification": (
                    "unknown_only" if email in unknown[email_type] and not in_lists
                    else "known_and_unknown" if email in unknown[email_type] and in_lists
                    else "known_only"
                ),
            })
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        fieldnames = [
            "email",
            "email_type",
            "known_list_count",
            "known_lists",
            "in_unknown_not_in_list",
            "classification",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_person_links(output_path: Path, known_paths: dict[str, Path], unknown: dict[str, set[str]], redact_values: bool) -> None:
    rows = []
    for source_name, path in sorted(known_paths.items()):
        rows.extend(person_link_rows_from_known_matrix(path, source_name, unknown, redact_values))

    fieldnames = [
        "source",
        "person_key",
        "person_table_row_number",
        "overall_risk_level",
        "institutional_email_count",
        "personal_email_count",
        "has_both_institutional_and_personal",
        "institutional_emails",
        "personal_emails",
        "institutional_emails_in_unknown_no_list",
        "personal_emails_in_unknown_no_list",
    ]
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run(args: argparse.Namespace) -> int:
    root = Path(args.output_dir).resolve()
    report_dir = Path(args.report_dir).resolve() if args.report_dir else root / "email_overlap_report"
    report_dir.mkdir(parents=True, exist_ok=True)

    known_sources = {}
    known_paths = {}
    for path in find_known_matrices(root):
        name = safe_name(path)
        known_paths[name] = path
        known_sources[name] = emails_from_known_matrix(path)

    unknown_path = find_unknown_clusters(root)
    if unknown_path:
        unknown, unknown_by_file = emails_from_unknown_clusters(unknown_path)
    else:
        unknown = {email_type: set() for email_type in EMAIL_TYPES}
        unknown_by_file = {}

    matrix_sources = dict(known_sources)
    matrix_sources["UNKNOWN_NOT_IN_LIST"] = unknown

    write_matrix(report_dir / "email_overlap_matrix.csv", matrix_sources)
    write_summary(report_dir / "email_overlap_summary.csv", known_sources, unknown)
    write_unknown_by_file(report_dir / "email_overlap_by_unknown_file.csv", unknown_by_file, known_sources)
    write_person_links(report_dir / "email_overlap_person_links.csv", known_paths, unknown, args.no_membership)
    if not args.no_membership:
        write_membership(report_dir / "email_overlap_membership.csv", known_sources, unknown)

    print(f"Known person-list matrices: {len(known_sources):,}")
    print(f"Unknown clusters file: {unknown_path if unknown_path else 'not found'}")
    print(f"Report directory: {report_dir}")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", help="Existing PiiScraper output directory to inspect.")
    parser.add_argument("--report-dir", default="", help="Directory for report CSVs. Default: OUTPUT_DIR/email_overlap_report")
    parser.add_argument("--no-membership", action="store_true", help="Do not write email_overlap_membership.csv with actual email values.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    return run(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
