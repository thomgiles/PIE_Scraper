#!/usr/bin/env python3
"""Extract simple not-in-list institutional and personal email lists.

Input can be either a scanner output directory or a direct path to
``clusters_not_in_list.csv``. Output is disclosive: it contains raw email
addresses from unknown/no-list identities.
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path


EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b")
EMAIL_TYPES = ("institutional", "personal")
USEFUL_FIELDS = ("cluster_anchor_values", "cluster_merge_keys", "evidence_values", "source_rows")


def find_unknown_clusters(path: Path) -> Path:
    path = path.resolve()
    if path.is_file():
        return path
    candidates = sorted(path.rglob("clusters_not_in_list.csv"))
    if not candidates:
        raise FileNotFoundError(f"No clusters_not_in_list.csv found under {path}")
    return candidates[0]


def labelled_emails(text: str) -> dict[str, set[str]]:
    result = {email_type: set() for email_type in EMAIL_TYPES}
    if not text:
        return result

    text = str(text)
    lower = text.lower()
    for token in [part.strip() for part in text.split("|") if part.strip()]:
        token_lower = token.lower()
        emails = {match.group(0).lower() for match in EMAIL_RE.finditer(token)}
        if not emails:
            continue
        if "institutional email" in token_lower:
            result["institutional"].update(emails)
        elif "personal email" in token_lower:
            result["personal"].update(emails)
        elif re.search(r"(?i)(^|[^a-z])email\s*=", token):
            result["personal"].update(emails)

    for match in EMAIL_RE.finditer(text):
        email = match.group(0).lower()
        if email in result["institutional"] or email in result["personal"]:
            continue
        context_start = max(0, match.start() - 80)
        context = lower[context_start:match.end()]
        if "institutional email" in context:
            result["institutional"].add(email)
        elif "personal email" in context:
            result["personal"].add(email)
        else:
            result["personal"].add(email)
    return result


def extract_not_in_list_emails(clusters_path: Path):
    emails = {email_type: set() for email_type in EMAIL_TYPES}
    email_rows = {}
    email_files = defaultdict(set)

    with clusters_path.open("r", newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            row_key = row.get("unknown_person_key") or row.get("person_cluster_id") or ""
            row_files = [
                part.strip()
                for part in str(row.get("file_paths", "")).split("|")
                if part.strip() and not part.strip().startswith("...(+")
            ]
            row_emails = {email_type: set() for email_type in EMAIL_TYPES}
            for field in USEFUL_FIELDS:
                extracted = labelled_emails(row.get(field, ""))
                for email_type in EMAIL_TYPES:
                    row_emails[email_type].update(extracted[email_type])
            for email_type in EMAIL_TYPES:
                for email in row_emails[email_type]:
                    emails[email_type].add(email)
                    email_rows.setdefault((email_type, email), set()).add(row_key)
                    for file_path in row_files:
                        email_files[(email_type, email)].add(file_path)
    return emails, email_rows, email_files


def write_list(path: Path, email_type: str, emails: set[str], email_rows, email_files):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["email_type", "email", "unknown_identity_count", "unknown_person_keys", "file_count", "file_paths"])
        writer.writeheader()
        for email in sorted(emails):
            key = (email_type, email)
            row_keys = sorted(v for v in email_rows.get(key, set()) if v)
            file_paths = sorted(v for v in email_files.get(key, set()) if v)
            writer.writerow({
                "email_type": email_type,
                "email": email,
                "unknown_identity_count": len(row_keys),
                "unknown_person_keys": " | ".join(row_keys),
                "file_count": len(file_paths),
                "file_paths": " | ".join(file_paths),
            })


def write_combined(path: Path, emails, email_rows, email_files):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["email_type", "email", "unknown_identity_count", "unknown_person_keys", "file_count", "file_paths"])
        writer.writeheader()
        for email_type in EMAIL_TYPES:
            for email in sorted(emails[email_type]):
                key = (email_type, email)
                row_keys = sorted(v for v in email_rows.get(key, set()) if v)
                file_paths = sorted(v for v in email_files.get(key, set()) if v)
                writer.writerow({
                    "email_type": email_type,
                    "email": email,
                    "unknown_identity_count": len(row_keys),
                    "unknown_person_keys": " | ".join(row_keys),
                    "file_count": len(file_paths),
                    "file_paths": " | ".join(file_paths),
                })


def default_output_dir(input_path: Path) -> Path:
    if input_path.is_file():
        return input_path.parent / "not_in_list_email_lists"
    if (input_path / "4.Reidentification").is_dir():
        return input_path / "4.Reidentification" / "not_in_list_email_lists"
    return input_path / "not_in_list_email_lists"


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Extract simple raw email lists from clusters_not_in_list.csv.")
    parser.add_argument("output_root_or_clusters_csv", help="Scanner output directory, 4.Reidentification directory, or clusters_not_in_list.csv.")
    parser.add_argument("--output-dir", default="", help="Output directory. Default: beside the not-in-list outputs.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    input_path = Path(args.output_root_or_clusters_csv).resolve()
    clusters_path = find_unknown_clusters(input_path)
    output_dir = Path(args.output_dir).resolve() if args.output_dir else default_output_dir(input_path)
    emails, email_rows, email_files = extract_not_in_list_emails(clusters_path)
    write_list(output_dir / "not_in_list_institutional_emails.csv", "institutional", emails["institutional"], email_rows, email_files)
    write_list(output_dir / "not_in_list_personal_emails.csv", "personal", emails["personal"], email_rows, email_files)
    write_combined(output_dir / "not_in_list_emails.csv", emails, email_rows, email_files)
    print(
        f"Wrote {len(emails['institutional']):,} institutional and "
        f"{len(emails['personal']):,} personal not-in-list emails to {output_dir}"
    )


if __name__ == "__main__":
    main()
