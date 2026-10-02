"""Email overlap reports for known-person and no-list outputs.

This module is loaded into ``pipeline.py`` before runtime orchestration. It
builds a compact diagnostic report from the Stage 3 CSV outputs:

- known-list ``*_pii_value_risk_matrix.csv`` files;
- ``clusters_not_in_list.csv``.

The report keeps person-level institutional/personal email linkage intact so a
known person with both email classes appears on one row.
"""

EMAIL_OVERLAP_PATTERN = r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}"
EMAIL_OVERLAP_RE = re.compile(rf"(?i)\b{EMAIL_OVERLAP_PATTERN}\b")
EMAIL_OVERLAP_TYPES = ("institutional", "personal")


def email_overlap_safe_name(path):
    path = Path(path)
    name = path.name
    suffix = "_pii_value_risk_matrix.csv"
    if name.endswith(suffix):
        name = name[: -len(suffix)]
    return name or path.stem


def email_overlap_split_values(value):
    if not value:
        return []
    values = []
    for part in [part.strip() for part in str(value).split("|")]:
        if not part or part.startswith("...(+"):
            continue
        values.extend(match.group(0).lower() for match in EMAIL_OVERLAP_RE.finditer(part))
    return values


def email_overlap_known_matrix_fields(fields):
    fields = set(fields or [])
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


def email_overlap_row_known_emails(row, fields):
    emails = {email_type: set() for email_type in EMAIL_OVERLAP_TYPES}
    institutional_fields, personal_fields, generic_fields = email_overlap_known_matrix_fields(fields)
    for field in institutional_fields:
        emails["institutional"].update(email_overlap_split_values(row.get(field, "")))
    for field in personal_fields:
        emails["personal"].update(email_overlap_split_values(row.get(field, "")))
    for field in generic_fields:
        if not institutional_fields and not personal_fields:
            emails["personal"].update(email_overlap_split_values(row.get(field, "")))
    return emails


def email_overlap_emails_from_known_matrix(path):
    emails = {email_type: set() for email_type in EMAIL_OVERLAP_TYPES}
    with open(path, "r", newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        for row in reader:
            row_emails = email_overlap_row_known_emails(row, fields)
            for email_type in EMAIL_OVERLAP_TYPES:
                emails[email_type].update(row_emails[email_type])
    return emails


def email_overlap_labelled_emails(text):
    result = {email_type: set() for email_type in EMAIL_OVERLAP_TYPES}
    if not text:
        return result

    for token in [part.strip() for part in str(text).split("|") if part.strip()]:
        token_lower = token.lower()
        token_emails = {match.group(0).lower() for match in EMAIL_OVERLAP_RE.finditer(token)}
        if not token_emails:
            continue
        if "institutional email" in token_lower:
            result["institutional"].update(token_emails)
        elif "personal email" in token_lower:
            result["personal"].update(token_emails)
        elif re.search(r"(?i)(^|[^a-z])email\s*=", token):
            result["personal"].update(token_emails)

    lower = str(text).lower()
    for email in (match.group(0).lower() for match in EMAIL_OVERLAP_RE.finditer(str(text))):
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


def email_overlap_from_unknown_clusters(path):
    emails = {email_type: set() for email_type in EMAIL_OVERLAP_TYPES}
    by_file = defaultdict(lambda: {email_type: set() for email_type in EMAIL_OVERLAP_TYPES})
    useful_fields = ("cluster_anchor_values", "cluster_merge_keys", "evidence_values", "source_rows")

    with open(path, "r", newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            row_emails = {email_type: set() for email_type in EMAIL_OVERLAP_TYPES}
            for field in useful_fields:
                extracted = email_overlap_labelled_emails(row.get(field, ""))
                for email_type in EMAIL_OVERLAP_TYPES:
                    row_emails[email_type].update(extracted[email_type])
            for email_type in EMAIL_OVERLAP_TYPES:
                emails[email_type].update(row_emails[email_type])
            for file_path in [
                part.strip()
                for part in row.get("file_paths", "").split("|")
                if part.strip() and not part.strip().startswith("...(+")
            ]:
                for email_type in EMAIL_OVERLAP_TYPES:
                    by_file[file_path][email_type].update(row_emails[email_type])
    return emails, by_file


def email_overlap_find_known_matrices(root):
    root = Path(root)
    return sorted(
        path for path in root.rglob("*_pii_value_risk_matrix.csv")
        if path.is_file() and not path.name.startswith("clusters_not_in_list")
    )


def email_overlap_find_unknown_clusters(root):
    root = Path(root)
    candidates = sorted(path for path in root.rglob("clusters_not_in_list.csv") if path.is_file())
    return candidates[0] if candidates else None


def email_overlap_write_matrix(output_path, sources):
    names = sorted(sources)
    rows = []
    for email_type in EMAIL_OVERLAP_TYPES:
        for left in names:
            row = {"email_type": email_type, "source": left}
            for right in names:
                row[right] = len(sources[left][email_type] & sources[right][email_type])
            rows.append(row)
    with open(output_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["email_type", "source"] + names)
        writer.writeheader()
        writer.writerows(rows)


def email_overlap_write_summary(output_path, known_sources, unknown):
    all_known = {email_type: set() for email_type in EMAIL_OVERLAP_TYPES}
    for source in known_sources.values():
        for email_type in EMAIL_OVERLAP_TYPES:
            all_known[email_type].update(source[email_type])

    rows = []
    for name, source in sorted(known_sources.items()):
        other_known = {
            email_type: set().union(*[
                other[email_type]
                for other_name, other in known_sources.items()
                if other_name != name
            ]) if len(known_sources) > 1 else set()
            for email_type in EMAIL_OVERLAP_TYPES
        }
        for email_type in EMAIL_OVERLAP_TYPES:
            values = source[email_type]
            rows.append({
                "source": name,
                "email_type": email_type,
                "total_unique_emails": len(values),
                "unique_to_this_list": len(values - other_known[email_type]),
                "also_in_other_known_lists": len(values & other_known[email_type]),
                "also_in_unknown_no_list": len(values & unknown[email_type]),
            })

    for email_type in EMAIL_OVERLAP_TYPES:
        rows.append({
            "source": "UNKNOWN_NOT_IN_LIST",
            "email_type": email_type,
            "total_unique_emails": len(unknown[email_type]),
            "unique_to_this_list": len(unknown[email_type] - all_known[email_type]),
            "also_in_other_known_lists": "",
            "also_in_unknown_no_list": "",
        })

    with open(output_path, "w", newline="", encoding="utf-8") as handle:
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


def email_overlap_write_unknown_by_file(output_path, by_file, known_sources):
    all_known = {email_type: set() for email_type in EMAIL_OVERLAP_TYPES}
    for source in known_sources.values():
        for email_type in EMAIL_OVERLAP_TYPES:
            all_known[email_type].update(source[email_type])

    rows = []
    for file_path, typed in sorted(by_file.items()):
        for email_type in EMAIL_OVERLAP_TYPES:
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
    with open(output_path, "w", newline="", encoding="utf-8") as handle:
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


def email_overlap_person_link_rows(path, source_name, unknown):
    rows = []
    with open(path, "r", newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        fields = set(reader.fieldnames or [])
        for row in reader:
            row_emails = email_overlap_row_known_emails(row, fields)
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
                "institutional_emails": " | ".join(sorted(institutional)),
                "personal_emails": " | ".join(sorted(personal)),
                "institutional_emails_in_unknown_no_list": len(institutional & unknown["institutional"]),
                "personal_emails_in_unknown_no_list": len(personal & unknown["personal"]),
            })
    return rows


def email_overlap_write_person_links(output_path, known_paths, unknown):
    rows = []
    for source_name, path in sorted(known_paths.items()):
        rows.extend(email_overlap_person_link_rows(path, source_name, unknown))
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
    with open(output_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_email_overlap_report(output_root, report_dir=None):
    output_root = Path(output_root)
    report_dir = Path(report_dir) if report_dir else output_root / "email_overlap_report"
    report_dir.mkdir(parents=True, exist_ok=True)

    known_sources = {}
    known_paths = {}
    for path in email_overlap_find_known_matrices(output_root):
        name = email_overlap_safe_name(path)
        known_paths[name] = path
        known_sources[name] = email_overlap_emails_from_known_matrix(path)

    unknown_path = email_overlap_find_unknown_clusters(output_root)
    if unknown_path:
        unknown, unknown_by_file = email_overlap_from_unknown_clusters(unknown_path)
    else:
        unknown = {email_type: set() for email_type in EMAIL_OVERLAP_TYPES}
        unknown_by_file = {}

    matrix_sources = dict(known_sources)
    matrix_sources["UNKNOWN_NOT_IN_LIST"] = unknown
    email_overlap_write_matrix(report_dir / "email_overlap_matrix.csv", matrix_sources)
    email_overlap_write_summary(report_dir / "email_overlap_summary.csv", known_sources, unknown)
    email_overlap_write_unknown_by_file(report_dir / "email_overlap_by_unknown_file.csv", unknown_by_file, known_sources)
    email_overlap_write_person_links(report_dir / "email_overlap_person_links.csv", known_paths, unknown)
    return {
        "report_dir": str(report_dir),
        "known_matrix_count": len(known_sources),
        "unknown_clusters_file": str(unknown_path or ""),
    }
