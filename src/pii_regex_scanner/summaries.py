"""File/entity/regex summary builders.

This module is loaded into pii_regex_scanner.pipeline's shared namespace.
"""

def file_risk_from_entity_counts(entity_counts):
    evidence = set(entity_counts)
    has_email = has_email_evidence(evidence)
    has_id = has_id_evidence(evidence)
    has_name = has_risk_role(evidence, "name")
    has_dob = has_risk_role(evidence, "dob")
    has_phone = has_risk_role(evidence, "phone")
    if evidence & HIGH_RISK_STANDALONE:
        return "high"
    if (evidence & SENSITIVE_CONTEXT) and (evidence & IDENTIFIABLE_EVIDENCE):
        return "high"
    if (has_name and has_dob) or (has_email and has_dob):
        return "high"
    if has_id and (has_name or has_dob or has_phone or has_email):
        return "high"
    if evidence & TIER_1_EVIDENCE:
        return "medium"
    if len(evidence & TIER_3_EVIDENCE) >= 3:
        return "medium"
    if evidence:
        return "low"
    return ""


def add_summary_evidence_counts(summary, entity_counts):
    summary["highest_file_risk"] = file_risk_from_entity_counts(entity_counts)
    summary["evidence_type_counts"] = "|".join(
        f"{evidence_type}={entity_counts[evidence_type]}"
        for evidence_type in sorted(entity_counts)
        if entity_counts[evidence_type]
    )
    for evidence_type, column in zip(EVIDENCE_COUNT_TYPES, EVIDENCE_COUNT_COLUMNS):
        summary[column] = entity_counts.get(evidence_type, 0)
    return summary


def add_summary_cluster_exclusion_counts(summary, excluded_count, reasons):
    summary["cluster_excluded_linked_evidence_count"] = excluded_count
    summary["cluster_exclusion_reasons"] = "|".join(
        f"{reason}={count}"
        for reason, count in sorted(reasons.items())
    )
    return summary


def summary_row(
    path,
    file_name,
    extension,
    size_bytes,
    md5,
    status,
    text_chars,
    finding_count,
    linked_evidence_count,
    error,
    detected_extension="",
    sha256="",
    duplicate_content_group="",
    duplicate_content_index="",
    duplicate_of="",
    duplicate_path_count="",
    duplicate_paths="",
    duplicate_content_action="",
):
    return {
        "file_path": path,
        "file_name": file_name,
        "extension": extension.lstrip("."),
        "detected_extension": (detected_extension or extension).lstrip("."),
        "size_bytes": size_bytes,
        "md5": md5,
        "sha256": sha256,
        "duplicate_content_group": duplicate_content_group,
        "duplicate_content_index": duplicate_content_index,
        "duplicate_of": duplicate_of,
        "duplicate_path_count": duplicate_path_count,
        "duplicate_paths": duplicate_paths,
        "duplicate_content_action": duplicate_content_action,
        "status": status,
        "text_chars_scanned": text_chars,
        "finding_count": finding_count,
        "cluster_excluded_linked_evidence_count": 0,
        "cluster_exclusion_reasons": "",
        "error": error,
    }


def error_row(path, file_name, extension, size_bytes, status, error):
    return {
        "file_path": path,
        "file_name": file_name,
        "extension": extension.lstrip("."),
        "size_bytes": size_bytes,
        "status": status,
        "error": error,
    }


def regex_summary_fieldnames():
    fields = list(REGEX_SUMMARY_FIELDS)
    for stem in PERSON_TABLE_SUMMARY_STEMS:
        column = "matched_to_" + rule_slug(stem)
        if column not in fields:
            fields.append(column)
    return fields


def build_regex_summary(evidence_dir, regex_summary_path):
    rows = []
    if not os.path.isdir(evidence_dir):
        return 0

    dynamic_fields = regex_summary_fieldnames()
    matched_columns = [field for field in dynamic_fields if field.startswith("matched_to_")]

    for entry in sorted(os.scandir(evidence_dir), key=lambda item: item.name):
        if not entry.is_file() or not entry.name.lower().endswith(".csv") or entry.name == "errors.csv":
            continue

        finding_count = 0
        unique_values = set()
        files = set()
        evidence_type = ""
        pattern_name = ""
        confidence = set()
        evidence_tier_values = set()
        matched_counts = Counter()
        not_matched = 0

        with open(entry.path, "r", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as f:
            for row in csv.DictReader(f):
                if row.get("evidence_tier") == "metadata" or row.get("pattern_name") == "max_findings_per_file":
                    continue
                finding_count += 1
                value = row.get("normalized_value") or row.get("matched_text") or ""
                if value:
                    unique_values.add(value)
                if row.get("file_path"):
                    files.add(row["file_path"])
                evidence_type = evidence_type or row.get("evidence_type", "")
                pattern_name = pattern_name or row.get("pattern_name", "")
                if row.get("confidence"):
                    confidence.add(row["confidence"])
                if row.get("evidence_tier"):
                    evidence_tier_values.add(row["evidence_tier"])
                matched_tables = split_pipe_values(row.get("matched_person_tables", ""))
                if matched_tables:
                    for stem in matched_tables:
                        matched_counts["matched_to_" + rule_slug(stem)] += 1
                else:
                    not_matched += 1

        if finding_count:
            out = {
                "evidence_type": evidence_type,
                "pattern_name": pattern_name,
                "finding_count": finding_count,
                "unique_value_count": len(unique_values),
                "file_count": len(files),
                "confidence": "|".join(sorted(confidence)),
                "evidence_tier": "|".join(sorted(evidence_tier_values)),
                "not_matched": not_matched,
            }
            for column in matched_columns:
                out[column] = matched_counts.get(column, 0)
            rows.append(out)

    with open(regex_summary_path, "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as f:
        writer = csv.DictWriter(f, fieldnames=dynamic_fields)
        writer.writeheader()
        writer.writerows(rows)

    return len(rows)


def count_csv_rows(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return 0
    with open(path, "r", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as f:
        return sum(1 for _ in csv.DictReader(f))


def build_entity_summary_from_file_summary(file_summary_path, entity_summary_path):
    entity_counts = Counter()
    entity_files = Counter()
    if os.path.exists(file_summary_path):
        with open(file_summary_path, "r", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as f:
            for row in csv.DictReader(f):
                for part in split_pipe_values(row.get("evidence_type_counts", "")):
                    if "=" not in part:
                        continue
                    evidence_type, count = part.rsplit("=", 1)
                    try:
                        count = int(count)
                    except ValueError:
                        continue
                    if count:
                        entity_counts[evidence_type] += count
                        entity_files[evidence_type] += 1

    with open(entity_summary_path, "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as f:
        writer = csv.DictWriter(f, fieldnames=ENTITY_SUMMARY_FIELDS)
        writer.writeheader()
        for evidence_type in sorted(entity_counts):
            writer.writerow(
                {
                    "evidence_type": evidence_type,
                    "finding_count": entity_counts[evidence_type],
                    "file_count": entity_files[evidence_type],
                }
            )
    return len(entity_counts)


# =============================================================================

# Merged from clustering(4).py

# =============================================================================

"""Person clustering, known-person linkage, and person-level output writers."""


