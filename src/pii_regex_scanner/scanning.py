"""Atomic evidence scanning, table routing, per-file processing, scan chunks, and XML scope scanning.

This module is loaded into pii_regex_scanner.pipeline's shared namespace.
"""

def signal_finding(file_info, evidence_type, matched_text, pattern_name, confidence, context):
    normalized = normalize_value(evidence_type, matched_text)
    return {
        "file_path": file_info["file_path"],
        "file_name": file_info["file_name"],
        "extension": file_info["extension"],
        "size_bytes": file_info["size_bytes"],
        "md5": file_info["md5"],
        "row_number": "",
        "evidence_type": evidence_type,
        "matched_text": matched_text,
        "normalized_value": normalized,
        "start": "",
        "end": "",
        "context": context,
        "pattern_name": pattern_name,
        "confidence": confidence,
        "evidence_tier": evidence_tier(evidence_type, pattern_name),
    }


def looks_like_identity_document_file_reference(value):
    """Return True for filenames/metadata that indicate an identity document.

    This is intentionally a conservative filename/metadata signal, not an OCR
    content signal and not an extracted passport number. Generic names such as
    ``passport.pdf`` are too weak to link to a person; OCR text can still link
    through names and identifiers found inside the document.
    """
    return valid_identity_document_file_reference(value)


def file_signal_findings(file_info, extension):
    findings = []
    active_evidence_types = set(EVIDENCE_COUNT_TYPES)

    if extension in IMAGE_EXTENSIONS and "Pictures" in active_evidence_types:
        findings.append(
            signal_finding(
                file_info,
                "Pictures",
                file_info["file_name"],
                "file_signal_image_file_extension",
                "high",
                "Image file identified by extension.",
            )
        )

    if extension in DOCUMENT_SIGNAL_EXTENSIONS and "Document Info" in active_evidence_types:
        findings.append(
            signal_finding(
                file_info,
                "Document Info",
                file_info["file_name"],
                "file_signal_document_file_extension",
                "low",
                "Document file identified by extension.",
            )
        )

    if (
        extension in (IMAGE_EXTENSIONS | DOCUMENT_SIGNAL_EXTENSIONS)
        and "Identity Document File" in active_evidence_types
        and looks_like_identity_document_file_reference(file_info.get("file_name", ""))
    ):
        findings.append(
            signal_finding(
                file_info,
                "Identity Document File",
                file_info["file_name"],
                "documents_identity_document_file_reference",
                "medium",
                "Identity-document-like file name identified by extension and filename.",
            )
        )

    return findings


FILE_SIGNAL_PATTERN_NAMES = {
    "file_signal_image_file_extension",
    "file_signal_document_file_extension",
    "documents_identity_document_file_reference",
}


def is_labelled_record_line(line):
    stripped = line.lstrip()
    return stripped.startswith(("TABLE_ROW ", "XML_SCOPE ", "JSON_RECORD ", "JSONL_RECORD ", "XML_RECORD ", "YAML_RECORD "))


TABLE_HEADER_EVIDENCE_ALIASES = {
    "email": {"email", "institutional_email", "personal_email"},
    "dob": {"dob"},
    "gender": {"gender_sex"},
    "sex": {"gender_sex"},
    "nationality": {"citizenship_country"},
    "country": {"citizenship_country"},
    "religion": {"religion"},
    "disability": {"disability"},
    "ethnicity": {"ethnicity"},
    "phone": {"phone"},
    "payment_card": {"payment_card"},
    "sort_code": {"bank_account"},
    "account_number": {"bank_account"},
    "utr": {"tax_reference"},
    "national_insurance_number": {"national_insurance_number"},
    "nhs_number": {"nhs_number"},
    "passport": {"passport"},
    "driving_licence": {"driving_licence"},
    "cas_number": {"cas_number"},
    "husid": {"husid"},
    "slc_id": {"slc_id"},
    "ssn": {"student_ssn"},
    "student_ssn": {"student_ssn"},
}



CELL_VALUE_EMPTY_MARKERS = {
    "", "-", "--", "---", "n/a", "na", "n.k.", "nk", "none", "null",
    "not applicable", "not known", "unknown", "missing",
}


def table_emit_metadata_evidence_types(metadata):
    evidence_types = values_as_list(metadata.get("evidence_types"))
    evidence_types += values_as_list(metadata.get("evidence_type"))
    deduped = []
    seen = set()
    for evidence_type in evidence_types:
        evidence_type = safe_cell(evidence_type)
        key = rule_slug(evidence_type)
        if evidence_type and key not in seen:
            seen.add(key)
            deduped.append(evidence_type)
    return deduped


def table_emit_metadata_validators(metadata):
    validators = values_as_list(metadata.get("validators")) + values_as_list(metadata.get("validator"))
    resolved = []
    for validator_name in validators:
        validator = VALIDATORS.get(str(validator_name))
        if validator is not None:
            resolved.append(validator)
    return resolved


def plausible_sensitive_table_value(evidence_type, value):
    cleaned = safe_cell(value)
    if not cleaned:
        return False
    folded = re.sub(r"\s+", " ", cleaned.casefold()).strip()
    if folded in SENSITIVE_TABLE_EMPTY_VALUES:
        return False
    if evidence_type == "Gender/Sex":
        return bool(GENDER_VALUE_RE.fullmatch(cleaned))
    if evidence_type == "Religion":
        return valid_religion_value(cleaned)
    if evidence_type == "Ethnicity":
        return valid_ethnicity_value(cleaned)
    if evidence_type in {"Citizenship Country", "Citizenship/Country"}:
        return valid_citizenship_country_value(cleaned)
    if evidence_type == "Disability":
        return valid_disability_value(cleaned)
    if evidence_type == "Marital Status":
        return valid_marital_status_value(cleaned)
    return True


def valid_header_confirmed_cell_value(evidence_type, value, metadata):
    value = safe_cell(value)
    if value.casefold() in CELL_VALUE_EMPTY_MARKERS:
        return False
    if len(value) > int(metadata.get("max_cell_value_length", 500) or 500):
        return False
    # Person names and addresses are handled by the dedicated assemblers.  Do
    # not let opt-in table emission bypass the stricter name/address guards.
    if evidence_type in {"Name", "Address"}:
        return False
    validators = table_emit_metadata_validators(metadata)
    if validators and not all(validator(value) for validator in validators):
        return False
    if evidence_type == "DOB" and not validators and not valid_contextual_date(value):
        return False
    if evidence_type in SENSITIVE_TABLE_EMIT_TYPES and not validators and not plausible_sensitive_table_value(evidence_type, value):
        return False
    return True


def table_cell_value_emissions_from_labelled_fields(labelled_fields):
    """Emit evidence values from explicitly opted-in table-column rules.

    These are header-confirmed values, not free-text regex matches.  A table rule
    must set ``emit_cell_value: true`` and provide an ``evidence_type``.  This is
    intended for fields such as Ethnicity, Religion, Disability, Gender/Sex and
    Citizenship Country where the header is the reliable signal and enumerating
    every possible value in regex rules would be both brittle and noisy.
    """
    return table_cell_value_emissions_from_labelled_fields_with_schema(labelled_fields)


def actionable_schema_plan_decisions(schema_plan_rows):
    """Build a conservative header decision map from integrated schema-plan rows."""
    decisions = {"by_header": {}, "by_table_header": {}}
    action_rank = {
        "route_suggested_rules_and_emit_cell_value": 3,
        "route_suggested_rules_and_emit_review_cell_value": 3,
        "route_suggested_rules": 2,
    }
    for row in schema_plan_rows or []:
        action = safe_cell(row.get("scan_action"))
        if action not in action_rank:
            continue
        header = safe_cell(row.get("raw_header"))
        table_name = safe_cell(row.get("table_name"))
        header_origin = safe_cell(row.get("header_origin"))
        suggested_type = safe_cell(row.get("suggested_type"))
        if not header or not suggested_type:
            continue
        target_map = decisions["by_table_header"] if header_origin == "headerless_generic" else decisions["by_header"]
        key = (table_name, header) if target_map is decisions["by_table_header"] else header
        existing = target_map.get(key)
        if existing and action_rank.get(existing.get("scan_action"), 0) >= action_rank[action]:
            continue
        target_map[key] = {
            "suggested_type": suggested_type,
            "scan_action": action,
            "confidence": safe_cell(row.get("confidence")),
            "reason": safe_cell(row.get("reason")),
        }
    if not decisions["by_header"] and not decisions["by_table_header"]:
        return None
    return decisions


def labelled_table_name_from_line(line):
    match = re.match(r"TABLE_ROW\s+(.+?)\s+#\d+\s+\|", safe_cell(line))
    return match.group(1) if match else ""


def labelled_fields_are_generic_headerless(labelled_fields):
    return bool(labelled_fields) and all(
        re.fullmatch(r"column_\d+", safe_cell(header).casefold())
        for header, _value in labelled_fields
    )


def labelled_fields_have_schema_decision(labelled_fields, schema_plan_decisions=None, table_name=""):
    """Return whether any labelled field has an actionable integrated schema decision."""
    if not labelled_fields or not schema_plan_decisions:
        return False
    table_name = safe_cell(table_name)
    by_table_header = schema_plan_decisions.get("by_table_header", {})
    by_header = schema_plan_decisions.get("by_header", {})
    for header, _value in labelled_fields:
        header = safe_cell(header)
        if by_table_header.get((table_name, header)) or by_header.get(header):
            return True
    return False


def schema_decision_for_header(header, schema_plan_decisions=None, table_name=""):
    if not schema_plan_decisions:
        return None
    header = safe_cell(header)
    if not header:
        return None
    if "by_header" in schema_plan_decisions or "by_table_header" in schema_plan_decisions:
        table_key = (safe_cell(table_name), header)
        return (
            schema_plan_decisions.get("by_table_header", {}).get(table_key)
            or schema_plan_decisions.get("by_header", {}).get(header)
        )
    return schema_plan_decisions.get(header)


def scan_header_match(header, schema_plan_decisions=None, table_name=""):
    header_match = resolve_table_header_match(header)
    if header_match is not None:
        return header_match, "resolved"
    decision = schema_decision_for_header(header, schema_plan_decisions, table_name=table_name)
    if not decision:
        return None, ""
    suggested_type = decision.get("suggested_type", "")
    metadata = resolve_table_header_metadata(suggested_type)
    if not metadata:
        return None, ""
    return {
        "canonical_header": suggested_type,
        "metadata": metadata,
        "schema_plan_decision": decision,
    }, "schema_plan"


def table_cell_value_emissions_from_labelled_fields_with_schema(labelled_fields, schema_plan_decisions=None, table_name=""):
    """Emit header-confirmed values, including safe integrated schema-plan routes."""
    emissions = []
    seen = set()
    for header, value in labelled_fields:
        value = safe_cell(value)
        if not value:
            continue
        header_match, match_source = scan_header_match(header, schema_plan_decisions, table_name=table_name)
        if header_match is None:
            continue
        metadata = header_match.get("metadata", {})
        if not metadata_truthy(metadata.get("emit_cell_value")):
            continue
        pattern_name = metadata.get("pattern_name") or f"table_column_{rule_slug(header_match.get('canonical_header', header))}"
        confidence = metadata.get("confidence") or "high"
        for evidence_type in table_emit_metadata_evidence_types(metadata):
            if not valid_header_confirmed_cell_value(evidence_type, value, metadata):
                continue
            if match_source != "schema_plan" and not header_context_supports_guard(header, metadata.get("context_guard")):
                continue
            normalized = normalize_value(evidence_type, value)
            key = (evidence_type, normalized, pattern_name)
            if key in seen:
                continue
            seen.add(key)
            emissions.append({
                "evidence_type": evidence_type,
                "matched_text": value,
                "normalized_value": normalized,
                "pattern_name": pattern_name,
                "confidence": confidence,
            })
    return emissions


def assembled_bank_accounts_from_labelled_fields(labelled_fields):
    """Assemble UK bank-account evidence from paired table columns.

    The regex rule catches free-text phrases where a sort code and account
    number are written together. Real tables often split those into separate
    columns. In that case the row-level headers are the context, so only emit
    when both resolved headers are present in the same labelled record.
    """
    sort_codes = []
    account_numbers = []
    for header, value in labelled_fields:
        value = safe_cell(value)
        if not value:
            continue
        resolved_header = resolve_table_header(header)
        digits = digits_only(value)
        if resolved_header == "sort code" and len(digits) == 6 and len(set(digits)) > 1:
            sort_codes.append((value, digits))
        elif resolved_header == "account number" and len(digits) == 8 and len(set(digits)) > 1:
            account_numbers.append((value, digits))

    emissions = []
    seen = set()
    for sort_text, sort_digits in sort_codes:
        for account_text, account_digits in account_numbers:
            normalized = sort_digits + account_digits
            if normalized in seen:
                continue
            seen.add(normalized)
            emissions.append({
                "evidence_type": "Bank Account",
                "matched_text": f"{sort_text} {account_text}",
                "normalized_value": normalized,
                "pattern_name": "assembled_table_bank_account",
                "confidence": "high",
            })
    return emissions


def labelled_segment_header_value(segment):
    segment = safe_cell(segment)
    if ":" not in segment:
        return "", ""
    header, value = segment.split(":", 1)
    return safe_cell(header), safe_cell(value)


def labelled_segment_context_allows_guard(segment, context_guard):
    if not context_guard_enabled(context_guard):
        return True
    header, _value = labelled_segment_header_value(segment)
    if not header:
        return False
    return header_context_supports_guard(header, context_guard)


def pattern_context_allows_guard(segment, context_guard, is_labelled_scope=False):
    if not context_guard_enabled(context_guard):
        return True
    if is_labelled_scope:
        return labelled_segment_context_allows_guard(segment, context_guard)
    return header_context_supports_guard(segment, context_guard)


def table_pattern_relevant_to_header(pattern, header_match):
    """Return whether a resolved table column should run a regex rule."""
    canonical_header = header_match["canonical_header"]
    metadata = header_match.get("metadata", {})
    canonical_slug = rule_slug(canonical_header)
    evidence_slug = rule_slug(pattern.get("evidence_type", ""))

    configured_evidence_types = metadata.get("evidence_types", metadata.get("evidence_type", []))
    if isinstance(configured_evidence_types, str):
        configured_evidence_types = [configured_evidence_types]
    if evidence_slug in {rule_slug(value) for value in configured_evidence_types or []}:
        return True

    configured_pattern_names = metadata.get("pattern_names", metadata.get("pattern_name", []))
    if isinstance(configured_pattern_names, str):
        configured_pattern_names = [configured_pattern_names]
    if pattern.get("pattern_name") in set(configured_pattern_names or []):
        return True

    if evidence_slug == canonical_slug:
        return True
    if evidence_slug in TABLE_HEADER_EVIDENCE_ALIASES.get(canonical_slug, set()):
        return True

    canonical_lower = canonical_header.casefold()
    return any(trigger in canonical_lower for trigger in (pattern.get("line_triggers") or ()))


def unresolved_table_pattern_allowed(pattern):
    if pattern.get("labelled_fields_only"):
        return False
    if pattern.get("line_triggers"):
        return False
    evidence_type = pattern.get("evidence_type", "")
    if evidence_type == "Name" or evidence_type in SENSITIVE_CONTEXT:
        return False
    # Unresolved table fields keep raw fallback for standalone, non-contextual
    # identifiers such as emails, IPs, payment cards and validated IDs, while
    # blocking contextual/sensitive rules that depend on a trusted label.
    return True


def table_patterns_for_header(header):
    """Resolve and cache the regex rules relevant to one table header.

    ``None`` means that the header is unresolved and must use the complete raw
    regex fallback. A tuple (including an empty tuple) means it was resolved.
    """
    header = safe_cell(header)
    if header in TABLE_HEADER_PATTERN_CACHE:
        return TABLE_HEADER_PATTERN_CACHE[header]

    header_match = resolve_table_header_match(header)
    if header_match is None:
        patterns = None
    else:
        patterns = tuple(
            pattern for pattern in PATTERNS
            if table_pattern_relevant_to_header(pattern, header_match)
        )

    if len(TABLE_HEADER_PATTERN_CACHE) >= 512:
        TABLE_HEADER_PATTERN_CACHE.clear()
    TABLE_HEADER_PATTERN_CACHE[header] = patterns
    return patterns


def table_patterns_for_header_with_schema(header, schema_plan_decisions=None):
    header = safe_cell(header)
    if resolve_table_header_match(header) is not None or not schema_plan_decisions:
        return table_patterns_for_header(header)
    header_match, match_source = scan_header_match(header, schema_plan_decisions)
    if header_match is None or match_source != "schema_plan":
        return None
    return tuple(
        pattern for pattern in PATTERNS
        if table_pattern_relevant_to_header(pattern, header_match)
    )


def table_line_pattern_scopes(line, schema_plan_decisions=None):
    """Yield each routed rule with the original cell text and line offset."""
    return table_line_pattern_scopes_for_patterns(line, PATTERNS, schema_plan_decisions=schema_plan_decisions)


def table_line_pattern_scopes_for_patterns(line, patterns, schema_plan_decisions=None):
    first_separator = line.find("|")
    if first_separator < 0:
        return []
    table_name = labelled_table_name_from_line(line)

    scopes = []
    start = first_separator + 1
    line_length = len(line)
    while start < line_length:
        end = line.find("|", start)
        if end < 0:
            end = line_length
        content_start = start
        while content_start < end and line[content_start].isspace():
            content_start += 1
        content_end = end
        while content_end > content_start and line[content_end - 1].isspace():
            content_end -= 1
        segment = line[content_start:content_end]
        if ":" in segment:
            header, _value = segment.split(":", 1)
            header_match, _match_source = scan_header_match(header, schema_plan_decisions, table_name=table_name)
            if (
                schema_plan_decisions
                and header_match is None
                and re.fullmatch(r"column_\d+", safe_cell(header).casefold())
            ):
                start = end + 1
                continue
            relevant_patterns = (
                tuple(pattern for pattern in patterns if unresolved_table_pattern_allowed(pattern))
                if header_match is None
                else tuple(pattern for pattern in patterns if table_pattern_relevant_to_header(pattern, header_match))
            )
            scopes.append((segment, content_start, {id(pattern) for pattern in relevant_patterns}))
        start = end + 1

    routed = []
    for pattern in patterns:
        pattern_id = id(pattern)
        for segment, segment_start, pattern_ids in scopes:
            if pattern_id in pattern_ids:
                routed.append((pattern, segment, segment_start))
    return routed


def pattern_fingerprint(pattern):
    validator = pattern.get("validator")
    payload = {
        "pattern_name": pattern.get("pattern_name", ""),
        "evidence_type": pattern.get("evidence_type", ""),
        "confidence": pattern.get("confidence", ""),
        "regex": pattern["regex"].pattern,
        "flags": pattern["regex"].flags,
        "labelled_fields_only": bool(pattern.get("labelled_fields_only")),
        "line_triggers": list(pattern.get("line_triggers") or ()),
        "validator": getattr(validator, "__name__", "") if validator else "",
        "context_guard": context_guard_payload(pattern.get("context_guard")),
    }
    if pattern.get("evidence_type") == "Email":
        payload["email_suffix_patterns"] = list(EMAIL_SUFFIX)
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def current_rule_fingerprints():
    return {pattern["pattern_name"]: pattern_fingerprint(pattern) for pattern in PATTERNS}


def scan_source_unit_patterns(source_text, file_info, row_number, patterns, schema_plan_decisions=None):
    findings = []
    entity_counts = Counter()
    line = source_text or ""
    is_labelled_scope = is_labelled_record_line(line)
    if is_labelled_scope:
        pattern_scopes = table_line_pattern_scopes_for_patterns(line, patterns, schema_plan_decisions=schema_plan_decisions)
    else:
        lower_line = line.lower()
        pattern_scopes = []
        for pattern in patterns:
            triggers = pattern.get("line_triggers") or ()
            if triggers and not any(token in lower_line for token in triggers):
                continue
            pattern_scopes.append((pattern, line, 0))

    for pattern, pattern_text, pattern_offset in pattern_scopes:
        if pattern.get("labelled_fields_only") and not is_labelled_record_line(line):
            continue
        for match in pattern["regex"].finditer(pattern_text):
            matched_text, value_start, value_end = extract_match_value(match)
            if not validate_pattern_match(pattern, matched_text):
                continue
            evidence_type = evidence_type_for_match(pattern["evidence_type"], matched_text)
            if not pattern_context_allows_guard(pattern_text, pattern.get("context_guard"), is_labelled_scope):
                continue
            normalized = normalize_value(evidence_type, matched_text)
            entity_counts[evidence_type] += 1
            abs_start = pattern_offset + value_start
            abs_end = pattern_offset + value_end
            findings.append(
                {
                    "file_path": file_info["file_path"],
                    "file_name": file_info["file_name"],
                    "extension": file_info["extension"],
                    "size_bytes": file_info["size_bytes"],
                    "md5": file_info["md5"],
                    "row_number": row_number,
                    "evidence_type": evidence_type,
                    "matched_text": matched_text,
                    "normalized_value": normalized,
                    "start": abs_start,
                    "end": abs_end,
                    "context": clean_context(line, abs_start, abs_end),
                    "pattern_name": pattern["pattern_name"],
                    "confidence": pattern["confidence"],
                    "evidence_tier": evidence_tier(evidence_type, pattern["pattern_name"]),
                }
            )
    return findings, entity_counts


def scan_text(text, file_info, max_findings, progress_callback=None, progress_base=0.0, progress_span=100.0,
              schema_plan_decisions=None):
    findings = []
    candidates = []
    finding_count = 0
    finding_rows_written = 0
    candidate_count = 0
    cluster_excluded_count = 0
    cluster_exclusion_reasons = Counter()
    entity_counts = Counter()
    truncated_findings = False
    standalone_patterns = STANDALONE_PATTERNS
    line_trigger_index = LINE_TRIGGER_INDEX

    row_number_offset = int(file_info.get("row_number_offset") or 0)
    row_locator_prefix = str(file_info.get("row_locator_prefix") or "")

    def row_locator(local_row_number):
        value = row_number_offset + local_row_number
        if row_locator_prefix:
            return f"{row_locator_prefix}{value}"
        return value

    offset = 0
    total_chars = max(1, len(text or ""))
    last_progress = time.monotonic()
    for local_row_number, line in enumerate(iter_text_lines(text), start=1):
        if progress_callback:
            now = time.monotonic()
            if now - last_progress >= 1.0:
                progress_callback(progress_base + progress_span * min(1.0, offset / total_chars), "regex scanning")
                last_progress = now
        row_number = row_locator(local_row_number)
        line_findings = []
        line_patterns = list(standalone_patterns)
        line_finding_start = len(findings)
        labelled_table_name = labelled_table_name_from_line(line)

        labelled_fields = labelled_fields_from_line(line)
        generic_headerless = (
            is_labelled_record_line(line)
            and labelled_fields_are_generic_headerless(labelled_fields)
        )
        generic_headerless_has_schema = labelled_fields_have_schema_decision(
            labelled_fields,
            schema_plan_decisions,
            table_name=labelled_table_name,
        )
        generic_headerless_without_schema = (
            generic_headerless
            and not generic_headerless_has_schema
        )
        exact_matches = person_table_exact_candidates_from_line(line, labelled_fields)
        line_matched_person_tables = person_refs_to_table_stems(
            ref for exact_match in exact_matches for ref in exact_match.get("person_table_refs", set())
        )
        matched_person_tables_text = "|".join(line_matched_person_tables)
        address_matches = [] if generic_headerless_without_schema else assembled_addresses_from_labelled_line(line, labelled_fields)
        address_pattern_name = "assembled_table_address"

        authoritative_name_matches = authoritative_known_person_name_matches_from_exact_matches(exact_matches)
        if authoritative_name_matches:
            # Known-person row/scope: person-table identity is authoritative.
            # Emit the known person's own name(s), and only add extra values from
            # explicit full-name fields such as birth/maiden/legal/preferred name.
            name_matches = merge_name_match_rows(
                authoritative_name_matches,
                explicit_full_name_matches_from_labelled_fields(labelled_fields),
            )
            name_pattern_name = "person_table_authoritative_name"
        else:
            # Unknown/unmatched row/scope: fall back to the conservative table /
            # structured name assembler.  Unknown name columns will only have
            # been inferred when supported by several known person-table values,
            # or when the source header is explicitly a person-name header.
            name_matches = [] if generic_headerless_without_schema else assembled_names_from_labelled_line(line, labelled_fields)
            name_pattern_name = "assembled_table_name"

        for name_match_row in name_matches:
            evidence_type = "Name"
            matched_text = name_match_row["matched_text"]
            normalized = name_match_row["normalized_value"]
            entity_counts[evidence_type] += 1
            line_findings.append(
                {
                    "evidence_type": evidence_type,
                    "normalized_value": normalized,
                }
            )
            finding_count += 1

            if max_findings <= 0 or finding_rows_written < max_findings:
                value_offset = line.casefold().find(matched_text.casefold())
                if value_offset < 0:
                    value_offset = 0
                abs_start = offset + value_offset
                abs_end = min(len(text), abs_start + len(matched_text))
                finding_row = {
                    "file_path": file_info["file_path"],
                    "file_name": file_info["file_name"],
                    "extension": file_info["extension"],
                    "size_bytes": file_info["size_bytes"],
                    "md5": file_info["md5"],
                    "row_number": row_number,
                    "evidence_type": evidence_type,
                    "matched_text": matched_text,
                    "normalized_value": normalized,
                    "start": abs_start,
                    "end": abs_end,
                    "context": clean_context(text, abs_start, abs_end),
                    "pattern_name": name_pattern_name,
                    "confidence": name_match_row["confidence"],
                    "evidence_tier": evidence_tier(evidence_type, name_pattern_name),
                }
                findings.append(finding_row)
                finding_rows_written += 1
            else:
                truncated_findings = True

        for address_match in address_matches:
            evidence_type = "Address"
            matched_text = address_match["matched_text"]
            normalized = address_match["normalized_value"]
            entity_counts[evidence_type] += 1
            line_findings.append(
                {
                    "evidence_type": evidence_type,
                    "normalized_value": normalized,
                }
            )
            finding_count += 1

            if max_findings <= 0 or finding_rows_written < max_findings:
                postcode_offset = line.lower().find(address_match["postcode"].lower())
                if postcode_offset < 0:
                    compact_postcode = address_match["postcode"].replace(" ", "").lower()
                    postcode_offset = line.lower().replace(" ", "").find(compact_postcode)
                    if postcode_offset < 0:
                        postcode_offset = 0
                abs_start = offset + postcode_offset
                abs_end = min(len(text), abs_start + len(matched_text))
                finding_row = {
                    "file_path": file_info["file_path"],
                    "file_name": file_info["file_name"],
                    "extension": file_info["extension"],
                    "size_bytes": file_info["size_bytes"],
                    "md5": file_info["md5"],
                    "row_number": row_number,
                    "evidence_type": evidence_type,
                    "matched_text": matched_text,
                    "normalized_value": normalized,
                    "start": abs_start,
                    "end": abs_end,
                    "context": clean_context(text, abs_start, abs_end),
                    "pattern_name": address_pattern_name,
                    "confidence": address_match["confidence"],
                    "evidence_tier": evidence_tier(evidence_type, address_pattern_name),
                }
                findings.append(finding_row)
                finding_rows_written += 1
            else:
                truncated_findings = True

        for exact_match in exact_matches:
            evidence_type = exact_match["evidence_type"]
            matched_text = exact_match["matched_text"]
            normalized = exact_match["normalized_value"]
            entity_counts[evidence_type] += 1
            line_findings.append(
                {
                    "evidence_type": evidence_type,
                    "normalized_value": normalized,
                    "person_table_refs": set(exact_match.get("person_table_refs", set())),
                }
            )
            finding_count += 1

            if max_findings <= 0 or finding_rows_written < max_findings:
                abs_start = offset + int(exact_match.get("start", 0) or 0)
                abs_end = offset + int(exact_match.get("end", exact_match.get("start", 0)) or 0)
                finding_row = {
                    "file_path": file_info["file_path"],
                    "file_name": file_info["file_name"],
                    "extension": file_info["extension"],
                    "size_bytes": file_info["size_bytes"],
                    "md5": file_info["md5"],
                    "row_number": row_number,
                    "evidence_type": evidence_type,
                    "matched_text": matched_text,
                    "normalized_value": normalized,
                    "start": abs_start,
                    "end": abs_end,
                    "context": clean_context(text, abs_start, abs_end),
                    "pattern_name": PERSON_TABLE_EXACT_PATTERN_NAME,
                    "confidence": exact_match.get("confidence", "high"),
                    "evidence_tier": evidence_tier(evidence_type, PERSON_TABLE_EXACT_PATTERN_NAME),
                }
                findings.append(finding_row)
                finding_rows_written += 1
            else:
                truncated_findings = True

        table_emitted_keys = set()
        bank_account_matches = [] if generic_headerless_without_schema else assembled_bank_accounts_from_labelled_fields(labelled_fields)
        for bank_account in bank_account_matches:
            evidence_type = bank_account["evidence_type"]
            matched_text = bank_account["matched_text"]
            normalized = bank_account["normalized_value"]
            pattern_name = bank_account["pattern_name"]
            table_emitted_keys.add((evidence_type, normalized))
            entity_counts[evidence_type] += 1
            line_findings.append(
                {
                    "evidence_type": evidence_type,
                    "normalized_value": normalized,
                }
            )
            finding_count += 1

            if max_findings <= 0 or finding_rows_written < max_findings:
                sort_text = matched_text.split(" ", 1)[0]
                value_offset = line.casefold().find(sort_text.casefold())
                if value_offset < 0:
                    value_offset = line.casefold().find(matched_text.casefold())
                if value_offset < 0:
                    value_offset = 0
                abs_start = offset + value_offset
                abs_end = min(len(text), abs_start + len(matched_text))
                finding_row = {
                    "file_path": file_info["file_path"],
                    "file_name": file_info["file_name"],
                    "extension": file_info["extension"],
                    "size_bytes": file_info["size_bytes"],
                    "md5": file_info["md5"],
                    "row_number": row_number,
                    "evidence_type": evidence_type,
                    "matched_text": matched_text,
                    "normalized_value": normalized,
                    "start": abs_start,
                    "end": abs_end,
                    "context": clean_context(text, abs_start, abs_end),
                    "pattern_name": pattern_name,
                    "confidence": bank_account.get("confidence", "high"),
                    "evidence_tier": evidence_tier(evidence_type, pattern_name),
                }
                findings.append(finding_row)
                finding_rows_written += 1
            else:
                truncated_findings = True

        cell_emissions = [] if generic_headerless_without_schema else table_cell_value_emissions_from_labelled_fields_with_schema(labelled_fields, schema_plan_decisions, table_name=labelled_table_name)
        for cell_emission in cell_emissions:
            evidence_type = cell_emission["evidence_type"]
            matched_text = cell_emission["matched_text"]
            normalized = cell_emission["normalized_value"]
            pattern_name = cell_emission["pattern_name"]
            table_emitted_keys.add((evidence_type, normalized))
            entity_counts[evidence_type] += 1
            line_findings.append(
                {
                    "evidence_type": evidence_type,
                    "normalized_value": normalized,
                }
            )
            finding_count += 1

            if max_findings <= 0 or finding_rows_written < max_findings:
                value_offset = line.casefold().find(matched_text.casefold())
                if value_offset < 0:
                    value_offset = 0
                abs_start = offset + value_offset
                abs_end = min(len(text), abs_start + len(matched_text))
                finding_row = {
                    "file_path": file_info["file_path"],
                    "file_name": file_info["file_name"],
                    "extension": file_info["extension"],
                    "size_bytes": file_info["size_bytes"],
                    "md5": file_info["md5"],
                    "row_number": row_number,
                    "evidence_type": evidence_type,
                    "matched_text": matched_text,
                    "normalized_value": normalized,
                    "start": abs_start,
                    "end": abs_end,
                    "context": clean_context(text, abs_start, abs_end),
                    "pattern_name": pattern_name,
                    "confidence": cell_emission.get("confidence", "high"),
                    "evidence_tier": evidence_tier(evidence_type, pattern_name),
                }
                findings.append(finding_row)
                finding_rows_written += 1
            else:
                truncated_findings = True

        is_labelled_scope = is_labelled_record_line(line)
        if line_trigger_index and not is_labelled_scope:
            lower_line = line.lower()
            seen_triggered = set()
            for token, token_patterns in line_trigger_index:
                if token not in lower_line:
                    continue
                for pattern in token_patterns:
                    pattern_id = id(pattern)
                    if pattern_id in seen_triggered:
                        continue
                    seen_triggered.add(pattern_id)
                    line_patterns.append(pattern)

        if generic_headerless_without_schema:
            pattern_scopes = [(pattern, line, 0) for pattern in line_patterns]
        elif is_labelled_scope:
            pattern_scopes = table_line_pattern_scopes(line, schema_plan_decisions=schema_plan_decisions)
        else:
            pattern_scopes = [(pattern, line, 0) for pattern in line_patterns]

        for pattern, pattern_text, pattern_offset in pattern_scopes:
            if pattern.get("labelled_fields_only") and not is_labelled_record_line(line):
                continue
            for match in pattern["regex"].finditer(pattern_text):
                matched_text, value_start, value_end = extract_match_value(match)
                if not validate_pattern_match(pattern, matched_text):
                    continue

                evidence_type = evidence_type_for_match(pattern["evidence_type"], matched_text)
                if not pattern_context_allows_guard(pattern_text, pattern.get("context_guard"), is_labelled_scope):
                    continue
                normalized = normalize_value(evidence_type, matched_text)
                if (evidence_type, normalized) in table_emitted_keys:
                    continue
                entity_counts[evidence_type] += 1
                line_findings.append(
                    {
                        "evidence_type": evidence_type,
                        "normalized_value": normalized,
                    }
                )

                finding_count += 1

                if max_findings <= 0 or finding_rows_written < max_findings:
                    abs_start = offset + pattern_offset + value_start
                    abs_end = offset + pattern_offset + value_end
                    finding_row = {
                        "file_path": file_info["file_path"],
                        "file_name": file_info["file_name"],
                        "extension": file_info["extension"],
                        "size_bytes": file_info["size_bytes"],
                        "md5": file_info["md5"],
                        "row_number": row_number,
                        "evidence_type": evidence_type,
                        "matched_text": matched_text,
                        "normalized_value": normalized,
                        "start": abs_start,
                        "end": abs_end,
                        "context": clean_context(text, abs_start, abs_end),
                        "pattern_name": pattern["pattern_name"],
                        "confidence": pattern["confidence"],
                        "evidence_tier": evidence_tier(evidence_type, pattern["pattern_name"]),
                    }
                    findings.append(finding_row)
                    finding_rows_written += 1
                else:
                    truncated_findings = True

        if matched_person_tables_text:
            for finding in findings[line_finding_start:]:
                finding["matched_person_tables"] = matched_person_tables_text

        candidate = build_candidate(file_info, row_number, line, line_findings)
        if candidate is not None:
            candidates.append(candidate)
            candidate_count += 1
            if candidate.get("cluster_eligible") == "no":
                cluster_excluded_count += 1
                for reason in split_pipe_values(candidate.get("cluster_exclusion_reason", "")):
                    cluster_exclusion_reasons[reason] += 1

        offset += len(line)

    if progress_callback:
        progress_callback(progress_base + progress_span, "regex scanning")

    if truncated_findings:
        finding_row = {
            "file_path": file_info["file_path"],
            "file_name": file_info["file_name"],
            "extension": file_info["extension"],
            "size_bytes": file_info["size_bytes"],
            "md5": file_info["md5"],
            "row_number": "",
            "evidence_type": "SCAN_LIMIT",
            "matched_text": "",
            "normalized_value": "",
            "start": "",
            "end": "",
            "context": f"Finding output capped at {max_findings} rows for this file.",
            "pattern_name": "max_findings_per_file",
            "confidence": "info",
            "evidence_tier": "metadata",
            "matched_person_tables": "",
        }
        findings.append(finding_row)

    return (
        findings,
        candidates,
        finding_count,
        entity_counts,
        candidate_count,
        cluster_excluded_count,
        cluster_exclusion_reasons,
    )


def iter_text_lines(text):
    """Yield lines with endings using the fastest in-memory path.

    The scanner now keeps XML scope text in RAM by design. Using
    splitlines(True) avoids the previous repeated find("\r", start) scan,
    which became quadratic on large LF-only XML-derived scope text.
    """
    if not text:
        return
    for line in text.splitlines(True):
        yield line


def score_candidate(evidence_types):
    evidence = evidence_types if isinstance(evidence_types, set) else set(evidence_types)
    reasons = []
    has_email = has_email_evidence(evidence)
    has_id = has_id_evidence(evidence)
    has_name = has_risk_role(evidence, "name")
    has_dob = has_risk_role(evidence, "dob")
    has_phone = has_risk_role(evidence, "phone")
    has_address = has_risk_role(evidence, "address")

    if evidence & HIGH_RISK_STANDALONE:
        reasons.append("validated_or_contextual_strong_identifier")

    if (has_name and has_dob) or (has_email and has_dob):
        reasons.append("name_or_email_plus_dob")

    if has_id and (has_name or has_dob or has_phone or has_email):
        reasons.append("institutional_id_plus_identifying_detail")

    if (evidence & SENSITIVE_CONTEXT) and (evidence & IDENTIFIABLE_EVIDENCE):
        reasons.append("sensitive_attribute_plus_identifiable_person")

    if has_risk_role(evidence, "payment_card"):
        reasons.append("luhn_valid_payment_card")

    if (has_address and has_name) or (has_phone and has_email):
        reasons.append("supporting_contact_details_linked")

    if has_risk_role(evidence, "application_reference") and (has_name or has_id or has_email):
        reasons.append("application_reference_plus_applicant_context")

    if reasons and (
        "validated_or_contextual_strong_identifier" in reasons
        or "name_or_email_plus_dob" in reasons
        or "institutional_id_plus_identifying_detail" in reasons
        or "sensitive_attribute_plus_identifiable_person" in reasons
        or "luhn_valid_payment_card" in reasons
    ):
        return "high", "|".join(reasons)

    if reasons or len(evidence & TIER_1_EVIDENCE) >= 1:
        return "medium", "|".join(reasons or ["strong_identifier_without_linkage"])

    return "low", "weak_supporting_evidence_only"


def clustering_exclusion_reason(evidence_map):
    reasons = []

    for evidence_type in sorted(evidence_map):
        values = {value for value in evidence_map[evidence_type] if value}
        max_values = CLUSTER_MAX_VALUES_PER_EVIDENCE_TYPE.get(evidence_type)
        if max_values is None:
            continue

        value_count = len(values)
        if value_count > max_values:
            reasons.append(f"too_many_{rule_slug(evidence_type)}_values:{value_count}>{max_values}")

    return "|".join(reasons)


def build_candidate(file_info, row_number, source_row, line_findings):
    if not line_findings:
        return None

    exact_person_refs = set()
    for finding in line_findings:
        exact_person_refs.update(ref for ref in finding.get("person_table_refs", set()) if ref)
    if len(exact_person_refs) > 1:
        # Do not create a linked-evidence candidate from a source line/row that
        # contains exact person-table identifiers belonging to multiple known
        # rows. The raw evidence is still written, but clustering this line would
        # incorrectly merge different people.
        return None

    evidence_by_type = {}
    evidence_map = {}
    evidence_values = []
    seen = set()

    for finding in line_findings:
        evidence_type = finding["evidence_type"]
        normalized_value = finding["normalized_value"]
        evidence_by_type.setdefault(evidence_type, finding)
        evidence_map.setdefault(evidence_type, set()).add(normalized_value)
        key = (evidence_type, normalized_value)
        if key in seen:
            continue
        seen.add(key)
        evidence_values.append(f"{evidence_type}={normalized_value}")

    evidence_types_set = set(evidence_by_type)
    if len(evidence_types_set) == 1:
        evidence_type = next(iter(evidence_types_set))
        distinct_values = evidence_map.get(evidence_type, set())
        if evidence_type not in PERSON_CLUSTER_STRONG_ANCHORS or len(distinct_values) != 1:
            return None

    anchor = None
    for evidence_type in ANCHOR_PRIORITY:
        anchor = evidence_by_type.get(evidence_type)
        if anchor is not None:
            break

    if anchor is None:
        return None

    evidence_types = sorted(evidence_types_set)
    risk_level, risk_reasons = score_candidate(evidence_types_set)
    confidence = risk_level
    linked_evidence_key = f"{anchor['evidence_type']}:{anchor['normalized_value']}"
    cluster_exclusion_reason = clustering_exclusion_reason(evidence_map)

    return {
        "linked_evidence_key": linked_evidence_key,
        "file_path": file_info["file_path"],
        "file_name": file_info["file_name"],
        "extension": file_info["extension"],
        "row_number": row_number,
        "anchor_type": anchor["evidence_type"],
        "anchor_value": anchor["normalized_value"],
        "evidence_types": "|".join(evidence_types),
        "evidence_values": "|".join(evidence_values),
        "confidence": confidence,
        "risk_level": risk_level,
        "risk_reasons": risk_reasons,
        "cluster_eligible": "no" if cluster_exclusion_reason else "yes",
        "cluster_exclusion_reason": cluster_exclusion_reason,
        "source_row": " ".join(source_row.split())[:1000],
    }


def process_empty_folder(path):
    file_name = os.path.basename(path)
    return {
        "summary": summary_row(path, file_name, "", 0, "", "empty_folder", 0, 0, 0, ""),
        "errors": [],
        "findings": [],
        "finding_files": [],
        "candidates": [],
        "candidate_files": [],
        "candidate_count": 0,
        "entity_counts": Counter(),
        "entity_files": set(),
    }


def process_target(target, args):
    target_started_perf = time.perf_counter()
    target_started_wall = time.time()
    task_key = target_progress_key(target)
    file_path_for_progress = target_progress_path(target)
    emit_worker_progress(args, task_key, file_path_for_progress, "started", 0.0)

    emit_worker_progress(args, task_key, file_path_for_progress, "loading worker rules", 0.0)
    set_email_suffix(args.email_suffix)
    set_email_wildcards(getattr(args, "email_wildcard", []))
    set_nlp_mode(bool(
        getattr(args, "nlp", False)
        and getattr(args, "profile", "") not in {"standalone", "create_rules"}
    ))
    load_identity_anchor_config(args.rules)
    load_rules(args.rules)
    load_table_column_rules(args.rules)
    if getattr(args, "person_tables", None):
        emit_worker_progress(args, task_key, file_path_for_progress, "checking person-table index", 0.0)
    ensure_person_table_exact_match_index(
        args,
        progress_callback=lambda message: emit_worker_progress(
            args,
            task_key,
            file_path_for_progress,
            message,
            0.0,
        ),
    )
    target_type, path = target
    if target_type == "empty_folder":
        result = process_empty_folder(path)
    elif target_type == "scan_chunk":
        result = process_scan_chunk(path, args, task_key=task_key)
    else:
        result = process_file(path, args, task_key=task_key)

    finished_wall = time.time()
    result.setdefault("process_info", {
        "pid": os.getpid(),
        "task_key": task_key,
        "file_path": file_path_for_progress,
        "started_at_epoch": target_started_wall,
        "finished_at_epoch": finished_wall,
        "elapsed_seconds": time.perf_counter() - target_started_perf,
    })
    emit_worker_progress(args, task_key, file_path_for_progress, "complete", 100.0)
    return result


def should_hash_file(args, scan_extension):
    if args.hash_mode == "all":
        return True
    if args.hash_mode != "processed" or not processed_hash_eligible(args, scan_extension):
        return False
    return True


def processed_hash_eligible(args, scan_extension):
    if scan_extension not in SCAN_EXTRACTABLE_EXTENSIONS:
        return False
    return bool(args.scan_images) or scan_extension not in IMAGE_EXTENSIONS


def selected_file_hash_algorithm(args):
    value = safe_cell(getattr(args, "file_hash", "sha256") or "sha256").casefold()
    return "md5" if value == "md5" else "sha256"


def selected_content_hash(metadata, args):
    algorithm = selected_file_hash_algorithm(args)
    return safe_cell(metadata.get(algorithm) or "")


def hash_metadata_for_file(path, args, scan_extension, progress_callback=None, total_size=None, progress_base=5.0, progress_span=10.0, force=False):
    """Return hash metadata for a file according to --hash-mode/--file-hash."""
    algorithm = selected_file_hash_algorithm(args)
    metadata = {"md5": "", "sha256": ""}
    if not force and not should_hash_file(args, scan_extension):
        return metadata
    digest = hash_file(
        path,
        algorithm,
        progress_callback=progress_callback,
        total_size=total_size,
        progress_base=progress_base,
        progress_span=progress_span,
    )
    metadata[algorithm] = digest
    return metadata


def jsonl_lines_to_labelled_text(lines, start_line, max_depth=12, max_records=0, max_fields=400):
    records = []
    parsed_any = False
    raw_text = "".join(lines)
    for offset, line in enumerate(lines):
        if max_records and len(records) >= max_records:
            break
        line_number = start_line + offset
        stripped = line.strip()
        if not stripped:
            continue
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        parsed_any = True
        emitted = structured_emit_records(
            data,
            ["$", f"[{line_number}]"],
            "JSONL_RECORD",
            max_depth=max_depth,
            max_records=max(0, max_records - len(records)) if max_records else 0,
            max_fields=max_fields,
        )
        records.extend(emitted)
        if not emitted:
            fields = structured_all_scalar_fields(data, ["$", f"[{line_number}]"], max_depth)
            if structured_evidence_score(fields)[2] >= 2:
                fallback = structured_fields_to_line("JSONL_RECORD", f"$[{line_number}]", fields[:max_fields])
                if fallback:
                    records.append(fallback)
    if records:
        return "\n".join(records), "jsonl_chunk_structured_records"
    if parsed_any:
        return raw_text, "plain_jsonl_chunk_text"
    return raw_text, "plain_text_chunk"


def xml_elements_to_labelled_text(element_xml_values, root_tag, max_depth=12, max_records=0, max_fields=400):
    import xml.etree.ElementTree as ET

    records = []
    for element_xml in element_xml_values:
        if max_records and len(records) >= max_records:
            break
        element = ET.fromstring(element_xml)
        data = {root_tag: {element.tag: xml_element_to_structured_data(element)}}
        text = structured_data_to_labelled_text(
            data,
            "XML_RECORD",
            max_depth=max_depth,
            max_records=max(0, max_records - len(records)) if max_records else 0,
            max_fields=max_fields,
        )
        if text:
            records.append(text)
    return "\n".join(records), "xml_chunk_structured_records"


def xml_records_to_labelled_text(record_values, root_tag, max_depth=12, max_records=0, max_fields=400):
    records = []
    for element_tag, element_data in record_values:
        if max_records and len(records) >= max_records:
            break
        data = {root_tag: {element_tag: element_data}}
        text = structured_data_to_labelled_text(
            data,
            "XML_RECORD",
            max_depth=max_depth,
            max_records=max(0, max_records - len(records)) if max_records else 0,
            max_fields=max_fields,
        )
        if text:
            records.append(text)
    return "\n".join(records), "xml_chunk_structured_records"


def process_scan_chunk(chunk, args, task_key=""):
    started = time.perf_counter()
    timings = {
        "hash_seconds": 0.0,
        "extraction_seconds": 0.0,
        "regex_seconds": 0.0,
    }

    def finish_result(result):
        summary = result.get("summary")
        if summary is not None:
            for field in (
                "sha256",
                "duplicate_content_group",
                "duplicate_content_index",
                "duplicate_of",
                "duplicate_path_count",
                "duplicate_paths",
                "duplicate_content_action",
            ):
                if chunk.get(field) and not summary.get(field):
                    summary[field] = chunk.get(field)
        result["result_kind"] = "scan_chunk"
        result["chunk_index"] = chunk.get("chunk_index", 0)
        result["final_chunk"] = bool(chunk.get("final_chunk"))
        if chunk.get("expected_chunk_count"):
            result["expected_chunk_count"] = chunk["expected_chunk_count"]
        result["timings"] = dict(timings)
        result["timings"]["worker_total_seconds"] = time.perf_counter() - started
        return result

    path = chunk["file_path"]
    profile_mode = canonical_profile_mode(getattr(args, "profile", ""))
    global_schema_plan_decisions = getattr(args, "schema_plan_decisions", None)
    worker_profile_enabled = is_stage1_profile_mode(profile_mode) and not global_schema_plan_decisions
    integrated_profile_enabled = profile_mode == "integrated" and not global_schema_plan_decisions

    def progress(percent, stage):
        emit_worker_progress(args, task_key, path, stage, percent)

    local_profile_result_data = None
    schema_plan_decisions = global_schema_plan_decisions

    def attach_worker_profile(result, labelled_text):
        if not worker_profile_enabled:
            return result
        if integrated_profile_enabled and local_profile_result_data is not None:
            result.update(local_profile_result_data)
            return result
        progress(96.0, "profiling")
        result.update(profile_scan_chunk_local(chunk, labelled_text, args))
        progress(99.0, "profiling complete")
        return result

    progress(5.0, "preparing chunk")
    file_info = {
        "file_path": path,
        "file_name": chunk.get("file_name") or os.path.basename(path),
        "extension": str(chunk.get("extension") or os.path.splitext(path)[1].lstrip(".")),
        "size_bytes": chunk.get("size_bytes") or 0,
        "md5": chunk.get("md5") or "",
        "sha256": chunk.get("sha256") or "",
        "row_number_offset": chunk.get("row_number_offset") or 0,
        "row_locator_prefix": chunk.get("row_locator_prefix") or "",
    }
    extraction_started = time.perf_counter()
    try:
        chunk_type = chunk.get("chunk_type")
        if chunk_type == "jsonl":
            text, read_status = jsonl_lines_to_labelled_text(
                chunk.get("lines", []),
                chunk.get("start_line", 1),
                max_depth=args.structured_max_depth,
                max_records=args.structured_max_records_per_file,
                max_fields=args.structured_max_record_fields,
            )
        elif chunk_type == "delimited":
            text = table_rows_to_labelled_text(
                chunk.get("headers", []),
                chunk.get("rows", []),
                chunk.get("table_name") or file_info["file_name"],
            )
            read_status = "labelled_delimited_table_chunk" if text else "delimited_empty_chunk"
        elif chunk_type == "xml":
            if "records" in chunk:
                text, read_status = xml_records_to_labelled_text(
                    chunk.get("records", []),
                    chunk.get("root_tag") or "root",
                    max_depth=args.structured_max_depth,
                    max_records=args.structured_max_records_per_file,
                    max_fields=args.structured_max_record_fields,
                )
            else:
                text, read_status = xml_elements_to_labelled_text(
                    chunk.get("elements", []),
                    chunk.get("root_tag") or "root",
                    max_depth=args.structured_max_depth,
                    max_records=args.structured_max_records_per_file,
                    max_fields=args.structured_max_record_fields,
                )
        else:
            text = chunk.get("text", "")
            read_status = "plain_text_chunk"
    except Exception as exc:
        timings["extraction_seconds"] = time.perf_counter() - extraction_started
        error = f"{type(exc).__name__}: {exc}"
        return finish_result({
            "summary": summary_row(
                path,
                file_info["file_name"],
                file_info["extension"],
                file_info["size_bytes"],
                file_info["md5"],
                "chunk_extraction_error",
                0,
                0,
                0,
                error,
                detected_extension=chunk.get("detected_extension") or file_info["extension"],
                sha256=file_info["sha256"],
            ),
            "errors": [error_row(path, file_info["file_name"], file_info["extension"], file_info["size_bytes"], "chunk_extraction_error", error)],
            "findings": [],
            "finding_files": [],
            "candidates": [],
            "candidate_files": [],
            "candidate_count": 0,
            "entity_counts": Counter(),
            "entity_files": set(),
        })
    timings["extraction_seconds"] = time.perf_counter() - extraction_started
    progress(25.0, "chunk extracted")

    if integrated_profile_enabled:
        progress(25.0, "integrated profiling")
        local_profile_result_data = profile_scan_chunk_local(chunk, text, args)
        schema_plan_decisions = actionable_schema_plan_decisions(local_profile_result_data.get("schema_plan"))
        progress(30.0, "schema plan ready")
    elif schema_plan_decisions:
        progress(30.0, "schema plan ready")

    regex_progress_base = 30.0 if (integrated_profile_enabled or schema_plan_decisions) else 25.0
    progress(regex_progress_base, "regex scanning")
    regex_started = time.perf_counter()
    (
        findings,
        candidates,
        finding_count,
        entity_counts,
        candidate_count,
        cluster_excluded_count,
        cluster_exclusion_reasons,
    ) = scan_text(
        text,
        file_info,
        args.max_findings_per_file,
        progress_callback=progress,
        progress_base=regex_progress_base,
        progress_span=65.0 if (integrated_profile_enabled or schema_plan_decisions) else 70.0,
        schema_plan_decisions=schema_plan_decisions,
    )
    timings["regex_seconds"] = time.perf_counter() - regex_started
    progress(95.0, "regex complete")

    summary = summary_row(
        path,
        file_info["file_name"],
        file_info["extension"],
        file_info["size_bytes"],
        file_info["md5"],
        read_status,
        len(text),
        finding_count,
        candidate_count,
        "",
        detected_extension=chunk.get("detected_extension") or file_info["extension"],
        sha256=file_info["sha256"],
    )
    add_summary_cluster_exclusion_counts(summary, cluster_excluded_count, cluster_exclusion_reasons)
    return finish_result(attach_worker_profile({
        "summary": summary,
        "errors": [],
        "findings": findings,
        "finding_files": [],
        "candidates": candidates,
        "candidate_files": [],
        "candidate_count": candidate_count,
        "entity_counts": entity_counts,
        "entity_files": set(entity_counts),
    }, text))



# -----------------------------------------------------------------------------
# Fast XML anchor-scope scan
# -----------------------------------------------------------------------------

XML_TOKEN_RE = re.compile(r"(?s)<[^>]+>|[^<]+")
XML_START_TAG_RE = re.compile(r"<\s*([A-Za-z_][A-Za-z0-9_.:-]*)")
XML_END_TAG_RE = re.compile(r"<\s*/\s*([A-Za-z_][A-Za-z0-9_.:-]*)")
XML_ATTR_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_.:-]*)\s*=\s*(['\"])(.*?)\2", re.S)


def xml_local_name(tag):
    tag = safe_cell(tag)
    if not tag:
        return "node"
    if tag.startswith("{") and "}" in tag:
        tag = tag.split("}", 1)[1]
    if ":" in tag:
        tag = tag.rsplit(":", 1)[1]
    return tag or "node"


def xml_clean_value(value, max_chars=None):
    value = unescape(safe_cell(value))
    if max_chars and int(max_chars) > 0 and len(value) > int(max_chars):
        return value[:int(max_chars)] + " ...[truncated]"
    return value


def xml_anchor_patterns():
    """Return cheap regex patterns used only to detect identity-bearing XML scopes."""
    anchor_types = set(identity_anchor_evidence_types()) | set(ANCHOR_PRIORITY)
    patterns = []
    for pattern in PATTERNS:
        evidence_type = pattern.get("evidence_type", "")
        expanded = set(identity_anchor_aliases(evidence_type)) | {evidence_type}
        if expanded & anchor_types:
            patterns.append(pattern)
    return patterns or list(STANDALONE_PATTERNS)


def xml_anchor_match_count(text_value, patterns):
    """Count validated identity-anchor matches in a small text or attribute value."""
    if not text_value:
        return 0
    lower_text = text_value.lower()
    count = 0
    anchor_types = set(identity_anchor_evidence_types()) | set(ANCHOR_PRIORITY)
    for pattern in patterns:
        triggers = pattern.get("line_triggers") or ()
        if triggers and not any(token in lower_text for token in triggers):
            continue
        for match in pattern["regex"].finditer(text_value):
            matched_text, _value_start, _value_end = extract_match_value(match)
            if not validate_pattern_match(pattern, matched_text):
                continue
            evidence_type = evidence_type_for_match(pattern["evidence_type"], matched_text)
            if evidence_type in anchor_types or pattern.get("evidence_type") in anchor_types:
                count += 1
    return count


def xml_evidence_match_count(label, text_value):
    """Count validated configured-rule matches for an XML field.

    XML fields are routed through the same header-aware path as TABLE_ROW
    segments: resolved headers use relevant rules, unresolved headers fall back
    to the full pattern set. This makes XML_SCOPE evidence detection consistent
    with table-row evidence detection while avoiding full XML parsing.
    """
    if not text_value:
        return 0
    segment = f"{label}: {text_value}"
    patterns = table_patterns_for_header(label)
    if patterns is None:
        patterns = PATTERNS
    lower_segment = segment.lower()
    count = len(table_cell_value_emissions_from_labelled_fields([(label, text_value)]))
    for pattern in patterns:
        triggers = pattern.get("line_triggers") or ()
        if triggers and not any(token in lower_segment for token in triggers):
            continue
        if pattern.get("labelled_fields_only") and not is_labelled_record_line("XML_SCOPE " + segment):
            continue
        for match in pattern["regex"].finditer(segment):
            matched_text, _value_start, _value_end = extract_match_value(match)
            if not validate_pattern_match(pattern, matched_text):
                continue
            if not labelled_segment_context_allows_guard(segment, pattern.get("context_guard")):
                continue
            count += 1
    return count


def xml_scope_field_label(path_parts):
    clean_parts = [xml_local_name(part) for part in path_parts if safe_cell(part)]
    if not clean_parts:
        return "value"
    # Keep enough path context for header routing while avoiding very long labels.
    return ".".join(clean_parts[-4:])


def build_xml_evidence_scope_text_in_memory(
    path,
    *,
    max_fields=200,
):
    """Build table-like XML_SCOPE lines from raw XML text using no XML tree parser.

    The algorithm is deliberately simple and fast:
    - read the XML file fully into memory;
    - tokenise tags/text with regex;
    - maintain a lightweight tag stack;
    - mark ancestor scopes when any configured regex class is detected;
    - separately count rule-defined identity anchors;
    - emit the nearest evidence-bearing scope as an XML_SCOPE labelled line;
    - downstream scan_text() applies the same TABLE_ROW/XML_SCOPE scan and
      build_candidate() logic. This preserves all configured regex evidence while
      only creating person-linked rows when the scope contains a valid anchor.
    """
    raw = Path(path).read_bytes()
    if is_binary_like(raw):
        return "", "", 0, 0, 0, 0
    xml_text = decode_text_bytes(raw)
    anchor_patterns = xml_anchor_patterns()
    max_fields = max(1, int(max_fields or 200))

    frames = []
    scope_lines = []
    scope_counter = 0
    anchor_hit_count = 0
    evidence_hit_count = 0
    field_count = 0

    def append_field(path_parts, value):
        nonlocal anchor_hit_count, evidence_hit_count, field_count
        value = xml_clean_value(value, None)
        if not value or not frames:
            return
        label = xml_scope_field_label(path_parts)
        field_count += 1
        anchor_hits = xml_anchor_match_count(value, anchor_patterns)
        evidence_hits = xml_evidence_match_count(label, value)
        exact_hits = person_table_exact_match_count_for_value(value)
        if exact_hits:
            anchor_hits += exact_hits
            evidence_hits += exact_hits
        if anchor_hits:
            anchor_hit_count += anchor_hits
        if evidence_hits:
            evidence_hit_count += evidence_hits
        field = (label, value)
        for frame in frames:
            if len(frame["fields"]) < max_fields:
                frame["fields"].append(field)
            if evidence_hits:
                frame["has_evidence"] = True
                frame["evidence_hits"] += evidence_hits
            if exact_hits:
                frame["has_person_table_exact"] = True
            if anchor_hits:
                frame["has_anchor"] = True
                frame["anchor_hits"] += anchor_hits

    def emit_frame_if_candidate(frame):
        nonlocal scope_counter
        if frame.get("child_emitted"):
            return False
        if not frame.get("has_evidence"):
            return False
        fields = frame.get("fields", [])
        if not fields:
            return False
        if frame.get("has_person_table_exact") and len(fields) <= 1 and frames:
            # For exact person-table matches in XML, prefer the containing
            # record/scope over a single leaf node so co-located identifiers in
            # the same XML record can link together.
            return False
        scope_counter += 1
        path_label = "/" + "/".join(frame.get("path", []))
        parts = [f"XML_SCOPE {scope_counter} path: {path_label}"]
        seen = set()
        for label, value in fields[:max_fields]:
            key = (label, value)
            if key in seen:
                continue
            seen.add(key)
            parts.append(f"{label}: {value}")
        scope_lines.append(" | ".join(parts))
        return True

    def close_frame(expected_tag=None):
        if not frames:
            return
        if expected_tag:
            expected = xml_local_name(expected_tag).casefold()
            # Recover from simple malformed/mismatched XML by popping until a matching tag.
            while len(frames) > 1 and frames[-1]["tag"].casefold() != expected:
                orphan = frames.pop()
                emitted = emit_frame_if_candidate(orphan)
                if emitted or orphan.get("child_emitted"):
                    frames[-1]["child_emitted"] = True
            if frames and frames[-1]["tag"].casefold() != expected:
                # Still mismatched; close the current frame rather than failing.
                pass
        frame = frames.pop()
        emitted = emit_frame_if_candidate(frame)
        if frames and (emitted or frame.get("child_emitted")):
            frames[-1]["child_emitted"] = True

    for match in XML_TOKEN_RE.finditer(xml_text):
        token = match.group(0)
        if not token:
            continue
        if token.startswith("<"):
            if token.startswith("<![CDATA[") and token.endswith("]]>"):
                append_field([frame["tag"] for frame in frames] + ["cdata"], token[9:-3])
                continue
            if token.startswith(("<?", "<!--", "<!")):
                continue
            end_match = XML_END_TAG_RE.match(token)
            if end_match:
                close_frame(end_match.group(1))
                continue
            start_match = XML_START_TAG_RE.match(token)
            if not start_match:
                continue
            tag = xml_local_name(start_match.group(1))
            parent_path = frames[-1]["path"] if frames else []
            frame = {
                "tag": tag,
                "path": parent_path + [tag],
                "fields": [],
                "has_evidence": False,
                "evidence_hits": 0,
                "has_anchor": False,
                "anchor_hits": 0,
                "child_emitted": False,
                "has_person_table_exact": False,
            }
            frames.append(frame)
            for attr_name, _quote, attr_value in XML_ATTR_RE.findall(token):
                attr_path = frame["path"] + ["@" + xml_local_name(attr_name)]
                append_field(attr_path, attr_value)
            stripped = token.rstrip()
            if stripped.endswith("/>"):
                close_frame(tag)
            continue

        # Text node.
        if frames:
            append_field(frames[-1]["path"], token)

    while frames:
        close_frame()

    return xml_text, "\n".join(scope_lines), scope_counter, anchor_hit_count, evidence_hit_count, field_count


def scan_xml_scope_text_in_batches(text, file_info, max_findings, batch_lines=1000, progress_callback=None, progress_base=0.0,
                                   progress_span=100.0, schema_plan_decisions=None):
    """Scan XML_SCOPE labelled lines in bounded batches to avoid large-text slowdown.

    This preserves the same TABLE_ROW/XML_SCOPE co-localisation path used by
    scan_text(), but avoids passing a very large XML_SCOPE string through one
    monolithic scan. Row locators remain stable by offsetting each batch.
    """
    findings = []
    candidates = []
    finding_count = 0
    entity_counts = Counter()
    candidate_count = 0
    cluster_excluded_count = 0
    cluster_exclusion_reasons = Counter()

    batch = []
    batch_start = 1
    processed = 0
    batch_lines = max(1, int(batch_lines or 1000))

    def flush_batch():
        nonlocal findings, candidates, finding_count, entity_counts, candidate_count
        nonlocal cluster_excluded_count, cluster_exclusion_reasons, batch, batch_start
        if not batch:
            return
        batch_text = "".join(batch)
        batch_info = dict(file_info)
        batch_info["row_number_offset"] = batch_start - 1
        # Keep max_findings simple: the default unlimited path is the speed path.
        batch_max = 0 if not max_findings else max(1, int(max_findings))
        (
            batch_findings,
            batch_candidates,
            batch_finding_count,
            batch_entity_counts,
            batch_candidate_count,
            batch_cluster_excluded_count,
            batch_cluster_exclusion_reasons,
        ) = scan_text(batch_text, batch_info, batch_max, schema_plan_decisions=schema_plan_decisions)
        findings.extend(batch_findings)
        candidates.extend(batch_candidates)
        finding_count += batch_finding_count
        entity_counts.update(batch_entity_counts)
        candidate_count += batch_candidate_count
        cluster_excluded_count += batch_cluster_excluded_count
        cluster_exclusion_reasons.update(batch_cluster_exclusion_reasons)
        batch = []

    total_lines = max(1, text.count("\n") + 1)
    last_progress = time.monotonic()
    for line in iter_text_lines(text):
        processed += 1
        if progress_callback:
            now = time.monotonic()
            if now - last_progress >= 1.0:
                progress_callback(progress_base + progress_span * min(1.0, processed / total_lines), "regex scanning")
                last_progress = now
        if not batch:
            batch_start = processed
        batch.append(line)
        if len(batch) >= batch_lines:
            flush_batch()
    flush_batch()
    if progress_callback:
        progress_callback(progress_base + progress_span, "regex scanning")

    if max_findings and len(findings) > max_findings:
        findings = findings[:max_findings]

    return (
        findings,
        candidates,
        finding_count,
        entity_counts,
        candidate_count,
        cluster_excluded_count,
        cluster_exclusion_reasons,
    )


def process_file(path, args, task_key=""):
    started = time.perf_counter()
    timings = {
        "hash_seconds": 0.0,
        "extraction_seconds": 0.0,
        "regex_seconds": 0.0,
    }

    def finish_result(result):
        try:
            metadata = precomputed_metadata
        except NameError:
            metadata = {}
        summary = result.get("summary")
        if summary is not None and metadata:
            for field in (
                "sha256",
                "duplicate_content_group",
                "duplicate_content_index",
                "duplicate_of",
                "duplicate_path_count",
                "duplicate_paths",
                "duplicate_content_action",
            ):
                if metadata.get(field) and not summary.get(field):
                    summary[field] = metadata.get(field)
        result["timings"] = dict(timings)
        result["timings"]["worker_total_seconds"] = time.perf_counter() - started
        return result

    def progress(percent, stage):
        emit_worker_progress(args, task_key, path, stage, percent)

    progress(1.0, "starting")
    profile_mode = canonical_profile_mode(getattr(args, "profile", ""))
    global_schema_plan_decisions = getattr(args, "schema_plan_decisions", None)
    worker_profile_enabled = is_stage1_profile_mode(profile_mode) and not global_schema_plan_decisions
    integrated_profile_enabled = profile_mode == "integrated" and not global_schema_plan_decisions

    file_name = os.path.basename(path)
    extension = os.path.splitext(file_name)[1].lower()
    precomputed_metadata = getattr(args, "precomputed_file_metadata", {}).get(path, {})
    detected_extension = extension
    size_bytes = ""

    progress(3.0, "reading file metadata")
    try:
        size_bytes = precomputed_metadata.get("size_bytes") or os.path.getsize(path)
    except OSError as exc:
        return finish_result({
            "summary": summary_row(path, file_name, extension, size_bytes, "", "stat_error", 0, 0, 0, str(exc)),
            "errors": [error_row(path, file_name, extension, size_bytes, "stat_error", str(exc))],
            "findings": [],
            "finding_files": [],
            "candidates": [],
            "candidate_files": [],
            "candidate_count": 0,
            "entity_counts": Counter(),
            "entity_files": set(),
        })

    progress(5.0, "detecting content type")
    detected_extension = precomputed_metadata.get("detected_extension") or detect_extension_from_content(path, extension)
    scan_extension = detected_extension or extension
    progress(8.0, "content type ready")
    md5 = precomputed_metadata.get("md5") or ""
    sha256 = precomputed_metadata.get("sha256") or ""

    if scan_extension not in SCAN_EXTRACTABLE_EXTENSIONS and scan_extension not in LEGACY_UNSUPPORTED_DOCUMENT_EXTENSIONS:
        message = "Skipped because neither the extension nor content signature matched a configured text/document/image extractor."
        return finish_result({
            "summary": summary_row(
                path,
                file_name,
                extension,
                size_bytes,
                "",
                "skipped_extension",
                0,
                0,
                0,
                message,
                detected_extension=scan_extension,
                sha256=sha256,
            ),
            "errors": [],
            "findings": [],
            "finding_files": [],
            "candidates": [],
            "candidate_files": [],
            "candidate_count": 0,
            "entity_counts": Counter(),
            "entity_files": set(),
        })

    hash_started = time.perf_counter()
    hash_performed = False
    try:
        if not selected_content_hash({"md5": md5, "sha256": sha256}, args) and should_hash_file(args, scan_extension):
            hash_performed = True
            hash_metadata = hash_metadata_for_file(
                path,
                args,
                scan_extension,
                progress_callback=progress,
                total_size=size_bytes,
                progress_base=5.0,
                progress_span=10.0,
            )
            md5 = hash_metadata.get("md5") or md5
            sha256 = hash_metadata.get("sha256") or sha256
    except OSError as exc:
        timings["hash_seconds"] = time.perf_counter() - hash_started
        return finish_result({
            "summary": summary_row(
                path,
                file_name,
                extension,
                size_bytes,
                "",
                "hash_error",
                0,
                0,
                0,
                str(exc),
                detected_extension=scan_extension,
            ),
            "errors": [error_row(path, file_name, extension, size_bytes, "hash_error", str(exc))],
            "findings": [],
            "finding_files": [],
            "candidates": [],
            "candidate_files": [],
            "candidate_count": 0,
            "entity_counts": Counter(),
            "entity_files": set(),
        })
    timings["hash_seconds"] = time.perf_counter() - hash_started
    progress(15.0, "hash complete" if hash_performed else "hash skipped")

    file_info = {
        "file_path": path,
        "file_name": file_name,
        "extension": extension.lstrip("."),
        "size_bytes": size_bytes,
        "md5": md5,
        "sha256": sha256,
    }

    local_profile_result_data = None
    schema_plan_decisions = global_schema_plan_decisions

    def build_integrated_schema_plan(detected_extension="", labelled_text=""):
        nonlocal local_profile_result_data, schema_plan_decisions
        if not integrated_profile_enabled:
            return
        progress(60.0, "integrated profiling")
        local_profile_result_data = profile_scanned_content_local(
            path,
            detected_extension or scan_extension or extension,
            labelled_text,
            args,
            known_md5=md5,
            known_hash=sha256 or md5,
        )
        schema_plan_decisions = actionable_schema_plan_decisions(local_profile_result_data.get("schema_plan"))
        progress(62.0, "schema plan ready")

    def attach_worker_profile(result, detected_extension="", labelled_text=""):
        if not worker_profile_enabled:
            return result
        if integrated_profile_enabled and local_profile_result_data is not None:
            result.update(local_profile_result_data)
            return result
        progress(96.0, "profiling")
        result.update(
            profile_scanned_content_local(
                path,
                detected_extension or scan_extension or extension,
                labelled_text,
                args,
                known_md5=md5,
                known_hash=sha256 or md5,
            )
        )
        progress(99.0, "profiling complete")
        return result

    signal_findings = file_signal_findings(file_info, scan_extension)
    signal_counts = Counter(f["evidence_type"] for f in signal_findings)

    if scan_extension in LEGACY_UNSUPPORTED_DOCUMENT_EXTENSIONS:
        message = "Unsupported legacy/binary document format; convert to a parser-supported format or run a specialist extractor first."
        findings = signal_findings
        return finish_result({
            "summary": summary_row(
                path,
                file_name,
                extension,
                size_bytes,
                md5,
                "unsupported_extension",
                0,
                len(signal_findings),
                0,
                message,
                detected_extension=scan_extension,
            ),
            "errors": [error_row(path, file_name, extension, size_bytes, "unsupported_extension", message)],
            "findings": findings,
            "finding_files": [],
            "candidates": [],
            "candidate_files": [],
            "candidate_count": 0,
            "entity_counts": signal_counts,
            "entity_files": set(signal_counts),
        })

    if scan_extension == ".xml" and getattr(args, "xml_scan", "fast") == "fast":
        progress(20.0, "building XML scopes")
        extraction_started = time.perf_counter()
        try:
            raw_xml_text, text, xml_scope_count, xml_anchor_hit_count, xml_evidence_hit_count, xml_field_count = build_xml_evidence_scope_text_in_memory(
                path,
                max_fields=args.xml_max_fields,
            )
        except Exception as exc:
            timings["extraction_seconds"] = time.perf_counter() - extraction_started
            error = f"{type(exc).__name__}: {exc}"
            findings = signal_findings
            return finish_result({
                "summary": summary_row(
                    path,
                    file_name,
                    extension,
                    size_bytes,
                    md5,
                    "xml_evidence_scope_error",
                    0,
                    len(signal_findings),
                    0,
                    error,
                    detected_extension=scan_extension,
                    sha256=sha256,
                ),
                "errors": [error_row(path, file_name, extension, size_bytes, "xml_evidence_scope_error", error)],
                "findings": findings,
                "finding_files": [],
                "candidates": [],
                "candidate_files": [],
                "candidate_count": 0,
                "entity_counts": signal_counts,
                "entity_files": set(signal_counts),
            })
        timings["extraction_seconds"] = time.perf_counter() - extraction_started
        timings["xml_evidence_scope_seconds"] = timings["extraction_seconds"]
        progress(60.0, "XML scopes built")
        build_integrated_schema_plan(scan_extension, text)

        regex_started = time.perf_counter()
        xml_file_info = dict(file_info)
        xml_file_info["row_locator_prefix"] = "xml_scope:"
        (
            findings,
            candidates,
            finding_count,
            scan_entity_counts,
            candidate_count,
            cluster_excluded_count,
            cluster_exclusion_reasons,
        ) = scan_xml_scope_text_in_batches(
            text,
            xml_file_info,
            args.max_findings_per_file,
            progress_callback=progress,
            progress_base=62.0 if integrated_profile_enabled else 60.0,
            progress_span=33.0 if integrated_profile_enabled else 35.0,
            schema_plan_decisions=schema_plan_decisions,
        ) if text else ([], [], 0, Counter(), 0, 0, Counter())
        timings["regex_seconds"] = time.perf_counter() - regex_started
        progress(95.0, "regex complete")
        findings = signal_findings + findings
        finding_count += len(signal_findings)
        entity_counts = signal_counts + scan_entity_counts
        entity_files = set(entity_counts)
        status = "xml_evidence_scope_raw_in_ram" if text else "xml_evidence_scope_no_evidence"
        error = ""
        summary = summary_row(
            path,
            file_name,
            extension,
            size_bytes,
            md5,
            status,
            len(raw_xml_text),
            finding_count,
            candidate_count,
            error,
            detected_extension=scan_extension,
            sha256=sha256,
        )
        add_summary_cluster_exclusion_counts(summary, cluster_excluded_count, cluster_exclusion_reasons)
        summary["xml_scope_count"] = xml_scope_count
        summary["xml_anchor_hit_count"] = xml_anchor_hit_count
        summary["xml_evidence_hit_count"] = xml_evidence_hit_count
        summary["xml_field_count"] = xml_field_count
        return finish_result(attach_worker_profile({
            "summary": summary,
            "errors": [],
            "findings": findings,
            "finding_files": [],
            "candidates": candidates,
            "candidate_files": [],
            "candidate_count": candidate_count,
            "entity_counts": entity_counts,
            "entity_files": entity_files,
        }, scan_extension, text))

    progress(20.0, "extracting")
    extraction_started = time.perf_counter()
    try:
        text, read_status = extract_text_for_scan(
            path,
            scan_extension,
            0,
            args.scan_images,
            structured_records=args.structured_records,
            structured_max_depth=args.structured_max_depth,
            structured_max_records=args.structured_max_records_per_file,
            structured_max_record_fields=args.structured_max_record_fields,
        )
    except Exception as exc:
        timings["extraction_seconds"] = time.perf_counter() - extraction_started
        error = f"{type(exc).__name__}: {exc}"
        findings = signal_findings
        return finish_result({
            "summary": summary_row(
                path,
                file_name,
                extension,
                size_bytes,
                md5,
                "extraction_error",
                0,
                len(signal_findings),
                0,
                error,
                detected_extension=scan_extension,
                sha256=sha256,
            ),
            "errors": [error_row(path, file_name, extension, size_bytes, "extraction_error", error)],
            "findings": findings,
            "finding_files": [],
            "candidates": [],
            "candidate_files": [],
            "candidate_count": 0,
            "entity_counts": signal_counts,
            "entity_files": set(signal_counts),
        })
    timings["extraction_seconds"] = time.perf_counter() - extraction_started
    progress(60.0, "extraction complete")

    if read_status in {"binary_like_content", "unsupported_extension", "scanned_ocr_disabled"}:
        if read_status == "binary_like_content":
            message = "Skipped because the file contains binary-like bytes."
        elif read_status == "scanned_ocr_disabled":
            message = "Image OCR disabled."
        else:
            message = "Unsupported extension."
        findings = signal_findings
        return finish_result({
            "summary": summary_row(
                path,
                file_name,
                extension,
                size_bytes,
                md5,
                read_status,
                0,
                len(signal_findings),
                0,
                message,
                detected_extension=scan_extension,
                sha256=sha256,
            ),
            "errors": [error_row(path, file_name, extension, size_bytes, read_status, message)],
            "findings": findings,
            "finding_files": [],
            "candidates": [],
            "candidate_files": [],
            "candidate_count": 0,
            "entity_counts": signal_counts,
            "entity_files": set(signal_counts),
        })

    build_integrated_schema_plan(scan_extension, text)

    regex_progress_base = 62.0 if integrated_profile_enabled else 60.0
    progress(regex_progress_base, "regex scanning")
    regex_started = time.perf_counter()
    (
        findings,
        candidates,
        finding_count,
        scan_entity_counts,
        candidate_count,
        cluster_excluded_count,
        cluster_exclusion_reasons,
    ) = scan_text(
        text,
        file_info,
        args.max_findings_per_file,
        progress_callback=progress,
        progress_base=regex_progress_base,
        progress_span=33.0 if integrated_profile_enabled else 35.0,
        schema_plan_decisions=schema_plan_decisions,
    )
    timings["regex_seconds"] = time.perf_counter() - regex_started
    progress(95.0, "regex complete")
    findings = signal_findings + findings
    finding_count += len(signal_findings)
    entity_counts = signal_counts + scan_entity_counts
    entity_files = set(entity_counts)
    error = ""
    status = read_status

    if read_status.startswith("truncated"):
        error = "Scanned a truncated text extraction."

    summary = summary_row(
        path,
        file_name,
        extension,
        size_bytes,
        md5,
        status,
        len(text),
        finding_count,
        candidate_count,
        error,
        detected_extension=scan_extension,
        sha256=sha256,
    )
    add_summary_cluster_exclusion_counts(summary, cluster_excluded_count, cluster_exclusion_reasons)

    return finish_result(attach_worker_profile({
        "summary": summary,
        "errors": [error_row(path, file_name, extension, size_bytes, "truncated", error)] if error else [],
        "findings": findings,
        "finding_files": [],
        "candidates": candidates,
        "candidate_files": [],
        "candidate_count": candidate_count,
        "entity_counts": entity_counts,
        "entity_files": entity_files,
    }, scan_extension, text))
