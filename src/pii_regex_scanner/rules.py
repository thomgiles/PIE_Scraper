"""Load and validate scanner rules, then derive runtime metadata from them.

This module turns persisted JSON configuration into the in-memory structures
used by scanning and reporting:

- compiled regex patterns;
- table-column/header interpretation rules;
- identity-anchor configuration for clustering;
- derived evidence-type metadata such as normalization, risk roles, and output
  columns.

The implementation is loaded into the shared pipeline namespace so the package
and standalone forms stay aligned.
"""

def evidence_type_for_match(evidence_type, matched_text):
    """Map a configured evidence type to the emitted runtime evidence type.

    The main special case is Email, which can be split into Institutional Email
    and Personal Email at runtime when `--email-suffix` is configured.
    """
    if evidence_type == "Email":
        return email_evidence_type(matched_text)
    return evidence_type


def evidence_tier(evidence_type, pattern_name=""):
    """Return the reporting tier label for one emitted evidence type."""
    if evidence_type in TIER_1_EVIDENCE:
        return "tier_1_strong_identifier"
    if evidence_type in TIER_2_EVIDENCE:
        return "tier_2_sensitive_contextual"
    if evidence_type in TIER_3_EVIDENCE:
        return "tier_3_supporting_evidence"
    if pattern_name == "max_findings_per_file":
        return "metadata"
    return "tier_3_supporting_evidence"


def validate_pattern_match(pattern, matched_text):
    """Run an optional post-regex validator for a matched value."""
    validator = pattern.get("validator")
    if validator is None:
        return True
    return validator(matched_text)


PATTERNS = []


def rule_slug(value):
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


HEADER_WORD_SEPARATOR_CANDIDATES = "_-~#|"


def header_word_separator_pattern(extra_separators=""):
    """Return the regex used to space-normalise header word separators.

    Whitespace is always a word separator. Other punctuation is only included
    after a table/header-specific detection step has shown that splitting on it
    improves header resolution.
    """
    extras = "".join(sorted(set(str(extra_separators or ""))))
    return r"[\s" + re.escape(extras) + r"]+"


REGEX_FLAG_NAMES = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "ASCII": re.ASCII,
}


VALIDATORS = {
    "valid_luhn": valid_luhn,
    "valid_nhs_number": valid_nhs_number,
    "valid_ucas_personal_id": valid_ucas_personal_id,
    "valid_saturn_id": valid_saturn_id,
    "valid_cas_number": valid_cas_number,
    "valid_husid_entry_year": valid_husid_entry_year,
    "valid_uk_driving_licence": valid_uk_driving_licence,
    "valid_bare_8_digit_id": valid_bare_8_digit_id,
    "valid_uk_postcode": valid_uk_postcode,
    "valid_contextual_date": valid_contextual_date,
    "valid_passport_like": valid_passport_like,
    "valid_china_national_id": valid_china_national_id,
    "valid_orcid": valid_orcid,
    "valid_uk_phone_rough": valid_uk_phone_rough,
    "valid_uk_national_insurance_number": valid_uk_national_insurance_number,
    "valid_religion_value": valid_religion_value,
    "valid_ethnicity_value": valid_ethnicity_value,
    "valid_citizenship_country_value": valid_citizenship_country_value,
    "valid_disability_value": valid_disability_value,
    "valid_marital_status_value": valid_marital_status_value,
    "valid_positive_indicator_value": valid_positive_indicator_value,
    "valid_positive_amount_value": valid_positive_amount_value,
    "valid_positive_count_value": valid_positive_count_value,
    "valid_identity_document_file_reference": valid_identity_document_file_reference,
}


def regex_flags_from_names(flag_names):
    """Translate JSON regex flag names into Python `re` flags."""
    flags = 0
    for name in flag_names or []:
        flag = REGEX_FLAG_NAMES.get(str(name).upper())
        if flag is None:
            raise ValueError(f"Unknown regex flag in rules JSON: {name}")
        flags |= flag
    return flags


def parse_bool(value):
    """Parse the CLI's flexible TRUE/FALSE style boolean values."""
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "t", "tr", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "f", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"Expected TRUE or FALSE, got: {value}")


def compile_rule_pattern(rule):
    """Compile one regex rule JSON object into runtime form.

    This is where policy constraints are enforced. For example, free-text Name
    regex rules are rejected because Names must come from structured assembly or
    authoritative person-table exact matches, not loose text matching.
    """
    if str(rule.get("evidence_type", "")).strip() == "Name":
        raise ValueError("Name evidence cannot be supplied by free-text regex rules; use --person-tables exact matching or table/structured name assembly.")
    pattern = {
        "evidence_type": rule["evidence_type"],
        "pattern_name": rule["pattern_name"],
        "confidence": rule.get("confidence", "medium"),
        "regex": re.compile(rule["regex"], regex_flags_from_names(rule.get("flags", []))),
        "labelled_fields_only": bool(rule.get("labelled_fields_only")),
    }
    context_guard = normalize_context_guard_config(rule.get("context_guard"))
    if context_guard:
        pattern["context_guard"] = context_guard
    validator_name = rule.get("validator")
    if validator_name:
        validator = VALIDATORS.get(validator_name)
        if validator is None:
            raise ValueError(f"Unknown validator in rules JSON: {validator_name}")
        pattern["validator"] = validator
    line_triggers = rule.get("line_triggers", rule.get("prefilter", []))
    if line_triggers:
        pattern["line_triggers"] = tuple(str(token).lower() for token in line_triggers if str(token).strip())
    return pattern


def risk_tier_for_rule(rule):
    """Return the configured risk tier for a rule with sensible fallbacks."""
    return rule.get("risk_tier") or rule.get("tier") or "tier_3_supporting_evidence"


def rule_objects_from_json_file(path):
    """Load one rule JSON file and normalize it into a list of rule objects."""
    with open(path, "r", encoding="utf-8") as f:
        loaded = json.load(f)

    if isinstance(loaded, list):
        return loaded
    if not isinstance(loaded, dict):
        raise ValueError(f"Rule JSON must contain an object or list: {path}")
    if "patterns" in loaded:
        tier_by_type = {
            row.get("name"): row.get("risk_tier") or row.get("tier")
            for row in loaded.get("evidence_types", [])
            if row.get("name")
        }
        rules = []
        for rule in loaded.get("patterns", []):
            rule = dict(rule)
            rule.setdefault("risk_tier", tier_by_type.get(rule.get("evidence_type"), "tier_3_supporting_evidence"))
            rules.append(rule)
        return rules
    return [loaded]


def regex_rules_path_from_rules_path(rules_path):
    """Resolve the effective regex-rules location from a user-supplied path.

    The user may point at:

    - a rules root containing `regex_searching/`;
    - the regex directory itself; or
    - a legacy single JSON file.
    """
    path = Path(rules_path or DEFAULT_RULES_PATH)
    if path.is_dir():
        direct = path / "regex_searching"
        if direct.is_dir():
            return direct
        nested = path / "rules" / "regex_searching"
        if nested.is_dir():
            return nested
    return path


def load_rule_objects(rules_path):
    """Load raw regex rule objects from the configured rules path."""
    if not rules_path:
        return [BUILTIN_EMAIL_RULE]
    path = regex_rules_path_from_rules_path(rules_path)
    if path.is_dir():
        rule_files = sorted(path.rglob("*.json"))
        if not rule_files:
            raise ValueError(f"Rules directory contains no JSON files: {path}")
        rules = []
        for rule_file in rule_files:
            rules.extend(rule_objects_from_json_file(rule_file))
        return rules
    if path.is_file():
        return rule_objects_from_json_file(path)
    raise FileNotFoundError(f"Rules path does not exist: {path}")


def table_column_rules_path_from_rules_path(rules_path):
    """Resolve the table-column rules location from a user-supplied rules path."""
    if not rules_path:
        return None
    path = Path(rules_path)
    if path.is_dir():
        candidates = [
            path / "table_column_rules",
            path / "rules" / "table_column_rules",
            path / "table_column_rules.json",
            path / "rules" / "table_column_rules.json",
            path.parent / "table_column_rules",
            path.parent / "table_column_rules.json",
        ]
        for candidate in candidates:
            if candidate.is_dir() or candidate.is_file():
                return candidate
    return None


def load_table_column_rule_objects(path):
    """Load table-column rule JSON in either directory or file form."""
    if path.is_dir():
        rule_files = sorted(path.rglob("*.json"))
        if not rule_files:
            raise ValueError(f"Table column rules directory contains no JSON files: {path}")
        rules = []
        for rule_file in rule_files:
            with open(rule_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if not isinstance(loaded, dict):
                raise ValueError(f"Table column rule JSON must contain one object: {rule_file}")
            rules.append(loaded)
        return rules

    with open(path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    if not isinstance(loaded, dict):
        raise ValueError(f"Table column rules JSON must contain one object: {path}")
    if (
        "header_patterns" in loaded
        or "header_terms" in loaded
        or "header_groups" in loaded
        or "column_groups" in loaded
        or "columns" in loaded
    ):
        return [loaded]
    if "rules" in loaded and isinstance(loaded["rules"], list):
        return loaded["rules"]
    raise ValueError(f"Table column rules JSON must contain header_patterns, header_groups, header_terms, or rules: {path}")


def table_header_term_pattern(term):
    """Convert a simple header term into a flexible header-matching regex."""
    escaped = re.escape(str(term).strip())
    escaped = escaped.replace(r"\ ", header_word_separator_pattern())
    return rf"\b{escaped}\b"


def table_header_patterns_from_group(group):
    """Return the compiled pattern strings declared by one header rule group."""
    patterns = (
        group.get("header_patterns")
        or group.get("patterns")
        or group.get("header_terms")
        or group.get("terms")
        or []
    )
    if not isinstance(patterns, list) or not patterns:
        raise ValueError(f"Table column header group requires non-empty header_patterns: {group}")
    return [str(pattern) for pattern in patterns if str(pattern).strip()]


def table_header_group_label(group):
    """Return the canonical label emitted when a header group matches."""
    label = (
        group.get("canonical_header")
        or group.get("canonical_label")
        or group.get("canonical")
        or group.get("key")
        or group.get("label")
    )
    label = safe_cell(label)
    if not label:
        raise ValueError(f"Table column header group requires canonical_header: {group}")
    return label


def table_header_groups_from_rule(rule):
    """Normalize one table-column rule into a list of header groups."""
    if "header_patterns" in rule:
        return [rule]

    groups = rule.get("header_groups") or rule.get("column_groups") or rule.get("columns") or []
    if groups:
        if not isinstance(groups, list):
            raise ValueError(f"Table column rule header_groups must be a list: {rule}")
        return groups

    terms = rule.get("header_terms", [])
    if not isinstance(terms, list) or not terms:
        raise ValueError(f"Table column rule requires header_terms or header_groups: {rule}")
    return [
        {
            "canonical_header": rule.get("canonical_header") or rule.get("rule_name") or "matched column",
            "header_patterns": [table_header_term_pattern(term) for term in terms],
        }
    ]


def compile_table_header_matchers(rule_objects):
    matchers = []
    for rule in rule_objects:
        for group in table_header_groups_from_rule(rule):
            canonical_header = table_header_group_label(group)
            metadata = {
                key: group.get(key, rule.get(key))
                for key in (
                    "name_part", "evidence_type", "evidence_types", "pattern_name", "pattern_names",
                    "emit_cell_value", "confidence", "risk_tier", "tier", "normalization",
                    "risk_roles", "is_identifiable", "is_high_risk_standalone",
                    "validator", "validators", "max_cell_value_length",
                )
                if group.get(key, rule.get(key)) is not None
            }
            context_guard = normalize_context_guard_config(group.get("context_guard", rule.get("context_guard")))
            if context_guard:
                metadata["context_guard"] = context_guard
            for pattern in table_header_patterns_from_group(group):
                matchers.append((re.compile(pattern, re.IGNORECASE), canonical_header, len(matchers), metadata))
    return tuple(matchers)


def load_table_column_rules(rules_path=""):
    global TABLE_COLUMN_RULES, LOADED_TABLE_COLUMN_RULES_PATH

    path = table_column_rules_path_from_rules_path(rules_path)
    resolved_path = os.path.abspath(path) if path else "__builtin_table_column_rules__"
    if LOADED_TABLE_COLUMN_RULES_PATH == resolved_path:
        return

    if path is None:
        rule_objects = DEFAULT_TABLE_COLUMN_RULES["rules"]
    else:
        rule_objects = load_table_column_rule_objects(path)

    header_terms = []
    min_non_empty_headers = 2
    for rule in rule_objects:
        if not isinstance(rule, dict):
            raise ValueError(f"Table column rule must be an object: {rule}")
        if "min_non_empty_headers" in rule:
            min_non_empty_headers = max(min_non_empty_headers, int(rule["min_non_empty_headers"]))
        terms = rule.get("header_terms", [])
        if isinstance(terms, list):
            header_terms.extend(terms)

    TABLE_COLUMN_RULES = {
        "min_non_empty_headers": min_non_empty_headers,
        "header_terms": tuple(sorted({str(term).lower() for term in header_terms if str(term).strip()})),
        "header_matchers": compile_table_header_matchers(rule_objects),
    }
    TABLE_HEADER_MATCH_CACHE.clear()
    TABLE_HEADER_PATTERN_CACHE.clear()
    TABLE_HEADER_ASSEMBLY_CACHE.clear()
    LOADED_TABLE_COLUMN_RULES_PATH = resolved_path


def identity_anchors_path_from_rules_path(rules_path):
    if not rules_path:
        return None
    path = Path(rules_path)
    if path.is_dir():
        candidates = [
            path / "person_identity_anchors.json",
            path / "rules" / "person_identity_anchors.json",
            path.parent / "person_identity_anchors.json",
        ]
        for candidate in candidates:
            if candidate.is_file():
                return candidate
    return None


def identity_anchor_aliases(evidence_type):
    evidence_type = safe_cell(evidence_type)
    if evidence_type == "Email":
        return ["Institutional Email", "Personal Email"] if EMAIL_SUFFIX else ["Email"]
    if rule_slug(evidence_type) == "full_name":
        return ["Name"]
    return [evidence_type]


def expand_identity_anchor_types(values):
    expanded = set()
    for value in values:
        expanded.update(identity_anchor_aliases(value))
    return expanded


def load_identity_anchor_config(rules_path=""):
    global PERSON_CLUSTER_STRONG_ANCHORS, PERSON_CLUSTER_COMPOUND_ANCHOR_SETS, ANCHOR_PRIORITY_BY_TYPE
    global LOADED_IDENTITY_ANCHORS_PATH

    path = identity_anchors_path_from_rules_path(rules_path)
    resolved_path = os.path.abspath(path) if path else "__builtin_identity_anchors__"
    loaded_key = (resolved_path, EMAIL_SUFFIX)
    if LOADED_IDENTITY_ANCHORS_PATH == loaded_key:
        return

    if path is None:
        config = {
            "strong_anchor_types": sorted(DEFAULT_PERSON_CLUSTER_STRONG_ANCHORS),
            "compound_anchor_sets": [list(anchor_set) for anchor_set in DEFAULT_PERSON_CLUSTER_COMPOUND_ANCHOR_SETS],
            "anchor_priority": dict(DEFAULT_ANCHOR_PRIORITY_BY_TYPE),
        }
    else:
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
        if not isinstance(config, dict):
            raise ValueError(f"Identity anchor config must contain one JSON object: {path}")

    strong_anchor_types = config.get("strong_anchor_types", DEFAULT_PERSON_CLUSTER_STRONG_ANCHORS)
    if not isinstance(strong_anchor_types, list):
        raise ValueError("Identity anchor config strong_anchor_types must be a list.")
    PERSON_CLUSTER_STRONG_ANCHORS = expand_identity_anchor_types(strong_anchor_types)

    compound_anchor_sets = config.get("compound_anchor_sets", DEFAULT_PERSON_CLUSTER_COMPOUND_ANCHOR_SETS)
    if not isinstance(compound_anchor_sets, list):
        raise ValueError("Identity anchor config compound_anchor_sets must be a list.")

    resolved_compound_sets = []
    for anchor_set in compound_anchor_sets:
        if not isinstance(anchor_set, list) or len(anchor_set) < 2:
            raise ValueError(f"Each compound anchor set must be a list of at least two evidence types: {anchor_set}")
        expanded_options = [expand_identity_anchor_types([evidence_type]) for evidence_type in anchor_set]
        combinations = [()]
        for options in expanded_options:
            combinations = [existing + (option,) for existing in combinations for option in sorted(options)]
        for combination in combinations:
            resolved_compound_sets.append(combination)

    PERSON_CLUSTER_COMPOUND_ANCHOR_SETS = sorted(set(resolved_compound_sets))

    anchor_priority = config.get("anchor_priority", DEFAULT_ANCHOR_PRIORITY_BY_TYPE)
    if not isinstance(anchor_priority, dict):
        raise ValueError("Identity anchor config anchor_priority must be an object.")
    ANCHOR_PRIORITY_BY_TYPE = {}
    for evidence_type, priority in anchor_priority.items():
        for expanded_type in expand_identity_anchor_types([evidence_type]):
            ANCHOR_PRIORITY_BY_TYPE[expanded_type] = int(priority)

    LOADED_IDENTITY_ANCHORS_PATH = loaded_key


def evidence_type_rows_from_rules(rules):
    rows = []
    seen = {}
    for rule in rules:
        evidence_type = str(rule.get("evidence_type", "")).strip()
        if not evidence_type:
            raise ValueError(f"Rule is missing evidence_type: {rule}")
        tier = risk_tier_for_rule(rule)
        evidence_key = rule_slug(evidence_type)
        previous = seen.get(evidence_key)
        if previous is not None:
            if previous["tier"] != tier:
                raise ValueError(
                    f"Conflicting risk_tier values for evidence_type {evidence_type}: {previous['tier']} and {tier}"
                )
            if rule.get("normalization") and previous.get("normalization") not in {"", rule.get("normalization")}:
                raise ValueError(
                    f"Conflicting normalization values for evidence_type {evidence_type}: "
                    f"{previous.get('normalization')} and {rule.get('normalization')}"
                )
            previous["is_identifiable"] = previous.get("is_identifiable", False) or bool(rule.get("is_identifiable"))
            previous["is_high_risk_standalone"] = previous.get("is_high_risk_standalone", False) or bool(
                rule.get("is_high_risk_standalone")
            )
            if rule.get("normalization"):
                previous["normalization"] = rule["normalization"]
            previous.setdefault("risk_roles", set()).update(risk_roles_for_rule(rule))
            continue
        row = {
            "name": evidence_type,
            "tier": tier,
            "normalization": rule.get("normalization", "none"),
            "is_identifiable": bool(rule.get("is_identifiable")),
            "is_high_risk_standalone": bool(rule.get("is_high_risk_standalone")),
            "risk_roles": risk_roles_for_rule(rule),
        }
        seen[evidence_key] = row
        rows.append(row)
    return rows


def risk_roles_for_rule(rule):
    explicit_roles = rule.get("risk_roles")
    if explicit_roles:
        return set(explicit_roles)

    evidence_slug = rule_slug(rule.get("evidence_type", ""))
    default_roles = {
        "address": {"address"},
        "dob": {"dob"},
        "email": {"email"},
        "institutional_email": {"email"},
        "personal_email": {"email"},
        "id": {"id"},
        "name": {"name"},
        "payment_card": {"payment_card"},
        "phone": {"phone"},
        "application_number": {"application_reference"},
    }
    return set(default_roles.get(evidence_slug, set()))


def identity_anchor_evidence_types():
    evidence_types = set(globals().get("PERSON_CLUSTER_STRONG_ANCHORS", {"Email"}))
    for anchor_set in globals().get("PERSON_CLUSTER_COMPOUND_ANCHOR_SETS", []):
        evidence_types.update(anchor_set)
    return evidence_types


def cluster_max_values_from_rules(rules):
    identity_types = identity_anchor_evidence_types()
    email_evidence_types = {"Institutional Email", "Personal Email"} if EMAIL_SUFFIX else {"Email"}
    max_values_by_type = {}

    for rule in rules:
        evidence_type = str(rule.get("evidence_type", "") or "").strip()
        if not evidence_type:
            continue

        if evidence_type == "Email" and EMAIL_SUFFIX:
            by_type = rule.get("max_per_cluster_by_evidence_type", {})
            if not isinstance(by_type, dict):
                raise ValueError("Email rule max_per_cluster_by_evidence_type must be an object.")
            for expanded_type in sorted(email_evidence_types & identity_types):
                max_value = by_type.get(expanded_type, rule.get("max_per_cluster"))
                if max_value is None:
                    continue
                max_value = int(max_value)
                if max_value <= 0:
                    continue
                max_values_by_type[expanded_type] = min(
                    max_value,
                    max_values_by_type.get(expanded_type, max_value),
                )
            continue

        if evidence_type not in identity_types or "max_per_cluster" not in rule:
            continue
        max_value = int(rule["max_per_cluster"])
        if max_value <= 0:
            continue
        max_values_by_type[evidence_type] = min(
            max_value,
            max_values_by_type.get(evidence_type, max_value),
        )

    return max_values_by_type


def apply_email_suffix_evidence_split(evidence_type_rows):
    if not EMAIL_SUFFIX:
        return evidence_type_rows

    rows = []
    seen = set()
    for row in evidence_type_rows:
        if row["name"] == "Email":
            for evidence_type in ("Institutional Email", "Personal Email"):
                if evidence_type not in seen:
                    split_row = dict(row)
                    split_row["name"] = evidence_type
                    split_row["risk_roles"] = set(row.get("risk_roles", set())) | {"email"}
                    rows.append(split_row)
                    seen.add(evidence_type)
            continue
        if row["name"] not in seen:
            rows.append(row)
            seen.add(row["name"])
    return rows


def rebuild_rule_derived_fields(evidence_type_rows):
    global EVIDENCE_COUNT_TYPES, EVIDENCE_COUNT_COLUMNS, EVIDENCE_FLAG_COLUMNS
    global EVIDENCE_NORMALIZATION, EVIDENCE_RISK_ROLES, EMAIL_EVIDENCE_TYPES
    global FILE_SUMMARY_FIELDS, KNOWN_PERSON_RISK_MATRIX_FIELDS
    global TIER_1_EVIDENCE, TIER_2_EVIDENCE, TIER_3_EVIDENCE
    global ANCHOR_PRIORITY, IDENTIFIABLE_EVIDENCE, HIGH_RISK_STANDALONE, SENSITIVE_CONTEXT, ID_EVIDENCE_TYPES

    evidence_type_rows = apply_email_suffix_evidence_split(evidence_type_rows)

    EVIDENCE_COUNT_TYPES = [row["name"] for row in evidence_type_rows]
    EVIDENCE_COUNT_COLUMNS = ["count_" + rule_slug(evidence_type) for evidence_type in EVIDENCE_COUNT_TYPES]
    EVIDENCE_FLAG_COLUMNS = ["has_" + rule_slug(evidence_type) for evidence_type in EVIDENCE_COUNT_TYPES]
    EVIDENCE_NORMALIZATION = {
        row["name"]: row.get("normalization", "none") or "none"
        for row in evidence_type_rows
    }
    EVIDENCE_RISK_ROLES = {
        row["name"]: set(row.get("risk_roles", set()))
        for row in evidence_type_rows
    }
    FILE_SUMMARY_FIELDS = BASE_FILE_SUMMARY_FIELDS + ["highest_file_risk", "evidence_type_counts"] + EVIDENCE_COUNT_COLUMNS

    TIER_1_EVIDENCE = {
        row["name"] for row in evidence_type_rows if row.get("tier") == "tier_1_strong_identifier"
    }
    TIER_2_EVIDENCE = {
        row["name"] for row in evidence_type_rows if row.get("tier") == "tier_2_sensitive_contextual"
    }
    TIER_3_EVIDENCE = {
        row["name"] for row in evidence_type_rows if row.get("tier") == "tier_3_supporting_evidence"
    }
    KNOWN_PERSON_RISK_MATRIX_FIELDS = BASE_KNOWN_PERSON_RISK_MATRIX_FIELDS + EVIDENCE_FLAG_COLUMNS

    ANCHOR_PRIORITY = [
        evidence_type
        for evidence_type in sorted(
            (row["name"] for row in evidence_type_rows if row["name"] in ANCHOR_PRIORITY_BY_TYPE),
            key=lambda evidence_type: (ANCHOR_PRIORITY_BY_TYPE[evidence_type], evidence_type),
        )
    ]
    EMAIL_EVIDENCE_TYPES = {
        row["name"] for row in evidence_type_rows if "email" in row.get("risk_roles", set())
    }
    IDENTIFIABLE_EVIDENCE = {row["name"] for row in evidence_type_rows if row.get("is_identifiable")}
    HIGH_RISK_STANDALONE = {
        row["name"] for row in evidence_type_rows if row.get("is_high_risk_standalone")
    }
    SENSITIVE_CONTEXT = set(TIER_2_EVIDENCE)
    ID_EVIDENCE_TYPES = {
        row["name"] for row in evidence_type_rows if "id" in row.get("risk_roles", set())
    }



def metadata_truthy(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "t", "yes", "y", "on"}


def values_as_list(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if str(item).strip()]
    if str(value).strip():
        return [value]
    return []


def table_cell_value_emit_rule_objects_from_rules_path(rules_path):
    """Return pseudo rule objects for table-column rules that emit cell values.

    Regex rules define free-text detection.  Table-column rules can now opt in
    to header-confirmed evidence with ``emit_cell_value: true``.  These pseudo
    rules add their evidence types to summaries, risk matrices and output
    columns without compiling broad free-text regexes.
    """
    path = table_column_rules_path_from_rules_path(rules_path)
    if path is None:
        return []

    try:
        rule_objects = load_table_column_rule_objects(path)
    except Exception:
        # Let load_table_column_rules raise the detailed error later in the
        # normal setup path.  This helper is only used to build the evidence
        # universe before table header matchers are loaded.
        return []

    emit_rules = []
    seen = set()
    for rule in rule_objects:
        if not isinstance(rule, dict):
            continue
        for group in table_header_groups_from_rule(rule):
            if not metadata_truthy(group.get("emit_cell_value", rule.get("emit_cell_value"))):
                continue
            evidence_types = values_as_list(group.get("evidence_types", rule.get("evidence_types")))
            evidence_types += values_as_list(group.get("evidence_type", rule.get("evidence_type")))
            if not evidence_types:
                continue
            canonical_header = table_header_group_label(group)
            pattern_name = (
                group.get("pattern_name")
                or rule.get("pattern_name")
                or f"table_column_{rule_slug(canonical_header)}"
            )
            for evidence_type in evidence_types:
                evidence_type = safe_cell(evidence_type)
                if not evidence_type:
                    continue
                key = (evidence_type, pattern_name)
                if key in seen:
                    continue
                seen.add(key)
                emit_rules.append({
                    "evidence_type": evidence_type,
                    "pattern_name": pattern_name,
                    "risk_tier": group.get("risk_tier", rule.get("risk_tier", group.get("tier", rule.get("tier", "tier_3_supporting_evidence")))),
                    "normalization": group.get("normalization", rule.get("normalization", "none")),
                    "risk_roles": group.get("risk_roles", rule.get("risk_roles", [])),
                    "is_identifiable": bool(group.get("is_identifiable", rule.get("is_identifiable", False))),
                    "is_high_risk_standalone": bool(group.get("is_high_risk_standalone", rule.get("is_high_risk_standalone", False))),
                    "_table_emit_cell_value": True,
                })
                context_guard = normalize_context_guard_config(group.get("context_guard", rule.get("context_guard")))
                if context_guard:
                    emit_rules[-1]["context_guard"] = context_guard
    return emit_rules

def load_rules(rules_path):
    global PATTERNS, LOADED_RULES_PATH, CLUSTER_MAX_VALUES_PER_EVIDENCE_TYPE, TABLE_CELL_VALUE_EMIT_RULES

    resolved_path = os.path.abspath(regex_rules_path_from_rules_path(rules_path)) if rules_path else "__builtin_email__"
    table_rules_path = table_column_rules_path_from_rules_path(rules_path)
    resolved_table_path = os.path.abspath(table_rules_path) if table_rules_path else "__builtin_table_column_rules__"
    loaded_rules_key = (resolved_path, resolved_table_path, EMAIL_SUFFIX)
    if LOADED_RULES_PATH == loaded_rules_key:
        return

    loaded_patterns = load_rule_objects(rules_path)
    if not loaded_patterns:
        raise ValueError(f"Rules path contains no rules: {resolved_path}")

    # Name and Address are assembled from structured fields in code. Ignore
    # legacy regex definitions so old rule bundles cannot re-enable permissive
    # free-text matching or override the assemblers' normalization metadata.
    raw_patterns = [
        rule
        for rule in loaded_patterns
        if str(rule.get("evidence_type", "")).strip() not in CODE_DERIVED_EVIDENCE_TYPES
        and str(rule.get("evidence_type", "")).strip() not in HEADER_CONFIRMED_ONLY_EVIDENCE_TYPES
    ]

    TABLE_CELL_VALUE_EMIT_RULES = table_cell_value_emit_rule_objects_from_rules_path(rules_path)
    derived_rules = raw_patterns + CODE_DERIVED_EVIDENCE_RULES + TABLE_CELL_VALUE_EMIT_RULES
    evidence_type_rows = evidence_type_rows_from_rules(derived_rules)
    PATTERNS = [compile_rule_pattern(rule) for rule in raw_patterns]
    TABLE_HEADER_PATTERN_CACHE.clear()
    CLUSTER_MAX_VALUES_PER_EVIDENCE_TYPE = cluster_max_values_from_rules(derived_rules)
    rebuild_rule_derived_fields(evidence_type_rows)
    configure_pattern_line_triggers()
    LOADED_RULES_PATH = loaded_rules_key


def configure_pattern_line_triggers():
    """Attach cheap lowercase substring triggers to expensive contextual regexes.

    This avoids running every broad context regex against every line in large
    text dumps. Patterns without line triggers still run on all lines because
    they are standalone identifiers or compact expressions.
    """
    global STANDALONE_PATTERNS, LINE_TRIGGER_INDEX

    token_to_patterns = {}
    standalone_patterns = []
    for pattern in PATTERNS:
        pattern["line_triggers"] = pattern.get("line_triggers")
        pattern["evidence_tier"] = evidence_tier(pattern["evidence_type"], pattern["pattern_name"])
        if pattern["line_triggers"]:
            for token in pattern["line_triggers"]:
                token_to_patterns.setdefault(token, []).append(pattern)
        else:
            standalone_patterns.append(pattern)

    STANDALONE_PATTERNS = standalone_patterns
    LINE_TRIGGER_INDEX = sorted(token_to_patterns.items(), key=lambda item: len(item[0]), reverse=True)


ANCHOR_PRIORITY = []
EMAIL_EVIDENCE_TYPES = {"Email"}
IDENTIFIABLE_EVIDENCE = set()
HIGH_RISK_STANDALONE = set()
SENSITIVE_CONTEXT = set()

# Email-only fallback used when no person_identity_anchors.json is loaded.
PERSON_CLUSTER_STRONG_ANCHORS = {"Email"}

DEFAULT_PERSON_CLUSTER_STRONG_ANCHORS = set(PERSON_CLUSTER_STRONG_ANCHORS)
PERSON_CLUSTER_COMPOUND_ANCHOR_SETS = []
DEFAULT_PERSON_CLUSTER_COMPOUND_ANCHOR_SETS = list(PERSON_CLUSTER_COMPOUND_ANCHOR_SETS)
ANCHOR_PRIORITY_BY_TYPE = {"Email": 10}
DEFAULT_ANCHOR_PRIORITY_BY_TYPE = dict(ANCHOR_PRIORITY_BY_TYPE)

RISK_ORDER = {"": 0, "low": 1, "medium": 2, "high": 3}

CLUSTER_MAX_VALUES_PER_EVIDENCE_TYPE = {}
