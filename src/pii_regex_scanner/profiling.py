"""Schema/column profiling for rule-discovery work.

This module provides a profiling-only pass over structured and tabular sources.
It does not emit atomic evidence, clustering outputs, or person matches. Its
goal is to answer:

- which columns/structured fields are present;
- which ones are already resolved by current rules;
- which unresolved labels behave like a known type and may deserve a new rule.

The outputs avoid raw rows, file paths, and extracted context. For unresolved or
ambiguous columns, the profile reports can include a small bounded sample of
distinct cell values to support rule authoring and review.
"""

from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from functools import lru_cache
import multiprocessing as mp
import queue as queue_module

try:
    import spacy
    from spacy.matcher import PhraseMatcher
except Exception:  # pragma: no cover - optional dependency
    spacy = None
    PhraseMatcher = None

PROFILE_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PROFILE_PLACEHOLDER_LABEL_RE = re.compile(r"^(?:column|col|field|value|attribute|unnamed)[ _-]?\d+$", re.IGNORECASE)
PROFILE_PATTERN_MATCH_CACHE = {}
PROFILE_LABEL_NORMALIZE_REPLACEMENTS = {
    "emailid": "email id",
    "notifyemail": "notify email",
    "registeredemail": "registered email",
    "ipaddress": "ip address",
    "usercontact": "user contact",
    "username": "user name",
    "middlename": "middle name",
    "creditcard": "credit card",
    "creditcardno": "credit card no",
    "creditcardnumber": "credit card number",
    "creditcardlastfour": "credit card last four",
    "creditcardlast4": "credit card last 4",
    "refno": "ref no",
    "transid": "trans id",
    "emplid": "empl id",
    "maritalstatus": "marital status",
    "relationshipstatus": "relationship status",
    "careleaver": "care leaver",
    "careexperienced": "care experienced",
}
PROFILE_NLP_HINTS = {
    "email": ["email", "e mail", "mailbox", "mail", "inbox"],
    "DOB": ["dob", "date of birth", "birth date", "birth", "born"],
    "postcode": ["postcode", "post code", "postal code", "zip code", "zip"],
    "phone": ["phone", "telephone", "mobile", "contact number"],
    "address": ["address", "street address", "home address", "postal address"],
    "student id": ["student id", "student number", "student no", "student reference"],
    "full name": ["full name", "name of person", "person name"],
    "first name": ["first name", "forename", "given name"],
    "last name": ["last name", "surname", "family name"],
    "IP Address": ["ip address", "ipaddr", "ip addr", "ipv4", "ipv6", "ipaddress"],
    "payment card": ["credit card", "credit card number", "credit card no", "card number", "card no", "payment card", "card last four", "credit card last four"],
    "person id": ["person id", "person number", "candidate id", "candidate number", "applicant id", "customer id", "customer number", "customer reference number", "receipt number", "empl id", "emplid"],
    "staff id": ["staff id", "employee id", "employee number", "member id", "user id"],
    "middle name": ["middle name", "middle names", "middlename"],
    "username": ["username", "user name", "login name", "screen name"],
    "gender/sex": ["gender", "sex"],
    "religion": ["religion", "faith", "religious belief"],
    "ethnicity": ["ethnicity", "ethnic group", "race"],
    "citizenship country": ["citizenship", "nationality", "country of citizenship", "country of nationality"],
    "disability": ["disability", "disabled", "accessibility", "reasonable adjustment"],
    "passport": ["passport", "passport number"],
    "marital status": ["marital status", "relationship status", "civil partnership status"],
    "care leaver": ["care leaver", "care experienced"],
    "household income": ["household income", "family income"],
    "principal earner income": ["principal earner income", "principle earner income"],
    "dependants adg indicator": ["dependants adg indicator", "dependent adg indicator"],
    "dependants ccg indicator": ["dependants ccg indicator", "dependent ccg indicator"],
    "number of sponsors": ["number of sponsors", "sponsors"],
    "maintenance grant": ["maintenance grant"],
    "special support element": ["special support element"],
    "special support grant": ["special support grant"],
}
PROFILE_SEMANTIC_MIN_SIMILARITY = 0.68
PROFILE_SEMANTIC_HIGH_SIMILARITY = 0.80
PROFILE_VALUE_ONLY_SENSITIVE_HEADERS = {
    "citizenship country",
    "disability",
    "ethnicity",
    "gender/sex",
    "marital status",
    "religion",
}
PROFILE_NON_SUBSTANTIVE_VOCAB_VALUES = {
    "a", "b", "c", "cd", "ci", "cond", "f", "fnd", "ll", "lll", "m",
    "n", "na", "new", "no", "none", "null", "other", "p", "pg", "pgr",
    "pgt", "pri", "s", "sc", "u", "ug", "unknown", "y", "yes",
}

PROFILE_OUTPUT_FIELDS = [
    "source_kind",
    "header_origin",
    "source_label",
    "current_status",
    "resolved_header",
    "suggested_header",
    "action_type",
    "suggestion_basis",
    "suggestion_source",
    "suggestion_confidence",
    "candidate_score",
    "suggested_rule_json",
    "processing_decision",
    "processing_decision_reason",
    "files_seen",
    "rows_seen",
    "non_empty_values",
    "blank_values",
    "distinct_value_count_estimate",
    "uniqueness_ratio",
    "min_length",
    "max_length",
    "avg_length",
    "email_like_rate",
    "date_like_rate",
    "postcode_like_rate",
    "numeric_like_rate",
    "person_table_exact_rate",
    "low_cardinality",
    "sample_values_preview",
]

SCHEMA_PLAN_FIELDS = [
    "file_token",
    "source_kind",
    "table_name",
    "column_index",
    "raw_header",
    "header_origin",
    "resolved_header",
    "suggested_type",
    "confidence",
    "reason",
    "scan_action",
    "linking_scope",
    "orientation",
    "orientation_confidence",
    "orientation_reason",
    "detected_separator",
    "schema_signature",
    "schema_reused_from",
]

TABLE_SKETCH_FIELDS = [
    "family_id",
    "family_status",
    "file_token",
    "source_kind",
    "table_name",
    "column_count",
    "header_mode",
    "orientation",
    "detected_separator",
    "schema_signature",
    "resolved_type_sequence",
    "suggested_type_sequence",
]

TABLE_FAMILY_FIELDS = [
    "family_id",
    "family_status",
    "source_kinds",
    "table_count",
    "headered_table_count",
    "headerless_table_count",
    "column_count",
    "orientation",
    "detected_separator",
    "schema_signature",
    "consensus_type_sequence",
    "propagated_column_count",
    "conflict_reason",
]

PROFILE_CANDIDATE_FIELDS = [
    "suggested_header",
    "action_type",
    "suggestion_confidence",
    "candidate_score_max",
    "source_kinds",
    "header_origins",
    "contributing_labels_count",
    "source_labels",
    "files_seen_total",
    "rows_seen_total",
    "non_empty_values_total",
    "suggestion_sources",
    "suggestion_basis",
    "suggested_rule_json",
]

REVIEW_ONLY_CANDIDATE_FIELDS = [
    "suggested_header",
    "processing_decision_reason",
    "suggestion_confidence",
    "candidate_score_max",
    "source_kinds",
    "header_origins",
    "contributing_labels_count",
    "source_labels",
    "files_seen_total",
    "rows_seen_total",
    "non_empty_values_total",
    "suggestion_sources",
    "suggestion_basis",
]

RULE_COVERAGE_FIELDS = [
    "rule_kind",
    "rule_name",
    "evidence_types",
    "emit_cell_value",
    "status",
    "coverage_score",
    "recommended_action",
    "matched_source_labels_count",
    "files_seen",
    "rows_seen",
    "non_empty_values",
    "notes",
]

RULE_COVERAGE_STATUS_ORDER = {
    "likely_stale_for_structured_data": 0,
    "not_observed_in_profile": 1,
    "seen_rarely": 2,
    "seen_some": 3,
    "seen_often": 4,
}

SUGGESTION_CONFIDENCE_ORDER = {
    "low": 0,
    "medium": 1,
    "high": 2,
}

VALUE_TYPE_CANDIDATE_FIELDS = [
    "source_kind",
    "header_origin",
    "source_label",
    "candidate_kind",
    "action_type",
    "suggestion_basis",
    "candidate_score",
    "files_seen",
    "rows_seen",
    "non_empty_values",
    "distinct_value_count_estimate",
    "uniqueness_ratio",
    "email_like_rate",
    "date_like_rate",
    "postcode_like_rate",
    "numeric_like_rate",
    "person_table_exact_rate",
    "suggested_rule_json",
]

DRAFT_RULE_MANIFEST_FIELDS = [
    "draft_filename",
    "canonical_header",
    "suggestion_confidence",
    "action_type",
    "candidate_score_max",
    "contributing_labels_count",
    "source_labels",
    "suggestion_sources",
]

PROFILE_SAMPLE_VALUE_LIMIT = 5
PROFILE_SAMPLE_VALUE_MAX_CHARS = 80
PROFILE_SCHEMA_VALUE_SAMPLE_LIMIT = 200
PROFILE_INTEGRATED_GENERIC_VALUE_LIMIT = 200
PROFILE_VOCAB_MIN_VALUE_MATCHES = 3
PROFILE_VOCAB_MIN_VALUE_RATE = 0.60
PROFILE_VOCAB_HIGH_VALUE_RATE = 0.80


def profiling_output_paths(output_dir):
    profiling_dir = os.path.join(output_dir, "3.Profiling")
    return {
        "all_profiles": os.path.join(profiling_dir, "columns_all_profiles.csv"),
        "profiles": os.path.join(profiling_dir, "columns_unknown_profiles.csv"),
        "candidates": os.path.join(profiling_dir, "columns_rule_candidates.csv"),
        "review_only_candidates": os.path.join(profiling_dir, "columns_review_candidates.csv"),
        "schema_plan": os.path.join(profiling_dir, "schema_plan.csv"),
        "table_sketches": os.path.join(profiling_dir, "table_sketches.csv"),
        "table_families": os.path.join(profiling_dir, "table_families.csv"),
        "value_type_candidates": os.path.join(profiling_dir, "value_type_candidates.csv"),
        "rule_coverage": os.path.join(profiling_dir, "rule_coverage.csv"),
        "draft_rules_dir": os.path.join(profiling_dir, "draft_table_column_rules"),
        "draft_rule_manifest": os.path.join(profiling_dir, "draft_table_column_rules", "draft_rule_manifest.csv"),
    }


def draft_rule_pattern_name(canonical_header):
    slug = rule_slug(canonical_header) or "candidate"
    return f"profile_candidate_{slug}_column"


def create_rule_drafts_from_profile(args, paths, run_info):
    profile_paths = profiling_output_paths(args.output_dir)
    candidates_path = profile_paths["candidates"]
    draft_dir = profile_paths["draft_rules_dir"]
    manifest_path = profile_paths["draft_rule_manifest"]

    if not os.path.exists(candidates_path):
        raise FileNotFoundError(
            f"Profile candidate file not found: {candidates_path}. "
            "Run '--profile standalone' first."
        )

    with open(candidates_path, newline="", encoding="utf-8") as handle:
        candidate_rows = list(csv.DictReader(handle))

    os.makedirs(draft_dir, exist_ok=True)

    manifest_rows = []
    written = 0
    used_filenames = set()
    for row in candidate_rows:
        canonical_header = safe_cell(row.get("suggested_header"))
        raw_json = safe_cell(row.get("suggested_rule_json"))
        if not canonical_header or not raw_json:
            continue
        try:
            payload = json.loads(raw_json)
        except json.JSONDecodeError:
            continue

        payload["canonical_header"] = canonical_header
        payload["pattern_name"] = payload.get("pattern_name") or draft_rule_pattern_name(canonical_header)
        header_patterns = payload.get("header_patterns") or []
        payload["header_patterns"] = sorted({safe_cell(pattern) for pattern in header_patterns if safe_cell(pattern)})
        if not payload["header_patterns"]:
            continue

        payload["review_required"] = True
        payload["profile_suggestion"] = {
            "created_from_profile_mode": "create_rules",
            "suggestion_confidence": safe_cell(row.get("suggestion_confidence")),
            "candidate_score_max": safe_cell(row.get("candidate_score_max")),
            "contributing_labels_count": safe_cell(row.get("contributing_labels_count")),
            "source_labels": [
                label for label in
                (safe_cell(value) for value in str(row.get("source_labels", "")).split("|"))
                if label
            ],
            "suggestion_sources": [
                value for value in
                (safe_cell(part) for part in str(row.get("suggestion_sources", "")).split("|"))
                if value
            ],
            "suggestion_basis": [
                value for value in
                (safe_cell(part) for part in str(row.get("suggestion_basis", "")).split("|"))
                if value
            ],
        }

        base_filename = f"{rule_slug(canonical_header) or 'candidate'}.json"
        filename = base_filename
        suffix = 2
        while filename in used_filenames:
            filename = f"{rule_slug(canonical_header) or 'candidate'}__{suffix}.json"
            suffix += 1
        used_filenames.add(filename)

        with open(os.path.join(draft_dir, filename), "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
            handle.write("\n")

        manifest_rows.append({
            "draft_filename": filename,
            "canonical_header": canonical_header,
            "suggestion_confidence": safe_cell(row.get("suggestion_confidence")),
            "action_type": safe_cell(row.get("action_type")),
            "candidate_score_max": safe_cell(row.get("candidate_score_max")),
            "contributing_labels_count": safe_cell(row.get("contributing_labels_count")),
            "source_labels": safe_cell(row.get("source_labels")),
            "suggestion_sources": safe_cell(row.get("suggestion_sources")),
        })
        written += 1

    manifest_rows.sort(key=lambda item: (item["canonical_header"], item["draft_filename"]))
    with open(manifest_path, "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
        writer = csv.DictWriter(handle, fieldnames=DRAFT_RULE_MANIFEST_FIELDS)
        writer.writeheader()
        writer.writerows(manifest_rows)

    run_info["profile"] = args.profile
    run_info["worker_count"] = 0
    run_info["files_discovered"] = 0
    run_info["files_processed"] = 0
    run_info["profiled_files"] = 0
    run_info["unknown_column_profile_rows"] = 0
    run_info["column_rule_candidate_rows"] = len(candidate_rows)
    run_info["value_type_candidate_rows"] = 0
    run_info["rule_coverage_rows"] = 0
    run_info["draft_rule_rows"] = written
    return written


def profile_file_token(path, args, progress_callback=None):
    """Return the profiler's file identity token according to --hash-mode.

    Profiling uses this token only for non-disclosive distinct-file accounting.
    - none/duplicate-candidates: hash the path string only
    - processed/all: hash file content with the selected --file-hash algorithm
    """
    mode = getattr(args, "hash_mode", "duplicate-candidates")
    if mode in {"none", "duplicate-candidates"}:
        return distinct_hash(os.path.abspath(path))
    try:
        total_size = 0
        try:
            total_size = os.path.getsize(path)
        except OSError:
            total_size = 0
        return hash_file(
            path,
            selected_file_hash_algorithm(args),
            progress_callback=progress_callback,
            total_size=total_size,
            progress_base=5.0,
            progress_span=10.0,
        )
    except Exception:
        return distinct_hash(os.path.abspath(path))


def profile_file_token_from_metadata(path, args, known_md5="", known_hash="", progress_callback=None):
    """Return a profile token, reusing an already-computed content hash when possible."""
    mode = getattr(args, "hash_mode", "duplicate-candidates")
    if mode == "none":
        return distinct_hash(os.path.abspath(path))
    known_hash = safe_cell(known_hash) or safe_cell(known_md5)
    if known_hash:
        return known_hash
    if mode == "duplicate-candidates":
        return distinct_hash(os.path.abspath(path))
    return profile_file_token(path, args, progress_callback=progress_callback)


def nonempty_ratio(count, total):
    return float(count) / float(total) if total else 0.0


def distinct_hash(value):
    return hashlib.md5(str(value).encode("utf-8", errors="ignore")).hexdigest()


def profile_rate(entry, key):
    return nonempty_ratio(entry[key], entry["non_empty_values"])


def flexible_header_pattern(label):
    escaped = re.escape(safe_cell(label))
    if not escaped:
        return ""
    escaped = escaped.replace(r"\ ", header_word_separator_pattern())
    return rf"\b{escaped}\b"


def profile_vocab_term_text(value):
    value = safe_cell(value)
    if not value:
        return ""
    value = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", value)
    value = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", value)
    value = value.replace("_", " ").replace("-", " ").replace("/", " ").replace(".", " ")
    compact = re.sub(r"[^a-z0-9]+", "", value.casefold())
    replacement = PROFILE_LABEL_NORMALIZE_REPLACEMENTS.get(compact)
    if replacement:
        value = replacement
    return re.sub(r"\s+", " ", value).strip().casefold()


def profile_vocab_terms_from_value(value):
    terms = set()
    if isinstance(value, dict):
        for item in value.values():
            terms.update(profile_vocab_terms_from_value(item))
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            terms.update(profile_vocab_terms_from_value(item))
    else:
        term = profile_vocab_term_text(value)
        if term:
            terms.add(term)
    return terms


def profile_add_vocab_terms(targets, canonical_header, terms, term_kind, source_id):
    if not canonical_header:
        return
    entry = targets.setdefault(
        canonical_header,
        {"header_terms": set(), "value_terms": set(), "sources": set()},
    )
    cleaned_terms = {profile_vocab_term_text(term) for term in terms}
    cleaned_terms.discard("")
    entry[term_kind].update(cleaned_terms)
    if source_id:
        entry["sources"].add(source_id)


def profile_load_vocab_json(resources_dir, filename):
    path = resources_dir / filename
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return {}


@lru_cache(maxsize=1)
def profile_vocabulary_targets():
    resources_dir = SCRIPT_DIR / "resources" / "vocabularies"
    targets = {}

    ethnicity = profile_load_vocab_json(resources_dir, "ons_ethnic_groups_2021_england_wales.json")
    profile_add_vocab_terms(targets, "ethnicity", ethnicity.get("groups", {}).keys(), "value_terms", "govuk_ethnic_groups_2021")
    profile_add_vocab_terms(targets, "ethnicity", ethnicity.get("flat_terms", []), "value_terms", "govuk_ethnic_groups_2021")
    profile_add_vocab_terms(targets, "ethnicity", ["ethnicity", "ethnic group", "ethnic category"], "header_terms", "govuk_ethnic_groups_2021")

    religion = profile_load_vocab_json(resources_dir, "ons_religion_response_options_england_wales_2021.json")
    profile_add_vocab_terms(targets, "religion", religion.get("religions", []), "value_terms", "ons_religion_england_wales_census_2021")
    profile_add_vocab_terms(targets, "religion", religion.get("aliases", {}), "value_terms", "ons_religion_england_wales_census_2021")
    profile_add_vocab_terms(targets, "religion", ["religion", "religious belief", "faith"], "header_terms", "ons_religion_england_wales_census_2021")

    marital = profile_load_vocab_json(resources_dir, "common_marital_status_terms.json")
    profile_add_vocab_terms(targets, "marital status", marital.get("header_aliases", []), "header_terms", "common_marital_status_seed")
    profile_add_vocab_terms(targets, "marital status", marital.get("canonical_values", {}), "value_terms", "common_marital_status_seed")

    public_sector = profile_load_vocab_json(resources_dir, "public_sector_demographic_variants.json")
    profile_add_vocab_terms(targets, "ethnicity", public_sector.get("ethnicity", {}).get("broad_groups", []), "value_terms", "public_sector_demographic_variants")
    profile_add_vocab_terms(targets, "ethnicity", public_sector.get("ethnicity", {}).get("value_aliases", []), "value_terms", "public_sector_demographic_variants")
    profile_add_vocab_terms(targets, "ethnicity", public_sector.get("ethnicity", {}).get("code_aliases", []), "value_terms", "public_sector_demographic_variants")
    profile_add_vocab_terms(targets, "religion", public_sector.get("religion", {}).get("value_aliases", []), "value_terms", "public_sector_demographic_variants")
    profile_add_vocab_terms(targets, "marital status", public_sector.get("marital_status", {}).get("value_aliases", []), "value_terms", "public_sector_demographic_variants")

    disability = profile_load_vocab_json(resources_dir, "disability_and_adjustment_terms.json")
    profile_add_vocab_terms(targets, "disability", disability.get("header_aliases", []), "header_terms", "disability_adjustment_seed")
    profile_add_vocab_terms(targets, "disability", disability.get("groups", {}), "value_terms", "disability_adjustment_seed")

    country_seed = profile_load_vocab_json(resources_dir, "country_name_and_nationality_seed.json")
    country_terms = []
    for entry in country_seed.get("entries", []):
        country_terms.append(entry.get("country", ""))
        country_terms.extend(entry.get("aliases", []))
    profile_add_vocab_terms(targets, "citizenship country", country_terms, "value_terms", "country_name_and_nationality_seed")
    country_names = profile_load_vocab_json(resources_dir, "country_names_babel_en.json")
    profile_add_vocab_terms(
        targets,
        "citizenship country",
        [entry.get("name", "") for entry in country_names.get("entries", [])],
        "value_terms",
        "country_names_babel_en",
    )
    profile_add_vocab_terms(
        targets,
        "citizenship country",
        ["nationality", "citizenship", "domicile", "country of nationality", "country of citizenship", "country of domicile"],
        "header_terms",
        "country_name_and_nationality_seed",
    )

    student_support = profile_load_vocab_json(resources_dir, "student_support_and_contextual_terms.json")
    student_support_map = {
        "care_leaver": "care leaver",
        "household_income": "household income",
        "principal_earner_income": "principal earner income",
        "dependants_adg_indicator": "dependants adg indicator",
        "dependants_ccg_indicator": "dependants ccg indicator",
        "number_of_sponsors": "number of sponsors",
        "maintenance_grant": "maintenance grant",
        "special_support_element": "special support element",
        "special_support_grant": "special support grant",
    }
    for key, canonical_header in student_support_map.items():
        group = student_support.get("groups", {}).get(key, {})
        profile_add_vocab_terms(targets, canonical_header, group.get("header_aliases", []), "header_terms", "student_support_seed")
        profile_add_vocab_terms(targets, canonical_header, group.get("value_aliases", []), "value_terms", "student_support_seed")

    for filename, source_id in (
        ("nhs_demographic_code_sets_seed.json", "nhs_demographic_code_sets_seed"),
        ("hesa_student_data_terms_seed.json", "hesa_student_data_terms_seed"),
        ("ucas_applicant_terms_seed.json", "ucas_applicant_terms_seed"),
    ):
        payload = profile_load_vocab_json(resources_dir, filename)
        for key, group in (payload.get("vocabularies") or {}).items():
            canonical_header = {
                "marital_status": "marital status",
                "sex_gender": "gender/sex",
                "ethnicity": "ethnicity",
                "religion": "religion",
                "religion_or_belief": "religion",
                "nationality_or_domicile": "citizenship country",
                "domicile_nationality_residency": "citizenship country",
                "disability": "disability",
                "disability_status": "disability",
                "disability_support": "disability",
                "finance_and_support": "",
                "contextual_and_widening_participation": "care leaver",
                "care_and_contextual_status": "care leaver",
            }.get(key, "")
            if not canonical_header:
                continue
            profile_add_vocab_terms(targets, canonical_header, group.get("header_aliases", []), "header_terms", source_id)
            profile_add_vocab_terms(targets, canonical_header, group.get("value_aliases", []), "value_terms", source_id)

    for canonical_header, entry in targets.items():
        entry["header_terms"].add(profile_vocab_term_text(canonical_header))
        entry["sources"] = tuple(sorted(entry["sources"]))
    return targets


def profile_vocabulary_match_score(label, values):
    label_text = profile_vocab_term_text(label)
    value_terms = [profile_vocab_term_text(value) for value in values if profile_vocab_term_text(value)]
    best = ("", 0, "", "", "")
    for canonical_header, entry in profile_vocabulary_targets().items():
        score = 0
        basis = []
        header_terms = entry["header_terms"]
        matched_header_terms = [
            term for term in header_terms
            if term and (term == label_text or (len(term) >= 4 and term in label_text))
        ]
        if matched_header_terms:
            score += 65
            basis.append("vocabulary_header_match")

        matched_values = 0
        if value_terms and entry["value_terms"]:
            value_set = entry["value_terms"]
            matched_values = sum(1 for value in value_terms if profile_value_matches_vocab_terms(value, value_set))
            value_rate = nonempty_ratio(matched_values, len(value_terms))
            substantive_matched_values = sum(
                1
                for value in value_terms
                if profile_value_matches_vocab_terms(value, value_set)
                and profile_vocab_value_is_substantive(value)
            )
            if matched_values >= PROFILE_VOCAB_MIN_VALUE_MATCHES and value_rate >= PROFILE_VOCAB_MIN_VALUE_RATE:
                if (
                    matched_header_terms
                    or canonical_header not in PROFILE_VALUE_ONLY_SENSITIVE_HEADERS
                    or substantive_matched_values >= PROFILE_VOCAB_MIN_VALUE_MATCHES
                ):
                    score += 35 if value_rate >= PROFILE_VOCAB_HIGH_VALUE_RATE else 25
                    basis.append("vocabulary_value_match")

        if score <= best[1]:
            continue
        confidence = "high" if score >= 80 else "medium"
        source = "vocabulary_" + "_and_".join(part.replace("vocabulary_", "") for part in basis)
        best = (
            canonical_header,
            score,
            source,
            confidence,
            " | ".join(list(basis) + list(entry.get("sources") or ())),
        )
    return best


def profile_vocab_value_is_substantive(value):
    value = profile_vocab_term_text(value)
    if not value:
        return False
    if value in PROFILE_NON_SUBSTANTIVE_VOCAB_VALUES:
        return False
    if len(value) < 4:
        return False
    if not re.search(r"[a-z]", value):
        return False
    if re.fullmatch(r"[a-z]{1,3}\d?", value):
        return False
    if re.fullmatch(r"\d+(?:\.\d+)?", value):
        return False
    return True


@lru_cache(maxsize=32768)
def profile_label_token_set(label):
    return frozenset(profile_label_tokens(label))


def profile_value_matches_vocab_terms(value, vocab_terms):
    if value in vocab_terms:
        return True
    value_tokens = profile_label_token_set(value)
    for term in vocab_terms:
        if len(term) < 4:
            continue
        if term in value or value in term:
            return True
        term_tokens = profile_label_token_set(term)
        if term_tokens and term_tokens <= value_tokens:
            return True
    return False


@lru_cache(maxsize=4096)
def profile_value_looks_like_vocabulary_value(value):
    value_text = profile_vocab_term_text(value)
    if not value_text:
        return False
    for entry in profile_vocabulary_targets().values():
        if profile_value_matches_vocab_terms(value_text, entry.get("value_terms") or set()):
            return True
    return False


@lru_cache(maxsize=1)
def nlp_header_bundle():
    """Load a lightweight spaCy pipeline for header/key inference."""
    if spacy is None or PhraseMatcher is None:
        return None, "", None, {}

    nlp = None
    model_name = ""
    for candidate in ("en_core_web_lg", "en_core_web_md", "en_core_web_sm"):
        try:
            nlp = spacy.load(candidate, exclude=["parser", "ner", "textcat", "tagger", "lemmatizer"])
            model_name = candidate
            break
        except Exception:
            continue
    if nlp is None:
        try:
            nlp = spacy.blank("en")
            model_name = "spacy.blank.en"
        except Exception:
            return None, "", None, {}

    matcher = PhraseMatcher(nlp.vocab, attr="LOWER")
    semantic_docs = {}
    for canonical_header, phrases in profile_nlp_targets().items():
        docs = [nlp.make_doc(phrase) for phrase in phrases if safe_cell(phrase)]
        if docs:
            matcher.add(canonical_header, docs)
            semantic_docs[canonical_header] = [nlp(phrase) for phrase in phrases if safe_cell(phrase)]
    return nlp, model_name, matcher, semantic_docs


def nlp_header_backend_name():
    _nlp, model_name, _matcher, _semantic_docs = nlp_header_bundle()
    return model_name


def nlp_header_bundle_loaded():
    """Return whether this process has already initialized the spaCy header bundle."""
    try:
        return bool(nlp_header_bundle.cache_info().currsize)
    except Exception:
        return False


def profile_nlp_enabled(args):
    return bool(getattr(args, "nlp", False))


def maybe_report_nlp_model_loading(args, progress_callback=None, percent=0.0):
    """Emit a one-time progress stage before spaCy is initialized in this process."""
    if progress_callback is None or not profile_nlp_enabled(args) or nlp_header_bundle_loaded():
        return
    progress_callback(percent, "loading NLP model")


def nlp_header_label_text(label):
    label = safe_cell(label)
    if not label:
        return ""
    if "." in label:
        label = label.rsplit(".", 1)[-1]
    label = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", label)
    label = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", " ", label)
    label = label.replace("_", " ").replace("-", " ").replace("/", " ")
    compact = re.sub(r"[^a-z0-9]+", "", label.casefold())
    replacement = PROFILE_LABEL_NORMALIZE_REPLACEMENTS.get(compact)
    if replacement:
        label = replacement
    return re.sub(r"\s+", " ", label).strip()


@lru_cache(maxsize=1)
def profile_nlp_targets():
    targets = {}
    for canonical_header, phrases in PROFILE_NLP_HINTS.items():
        values = {nlp_header_label_text(canonical_header), safe_cell(canonical_header)}
        for phrase in phrases:
            values.add(nlp_header_label_text(phrase))
            values.add(safe_cell(phrase))
        if canonical_header == "gender/sex":
            values.update({"gender", "sex", "gender sex"})
        targets[canonical_header] = tuple(sorted({safe_cell(value) for value in values if safe_cell(value)}))
    for _pattern, canonical_header, _order, _metadata in TABLE_COLUMN_RULES.get("header_matchers", ()):
        targets.setdefault(
            canonical_header,
            tuple(sorted({
                safe_cell(canonical_header),
                nlp_header_label_text(canonical_header),
            } - {""}))
        )
    for canonical_header, entry in profile_vocabulary_targets().items():
        values = set(targets.get(canonical_header, ()))
        values.add(safe_cell(canonical_header))
        values.add(nlp_header_label_text(canonical_header))
        values.update(entry.get("header_terms") or ())
        targets[canonical_header] = tuple(sorted({safe_cell(value) for value in values if safe_cell(value)}))
    return targets


def nlp_header_suggestion(label):
    label_text = nlp_header_label_text(label)
    if not label_text:
        return "", ""
    nlp, _model_name, matcher, semantic_docs = nlp_header_bundle()
    if nlp is None or matcher is None:
        return "", ""
    doc = nlp.make_doc(label_text)
    matches = matcher(doc)
    scored = Counter()
    for match_id, start, end in matches:
        canonical_header = nlp.vocab.strings[match_id]
        span_len = max(1, end - start)
        scored[canonical_header] += span_len
    if scored:
        best_header, best_score = scored.most_common(1)[0]
        if best_score > 0:
            confidence = "high" if best_score >= 2 else "medium"
            return best_header, confidence

    if not semantic_docs or _model_name == "spacy.blank.en":
        return "", ""

    semantic_doc = nlp(label_text)
    if not semantic_doc.has_vector:
        return "", ""
    best_header = ""
    best_score = 0.0
    second_best = 0.0
    for canonical_header, docs in semantic_docs.items():
        header_score = 0.0
        for alias_doc in docs:
            if not alias_doc.has_vector:
                continue
            try:
                score = semantic_doc.similarity(alias_doc)
            except Exception:
                score = 0.0
            header_score = max(header_score, float(score or 0.0))
        if header_score > best_score:
            second_best = best_score
            best_score = header_score
            best_header = canonical_header
        elif header_score > second_best:
            second_best = header_score

    if best_score < PROFILE_SEMANTIC_MIN_SIMILARITY:
        return "", ""
    if best_score - second_best < 0.03 and best_score < PROFILE_SEMANTIC_HIGH_SIMILARITY:
        return "", ""
    confidence = "high" if best_score >= PROFILE_SEMANTIC_HIGH_SIMILARITY else "medium"
    return best_header, confidence


def suggested_header_from_nlp_label(label, args):
    if not profile_nlp_enabled(args):
        return "", "", ""
    best_header, confidence = nlp_header_suggestion(label)
    if not best_header:
        return "", "", ""
    return best_header, "nlp_label_inference", confidence


def profile_numeric_like(value):
    cleaned = re.sub(r"[\s,.\-_/()+]+", "", safe_cell(value))
    return bool(cleaned) and cleaned.isdigit()


def profile_value_flags(value):
    value = safe_cell(value)
    return {
        "email_like": bool(PROFILE_EMAIL_RE.search(value)),
        "date_like": bool(valid_contextual_date(value)),
        "postcode_like": bool(valid_uk_postcode(value)),
        "numeric_like": profile_numeric_like(value),
        "person_table_exact": profile_person_table_exact_signal(value),
    }


def profile_person_table_exact_signal(value):
    """Return whether person-table exact overlap is meaningful for profiling.

    The person tables often contain dates, low-cardinality flags and short admin
    codes.  Treating those as exact-match evidence makes unrelated date/status
    columns look like strong candidates.  Keep the signal for plausible names or
    identifiers, but suppress it for value families that already have a clearer
    type or are too generic to identify a person.
    """
    value = safe_cell(value)
    if not value:
        return False
    if PROFILE_EMAIL_RE.search(value) or valid_contextual_date(value) or valid_uk_postcode(value):
        return False
    folded = profile_vocab_term_text(value)
    if folded in PROFILE_NON_SUBSTANTIVE_VOCAB_VALUES:
        return False
    if profile_value_looks_like_vocabulary_value(value):
        return False
    digits = digits_only(value)
    if profile_numeric_like(value):
        if len(digits) < 6:
            return False
        if re.fullmatch(r"(?:19|20)\d{2}", digits):
            return False
    if len(folded) <= 2:
        return False
    return person_table_exact_match_count_for_value(value) > 0


def profile_metrics_for_values(values):
    values = [safe_cell(value) for value in values]
    non_empty_values = [value for value in values if value]
    total = len(non_empty_values)
    counts = Counter()
    for value in non_empty_values:
        for key, matched in profile_value_flags(value).items():
            if matched:
                counts[key] += 1
    distinct_count = len({distinct_hash(value) for value in non_empty_values})
    return {
        "email_like_rate": f"{nonempty_ratio(counts['email_like'], total):.4f}",
        "date_like_rate": f"{nonempty_ratio(counts['date_like'], total):.4f}",
        "postcode_like_rate": f"{nonempty_ratio(counts['postcode_like'], total):.4f}",
        "numeric_like_rate": f"{nonempty_ratio(counts['numeric_like'], total):.4f}",
        "person_table_exact_rate": f"{nonempty_ratio(counts['person_table_exact'], total):.4f}",
        "distinct_value_count_estimate": str(distinct_count),
        "uniqueness_ratio": f"{nonempty_ratio(distinct_count, total):.4f}",
        "non_empty_values": str(total),
        "low_cardinality": "yes" if 0 < distinct_count <= 10 else "no",
    }


def profile_label_slug(label):
    return rule_slug(nlp_header_label_text(label) or label)


def profile_label_tokens(label):
    return [token for token in profile_label_slug(label).split("_") if token]


def profile_label_is_placeholder(label):
    label = safe_cell(label)
    if not label:
        return False
    if PROFILE_PLACEHOLDER_LABEL_RE.fullmatch(label):
        return True
    return PROFILE_PLACEHOLDER_LABEL_RE.fullmatch(profile_label_slug(label) or "") is not None


def profile_label_looks_like_value(label):
    label = safe_cell(label)
    if not label or profile_label_is_placeholder(label):
        return False
    if header_label_looks_like_free_text(label):
        return True
    if PROFILE_EMAIL_RE.search(label) or valid_contextual_date(label) or valid_uk_postcode(label):
        return True
    if profile_value_looks_like_vocabulary_value(label):
        return True
    digits = sum(1 for char in label if char.isdigit())
    letters = sum(1 for char in label if char.isalpha())
    if digits >= 4 and digits >= letters:
        return True
    if profile_numeric_like(label) and digits >= 4:
        return True
    return False


def profile_header_row_looks_like_data(headers):
    values = [safe_cell(value) for value in headers if safe_cell(value)]
    if len(values) < 2:
        return False
    value_like = 0
    for value in values:
        if profile_label_looks_like_value(value):
            value_like += 1
            continue
        flags = profile_value_flags(value)
        if flags["email_like"] or flags["date_like"] or flags["postcode_like"]:
            value_like += 1
    return value_like >= max(2, int(len(values) * 0.5))


def profile_header_cell_looks_like_header(value, args):
    value = safe_cell(value)
    if not value:
        return False
    if profile_label_is_placeholder(value) or profile_label_looks_like_value(value):
        return False
    normalized = nlp_header_label_text(value)
    if not normalized:
        return False
    if len(normalized) > 64 or len(normalized.split()) > 8:
        return False
    if not any(char.isalpha() for char in normalized):
        return False
    if resolve_table_header(value):
        return True
    if profile_nlp_enabled(args) and suggested_header_from_nlp_label(value, args)[0]:
        return True
    if len(normalized.split()) <= 4:
        return True
    return False


def profile_header_row_looks_like_headers(headers, sampled_rows, args):
    values = [safe_cell(value) for value in headers if safe_cell(value)]
    if len(values) < 2:
        return False
    header_like = sum(1 for value in values if profile_header_cell_looks_like_header(value, args))
    if header_like < max(2, int(len(values) * 0.5)):
        return False

    if not sampled_rows:
        return True

    sample_values = []
    for row in sampled_rows[:10]:
        sample_values.extend(safe_cell(value) for value in row if safe_cell(value))
    if not sample_values:
        return True
    sample_data_like = sum(1 for value in sample_values if profile_label_looks_like_value(value))
    header_data_like = sum(1 for value in values if profile_label_looks_like_value(value))
    return sample_data_like >= header_data_like


def profile_label_supports_suggested_header(row):
    label = safe_cell(row.get("source_label"))
    suggested_header = safe_cell(row.get("suggested_header"))
    if not label or not suggested_header:
        return False, "missing_label_or_suggestion"
    if profile_label_is_placeholder(label):
        return False, "placeholder_or_headerless_label"
    if profile_label_looks_like_value(label):
        return False, "label_looks_like_data_value"
    if row.get("header_origin") == "headerless_generic":
        return False, "headerless_generic_column"

    label_slug = profile_label_slug(label)
    label_tokens = set(profile_label_tokens(label))
    label_text = nlp_header_label_text(label).casefold()

    if suggested_header == "DOB":
        if {"dob", "birth", "born"} & label_tokens or "date of birth" in label_text:
            return True, "birth_semantics_in_label"
        return False, "date_values_without_birth_semantics"

    if suggested_header == "email":
        if {"type", "status", "source", "category"} & label_tokens:
            return False, "email_metadata_label"
        if (
            {"email", "mail", "mailbox", "inbox"} & label_tokens
            or "mail" in label_slug
            or "email" in label_slug
        ):
            return True, "email_semantics_in_label"
        if "contact" in label_tokens and float(row.get("email_like_rate") or 0.0) >= 0.8:
            return True, "contact_label_with_email_values"
        return False, "email_values_without_email_semantics"

    if suggested_header == "postcode":
        if {"postcode", "postal", "zip", "address", "addr"} & label_tokens:
            return True, "postcode_semantics_in_label"
        return False, "postcode_values_without_postcode_semantics"

    if suggested_header == "phone":
        if {"type", "status", "source", "category"} & label_tokens:
            return False, "phone_metadata_label"
        if {"phone", "telephone", "mobile", "tel", "contact"} & label_tokens:
            return True, "phone_semantics_in_label"
        return False, "phone_values_without_phone_semantics"

    if suggested_header == "IP Address":
        if (
            {"ip", "ipv4", "ipv6"} & label_tokens
            or "ipaddress" in label_slug
            or "ip_addr" in label_slug
        ):
            return True, "ip_semantics_in_label"
        return False, "ip_values_without_ip_semantics"

    if suggested_header == "payment card":
        if {"type", "country", "method", "source", "category"} & label_tokens:
            return False, "payment_card_metadata_label"
        if {"card", "credit", "payment"} & label_tokens:
            return True, "payment_card_semantics_in_label"
        return False, "payment_card_values_without_card_semantics"

    if suggested_header == "payment method":
        if {"payment", "method", "debit"} & label_tokens:
            return True, "payment_method_semantics_in_label"
        return False, "payment_method_values_without_payment_semantics"

    if suggested_header in {"full name", "first name", "last name"}:
        if is_non_person_name_header(label):
            return False, "non_person_name_semantics"
        if suggested_header == "full name" and is_full_name_header(label):
            return True, "full_name_semantics_in_label"
        if suggested_header == "first name" and name_part_for_header(label) == "first":
            return True, "first_name_semantics_in_label"
        if suggested_header == "last name" and name_part_for_header(label) == "last":
            return True, "last_name_semantics_in_label"
        return False, "name_values_without_name_semantics"

    if suggested_header == "middle name":
        if {"middle", "name"} <= label_tokens or label_slug in {"middlename", "middle_name"}:
            return True, "middle_name_semantics_in_label"
        return False, "name_values_without_middle_name_semantics"

    if suggested_header == "username":
        if (
            label_slug in {"username", "user_name", "login_name"}
            or {"user", "name"} <= label_tokens
            or {"login", "name"} <= label_tokens
        ):
            return True, "username_semantics_in_label"
        return False, "name_values_without_username_semantics"

    if suggested_header == "student id":
        if {"student", "id", "identifier", "number", "reference", "emplid"} & label_tokens:
            return True, "identifier_semantics_in_label"
        return False, "identifier_values_without_identifier_semantics"

    if suggested_header == "staff id":
        if label_slug in {"emplid", "empl_id"}:
            return True, "known_staff_identifier_label"
        if {"staff", "employee", "member", "user"} & label_tokens and {"id", "identifier", "number", "no"} & label_tokens:
            return True, "staff_identifier_semantics_in_label"
        return False, "identifier_values_without_staff_semantics"

    if suggested_header == "citizenship country":
        if "passport" in label_tokens:
            return False, "citizenship_country_passport_metadata_label"
        if any(phrase in label_text for phrase in (
            "country of nationality",
            "country of citizenship",
            "country of domicile",
        )):
            return True, "citizenship_country_semantics_in_label"
        if {"nationality", "citizenship", "domicile", "citizen"} & label_tokens:
            return True, "citizenship_country_semantics_in_label"
        return False, "country_values_without_citizenship_semantics"

    if suggested_header == "disability":
        if {"term", "admit", "course", "programme", "program", "atas", "placement", "work"} & label_tokens:
            return False, "disability_admin_label"
        if {"disability", "disabled", "accessibility", "adjustment", "impairment"} & label_tokens:
            return True, "disability_semantics_in_label"
        if "reasonable adjustment" in label_text or "accessibility needs" in label_text:
            return True, "disability_semantics_in_label"
        return False, "disability_values_without_disability_semantics"

    if suggested_header == "religion":
        if {"religion", "religious", "faith", "belief"} & label_tokens:
            return True, "religion_semantics_in_label"
        return False, "religion_values_without_religion_semantics"

    if suggested_header == "ethnicity":
        if {"ethnicity", "ethnic", "race"} & label_tokens or "ethnic group" in label_text:
            return True, "ethnicity_semantics_in_label"
        return False, "ethnicity_values_without_ethnicity_semantics"

    if suggested_header == "marital status":
        if {"marital", "marriage"} & label_tokens or "relationship status" in label_text:
            return True, "marital_status_semantics_in_label"
        return False, "marital_values_without_marital_semantics"

    if suggested_header == "gender/sex":
        if {"gender", "sex"} & label_tokens:
            return True, "gender_sex_semantics_in_label"
        return False, "gender_values_without_gender_semantics"

    if suggested_header == "person id":
        if label_slug in {"emplid", "empl_id"}:
            return True, "known_person_identifier_label"
        subject_tokens = {"candidate", "applicant", "person", "customer", "user", "employee", "staff", "student", "member"}
        id_tokens = {"id", "identifier", "number", "no", "ref", "reference"}
        if subject_tokens & label_tokens and id_tokens & label_tokens:
            return True, "person_identifier_semantics_in_label"
        return False, "identifier_values_without_subject_semantics"

    if suggested_header in {"passport", "visa", "national id", "BRP", "driving licence", "sort code", "account number", "IBAN", "UTR", "UCAS ID", "HUSID", "SLC ID", "SSN", "NHS number", "National Insurance Number", "CAS number"}:
        if set(profile_label_tokens(suggested_header)) & label_tokens:
            return True, "known_identifier_term_in_label"
        return False, "identifier_values_without_matching_identifier_term"

    inferred_header, _confidence = nlp_header_suggestion(label)
    if inferred_header == suggested_header:
        return True, "nlp_label_support"
    if set(profile_label_tokens(suggested_header)) & label_tokens:
        return True, "token_overlap_with_suggested_header"
    return False, "label_semantics_do_not_support_suggestion"


def profile_processing_decision(row):
    if row["resolved_header"]:
        return "resolved_existing_rule", "resolved_by_current_rules"
    if not row["suggested_header"]:
        return "no_suggestion", ""
    supported, reason = profile_label_supports_suggested_header(row)
    if supported:
        return "rule_candidate", reason
    return "review_only", reason


def new_profile_entry(source_kind, header_origin, source_label, resolved_header, suggested_header, suggestion_source, suggestion_confidence):
    return {
        "source_kind": source_kind,
        "header_origin": header_origin,
        "source_label": source_label,
        "resolved_header": resolved_header,
        "suggested_header": suggested_header,
        "suggestion_source": suggestion_source,
        "suggestion_confidence": suggestion_confidence,
        "files": set(),
        "rows_seen": 0,
        "non_empty_values": 0,
        "blank_values": 0,
        "distinct_values": set(),
        "min_length": None,
        "max_length": 0,
        "length_total": 0,
        "email_like": 0,
        "date_like": 0,
        "postcode_like": 0,
        "numeric_like": 0,
        "person_table_exact": 0,
        "sample_values": {},
    }


def new_rule_coverage_entry(rule_kind, rule_name, evidence_types=(), emit_cell_value=False, notes=""):
    return {
        "rule_kind": rule_kind,
        "rule_name": rule_name,
        "evidence_types": tuple(evidence_types),
        "emit_cell_value": bool(emit_cell_value),
        "files": set(),
        "rows_seen": 0,
        "non_empty_values": 0,
        "matched_source_labels": set(),
        "notes": notes,
    }


def merge_profile_entry(target, source):
    target["files"].update(source["files"])
    target["rows_seen"] += source["rows_seen"]
    target["non_empty_values"] += source["non_empty_values"]
    target["blank_values"] += source["blank_values"]
    target["distinct_values"].update(source["distinct_values"])
    if source["min_length"] is not None:
        if target["min_length"] is None:
            target["min_length"] = source["min_length"]
        else:
            target["min_length"] = min(target["min_length"], source["min_length"])
    target["max_length"] = max(target["max_length"], source["max_length"])
    target["length_total"] += source["length_total"]
    for key in ["email_like", "date_like", "postcode_like", "numeric_like", "person_table_exact"]:
        target[key] += source[key]
    merge_profile_samples(target, source)


def sample_profile_value_text(value):
    value = safe_cell(value)
    if not value:
        return ""
    value = re.sub(r"\s+", " ", value).strip()
    if len(value) > PROFILE_SAMPLE_VALUE_MAX_CHARS:
        return value[: PROFILE_SAMPLE_VALUE_MAX_CHARS - 1].rstrip() + "…"
    return value


def update_profile_samples(entry, value):
    sample_value = sample_profile_value_text(value)
    if not sample_value:
        return
    token = distinct_hash(sample_value)
    samples = entry["sample_values"]
    if token in samples:
        return
    if len(samples) < PROFILE_SAMPLE_VALUE_LIMIT:
        samples[token] = sample_value
        return
    largest_token = max(samples)
    if token < largest_token:
        samples.pop(largest_token, None)
        samples[token] = sample_value


def merge_profile_samples(target, source):
    source_samples = source.get("sample_values") or {}
    if not source_samples:
        return
    for token, value in source_samples.items():
        if token in target["sample_values"]:
            continue
        if len(target["sample_values"]) < PROFILE_SAMPLE_VALUE_LIMIT:
            target["sample_values"][token] = value
            continue
        largest_token = max(target["sample_values"])
        if token < largest_token:
            target["sample_values"].pop(largest_token, None)
            target["sample_values"][token] = value


def merge_rule_coverage_entry(target, source):
    target["files"].update(source["files"])
    target["rows_seen"] += source["rows_seen"]
    target["non_empty_values"] += source["non_empty_values"]
    target["matched_source_labels"].update(source["matched_source_labels"])


def update_profile_entry(entry, file_token, value):
    entry["files"].add(file_token)
    entry["rows_seen"] += 1
    value = safe_cell(value)
    if not value:
        entry["blank_values"] += 1
        return

    entry["non_empty_values"] += 1
    entry["distinct_values"].add(distinct_hash(value))
    update_profile_samples(entry, value)
    value_len = len(value)
    entry["min_length"] = value_len if entry["min_length"] is None else min(entry["min_length"], value_len)
    entry["max_length"] = max(entry["max_length"], value_len)
    entry["length_total"] += value_len

    flags = profile_value_flags(value)
    for key, matched in flags.items():
        if matched:
            entry[key] += 1


@lru_cache(maxsize=1)
def profile_unresolved_patterns():
    return tuple(pattern for pattern in PATTERNS if unresolved_table_pattern_allowed(pattern))


def profile_pattern_route_for_header(header, header_separator_chars=""):
    header = safe_cell(header)
    if not header:
        return profile_unresolved_patterns(), "unresolved"
    header_match = resolve_table_header_match(header, header_separator_chars=header_separator_chars)
    if header_match is None:
        return profile_unresolved_patterns(), "unresolved"
    patterns = table_patterns_for_header(header)
    if patterns is None:
        patterns = profile_unresolved_patterns()
    return patterns, f"resolved:{header_match.get('canonical_header', header)}"


def profile_matching_patterns(value, patterns=None, cache_key="all"):
    value = safe_cell(value)
    if not value:
        return ()
    cache_token = (cache_key, value)
    cached = PROFILE_PATTERN_MATCH_CACHE.get(cache_token)
    if cached is not None:
        return cached

    patterns = tuple(patterns) if patterns is not None else tuple(PATTERNS)
    if not patterns:
        return ()

    hits = []
    for pattern in patterns:
        try:
            for match in pattern["regex"].finditer(value):
                matched_text, start, end = extract_match_value(match)
                if not validate_pattern_match(pattern, matched_text):
                    continue
                if value[:start].strip() or value[end:].strip():
                    continue
                hits.append((pattern.get("pattern_name", ""), pattern.get("evidence_type", "")))
                break
        except Exception:
            continue
    hits = tuple(hits)
    if len(PROFILE_PATTERN_MATCH_CACHE) >= 4096:
        PROFILE_PATTERN_MATCH_CACHE.clear()
    PROFILE_PATTERN_MATCH_CACHE[cache_token] = hits
    return hits


def current_status_for_profile(entry):
    if entry["resolved_header"]:
        return "resolved"
    if entry["suggested_header"]:
        return "unresolved_but_suggested"
    return "unresolved_no_suggestion"


def action_type_for_profile(row):
    if row["resolved_header"]:
        return "existing_rule_match"
    if row.get("processing_decision") == "review_only":
        return "review_only"
    if not row["suggested_header"]:
        return "review_only"
    metadata = resolve_table_header_metadata(row["suggested_header"])
    if metadata_truthy(metadata.get("emit_cell_value")):
        return "add_header_synonym_with_emit_cell_value"
    if row["suggestion_source"] == "person_table_value_inference":
        return "add_header_synonym"
    return "add_header_synonym"


def header_candidate_threshold_met(row):
    score = int(row["candidate_score"])
    files_seen = int(row["files_seen"])
    non_empty = int(row["non_empty_values"])
    return (
        row.get("processing_decision") == "rule_candidate"
        and bool(row["suggested_header"])
        and score >= 45
        and (files_seen >= 2 or non_empty >= 25)
    )


def profile_row_may_be_identifier(row):
    return (
        float(row["numeric_like_rate"]) >= 0.8
        and float(row["uniqueness_ratio"]) >= 0.8
        and int(row["distinct_value_count_estimate"]) >= 20
        and float(row["date_like_rate"]) < 0.2
        and float(row["postcode_like_rate"]) < 0.2
        and float(row["email_like_rate"]) < 0.2
    )


def profile_row_may_be_enum(row):
    return (
        row["low_cardinality"] == "yes"
        and int(row["distinct_value_count_estimate"]) >= 2
        and int(row["distinct_value_count_estimate"]) <= 10
        and float(row["uniqueness_ratio"]) <= 0.2
    )


def value_type_candidate_row_from_profile(row):
    candidate_kind = ""
    action_type = ""
    basis = []
    score = 0
    suggested_rule_json = ""

    if profile_row_may_be_identifier(row):
        candidate_kind = "possible_identifier_family"
        action_type = "review_new_identifier_type"
        basis.extend(["high_numeric_like_rate", "high_uniqueness"])
        score = 60 + min(20, int(row["files_seen"]) * 2)
        payload = {
            "evidence_type": f"Unknown Identifier: {safe_cell(row['source_label']) or 'candidate'}",
            "pattern_name": f"profile_candidate_{rule_slug(row['source_label']) or 'candidate'}",
            "normalization": "compact_upper",
            "risk_roles": ["id"],
        }
        suggested_rule_json = json.dumps(payload, sort_keys=True)
    elif profile_row_may_be_enum(row):
        candidate_kind = "possible_enum_family"
        action_type = "review_new_enum_or_emit_rule"
        basis.append("low_cardinality")
        score = 35 + min(15, int(row["files_seen"]) * 2)

    if not candidate_kind:
        return None

    return {
        "source_kind": row["source_kind"],
        "header_origin": row["header_origin"],
        "source_label": row["source_label"],
        "candidate_kind": candidate_kind,
        "action_type": action_type,
        "suggestion_basis": " | ".join(basis),
        "candidate_score": min(100, score),
        "files_seen": row["files_seen"],
        "rows_seen": row["rows_seen"],
        "non_empty_values": row["non_empty_values"],
        "distinct_value_count_estimate": row["distinct_value_count_estimate"],
        "uniqueness_ratio": row["uniqueness_ratio"],
        "email_like_rate": row["email_like_rate"],
        "date_like_rate": row["date_like_rate"],
        "postcode_like_rate": row["postcode_like_rate"],
        "numeric_like_rate": row["numeric_like_rate"],
        "person_table_exact_rate": row["person_table_exact_rate"],
        "suggested_rule_json": suggested_rule_json,
    }


def suggestion_basis_for_profile(entry):
    basis = []
    if entry["suggestion_source"]:
        basis.append(entry["suggestion_source"])
    if entry["non_empty_values"]:
        if profile_rate(entry, "person_table_exact") >= 0.8:
            basis.append("high_person_table_exact_rate")
        if profile_rate(entry, "email_like") >= 0.8:
            basis.append("high_email_like_rate")
        if profile_rate(entry, "date_like") >= 0.8:
            basis.append("high_date_like_rate")
        if profile_rate(entry, "postcode_like") >= 0.8:
            basis.append("high_postcode_like_rate")
        if len(entry["distinct_values"]) <= 10:
            basis.append("low_cardinality")
    return " | ".join(basis)


def candidate_score_for_entry(entry):
    score = 0
    if entry["suggestion_source"] == "person_table_value_inference":
        score += 60
    elif entry["suggestion_source"].startswith("vocabulary_"):
        score += 55
    elif entry["suggestion_source"] == "nlp_label_inference":
        score += 50
    elif entry["suggestion_source"] == "value_shape_inference":
        score += 40
    score += min(20, len(entry["files"]) * 2)
    score += min(10, entry["non_empty_values"] // 25)
    if entry["non_empty_values"]:
        score += int(10 * profile_rate(entry, "person_table_exact"))
        score += int(8 * profile_rate(entry, "email_like"))
        score += int(8 * profile_rate(entry, "date_like"))
        score += int(8 * profile_rate(entry, "postcode_like"))
    return min(100, score)


def suggested_rule_json_for_profile(row):
    if not row["suggested_header"] or row.get("processing_decision") != "rule_candidate":
        return ""
    payload = {
        "canonical_header": row["suggested_header"],
        "header_patterns": [flexible_header_pattern(row["source_label"])],
    }
    metadata = resolve_table_header_metadata(row["suggested_header"])
    configured_evidence_types = configured_evidence_types_from_header_metadata(metadata)
    if configured_evidence_types:
        if len(configured_evidence_types) == 1:
            payload["evidence_type"] = configured_evidence_types[0]
        else:
            payload["evidence_types"] = configured_evidence_types
    if metadata_truthy(metadata.get("emit_cell_value")):
        payload["emit_cell_value"] = True
        validators = values_as_list(metadata.get("validators")) + values_as_list(metadata.get("validator"))
        validators = [safe_cell(value) for value in validators if safe_cell(value)]
        if validators:
            payload["validators"] = validators
    context_guard = context_guard_payload(metadata.get("context_guard"))
    if context_guard:
        payload["context_guard"] = context_guard
    return json.dumps(payload, sort_keys=True)


def initialize_rule_coverage():
    coverage = {}
    seen_emit = set()
    for pattern in PATTERNS:
        key = ("regex_rule", f"{pattern.get('evidence_type', '')}::{pattern.get('pattern_name', '')}")
        coverage[key] = new_rule_coverage_entry(
            "regex_rule",
            pattern.get("pattern_name", ""),
            evidence_types=[pattern.get("evidence_type", "")],
            emit_cell_value=False,
            notes="Cell-level coverage for existing regex rules in profiled structured/tabular values.",
        )
    for _pattern, canonical_header, _order, metadata in TABLE_COLUMN_RULES.get("header_matchers", ()):
        key = ("table_header", canonical_header)
        if key not in coverage:
            coverage[key] = new_rule_coverage_entry(
                "table_header",
                canonical_header,
                evidence_types=configured_evidence_types_from_header_metadata(metadata),
                emit_cell_value=metadata_truthy(metadata.get("emit_cell_value")),
                notes="Profile coverage for existing table/structured header resolution.",
            )
        if metadata_truthy(metadata.get("emit_cell_value")) and canonical_header not in seen_emit:
            emit_key = ("table_emit_cell_value", canonical_header)
            coverage[emit_key] = new_rule_coverage_entry(
                "table_emit_cell_value",
                canonical_header,
                evidence_types=configured_evidence_types_from_header_metadata(metadata),
                emit_cell_value=True,
                notes="Header-confirmed value emission coverage in profiled table/structured data.",
            )
            seen_emit.add(canonical_header)
    return coverage


def update_rule_coverage_entry(entry, file_token, source_label, value):
    entry["files"].add(file_token)
    entry["rows_seen"] += 1
    value = safe_cell(value)
    entry["matched_source_labels"].add(safe_cell(source_label))
    if value:
        entry["non_empty_values"] += 1


def finalize_profile_entry(entry):
    non_empty = entry["non_empty_values"]
    distinct_count = len(entry["distinct_values"])
    avg_length = round(entry["length_total"] / non_empty, 2) if non_empty else 0.0
    uniqueness = round(nonempty_ratio(distinct_count, non_empty), 4)
    row = {
        "source_kind": entry["source_kind"],
        "header_origin": entry["header_origin"],
        "source_label": entry["source_label"],
        "files_seen": len(entry["files"]),
        "rows_seen": entry["rows_seen"],
        "non_empty_values": non_empty,
        "blank_values": entry["blank_values"],
        "distinct_value_count_estimate": distinct_count,
        "uniqueness_ratio": f"{uniqueness:.4f}",
        "min_length": entry["min_length"] or 0,
        "max_length": entry["max_length"],
        "avg_length": f"{avg_length:.2f}",
        "email_like_rate": f"{nonempty_ratio(entry['email_like'], non_empty):.4f}",
        "date_like_rate": f"{nonempty_ratio(entry['date_like'], non_empty):.4f}",
        "postcode_like_rate": f"{nonempty_ratio(entry['postcode_like'], non_empty):.4f}",
        "numeric_like_rate": f"{nonempty_ratio(entry['numeric_like'], non_empty):.4f}",
        "person_table_exact_rate": f"{nonempty_ratio(entry['person_table_exact'], non_empty):.4f}",
        "low_cardinality": "yes" if 0 < distinct_count <= 10 else "no",
        "sample_values_preview": " | ".join(
            entry["sample_values"][token]
            for token in sorted(entry.get("sample_values") or {})
        ),
    }
    row["resolved_header"] = entry["resolved_header"]
    row["suggested_header"] = entry["suggested_header"]
    row["suggestion_source"] = entry["suggestion_source"]
    row["suggestion_confidence"] = entry["suggestion_confidence"]
    row["processing_decision"], row["processing_decision_reason"] = profile_processing_decision(row)
    if row["resolved_header"]:
        row["current_status"] = "resolved"
    elif not row["suggested_header"]:
        row["current_status"] = "unresolved_no_suggestion"
    elif row["processing_decision"] == "rule_candidate":
        row["current_status"] = "unresolved_but_suggested"
    else:
        row["current_status"] = "unresolved_review_only"
    row["action_type"] = action_type_for_profile(row)
    row["suggestion_basis"] = suggestion_basis_for_profile(entry)
    row["candidate_score"] = candidate_score_for_entry(entry)
    row["suggested_rule_json"] = suggested_rule_json_for_profile(row)
    return row


def candidate_row_from_profile(row):
    return {
        "source_kind": row["source_kind"],
        "header_origin": row["header_origin"],
        "source_label": row["source_label"],
        "current_status": row["current_status"],
        "suggested_header": row["suggested_header"],
        "action_type": row["action_type"],
        "suggestion_basis": row["suggestion_basis"],
        "suggestion_source": row["suggestion_source"],
        "suggestion_confidence": row["suggestion_confidence"],
        "candidate_score": row["candidate_score"],
        "suggested_rule_json": row["suggested_rule_json"],
        "processing_decision": row["processing_decision"],
        "processing_decision_reason": row["processing_decision_reason"],
        "files_seen": row["files_seen"],
        "rows_seen": row["rows_seen"],
        "non_empty_values": row["non_empty_values"],
        "distinct_value_count_estimate": row["distinct_value_count_estimate"],
        "email_like_rate": row["email_like_rate"],
        "date_like_rate": row["date_like_rate"],
        "postcode_like_rate": row["postcode_like_rate"],
        "numeric_like_rate": row["numeric_like_rate"],
        "person_table_exact_rate": row["person_table_exact_rate"],
    }


def finalize_rule_coverage_row(entry):
    files_seen = len(entry["files"])
    rows_seen = entry["rows_seen"]
    non_empty = entry["non_empty_values"]
    matched_labels = len(entry["matched_source_labels"])
    coverage_score = min(100, files_seen * 8 + min(36, rows_seen // 10) + min(24, matched_labels * 4))
    if rows_seen == 0:
        if entry["rule_kind"] in {"table_header", "table_emit_cell_value"}:
            status = "likely_stale_for_structured_data"
            recommended_action = "review_or_remove_header_rule"
        else:
            status = "not_observed_in_profile"
            recommended_action = "review_if_expected_in_structured_data"
    elif files_seen >= 5 or rows_seen >= 100:
        status = "seen_often"
        recommended_action = "keep"
    elif files_seen >= 2 or rows_seen >= 10:
        status = "seen_some"
        recommended_action = "keep"
    else:
        status = "seen_rarely"
        recommended_action = "review_for_specificity" if entry["rule_kind"] == "regex_rule" else "review_header_synonyms"
    return {
        "rule_kind": entry["rule_kind"],
        "rule_name": entry["rule_name"],
        "evidence_types": "|".join(entry["evidence_types"]),
        "emit_cell_value": "yes" if entry["emit_cell_value"] else "no",
        "status": status,
        "coverage_score": coverage_score,
        "recommended_action": recommended_action,
        "matched_source_labels_count": len(entry["matched_source_labels"]),
        "files_seen": files_seen,
        "rows_seen": rows_seen,
        "non_empty_values": non_empty,
        "notes": entry["notes"],
    }


def group_candidate_rows(candidate_rows):
    grouped = {}
    for row in candidate_rows:
        key = (
            row["suggested_header"],
            row["action_type"],
        )
        entry = grouped.setdefault(
            key,
            {
                "suggested_header": row["suggested_header"],
                "action_type": row["action_type"],
                "suggestion_confidence": row["suggestion_confidence"],
                "candidate_score_max": int(row["candidate_score"]),
                "source_kinds": set(),
                "header_origins": set(),
                "source_labels": set(),
                "files_seen_total": 0,
                "rows_seen_total": 0,
                "non_empty_values_total": 0,
                "suggestion_sources": set(),
                "suggestion_basis_parts": set(),
                "source_labels_for_rule": set(),
            },
        )
        if SUGGESTION_CONFIDENCE_ORDER.get(row["suggestion_confidence"], -1) > SUGGESTION_CONFIDENCE_ORDER.get(entry["suggestion_confidence"], -1):
            entry["suggestion_confidence"] = row["suggestion_confidence"]
        entry["candidate_score_max"] = max(entry["candidate_score_max"], int(row["candidate_score"]))
        entry["source_kinds"].add(row["source_kind"])
        entry["header_origins"].add(row["header_origin"])
        entry["source_labels"].add(row["source_label"])
        entry["files_seen_total"] += int(row["files_seen"])
        entry["rows_seen_total"] += int(row["rows_seen"])
        entry["non_empty_values_total"] += int(row["non_empty_values"])
        if row["suggestion_source"]:
            entry["suggestion_sources"].add(row["suggestion_source"])
        if row["source_label"]:
            entry["source_labels_for_rule"].add(row["source_label"])
        for part in split_pipe_values(row["suggestion_basis"]):
            if part:
                entry["suggestion_basis_parts"].add(part)

    grouped_rows = []
    for entry in grouped.values():
        grouped_rule_payload = {
            "canonical_header": entry["suggested_header"],
            "header_patterns": [
                flexible_header_pattern(label)
                for label in sorted(entry["source_labels_for_rule"])
                if flexible_header_pattern(label)
            ],
        }
        metadata = resolve_table_header_metadata(entry["suggested_header"])
        configured_evidence_types = configured_evidence_types_from_header_metadata(metadata)
        if configured_evidence_types:
            if len(configured_evidence_types) == 1:
                grouped_rule_payload["evidence_type"] = configured_evidence_types[0]
            else:
                grouped_rule_payload["evidence_types"] = configured_evidence_types
        if metadata_truthy(metadata.get("emit_cell_value")):
            grouped_rule_payload["emit_cell_value"] = True
            validators = values_as_list(metadata.get("validators")) + values_as_list(metadata.get("validator"))
            validators = [safe_cell(value) for value in validators if safe_cell(value)]
            if validators:
                grouped_rule_payload["validators"] = validators
        context_guard = context_guard_payload(metadata.get("context_guard"))
        if context_guard:
            grouped_rule_payload["context_guard"] = context_guard
        grouped_rows.append(
            {
                "suggested_header": entry["suggested_header"],
                "action_type": entry["action_type"],
                "suggestion_confidence": entry["suggestion_confidence"],
                "candidate_score_max": entry["candidate_score_max"],
                "source_kinds": " | ".join(sorted(entry["source_kinds"])),
                "header_origins": " | ".join(sorted(entry["header_origins"])),
                "contributing_labels_count": len(entry["source_labels"]),
                "source_labels": " | ".join(sorted(entry["source_labels"])),
                "files_seen_total": entry["files_seen_total"],
                "rows_seen_total": entry["rows_seen_total"],
                "non_empty_values_total": entry["non_empty_values_total"],
                "suggestion_sources": " | ".join(sorted(entry["suggestion_sources"])),
                "suggestion_basis": " | ".join(sorted(entry["suggestion_basis_parts"])),
                "suggested_rule_json": json.dumps(grouped_rule_payload, sort_keys=True),
            }
        )
    grouped_rows.sort(
        key=lambda row: (
            -int(row["candidate_score_max"]),
            -int(row["contributing_labels_count"]),
            -int(row["files_seen_total"]),
            row["suggested_header"],
            row["action_type"],
        )
    )
    return grouped_rows


def group_review_only_rows(review_rows):
    grouped = {}
    for row in review_rows:
        key = (
            row["suggested_header"],
            row.get("processing_decision_reason", ""),
        )
        entry = grouped.setdefault(
            key,
            {
                "suggested_header": row["suggested_header"],
                "processing_decision_reason": row.get("processing_decision_reason", ""),
                "suggestion_confidence": row["suggestion_confidence"],
                "candidate_score_max": int(row["candidate_score"]),
                "source_kinds": set(),
                "header_origins": set(),
                "source_labels": set(),
                "files_seen_total": 0,
                "rows_seen_total": 0,
                "non_empty_values_total": 0,
                "suggestion_sources": set(),
                "suggestion_basis_parts": set(),
            },
        )
        if SUGGESTION_CONFIDENCE_ORDER.get(row["suggestion_confidence"], -1) > SUGGESTION_CONFIDENCE_ORDER.get(entry["suggestion_confidence"], -1):
            entry["suggestion_confidence"] = row["suggestion_confidence"]
        entry["candidate_score_max"] = max(entry["candidate_score_max"], int(row["candidate_score"]))
        entry["source_kinds"].add(row["source_kind"])
        entry["header_origins"].add(row["header_origin"])
        entry["source_labels"].add(row["source_label"])
        entry["files_seen_total"] += int(row["files_seen"])
        entry["rows_seen_total"] += int(row["rows_seen"])
        entry["non_empty_values_total"] += int(row["non_empty_values"])
        if row["suggestion_source"]:
            entry["suggestion_sources"].add(row["suggestion_source"])
        for part in split_pipe_values(row["suggestion_basis"]):
            if part:
                entry["suggestion_basis_parts"].add(part)

    grouped_rows = []
    for entry in grouped.values():
        grouped_rows.append(
            {
                "suggested_header": entry["suggested_header"],
                "processing_decision_reason": entry["processing_decision_reason"],
                "suggestion_confidence": entry["suggestion_confidence"],
                "candidate_score_max": entry["candidate_score_max"],
                "source_kinds": " | ".join(sorted(entry["source_kinds"])),
                "header_origins": " | ".join(sorted(entry["header_origins"])),
                "contributing_labels_count": len(entry["source_labels"]),
                "source_labels": " | ".join(sorted(entry["source_labels"])),
                "files_seen_total": entry["files_seen_total"],
                "rows_seen_total": entry["rows_seen_total"],
                "non_empty_values_total": entry["non_empty_values_total"],
                "suggestion_sources": " | ".join(sorted(entry["suggestion_sources"])),
                "suggestion_basis": " | ".join(sorted(entry["suggestion_basis_parts"])),
            }
        )
    grouped_rows.sort(
        key=lambda row: (
            -int(row["candidate_score_max"]),
            -int(row["contributing_labels_count"]),
            -int(row["files_seen_total"]),
            row["suggested_header"],
            row["processing_decision_reason"],
        )
    )
    return grouped_rows


def dedupe_schema_plan_rows(schema_plan):
    seen = set()
    rows = []
    for row in schema_plan or []:
        normalized = {field: safe_cell(row.get(field, "")) for field in SCHEMA_PLAN_FIELDS}
        key = tuple(normalized[field] for field in SCHEMA_PLAN_FIELDS)
        if key in seen:
            continue
        seen.add(key)
        rows.append(normalized)
    rows.sort(key=lambda row: (
        row["file_token"],
        row["source_kind"],
        row["table_name"],
        int(row["column_index"] or 0),
        row["raw_header"],
    ))
    return rows


def schema_plan_table_key(row):
    return (
        safe_cell(row.get("file_token")),
        safe_cell(row.get("source_kind")),
        safe_cell(row.get("table_name")),
        safe_cell(row.get("schema_signature")),
    )


def schema_plan_row_type(row):
    return safe_cell(row.get("resolved_header")) or safe_cell(row.get("suggested_type"))


def schema_plan_header_mode(rows):
    origins = {safe_cell(row.get("header_origin")) for row in rows}
    if origins == {"headerless_generic"}:
        return "headerless"
    if "headerless_generic" in origins:
        return "mixed"
    return "headered"


def table_rows_from_schema_plan(schema_plan_rows):
    tables = {}
    for row in schema_plan_rows or []:
        key = schema_plan_table_key(row)
        if not all(key):
            continue
        tables.setdefault(key, []).append(row)
    for rows in tables.values():
        rows.sort(key=lambda row: int(safe_cell(row.get("column_index")) or 0))
    return tables


def schema_family_scan_action(suggested_type):
    metadata = resolve_table_header_metadata(suggested_type)
    if metadata_truthy(metadata.get("emit_cell_value")):
        return "route_suggested_rules_and_emit_cell_value"
    return "route_suggested_rules"


def family_id_for_signature(schema_signature):
    token = safe_cell(schema_signature)[:12] or "unknown"
    return f"schema_family_{token}"


def apply_schema_family_propagation(schema_plan_rows):
    """Cluster table/schema sketches and propagate safe family schemas.

    This is intentionally conservative. Headerless rows only inherit a type
    where the same shape has one clear non-headerless consensus type for that
    column. If headered examples disagree, the family is marked conflicted and
    no propagation happens.
    """
    rows = [dict(row) for row in schema_plan_rows or []]
    tables = table_rows_from_schema_plan(rows)
    families = defaultdict(list)
    for key, table_rows in tables.items():
        schema_signature = key[3]
        families[schema_signature].append((key, table_rows))

    sketch_rows = []
    family_rows = []
    row_by_identity = {
        (
            safe_cell(row.get("file_token")),
            safe_cell(row.get("source_kind")),
            safe_cell(row.get("table_name")),
            safe_cell(row.get("schema_signature")),
            safe_cell(row.get("column_index")),
        ): row
        for row in rows
    }

    for schema_signature, table_items in families.items():
        family_id = family_id_for_signature(schema_signature)
        source_kinds = sorted({key[1] for key, _rows in table_items if key[1]})
        orientations = sorted({safe_cell(table_rows[0].get("orientation")) for _key, table_rows in table_items if table_rows})
        separators = sorted({safe_cell(table_rows[0].get("detected_separator")) for _key, table_rows in table_items if table_rows})
        column_count = max((len(table_rows) for _key, table_rows in table_items), default=0)
        header_modes = {key: schema_plan_header_mode(table_rows) for key, table_rows in table_items}
        headered_items = [(key, table_rows) for key, table_rows in table_items if header_modes.get(key) != "headerless"]
        headerless_items = [(key, table_rows) for key, table_rows in table_items if header_modes.get(key) == "headerless"]

        consensus_types = []
        conflict_columns = []
        for column_index in range(1, column_count + 1):
            type_counts = Counter()
            for _key, table_rows in headered_items:
                for row in table_rows:
                    if int(safe_cell(row.get("column_index")) or 0) != column_index:
                        continue
                    row_type = schema_plan_row_type(row)
                    if row_type:
                        type_counts[row_type] += 1
                    break
            if not type_counts:
                consensus_types.append("")
                continue
            if len(type_counts) > 1:
                conflict_columns.append(str(column_index))
                consensus_types.append("")
                continue
            consensus_types.append(next(iter(type_counts)))

        conflict_reason = ""
        if conflict_columns:
            conflict_reason = "conflicting_headered_types_at_columns=" + "|".join(conflict_columns)
            family_status = "conflict_no_propagation"
        elif headered_items and headerless_items and any(consensus_types):
            family_status = "propagated_from_headered_examples"
        elif headered_items:
            family_status = "headered_no_headerless_targets"
        elif any(
            sum(1 for _key, table_rows in table_items for row in table_rows if schema_plan_row_type(row)) > 1
            for _ in [None]
        ):
            family_status = "headerless_value_inferred_only"
        else:
            family_status = "unresolved_headerless_family"

        propagated_columns = 0
        if family_status == "propagated_from_headered_examples":
            for key, table_rows in headerless_items:
                for row in table_rows:
                    column_index = int(safe_cell(row.get("column_index")) or 0)
                    if column_index <= 0 or column_index > len(consensus_types):
                        continue
                    suggested_type = consensus_types[column_index - 1]
                    if not suggested_type or schema_plan_row_type(row):
                        continue
                    identity = (
                        safe_cell(row.get("file_token")),
                        safe_cell(row.get("source_kind")),
                        safe_cell(row.get("table_name")),
                        safe_cell(row.get("schema_signature")),
                        safe_cell(row.get("column_index")),
                    )
                    target = row_by_identity.get(identity)
                    if target is None:
                        continue
                    target["suggested_type"] = suggested_type
                    target["confidence"] = "high" if len(headered_items) > 1 else "medium"
                    target["reason"] = f"schema_family_propagation:{family_id}"
                    target["scan_action"] = schema_family_scan_action(suggested_type)
                    target["schema_reused_from"] = family_id
                    propagated_columns += 1

        for key, table_rows in table_items:
            mode = header_modes.get(key, "")
            resolved_sequence = [safe_cell(row.get("resolved_header")) for row in table_rows]
            suggested_sequence = [safe_cell(row.get("suggested_type")) for row in table_rows]
            sketch_rows.append({
                "family_id": family_id,
                "family_status": family_status,
                "file_token": key[0],
                "source_kind": key[1],
                "table_name": key[2],
                "column_count": str(len(table_rows)),
                "header_mode": mode,
                "orientation": safe_cell(table_rows[0].get("orientation")) if table_rows else "",
                "detected_separator": safe_cell(table_rows[0].get("detected_separator")) if table_rows else "",
                "schema_signature": schema_signature,
                "resolved_type_sequence": "|".join(resolved_sequence),
                "suggested_type_sequence": "|".join(suggested_sequence),
            })

        family_rows.append({
            "family_id": family_id,
            "family_status": family_status,
            "source_kinds": "|".join(source_kinds),
            "table_count": str(len(table_items)),
            "headered_table_count": str(len(headered_items)),
            "headerless_table_count": str(len(headerless_items)),
            "column_count": str(column_count),
            "orientation": "|".join(orientations),
            "detected_separator": "|".join(separators),
            "schema_signature": schema_signature,
            "consensus_type_sequence": "|".join(consensus_types),
            "propagated_column_count": str(propagated_columns),
            "conflict_reason": conflict_reason,
        })

    sketch_rows.sort(key=lambda row: (row["family_id"], row["source_kind"], row["table_name"], row["file_token"]))
    family_rows.sort(key=lambda row: (-int(row["table_count"] or 0), row["family_id"]))
    return rows, sketch_rows, family_rows


def write_profile_outputs(output_dir, profiles, rule_coverage, schema_plan=None):
    paths = profiling_output_paths(output_dir)
    Path(paths["all_profiles"]).parent.mkdir(parents=True, exist_ok=True)
    all_rows = [
        finalize_profile_entry(entry)
        for entry in profiles.values()
        if entry["rows_seen"] > 0
    ]
    all_rows.sort(key=lambda row: (-int(row["candidate_score"]), row["source_kind"], row["source_label"], row["suggested_header"], row["resolved_header"]))

    with open(paths["all_profiles"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
        writer = csv.DictWriter(handle, fieldnames=PROFILE_OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(all_rows)

    rows = [row for row in all_rows if not row["resolved_header"]]

    with open(paths["profiles"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
        writer = csv.DictWriter(handle, fieldnames=PROFILE_OUTPUT_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    candidate_rows = [
        candidate_row_from_profile(row)
        for row in rows
        if not row["resolved_header"] and header_candidate_threshold_met(row)
    ]
    candidate_rows = group_candidate_rows(candidate_rows)

    with open(paths["candidates"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
        writer = csv.DictWriter(handle, fieldnames=PROFILE_CANDIDATE_FIELDS)
        writer.writeheader()
        writer.writerows(candidate_rows)

    review_only_rows = [
        candidate_row_from_profile(row)
        for row in rows
        if row.get("processing_decision") == "review_only" and int(row["candidate_score"]) >= 45
    ]
    review_only_rows = group_review_only_rows(review_only_rows)

    with open(paths["review_only_candidates"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
        writer = csv.DictWriter(handle, fieldnames=REVIEW_ONLY_CANDIDATE_FIELDS)
        writer.writeheader()
        writer.writerows(review_only_rows)

    schema_plan_rows = dedupe_schema_plan_rows(schema_plan)
    schema_plan_rows, table_sketch_rows, table_family_rows = apply_schema_family_propagation(schema_plan_rows)
    with open(paths["schema_plan"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
        writer = csv.DictWriter(handle, fieldnames=SCHEMA_PLAN_FIELDS)
        writer.writeheader()
        writer.writerows(schema_plan_rows)

    with open(paths["table_sketches"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
        writer = csv.DictWriter(handle, fieldnames=TABLE_SKETCH_FIELDS)
        writer.writeheader()
        writer.writerows(table_sketch_rows)

    with open(paths["table_families"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
        writer = csv.DictWriter(handle, fieldnames=TABLE_FAMILY_FIELDS)
        writer.writeheader()
        writer.writerows(table_family_rows)

    value_type_rows = []
    for row in rows:
        if row["resolved_header"] or row["suggested_header"]:
            continue
        candidate = value_type_candidate_row_from_profile(row)
        if candidate is not None:
            value_type_rows.append(candidate)
    value_type_rows.sort(key=lambda row: (-int(row["candidate_score"]), row["source_kind"], row["source_label"]))

    with open(paths["value_type_candidates"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
        writer = csv.DictWriter(handle, fieldnames=VALUE_TYPE_CANDIDATE_FIELDS)
        writer.writeheader()
        writer.writerows(value_type_rows)

    rule_rows = [finalize_rule_coverage_row(entry) for entry in rule_coverage.values()]
    rule_rows.sort(
        key=lambda row: (
            RULE_COVERAGE_STATUS_ORDER.get(row["status"], 99),
            int(row["coverage_score"]),
            row["rule_kind"],
            row["rule_name"],
        )
    )
    with open(paths["rule_coverage"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
        writer = csv.DictWriter(handle, fieldnames=RULE_COVERAGE_FIELDS)
        writer.writeheader()
        writer.writerows(rule_rows)

    return len(rows), len(candidate_rows), len(review_only_rows), len(value_type_rows), len(rule_rows), len(schema_plan_rows)


def suggested_header_for_values(label, values, args):
    if profile_nlp_enabled(args):
        header, _score, source, confidence, _basis = profile_vocabulary_match_score(label, values)
        if header:
            return header, source, confidence

        header, source, confidence = suggested_header_from_nlp_label(label, args)
        if header:
            return header, source, confidence

    header = infer_header_from_person_table_values(values)
    if header:
        return header, "person_table_value_inference", "high"

    evidence_type = dominant_column_evidence_type(values)
    if evidence_type:
        return inferred_header_for_evidence_type(evidence_type), "value_shape_inference", "medium"

    values = [safe_cell(value) for value in values if safe_cell(value)]
    if len(values) >= HEADER_INFERENCE_MIN_VALUES:
        flag_counts = Counter()
        for value in values:
            for key, matched in profile_value_flags(value).items():
                if matched:
                    flag_counts[key] += 1
        threshold = max(HEADER_INFERENCE_MIN_RATIO, 0.9)
        if nonempty_ratio(flag_counts.get("email_like", 0), len(values)) >= threshold:
            return "email", "value_shape_inference", "medium"
        if nonempty_ratio(flag_counts.get("postcode_like", 0), len(values)) >= threshold:
            return "postcode", "value_shape_inference", "medium"

    return "", "", ""


def schema_plan_suggestion_support(raw_header, header_origin, suggested_header, suggestion_confidence, profile_metrics=None):
    if not suggested_header:
        return False, "unresolved"
    metrics = dict(profile_metrics or {})
    row = {
        "source_label": safe_cell(raw_header),
        "header_origin": safe_cell(header_origin),
        "suggested_header": safe_cell(suggested_header),
        "suggestion_confidence": safe_cell(suggestion_confidence),
        "email_like_rate": metrics.get("email_like_rate", "0.0000"),
        "date_like_rate": metrics.get("date_like_rate", "0.0000"),
        "postcode_like_rate": metrics.get("postcode_like_rate", "0.0000"),
        "numeric_like_rate": metrics.get("numeric_like_rate", "0.0000"),
        "person_table_exact_rate": metrics.get("person_table_exact_rate", "0.0000"),
        "distinct_value_count_estimate": metrics.get("distinct_value_count_estimate", "0"),
        "uniqueness_ratio": metrics.get("uniqueness_ratio", "0.0000"),
        "non_empty_values": metrics.get("non_empty_values", "0"),
        "low_cardinality": metrics.get("low_cardinality", "no"),
        "resolved_header": "",
    }
    return profile_label_supports_suggested_header(row)


def schema_plan_scan_action(resolved_header, suggested_header, metadata, raw_header="", header_origin="",
                            suggestion_confidence="", profile_metrics=None):
    if resolved_header:
        if metadata_truthy(metadata.get("emit_cell_value")):
            return "route_rules_and_emit_cell_value"
        return "route_relevant_rules"
    if suggested_header:
        supported, _reason = schema_plan_suggestion_support(
            raw_header,
            header_origin,
            suggested_header,
            suggestion_confidence,
            profile_metrics=profile_metrics,
        )
        if supported and suggestion_confidence == "high" and header_origin != "headerless_generic":
            suggested_metadata = resolve_table_header_metadata(suggested_header)
            if metadata_truthy(suggested_metadata.get("emit_cell_value")):
                return "route_suggested_rules_and_emit_cell_value"
            return "route_suggested_rules"
        if supported and suggestion_confidence == "medium" and header_origin != "headerless_generic":
            suggested_metadata = resolve_table_header_metadata(suggested_header)
            if not metadata_truthy(suggested_metadata.get("emit_cell_value")):
                return "route_suggested_rules"
        return "review_only_raw_fallback"
    return "raw_fallback_unresolved"


def schema_plan_linking_scope(source_kind, transposed=False):
    if transposed:
        return "table_row_transposed_record"
    if source_kind in {"csv", "tsv", "xlsx", "xls", "xlsm", "ods", "html"}:
        return "table_row"
    return "structured_record"


def schema_plan_signature(source_kind, table_name, headers, sampled_columns, orientation, detected_separator=""):
    """Return a stable non-disclosive signature for a table/schema shape."""
    column_profiles = []
    for index, header in enumerate(headers):
        values = sampled_columns[index] if index < len(sampled_columns) else []
        metrics = profile_metrics_for_values(values)
        column_profiles.append({
            "index": index + 1,
            "email_like_rate": metrics.get("email_like_rate", "0.0000"),
            "date_like_rate": metrics.get("date_like_rate", "0.0000"),
            "postcode_like_rate": metrics.get("postcode_like_rate", "0.0000"),
            "numeric_like_rate": metrics.get("numeric_like_rate", "0.0000"),
            "person_table_exact_rate": metrics.get("person_table_exact_rate", "0.0000"),
            "uniqueness_ratio": metrics.get("uniqueness_ratio", "0.0000"),
            "low_cardinality": metrics.get("low_cardinality", "no"),
        })
    payload = {
        "source_kind": safe_cell(source_kind),
        "separator": safe_cell(detected_separator),
        "orientation": safe_cell(orientation),
        "columns": column_profiles,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def append_schema_plan_row(schema_plan, file_token, source_kind, table_name, column_index, raw_header,
                           header_origin, resolved_header, suggested_header, suggestion_source,
                           suggestion_confidence, transposed=False, profile_metrics=None,
                           orientation="normal", orientation_confidence="", orientation_reason="",
                           detected_separator="", schema_signature="", schema_reused_from=""):
    if schema_plan is None:
        return
    metadata = resolve_table_header_metadata(resolved_header) if resolved_header else {}
    if resolved_header:
        confidence = metadata.get("confidence") or "high"
        reason = "existing_rule_match"
    elif suggested_header:
        confidence = suggestion_confidence or "medium"
        supported, support_reason = schema_plan_suggestion_support(
            raw_header,
            header_origin,
            suggested_header,
            confidence,
            profile_metrics=profile_metrics,
        )
        reason = f"{suggestion_source or 'suggested_by_profile'}:{support_reason}"
        if not supported:
            reason = f"review_only:{reason}"
    else:
        confidence = ""
        reason = "unresolved"
    scan_action = schema_plan_scan_action(
        resolved_header,
        suggested_header,
        metadata,
        raw_header=raw_header,
        header_origin=header_origin,
        suggestion_confidence=confidence,
        profile_metrics=profile_metrics,
    )
    if orientation == "ambiguous":
        scan_action = "review_only_ambiguous_orientation"
    schema_plan.append({
        "file_token": file_token,
        "source_kind": source_kind,
        "table_name": table_name,
        "column_index": column_index,
        "raw_header": raw_header,
        "header_origin": header_origin,
        "resolved_header": resolved_header,
        "suggested_type": suggested_header,
        "confidence": confidence,
        "reason": reason,
        "scan_action": scan_action,
        "linking_scope": schema_plan_linking_scope(source_kind, transposed=transposed),
        "orientation": orientation,
        "orientation_confidence": orientation_confidence,
        "orientation_reason": orientation_reason,
        "detected_separator": detected_separator,
        "schema_signature": schema_signature,
        "schema_reused_from": schema_reused_from,
    })


def profile_table(headers, rows, table_name, source_kind, file_token, profiles, rule_coverage, args, progress_callback=None, progress_position=None, schema_plan=None, table_separator=""):
    if progress_callback:
        progress_callback(45.0, "sampling table")
    rows = iter(rows)
    sampled_data_rows = list(islice(rows, HEADER_INFERENCE_SAMPLE_ROWS))
    original_headers = list(headers)
    transposed = False

    original_headers, sampled_data_rows, metadata_rows_skipped = split_leading_transposed_metadata(
        original_headers,
        sampled_data_rows,
    )
    header_separator_chars = infer_table_header_separator_chars(
        original_headers,
        sampled_data_rows,
        include_first_column_labels=True,
    )
    orientation = table_orientation_assessment(
        original_headers,
        sampled_data_rows,
        header_separator_chars=header_separator_chars,
    )
    if metadata_rows_skipped:
        orientation = dict(orientation)
        orientation["reason"] = f"leading_metadata_rows_skipped={metadata_rows_skipped}; {orientation['reason']}"
    force_review_headerless = orientation["orientation"] == "ambiguous"

    if orientation["transpose"]:
        original_headers, rows = transpose_field_labelled_table(original_headers, sampled_data_rows, rows)
        sampled_data_rows = list(islice(rows, HEADER_INFERENCE_SAMPLE_ROWS))
        transposed = True

    initial_resolved_headers = [
        normalise_header(h, i + 1, header_separator_chars=header_separator_chars)
        for i, h in enumerate(original_headers)
    ]
    recognized_headers = looks_like_table_headers(initial_resolved_headers, header_separator_chars=header_separator_chars)
    headers_contain_evidence_values = any(full_cell_evidence_types(value) for value in original_headers)
    headers_contain_person_table_values = any(person_table_exact_match_count_for_value(value) for value in original_headers)
    headers_look_like_data = profile_header_row_looks_like_data(original_headers)
    headers_look_like_headers = profile_header_row_looks_like_headers(original_headers, sampled_data_rows, args)
    treat_first_row_as_data = (
        force_review_headerless
        or (not recognized_headers and not headers_look_like_headers)
        or headers_contain_evidence_values
        or headers_contain_person_table_values
        or headers_look_like_data
    )

    if treat_first_row_as_data:
        sampled_rows = [original_headers] + sampled_data_rows
        base_headers = [f"column_{index + 1}" for index in range(max([len(row) for row in sampled_rows] or [len(original_headers)]))]
        trust_base_headers = False
        data_rows = chain(sampled_rows, rows)
    else:
        sampled_rows = sampled_data_rows
        base_headers = original_headers
        trust_base_headers = True
        data_rows = chain(sampled_data_rows, rows)

    table_header_separator_chars = header_separator_chars if trust_base_headers or orientation["transpose"] else ""
    inferred_headers = infer_table_headers(
        sampled_rows,
        base_headers=base_headers,
        trust_base_headers=trust_base_headers,
        header_separator_chars=table_header_separator_chars,
    )
    if not inferred_headers:
        inferred_headers = [safe_cell(header) or f"column_{index + 1}" for index, header in enumerate(base_headers)]

    column_count = len(inferred_headers)
    sampled_columns = [
        [row[index] if index < len(row) else "" for row in sampled_rows]
        for index in range(column_count)
    ]
    table_schema_signature = schema_plan_signature(
        source_kind,
        table_name,
        inferred_headers,
        sampled_columns,
        orientation["orientation"],
        detected_separator=table_separator,
    )

    column_profiles = []
    column_pattern_routes = []
    for index in range(column_count):
        source_label = safe_cell(base_headers[index]) if index < len(base_headers) else f"column_{index + 1}"
        effective_label = safe_cell(inferred_headers[index]) or f"column_{index + 1}"
        resolved_header = resolve_table_header(effective_label, header_separator_chars=table_header_separator_chars)
        suggested_header = ""
        suggestion_source = ""
        suggestion_confidence = ""

        if not resolved_header:
            suggested_header, suggestion_source, suggestion_confidence = suggested_header_for_values(source_label, sampled_columns[index], args)

        if trust_base_headers and source_label:
            header_origin = "explicit_header"
        elif effective_label != source_label:
            header_origin = "inferred_header"
        else:
            header_origin = "headerless_generic"

        append_schema_plan_row(
            schema_plan,
            file_token=file_token,
            source_kind=source_kind,
            table_name=table_name,
            column_index=index + 1,
            raw_header=source_label,
            header_origin=header_origin,
            resolved_header=resolved_header,
            suggested_header=suggested_header,
            suggestion_source=suggestion_source,
            suggestion_confidence=suggestion_confidence,
            transposed=transposed,
            profile_metrics=profile_metrics_for_values(sampled_columns[index]),
            orientation=orientation["orientation"],
            orientation_confidence=orientation["confidence"],
            orientation_reason=orientation["reason"],
            detected_separator=table_separator,
            schema_signature=table_schema_signature,
        )

        key = (source_kind, header_origin, source_label, resolved_header, suggested_header)
        entry = profiles.setdefault(
            key,
            new_profile_entry(
                source_kind=source_kind,
                header_origin=header_origin,
                source_label=source_label,
                resolved_header=resolved_header,
                suggested_header=suggested_header,
                suggestion_source=suggestion_source,
                suggestion_confidence=suggestion_confidence,
            ),
        )
        column_profiles.append(entry)
        route_patterns, route_key = profile_pattern_route_for_header(
            effective_label,
            header_separator_chars=table_header_separator_chars,
        )
        column_pattern_routes.append((route_patterns, route_key))
        if resolved_header:
            coverage_entry = rule_coverage.get(("table_header", resolved_header))
            if coverage_entry is not None:
                for value in sampled_columns[index]:
                    update_rule_coverage_entry(coverage_entry, file_token, source_label, value)
            metadata = resolve_table_header_metadata(effective_label, header_separator_chars=table_header_separator_chars)
            if metadata_truthy(metadata.get("emit_cell_value")):
                emit_entry = rule_coverage.get(("table_emit_cell_value", resolved_header))
                if emit_entry is not None:
                    for value in sampled_columns[index]:
                        update_rule_coverage_entry(emit_entry, file_token, source_label, value)
        route_patterns, route_key = column_pattern_routes[index]
        for value in sampled_columns[index]:
            for pattern_name, evidence_type in profile_matching_patterns(value, route_patterns, route_key):
                regex_entry = rule_coverage.get(("regex_rule", f"{evidence_type}::{pattern_name}"))
                if regex_entry is not None:
                    update_rule_coverage_entry(regex_entry, file_token, source_label, value)

    processed_row_count = 0
    for row in data_rows:
        processed_row_count += 1
        cells = [safe_cell(value) for value in row]
        for index, entry in enumerate(column_profiles):
            value = cells[index] if index < len(cells) else ""
            update_profile_entry(entry, file_token, value)
            resolved_header = entry["resolved_header"]
            route_patterns, route_key = column_pattern_routes[index]
            if resolved_header:
                coverage_entry = rule_coverage.get(("table_header", resolved_header))
                if coverage_entry is not None:
                    update_rule_coverage_entry(coverage_entry, file_token, entry["source_label"], value)
                metadata = resolve_table_header_metadata(resolved_header)
                if metadata_truthy(metadata.get("emit_cell_value")):
                    emit_entry = rule_coverage.get(("table_emit_cell_value", resolved_header))
                    if emit_entry is not None:
                        update_rule_coverage_entry(emit_entry, file_token, entry["source_label"], value)
            for pattern_name, evidence_type in profile_matching_patterns(value, route_patterns, route_key):
                regex_entry = rule_coverage.get(("regex_rule", f"{evidence_type}::{pattern_name}"))
                if regex_entry is not None:
                    update_rule_coverage_entry(regex_entry, file_token, entry["source_label"], value)
        if progress_callback and progress_position and processed_row_count % 200 == 0:
            try:
                position_ratio = max(0.0, min(1.0, float(progress_position())))
            except Exception:
                position_ratio = 0.0
            progress_callback(45.0 + (45.0 * position_ratio), "profiling table")
    if progress_callback:
        progress_callback(90.0, "profiling table")


def profile_delimited_file(path, extension, profiles, rule_coverage, args, progress_callback=None, file_token="", schema_plan=None):
    if progress_callback:
        progress_callback(20.0, "reading delimited file")
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        sample = handle.read(8192)
        handle.seek(0)
        if extension == ".tsv":
            dialect = csv.excel_tab
        else:
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=TABLE_SNIFF_DELIMITERS)
            except csv.Error:
                dialect = csv.excel
        reader = csv.reader(handle, dialect)
        try:
            headers = next(reader)
        except StopIteration:
            return False
        total_size = 0
        try:
            total_size = max(1, os.path.getsize(path))
        except OSError:
            total_size = 0
        def progress_position():
            if total_size <= 0:
                return 0.0
            try:
                byte_pos = handle.buffer.tell() if hasattr(handle, "buffer") else handle.tell()
            except Exception:
                return 0.0
            return min(1.0, max(0.0, float(byte_pos) / float(total_size)))
        if progress_callback:
            progress_callback(35.0, "routing columns")
        file_token = file_token or profile_file_token_from_metadata(path, args, progress_callback=progress_callback)
        profile_table(
            headers,
            reader,
            Path(path).name,
            extension.lstrip("."),
            file_token,
            profiles,
            rule_coverage,
            args,
            progress_callback,
            progress_position,
            schema_plan=schema_plan,
            table_separator=getattr(dialect, "delimiter", ""),
        )
        return True


def profile_labelled_table_name_from_line(line):
    match = re.match(r"TABLE_ROW\s+(.+?)\s+#\d+\s+\|", safe_cell(line))
    return match.group(1) if match else ""


def profile_entry_light_update(entry, file_token, value):
    """Update cheap profile counters without value-type/NLP/regex checks."""
    entry["files"].add(file_token)
    entry["rows_seen"] += 1
    value = safe_cell(value)
    if not value:
        entry["blank_values"] += 1
        return
    entry["non_empty_values"] += 1
    entry["distinct_values"].add(distinct_hash(value))
    update_profile_samples(entry, value)
    value_len = len(value)
    entry["min_length"] = value_len if entry["min_length"] is None else min(entry["min_length"], value_len)
    entry["max_length"] = max(entry["max_length"], value_len)
    entry["length_total"] += value_len


def profile_labelled_text(text, source_kind, file_token, profiles, rule_coverage, args, progress_callback=None, schema_plan=None):
    if progress_callback:
        progress_callback(65.0, "profiling structured fields")
    saw_labelled = False
    total_lines = max(1, text.count("\n") + 1) if text else 1
    integrated_mode = safe_cell(getattr(args, "profile", "")) == "integrated"
    schema_inputs = {}
    for line_number, line in enumerate(iter_text_lines(text), start=1):
        if not is_labelled_record_line(line):
            if progress_callback and line_number % 200 == 0:
                progress_callback(65.0 + (25.0 * min(1.0, float(line_number) / float(total_lines))), "profiling structured fields")
            continue
        labelled_fields = labelled_fields_from_line(line)
        if line.lstrip().startswith("XML_SCOPE "):
            labelled_fields = [
                (header, value)
                for header, value in labelled_fields
                if not (header.startswith("XML_SCOPE ") and header.endswith(" path"))
            ]
        if not labelled_fields:
            if progress_callback and line_number % 200 == 0:
                progress_callback(65.0 + (25.0 * min(1.0, float(line_number) / float(total_lines))), "profiling structured fields")
            continue
        saw_labelled = True
        table_name = profile_labelled_table_name_from_line(line) or f"{source_kind}_records"
        by_header = defaultdict(list)
        for header, value in labelled_fields:
            by_header[safe_cell(header)].append(safe_cell(value))
        for header, values in by_header.items():
            resolved_header = resolve_table_header(header)
            route_patterns, route_key = profile_pattern_route_for_header(header)
            header_origin = (
                "headerless_generic"
                if re.fullmatch(r"column_\d+", safe_cell(header).casefold())
                else "structured_path"
            )
            schema_key = (source_kind, table_name, header)
            schema_entry = schema_inputs.setdefault(
                schema_key,
                {
                    "source_kind": source_kind,
                    "table_name": table_name,
                    "column_index": int(re.search(r"\d+", header).group(0)) if re.fullmatch(r"column_\d+", safe_cell(header).casefold()) else len(schema_inputs) + 1,
                    "raw_header": header,
                    "header_origin": header_origin,
                    "resolved_header": resolved_header,
                    "values": [],
                    "value_count": 0,
                },
            )
            for value in values:
                schema_entry["value_count"] += 1
                if len(schema_entry["values"]) < PROFILE_SCHEMA_VALUE_SAMPLE_LIMIT:
                    schema_entry["values"].append(value)

            suggested_header = ""
            key = (source_kind, header_origin, header, resolved_header, suggested_header)
            entry = profiles.setdefault(
                key,
                new_profile_entry(
                    source_kind=source_kind,
                    header_origin=header_origin,
                    source_label=header,
                    resolved_header=resolved_header,
                    suggested_header=suggested_header,
                    suggestion_source="",
                    suggestion_confidence="",
                ),
            )
            generic_integrated = integrated_mode and header_origin == "headerless_generic"
            for value in values:
                if generic_integrated and entry["rows_seen"] >= PROFILE_INTEGRATED_GENERIC_VALUE_LIMIT:
                    profile_entry_light_update(entry, file_token, value)
                    continue
                update_profile_entry(entry, file_token, value)
                if resolved_header:
                    coverage_entry = rule_coverage.get(("table_header", resolved_header))
                    if coverage_entry is not None:
                        update_rule_coverage_entry(coverage_entry, file_token, header, value)
                    metadata = resolve_table_header_metadata(resolved_header)
                    if metadata_truthy(metadata.get("emit_cell_value")):
                        emit_entry = rule_coverage.get(("table_emit_cell_value", resolved_header))
                        if emit_entry is not None:
                            update_rule_coverage_entry(emit_entry, file_token, header, value)
                for pattern_name, evidence_type in profile_matching_patterns(value, route_patterns, route_key):
                    regex_entry = rule_coverage.get(("regex_rule", f"{evidence_type}::{pattern_name}"))
                    if regex_entry is not None:
                        update_rule_coverage_entry(regex_entry, file_token, header, value)
        if progress_callback and line_number % 200 == 0:
            progress_callback(65.0 + (25.0 * min(1.0, float(line_number) / float(total_lines))), "profiling structured fields")
    structured_schema_signatures = {}
    schema_entries_by_table = defaultdict(list)
    for schema_entry in schema_inputs.values():
        schema_entries_by_table[(schema_entry["source_kind"], schema_entry["table_name"])].append(schema_entry)
    for (entry_source_kind, entry_table_name), table_entries in schema_entries_by_table.items():
        table_entries.sort(key=lambda item: int(item.get("column_index") or 0))
        structured_schema_signatures[(entry_source_kind, entry_table_name)] = schema_plan_signature(
            entry_source_kind,
            entry_table_name,
            [entry["raw_header"] for entry in table_entries],
            [entry["values"] for entry in table_entries],
            "normal",
            detected_separator="",
        )

    for schema_entry in schema_inputs.values():
        values = schema_entry["values"]
        resolved_header = schema_entry["resolved_header"]
        suggested_header = ""
        suggestion_source = ""
        suggestion_confidence = ""
        if not resolved_header:
            suggested_header, suggestion_source, suggestion_confidence = suggested_header_for_values(
                schema_entry["raw_header"],
                values,
                args,
            )
        append_schema_plan_row(
            schema_plan,
            file_token=file_token,
            source_kind=schema_entry["source_kind"],
            table_name=schema_entry["table_name"],
            column_index=schema_entry["column_index"],
            raw_header=schema_entry["raw_header"],
            header_origin=schema_entry["header_origin"],
            resolved_header=resolved_header,
            suggested_header=suggested_header,
            suggestion_source=suggestion_source,
            suggestion_confidence=suggestion_confidence,
            transposed=False,
            profile_metrics=profile_metrics_for_values(values),
            orientation="normal",
            orientation_confidence="high",
            orientation_reason="structured_key_value_record",
            schema_signature=structured_schema_signatures.get((schema_entry["source_kind"], schema_entry["table_name"]), ""),
        )
    if progress_callback:
        progress_callback(90.0, "profiling structured fields")
    return saw_labelled


def profile_file(path, args, profiles, rule_coverage, progress_callback=None, schema_plan=None):
    if progress_callback:
        progress_callback(5.0, "detecting file type")
    original_extension = Path(path).suffix.casefold()
    detected_extension = detect_extension_from_content(path, original_extension)
    file_token = profile_file_token(path, args, progress_callback=progress_callback)

    if detected_extension in {".csv", ".tsv"}:
        try:
            return profile_delimited_file(path, detected_extension, profiles, rule_coverage, args, progress_callback, schema_plan=schema_plan)
        except Exception:
            return False

    if detected_extension == ".xml" and getattr(args, "xml_scan", "fast") == "fast":
        try:
            if progress_callback:
                progress_callback(20.0, "building XML scopes")
            _raw_xml_text, text, _scope_count, _anchor_hit_count, _evidence_hit_count, _field_count = build_xml_evidence_scope_text_in_memory(
                path,
                max_fields=max(1, int(getattr(args, "xml_max_fields", 200) or 200)),
            )
            if progress_callback:
                progress_callback(60.0, "XML scopes built")
        except Exception:
            return False
        if not text:
            return False
        return profile_labelled_text(text, "xml", file_token, profiles, rule_coverage, args, progress_callback, schema_plan=schema_plan)

    try:
        text, status = extract_text_for_scan(
            path,
            detected_extension,
            max_text_chars=0,
            ocr_images=False,
            structured_records=True,
            structured_max_depth=getattr(args, "structured_max_depth", 12),
            structured_max_records=0,
            structured_max_record_fields=max(1, int(getattr(args, "xml_max_fields", 200) or 200)),
            progress_callback=progress_callback,
        )
    except Exception:
        return False

    if not text or "binary_like_content" in status or status == "unsupported_extension":
        return False

    source_kind = detected_extension.lstrip(".") or original_extension.lstrip(".") or "text"
    return profile_labelled_text(text, source_kind, file_token, profiles, rule_coverage, args, progress_callback, schema_plan=schema_plan)


def new_local_profile_state():
    return {}, initialize_rule_coverage(), []


def local_profile_result(profiled, profiles, rule_coverage, schema_plan=None):
    return {
        "profiled": bool(profiled),
        "profiles": profiles,
        "rule_coverage": rule_coverage,
        "schema_plan": list(schema_plan or []),
    }


def profile_scanned_content_local(path, detected_extension, labelled_text, args, known_md5="", known_hash="", progress_callback=None):
    """Profile already-extracted Stage 4 content without reopening non-structured sources."""
    maybe_report_nlp_model_loading(args, progress_callback, 95.5)
    local_profiles, local_rule_coverage, local_schema_plan = new_local_profile_state()
    extension = safe_cell(detected_extension).casefold()
    if extension and not extension.startswith("."):
        extension = "." + extension
    file_token = profile_file_token_from_metadata(path, args, known_md5=known_md5, known_hash=known_hash, progress_callback=progress_callback)
    profiled = False

    if extension in {".csv", ".tsv"}:
        try:
            profiled = profile_delimited_file(
                path,
                extension,
                local_profiles,
                local_rule_coverage,
                args,
                progress_callback=progress_callback,
                file_token=file_token,
                schema_plan=local_schema_plan,
            )
        except Exception:
            profiled = False
        return local_profile_result(profiled, local_profiles, local_rule_coverage, local_schema_plan)

    if extension == ".xml" and getattr(args, "xml_scan", "fast") == "fast":
        if labelled_text:
            profiled = profile_labelled_text(
                labelled_text,
                "xml",
                file_token,
                local_profiles,
                local_rule_coverage,
                args,
                progress_callback,
                schema_plan=local_schema_plan,
            )
        return local_profile_result(profiled, local_profiles, local_rule_coverage, local_schema_plan)

    source_kind = extension.lstrip(".") or Path(path).suffix.casefold().lstrip(".") or "text"
    if labelled_text:
        profiled = profile_labelled_text(
            labelled_text,
            source_kind,
            file_token,
            local_profiles,
            local_rule_coverage,
            args,
            progress_callback,
            schema_plan=local_schema_plan,
        )
    return local_profile_result(profiled, local_profiles, local_rule_coverage, local_schema_plan)


def profile_scan_chunk_local(chunk, labelled_text, args, progress_callback=None):
    """Profile one already-built Stage 1 scan chunk."""
    maybe_report_nlp_model_loading(args, progress_callback, 95.5)
    local_profiles, local_rule_coverage, local_schema_plan = new_local_profile_state()
    path = str(chunk.get("file_path", ""))
    extension = safe_cell(chunk.get("detected_extension") or chunk.get("extension") or Path(path).suffix).casefold()
    if extension and not extension.startswith("."):
        extension = "." + extension
    file_token = profile_file_token_from_metadata(
        path,
        args,
        known_md5=chunk.get("md5", ""),
        known_hash=chunk.get("sha256", "") or chunk.get("md5", ""),
        progress_callback=progress_callback,
    )
    chunk_type = safe_cell(chunk.get("chunk_type")).casefold()
    profiled = False

    if chunk_type == "delimited":
        try:
            profile_table(
                chunk.get("headers", []),
                chunk.get("rows", []),
                chunk.get("table_name") or Path(path).name,
                extension.lstrip(".") or "delimited",
                file_token,
                local_profiles,
                local_rule_coverage,
                args,
                progress_callback,
                schema_plan=local_schema_plan,
            )
            profiled = True
        except Exception:
            profiled = False
        return local_profile_result(profiled, local_profiles, local_rule_coverage, local_schema_plan)

    source_kind = "xml" if extension == ".xml" else (extension.lstrip(".") or chunk_type or "text")
    if labelled_text:
        profiled = profile_labelled_text(
            labelled_text,
            source_kind,
            file_token,
            local_profiles,
            local_rule_coverage,
            args,
            progress_callback,
            schema_plan=local_schema_plan,
        )
    return local_profile_result(profiled, local_profiles, local_rule_coverage, local_schema_plan)


def profile_file_local(path, args, progress_callback=None):
    maybe_report_nlp_model_loading(args, progress_callback, 2.0)
    local_profiles, local_rule_coverage, local_schema_plan = new_local_profile_state()
    profiled = profile_file(path, args, local_profiles, local_rule_coverage, progress_callback, schema_plan=local_schema_plan)
    return local_profile_result(profiled, local_profiles, local_rule_coverage, local_schema_plan)


def process_profile_target(path, args):
    target_started_perf = time.perf_counter()
    target_started_wall = time.time()
    task_key = target_progress_key(("file", path))
    emit_worker_progress(args, task_key, path, "started", 0.0)

    set_email_suffix(args.email_suffix)
    set_email_wildcards(getattr(args, "email_wildcard", []))
    set_nlp_mode(getattr(args, "nlp", False))
    load_identity_anchor_config(args.rules)
    load_rules(args.rules)
    load_table_column_rules(args.rules)
    ensure_person_table_exact_match_index(args)

    def progress(percent, stage):
        emit_worker_progress(args, task_key, path, stage, percent)

    result = profile_file_local(path, args, progress)
    result.setdefault("process_info", {
        "pid": os.getpid(),
        "task_key": task_key,
        "file_path": path,
        "started_at_epoch": target_started_wall,
        "finished_at_epoch": time.time(),
        "elapsed_seconds": time.perf_counter() - target_started_perf,
    })
    emit_worker_progress(args, task_key, path, "complete", 100.0)
    return result


def process_profile_batch_target(batch_paths, args):
    """Profile a same-folder batch with one rules/index initialisation.

    Profiling is often run over very large trees containing many small files.
    Submitting one process-pool job per file is expensive on Windows because the
    spawned worker has to unpickle args and reload rule/person-table state for
    every task. A batch keeps the output semantics file-level, but amortises that
    setup cost across a group of neighbouring files.
    """
    batch_paths = list(batch_paths or [])
    batch_started_perf = time.perf_counter()
    batch_started_wall = time.time()
    first_path = batch_paths[0] if batch_paths else ""
    task_key = f"profile_batch:{len(batch_paths)}:{first_path}"
    emit_worker_progress(args, task_key, first_path, "started", 0.0)

    set_email_suffix(args.email_suffix)
    set_email_wildcards(getattr(args, "email_wildcard", []))
    set_nlp_mode(getattr(args, "nlp", False))
    load_identity_anchor_config(args.rules)
    load_rules(args.rules)
    load_table_column_rules(args.rules)
    ensure_person_table_exact_match_index(args)

    profiles, rule_coverage, schema_plan = new_local_profile_state()
    completed_files = 0
    profiled_files = 0
    total = max(1, len(batch_paths))

    for index, path in enumerate(batch_paths):
        base_percent = 100.0 * float(index) / float(total)
        span_percent = 100.0 / float(total)
        emit_worker_progress(args, task_key, path, "profiling file", base_percent)

        def progress(percent, stage, current_path=path, base=base_percent, span=span_percent):
            overall = base + (span * (progress_percent(percent) / 100.0))
            emit_worker_progress(args, task_key, current_path, stage, overall)

        result = profile_file_local(path, args, progress)
        completed_files += 1
        if result.get("profiled"):
            profiled_files += 1
        merge_local_profile_result(profiles, rule_coverage, result, schema_plan=schema_plan)

    result = local_profile_result(profiled_files > 0, profiles, rule_coverage, schema_plan)
    result["completed_files"] = completed_files
    result["profiled_files"] = profiled_files
    result.setdefault("process_info", {
        "pid": os.getpid(),
        "task_key": task_key,
        "file_path": first_path,
        "started_at_epoch": batch_started_wall,
        "finished_at_epoch": time.time(),
        "elapsed_seconds": time.perf_counter() - batch_started_perf,
    })
    emit_worker_progress(args, task_key, first_path, "complete", 100.0)
    return result


def merge_local_profile_result(profiles, rule_coverage, result, schema_plan=None):
    for key, source in (result.get("profiles") or {}).items():
        target = profiles.get(key)
        if target is None:
            profiles[key] = source
        else:
            merge_profile_entry(target, source)
    for key, source in (result.get("rule_coverage") or {}).items():
        target = rule_coverage.get(key)
        if target is None:
            rule_coverage[key] = source
        else:
            merge_rule_coverage_entry(target, source)
    if schema_plan is not None:
        schema_plan.extend(result.get("schema_plan") or [])


def run_profile_scan(args, paths, run_info):
    profiles = {}
    rule_coverage = initialize_rule_coverage()
    schema_plan = []
    profile_paths = profiling_output_paths(args.output_dir)
    output_files = {
        paths["run_info"],
        paths["run_manifest"],
        profile_paths["profiles"],
        profile_paths["all_profiles"],
        profile_paths["candidates"],
        profile_paths["review_only_candidates"],
        profile_paths["schema_plan"],
        profile_paths["value_type_candidates"],
        profile_paths["rule_coverage"],
        profile_paths["draft_rules_dir"],
        profile_paths["draft_rule_manifest"],
    }

    print("Stage 3/7: profiling setup | discovering files...", flush=True)
    targets = list(iter_targets(
        args.root,
        args.output_dir,
        output_files,
        args.include_hidden,
        args.exclude,
    ))
    print(f"Stage 3/7: profiling setup | {len(targets):,} targets discovered", flush=True)
    if getattr(args, "priority", "discovery") != "discovery":
        print(f"Stage 3/7: profiling setup | prioritising targets by {args.priority}...", flush=True)
    targets = prioritize_targets(targets, args.priority)

    file_paths = [path for target_type, path in targets if target_type == "file"]
    print(f"Stage 3/7: profiling setup | {len(file_paths):,} files selected for profiling", flush=True)
    size_metadata_by_path = {}
    try:
        profile_file_index_path = file_index_path(args, paths)
        explicit_index_dir = bool(getattr(args, "index_dir", ""))
        if profile_file_index_path and os.path.exists(profile_file_index_path):
            size_metadata_by_path = load_file_index(profile_file_index_path, trust=explicit_index_dir)
            print(
                "Stage 3/7: profiling setup | "
                f"loaded size metadata for {len(size_metadata_by_path):,} files from {profile_file_index_path}",
                flush=True,
            )
    except Exception as exc:
        size_metadata_by_path = {}
        print(f"Stage 3/7: profiling setup | file index unavailable for size-aware batching: {exc}", flush=True)
    print("Stage 3/7: profiling setup | building folder batches...", flush=True)

    def build_profile_batches(paths_to_batch, max_files=250, max_bytes=128 * 1024 * 1024,
                              use_size_limit=False, size_metadata=None, singleton_threshold_bytes=0):
        size_metadata = size_metadata or {}
        batches = []
        current = []
        current_parent = None
        current_bytes = 0

        def flush():
            nonlocal current, current_parent, current_bytes
            if current:
                batches.append(current)
            current = []
            current_parent = None
            current_bytes = 0

        for path in paths_to_batch:
            parent = os.path.dirname(path)
            size_bytes = 0
            metadata = size_metadata.get(os.path.abspath(path)) or size_metadata.get(path) or {}
            if metadata.get("size_bytes"):
                try:
                    size_bytes = int(metadata.get("size_bytes") or 0)
                except (TypeError, ValueError):
                    size_bytes = 0
            elif use_size_limit:
                try:
                    size_bytes = max(0, os.path.getsize(path))
                except OSError:
                    size_bytes = 0
            if singleton_threshold_bytes > 0 and size_bytes >= singleton_threshold_bytes:
                flush()
                batches.append([path])
                continue
            should_flush = (
                current
                and (
                    parent != current_parent
                    or len(current) >= max_files
                    or (use_size_limit and (current_bytes + size_bytes) > max_bytes)
                )
            )
            if should_flush:
                flush()
            if not current:
                current_parent = parent
            current.append(path)
            current_bytes += size_bytes
        flush()
        return batches

    use_batch_size_limit = bool(size_metadata_by_path) or getattr(args, "priority", "discovery") == "size"
    singleton_threshold = large_file_threshold_bytes(args)
    profile_batches = build_profile_batches(
        file_paths,
        use_size_limit=use_batch_size_limit,
        size_metadata=size_metadata_by_path,
        singleton_threshold_bytes=singleton_threshold,
    )
    print(
        "Stage 3/7: profiling setup | "
        f"{len(profile_batches):,} folder batches ready"
        + (" (size-aware)" if use_batch_size_limit else "")
        + (f"; files >= {getattr(args, 'large_file_cutoff_mb', 0)} MB are singleton batches" if singleton_threshold > 0 else ""),
        flush=True,
    )
    processed_files = len(file_paths)
    profiled_files = 0
    completed_files = 0
    started_at = time.monotonic()
    started_at_wall = time.time()
    last_progress = started_at
    active = {}
    active_by_key = {}
    progress_manager = None
    progress_queue = None
    if args.progress_every > 0:
        try:
            progress_manager = mp.Manager()
            progress_queue = progress_manager.Queue()
            args.progress_queue = progress_queue
        except Exception:
            progress_manager = None
            progress_queue = None
            args.progress_queue = None
    else:
        args.progress_queue = None

    def drain_progress_queue():
        if progress_queue is None:
            return
        while True:
            try:
                message = progress_queue.get_nowait()
            except queue_module.Empty:
                break
            except Exception:
                break
            task_key = message.get("task_key")
            state = active_by_key.get(task_key)
            if not state:
                continue
            state["pid"] = message.get("pid") or state.get("pid")
            if message.get("file_path"):
                state["path"] = message.get("file_path")
                state["file"] = os.path.basename(message.get("file_path")) or message.get("file_path")
            state["status"] = message.get("stage") or state.get("status")
            if message.get("percent") is not None:
                state["percent"] = progress_percent(message.get("percent"))
            if message.get("stage") == "started":
                state["started_wall"] = message.get("timestamp") or state.get("started_wall")

    def report_progress(force=False):
        nonlocal last_progress
        drain_progress_queue()
        now = time.monotonic()
        now_wall = time.time()
        interval = float(getattr(args, "progress_every", 0.0) or 0.0)
        if not force and (interval <= 0 or now - last_progress < interval):
            return
        percent_complete = (100.0 * completed_files / processed_files) if processed_files else 100.0
        header = (
            f"Profile scan | {completed_files:,} / {processed_files:,} files complete "
            f"({percent_complete:.0f}%) | "
            f"{len(active):,} active | elapsed {format_hms(now_wall - started_at_wall)} | "
            f"profiled files {profiled_files:,}"
        )
        lines = [header, "", "Currently processing:"]
        if active:
            for state in sorted(active.values(), key=lambda item: item.get("started_wall", 0)):
                pid = state.get("pid") or "pending"
                elapsed = format_hms(now_wall - state.get("started_wall", now_wall))
                file_path = state.get("path") or state.get("file") or "not applicable"
                percent = state.get("percent")
                status = state.get("status") or state.get("process") or "processing"
                if percent is None:
                    progress_text = status
                else:
                    progress_text = f"{percent:.0f}% complete"
                    if status and status not in {"started", "complete"}:
                        progress_text += f" ({status})"
                batch_size = state.get("batch_size") or 1
                batch_text = f" [{batch_size:,} files]" if batch_size > 1 else ""
                lines.append(f"[pid {pid}] {elapsed}{batch_text}  {file_path}: {progress_text}")
        else:
            lines.append("none")
        print("\n".join(lines), flush=True)
        last_progress = now

    requested_workers = int(getattr(args, "workers", 0) or 0)
    if requested_workers > 0:
        worker_count = min(requested_workers, max(1, len(profile_batches)))
    else:
        worker_count = min(max(1, (os.cpu_count() or DEFAULT_AUTO_WORKERS) - 1), max(1, len(profile_batches)))
    print(f"Stage 3/7: profiling setup | starting {worker_count:,} workers...", flush=True)
    use_local_callbacks = worker_count <= 1

    def submit_next(pool, pending, iterator):
        try:
            batch_paths = next(iterator)
        except StopIteration:
            return False
        first_path = batch_paths[0] if batch_paths else ""
        task_key = f"profile_batch:{len(batch_paths)}:{first_path}"
        state = {
            "task_key": task_key,
            "file": os.path.basename(first_path) or first_path,
            "path": first_path,
            "batch_size": len(batch_paths),
            "process": "profiling batch",
            "status": "queued",
            "percent": None,
            "pid": "",
            "started_wall": time.time(),
        }
        future = pool.submit(process_profile_batch_target, batch_paths, args)
        active[future] = state
        active_by_key[task_key] = state
        pending.add(future)
        return True

    def consume(future):
        nonlocal completed_files, profiled_files
        state = active.pop(future, None)
        if state:
            active_by_key.pop(state.get("task_key"), None)
        result = future.result()
        completed_files += int(result.get("completed_files") or 1)
        profiled_files += int(result.get("profiled_files") or (1 if result.get("profiled") else 0))
        merge_local_profile_result(profiles, rule_coverage, result, schema_plan=schema_plan)
        report_progress()

    completed_normally = False
    try:
        if worker_count <= 1:
            class ImmediateFuture:
                def __init__(self):
                    self._result = None

                def result(self):
                    return self._result

            for batch_paths in profile_batches:
                first_path = batch_paths[0] if batch_paths else ""
                task_key = f"profile_batch:{len(batch_paths)}:{first_path}"
                state = {
                    "task_key": task_key,
                    "file": os.path.basename(first_path) or first_path,
                    "path": first_path,
                    "batch_size": len(batch_paths),
                    "process": "profiling batch",
                    "status": "queued",
                    "percent": None,
                    "pid": str(os.getpid()),
                    "started_wall": time.time(),
                }
                future = ImmediateFuture()
                active[future] = state
                active_by_key[task_key] = state

                def progress_callback(percent, status, item=state):
                    item["percent"] = percent
                    item["status"] = status

                report_progress(force=True)
                try:
                    future._result = process_profile_batch_target(batch_paths, args)
                    consume(future)
                except Exception:
                    completed_files += len(batch_paths)
                    active.pop(future, None)
                    active_by_key.pop(task_key, None)
                    report_progress()
        else:
            with ProcessPoolExecutor(max_workers=worker_count) as pool:
                pending = set()
                iterator = iter(profile_batches)
                for _ in range(max(1, worker_count)):
                    if not submit_next(pool, pending, iterator):
                        break
                report_progress(force=True)
                while pending:
                    timeout = args.progress_every if args.progress_every > 0 else None
                    done, pending = wait(pending, timeout=timeout, return_when=FIRST_COMPLETED)
                    if not done:
                        report_progress()
                        continue
                    for future in done:
                        try:
                            consume(future)
                        except Exception:
                            state = active.pop(future, None)
                            completed_files += int((state or {}).get("batch_size") or 1)
                            if state:
                                active_by_key.pop(state.get("task_key"), None)
                            report_progress()
                        submit_next(pool, pending, iterator)
        completed_normally = True
    finally:
        drain_progress_queue()
        if progress_manager is not None:
            try:
                progress_manager.shutdown()
            except Exception:
                pass

    if completed_normally:
        completed_files = processed_files
    report_progress(force=True)

    profile_count, candidate_count, review_only_candidate_count, value_type_candidate_count, rule_coverage_count, schema_plan_count = write_profile_outputs(args.output_dir, profiles, rule_coverage, schema_plan=schema_plan)
    run_info["profile"] = args.profile
    run_info["worker_count"] = worker_count
    run_info["files_discovered"] = processed_files
    run_info["files_processed"] = processed_files
    run_info["profiled_files"] = profiled_files
    run_info["unknown_column_profile_rows"] = profile_count
    run_info["column_rule_candidate_rows"] = candidate_count
    run_info["review_only_candidate_rows"] = review_only_candidate_count
    run_info["value_type_candidate_rows"] = value_type_candidate_count
    run_info["rule_coverage_rows"] = rule_coverage_count
    run_info["schema_plan_rows"] = schema_plan_count
    return profile_count, candidate_count, review_only_candidate_count, value_type_candidate_count, rule_coverage_count, schema_plan_count
