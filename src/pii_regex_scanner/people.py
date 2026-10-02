"""Known-person matching and person-level output generation.

This module covers the part of the workflow that starts after clustering:

- read one or more reference person tables;
- derive exact and structured anchors from those rows;
- match clusters, cluster-excluded linked rows, and direct raw evidence back to
  known people;
- produce known-person outputs and the corresponding "not in list" outputs;
- optionally write per-person evidence audit files.

The implementation is loaded into the shared pipeline namespace so the package
and standalone forms share the same matching logic.
"""

def person_table_exact_key(value):
    """Normalize a person-table value into a strict exact-match lookup key.

    This intentionally keeps only characters useful for IDs/emails and rejects
    trivial stopword-like values so noisy cells do not become anchors.
    """
    value = safe_cell(value)
    if not value:
        return ""
    if value.casefold() in PERSON_TABLE_EXACT_VALUE_STOPWORDS:
        return ""
    key = re.sub(r"[^A-Z0-9@._%+]+", "", value.upper())
    alnum = re.sub(r"[^A-Z0-9]+", "", key)
    if len(alnum) < PERSON_TABLE_EXACT_MIN_ALNUM_CHARS:
        return ""
    if key.casefold() in PERSON_TABLE_EXACT_VALUE_STOPWORDS:
        return ""
    return key


def person_table_exact_keys_for_value(value, evidence_type=""):
    """Return strict exact-match keys, including configured email aliases."""
    values = [safe_cell(value)]
    if safe_cell(evidence_type) in EMAIL_EVIDENCE_TYPES or "@" in safe_cell(value):
        values.extend(email_equivalent_values(value))
    keys = []
    seen = set()
    for candidate in values:
        key = person_table_exact_key(candidate)
        if key and key not in seen:
            seen.add(key)
            keys.append(key)
    return tuple(keys)


def person_table_dynamic_identifier_evidence_type(header):
    """Create a stable evidence type for an otherwise unknown ID-like column."""
    label = safe_cell(resolve_table_header(header) or header)
    if not label:
        label = "identifier"
    label = re.sub(r"\s+", " ", label).strip()
    return f"Known Person Identifier: {label}"


def configured_evidence_types_from_header_metadata(metadata):
    """Return configured evidence types from resolved header metadata."""
    configured = metadata.get("evidence_types", metadata.get("evidence_type", [])) if metadata else []
    if isinstance(configured, str):
        configured = [configured]
    return [safe_cell(value) for value in configured if safe_cell(value)]


def person_table_name_role(header):
    """Classify a person-table header as full, first, or last name when possible."""
    metadata = resolve_table_header_metadata(header)
    if is_full_name_header(header):
        return "full name"
    part = name_part_for_header(header, metadata)
    if part == "first":
        return "first name"
    if part == "last":
        return "last name"
    return ""


def person_table_inference_label_for_header(header):
    """Return the label used when person-table values help infer unknown headers."""
    name_role = person_table_name_role(header)
    if name_role:
        return name_role
    evidence_types = evidence_types_for_person_column(header)
    if evidence_types:
        return inferred_header_for_evidence_type(evidence_types[0])
    return resolve_table_header(header) or safe_cell(header)


def is_identifier_like_person_header(header):
    """Return whether a header looks like a reusable identifier column."""
    slug = rule_slug(resolve_table_header(header) or header)
    if not slug:
        return False
    if slug in {"id", "person_id", "student_id", "staff_id", "employee_id", "username", "user_name"}:
        return True
    return any(token in slug.split("_") for token in {"id", "identifier", "number", "no", "ref", "reference"})


def person_table_exact_evidence_types_for_header(header):
    """Return evidence types eligible for strict exact matching from this header.

    Weak contextual columns are excluded here on purpose. Exact matching is
    reserved for identifiers, emails, full names, and other values that can
    safely identify a person-table row.
    """
    name_role = person_table_name_role(header)
    if name_role in {"first name", "last name"}:
        return []
    if name_role == "full name":
        return ["Name"]

    evidence_types = [
        evidence_type for evidence_type in evidence_types_for_person_column(header)
        if evidence_type and evidence_type not in PERSON_TABLE_EXACT_CONTEXTUAL_TYPES
    ]
    if evidence_types:
        return evidence_types

    label = safe_cell(header)
    if not label or not is_identifier_like_person_header(label):
        return []
    return [person_table_dynamic_identifier_evidence_type(label)]


def register_person_table_exact_evidence_types(evidence_types):
    """Promote exact-match-only person-table identifiers into runtime metadata.

    When a reference table contains a reliable identifier column that is not
    already part of the regex rule set, we still need downstream summaries,
    risk matrices, and clustering logic to understand that evidence type.
    """
    global EVIDENCE_COUNT_TYPES, EVIDENCE_COUNT_COLUMNS, EVIDENCE_FLAG_COLUMNS
    global FILE_SUMMARY_FIELDS, KNOWN_PERSON_RISK_MATRIX_FIELDS, ANCHOR_PRIORITY

    added = False
    for evidence_type in sorted(set(evidence_types)):
        evidence_type = safe_cell(evidence_type)
        if not evidence_type or evidence_type in {"Name"} or evidence_type in EVIDENCE_COUNT_TYPES:
            continue
        PERSON_TABLE_EXACT_EVIDENCE_TYPES.add(evidence_type)
        EVIDENCE_COUNT_TYPES.append(evidence_type)
        count_column = "count_" + rule_slug(evidence_type)
        flag_column = "has_" + rule_slug(evidence_type)
        EVIDENCE_COUNT_COLUMNS.append(count_column)
        EVIDENCE_FLAG_COLUMNS.append(flag_column)
        if count_column not in FILE_SUMMARY_FIELDS:
            FILE_SUMMARY_FIELDS.append(count_column)
        if flag_column not in KNOWN_PERSON_RISK_MATRIX_FIELDS:
            KNOWN_PERSON_RISK_MATRIX_FIELDS.append(flag_column)
        EVIDENCE_NORMALIZATION[evidence_type] = "compact_upper"
        EVIDENCE_RISK_ROLES[evidence_type] = {"id"}
        TIER_1_EVIDENCE.add(evidence_type)
        IDENTIFIABLE_EVIDENCE.add(evidence_type)
        HIGH_RISK_STANDALONE.add(evidence_type)
        ID_EVIDENCE_TYPES.add(evidence_type)
        ANCHOR_PRIORITY_BY_TYPE.setdefault(evidence_type, 50)
        added = True

    if added:
        ANCHOR_PRIORITY = [
            evidence_type
            for evidence_type in sorted(
                (evidence_type for evidence_type in EVIDENCE_COUNT_TYPES if evidence_type in ANCHOR_PRIORITY_BY_TYPE),
                key=lambda evidence_type: (ANCHOR_PRIORITY_BY_TYPE[evidence_type], evidence_type),
            )
        ]


def build_person_table_exact_match_index(person_table_paths, progress_callback=None):
    """Build the exact-match indexes derived from all supplied person tables.

    Returns four related structures:

    - exact value -> person-table match specs;
    - exact value -> inferred header labels;
    - discovered person-table-only exact evidence types;
    - person-table row -> authoritative composite full-name values.
    """
    exact_index = defaultdict(list)
    infer_index = defaultdict(Counter)
    ref_name_index = defaultdict(list)
    exact_evidence_types = set()

    for table_path in person_table_paths or []:
        table_path = os.path.abspath(table_path)
        table_stem = safe_output_stem(table_path)
        if callable(progress_callback):
            progress_callback(f"reading person table {table_stem}")
        try:
            with open(table_path, "rb") as f:
                text = decode_person_table_bytes(f.read())
        except OSError:
            continue

        reader = csv.DictReader(io.StringIO(text, newline=""))
        headers = reader.fieldnames or []
        row_count = 0
        for row_number, row in enumerate(reader, start=1):
            row_count = row_number
            if callable(progress_callback) and row_number % 5000 == 0:
                progress_callback(f"indexing person table {table_stem}: {row_number:,} rows")
            person_ref = f"{table_stem}:{row_number}"
            for header in headers:
                raw_value = row.get(header, "")
                inference_label = person_table_inference_label_for_header(header)
                exact_evidence_types_for_header = person_table_exact_evidence_types_for_header(header)
                for value_part in split_person_cell_values(raw_value):
                    for key in person_table_exact_keys_for_value(value_part):
                        if inference_label:
                            infer_index[key][inference_label] += 1
                        for evidence_type in exact_evidence_types_for_header:
                            if not evidence_type:
                                continue
                            exact_evidence_types.add(evidence_type)
                            exact_index[key].append({
                                "evidence_type": evidence_type,
                                "source_table": table_stem,
                                "source_column": safe_cell(header),
                                "source_row_number": row_number,
                            })

            # Build authoritative full names from explicit first/last name columns.
            # These are later used to emit safe Name evidence once another strong
            # anchor has already identified the person-table row.
            fields = [
                (header, safe_cell(row.get(header, "")), resolve_table_header_metadata(header))
                for header in headers
            ]
            for name in assembled_names_from_fields(fields):
                matched_text = safe_cell(name.get("matched_text", ""))
                normalized_name = normalize_name_value(matched_text)
                if matched_text and normalized_name and valid_name_value(matched_text, require_full_name=True):
                    existing = {row.get("normalized_value") for row in ref_name_index[person_ref]}
                    if normalized_name not in existing:
                        ref_name_index[person_ref].append({
                            "matched_text": matched_text,
                            "normalized_value": normalized_name,
                            "confidence": name.get("confidence", "high"),
                        })
                for key in person_table_exact_keys_for_value(matched_text, "Name"):
                    infer_index[key]["full name"] += 1
                    exact_index[key].append({
                        "evidence_type": "Name",
                        "source_table": table_stem,
                        "source_column": "composite_name",
                        "source_row_number": row_number,
                    })
        if callable(progress_callback):
            progress_callback(f"indexed person table {table_stem}: {row_count:,} rows")

    # De-duplicate per value/source/type so repeated identical cells do not
    # inflate later exact-match evidence counts.
    deduped_index = {}
    for key, specs in exact_index.items():
        seen = set()
        deduped = []
        for spec in specs:
            dedupe_key = (spec.get("evidence_type", ""), spec.get("source_table", ""), spec.get("source_column", ""))
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            deduped.append(spec)
        if deduped:
            deduped_index[key] = tuple(deduped)

    return deduped_index, {key: Counter(value) for key, value in infer_index.items()}, exact_evidence_types, {key: tuple(value) for key, value in ref_name_index.items()}


def person_table_index_payload(person_table_paths, exact_index, infer_index, exact_evidence_types, ref_name_index, args):
    """Serialize the known-person exact-match index to a local reusable JSON payload."""
    return {
        "schema_version": 1,
        "created_at": iso_timestamp() if "iso_timestamp" in globals() else "",
        "person_tables": [os.path.abspath(path) for path in person_table_paths or []],
        "rules": os.path.abspath(getattr(args, "rules", "") or ""),
        "email_suffix": list(EMAIL_SUFFIX),
        "email_wildcard": [" == ".join(pair) for pair in globals().get("EMAIL_WILDCARDS", ())],
        "summary_stems": [safe_output_stem(path) for path in person_table_paths or []],
        "exact_evidence_types": sorted(safe_cell(value) for value in exact_evidence_types if safe_cell(value)),
        "exact_index": {
            key: [dict(spec) for spec in specs]
            for key, specs in exact_index.items()
        },
        "infer_index": {
            key: dict(counter)
            for key, counter in infer_index.items()
        },
        "ref_name_index": {
            key: [dict(row) for row in rows]
            for key, rows in ref_name_index.items()
        },
    }


def write_person_table_exact_match_index(index_path, person_table_paths, exact_index, infer_index, exact_evidence_types, ref_name_index, args):
    """Write a reusable person-table exact-match index for process workers."""
    if not index_path:
        return 0
    ensure_output_parent(index_path)
    payload = person_table_index_payload(
        person_table_paths,
        exact_index,
        infer_index,
        exact_evidence_types,
        ref_name_index,
        args,
    )
    with open(index_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return len(exact_index)


def load_person_table_exact_match_index(index_path):
    """Load a reusable person-table exact-match index produced by this tool."""
    if not index_path or not os.path.exists(index_path):
        return None
    try:
        with open(index_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        return None
    if not isinstance(payload, dict) or int(payload.get("schema_version") or 0) != 1:
        return None
    exact_index = {
        safe_cell(key): tuple(dict(spec) for spec in specs if isinstance(spec, dict))
        for key, specs in (payload.get("exact_index") or {}).items()
        if safe_cell(key) and isinstance(specs, list)
    }
    infer_index = {
        safe_cell(key): Counter(counter)
        for key, counter in (payload.get("infer_index") or {}).items()
        if safe_cell(key) and isinstance(counter, dict)
    }
    ref_name_index = {
        safe_cell(key): tuple(dict(row) for row in rows if isinstance(row, dict))
        for key, rows in (payload.get("ref_name_index") or {}).items()
        if safe_cell(key) and isinstance(rows, list)
    }
    exact_evidence_types = set(
        safe_cell(value)
        for value in (payload.get("exact_evidence_types") or [])
        if safe_cell(value)
    )
    summary_stems = [
        safe_cell(value)
        for value in (payload.get("summary_stems") or [])
        if safe_cell(value)
    ]
    return exact_index, infer_index, exact_evidence_types, ref_name_index, summary_stems


def ensure_person_table_exact_match_index(args, progress_callback=None):
    """Populate the cached person-table exact-match indexes for this run."""
    global PERSON_TABLE_EXACT_MATCH_INDEX, PERSON_TABLE_INFER_HEADER_INDEX, PERSON_TABLE_REF_NAME_INDEX
    global PERSON_TABLE_EXACT_EVIDENCE_TYPES, PERSON_TABLE_EXACT_INDEX_KEY, PERSON_TABLE_SUMMARY_STEMS

    person_tables = tuple(os.path.abspath(path) for path in getattr(args, "person_tables", []) or [])
    PERSON_TABLE_SUMMARY_STEMS = [safe_output_stem(path) for path in person_tables]
    index_path = os.path.abspath(getattr(args, "person_tables_index", "") or "") if getattr(args, "person_tables_index", "") else ""
    if not index_path and getattr(args, "index_dir", ""):
        index_path = os.path.join(os.path.abspath(getattr(args, "index_dir")), "person-tables.index.json")
    mode = safe_cell(getattr(args, "discovery_preprocessing", "integrated") or "integrated").casefold()
    cache_key = (
        person_tables,
        os.path.abspath(getattr(args, "rules", "") or ""),
        EMAIL_SUFFIX,
        globals().get("EMAIL_WILDCARDS", ()),
        index_path,
        mode,
    )
    if PERSON_TABLE_EXACT_INDEX_KEY == cache_key:
        return

    if not person_tables:
        PERSON_TABLE_EXACT_MATCH_INDEX = {}
        PERSON_TABLE_INFER_HEADER_INDEX = {}
        PERSON_TABLE_REF_NAME_INDEX = {}
        PERSON_TABLE_EXACT_EVIDENCE_TYPES = set()
        PERSON_TABLE_EXACT_INDEX_KEY = cache_key
        return

    if index_path and mode in {"integrated", "standalone"}:
        loaded = load_person_table_exact_match_index(index_path)
        if loaded is not None:
            try:
                with open(index_path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                loaded_suffix = tuple(payload.get("email_suffix") or [])
                loaded_wildcard = tuple(normalize_email_wildcard_rules(payload.get("email_wildcard") or []))
            except Exception:
                loaded_suffix = ()
                loaded_wildcard = ()
            if loaded_suffix != tuple(EMAIL_SUFFIX) or loaded_wildcard != tuple(globals().get("EMAIL_WILDCARDS", ())):
                loaded = None
        if loaded is not None:
            exact_index, infer_index, exact_evidence_types, ref_name_index, summary_stems = loaded
            PERSON_TABLE_EXACT_MATCH_INDEX = exact_index
            PERSON_TABLE_INFER_HEADER_INDEX = infer_index
            PERSON_TABLE_REF_NAME_INDEX = ref_name_index
            PERSON_TABLE_EXACT_EVIDENCE_TYPES = set(exact_evidence_types)
            PERSON_TABLE_SUMMARY_STEMS = summary_stems or PERSON_TABLE_SUMMARY_STEMS
            register_person_table_exact_evidence_types(exact_evidence_types)
            PERSON_TABLE_EXACT_INDEX_KEY = cache_key
            if callable(progress_callback):
                progress_callback(f"loaded person-table index {os.path.basename(index_path)}: {len(exact_index):,} keys")
            return

    exact_index, infer_index, exact_evidence_types, ref_name_index = build_person_table_exact_match_index(
        person_tables,
        progress_callback=progress_callback,
    )
    PERSON_TABLE_EXACT_MATCH_INDEX = exact_index
    PERSON_TABLE_INFER_HEADER_INDEX = infer_index
    PERSON_TABLE_REF_NAME_INDEX = ref_name_index
    PERSON_TABLE_EXACT_EVIDENCE_TYPES = set(exact_evidence_types)
    register_person_table_exact_evidence_types(exact_evidence_types)
    PERSON_TABLE_EXACT_INDEX_KEY = cache_key

    if index_path and mode in {"integrated", "standalone"}:
        try:
            written = write_person_table_exact_match_index(
                index_path,
                person_tables,
                exact_index,
                infer_index,
                exact_evidence_types,
                ref_name_index,
                args,
            )
            if callable(progress_callback):
                progress_callback(f"wrote person-table index {os.path.basename(index_path)}: {written:,} keys")
        except OSError as exc:
            if callable(progress_callback):
                progress_callback(f"could not write person-table index {os.path.basename(index_path)}: {exc}")


def infer_header_from_person_table_values(values):
    """Infer a likely header label from a column's values using person tables.

    This is used as a conservative fallback for headerless structured tables:
    if a column repeatedly contains values that also appear under a consistent
    header in the supplied person tables, that header label can be reused.
    """
    if not PERSON_TABLE_INFER_HEADER_INDEX:
        return ""

    counts = Counter()
    label_keys = defaultdict(set)
    non_empty = 0
    seen_per_column = set()
    for value in values:
        value = safe_cell(value)
        if not value:
            continue
        non_empty += 1
        row_labels = Counter()
        for value_part in split_person_cell_values(value):
            key = person_table_exact_key(value_part)
            if key and key in PERSON_TABLE_INFER_HEADER_INDEX:
                row_labels.update(PERSON_TABLE_INFER_HEADER_INDEX[key])
                for label in PERSON_TABLE_INFER_HEADER_INDEX[key]:
                    label_keys[label].add(key)
        if row_labels:
            # A label should contribute at most once per row, otherwise one noisy
            # multi-value cell would dominate the inference score.
            for label in row_labels:
                counts[label] += 1
                seen_per_column.add(label)

    if non_empty < HEADER_INFERENCE_MIN_VALUES or not counts:
        return ""

    ranked = counts.most_common()
    label, count = ranked[0]
    ratio = count / non_empty
    if count < HEADER_INFERENCE_MIN_VALUES or ratio < HEADER_INFERENCE_MIN_RATIO:
        return ""
    if len(label_keys.get(label, set())) < HEADER_INFERENCE_MIN_VALUES:
        return ""
    if len(ranked) > 1 and ranked[1][1] == count:
        return ""
    return label


def person_table_exact_match_count_for_value(value):
    if not PERSON_TABLE_EXACT_MATCH_INDEX:
        return 0
    keys = set()
    key = person_table_exact_key(value)
    if key:
        keys.add(key)
    for match in PERSON_TABLE_EXACT_TOKEN_RE.finditer(safe_cell(value)):
        key = person_table_exact_key(match.group(0))
        if key:
            keys.add(key)
    return sum(len(PERSON_TABLE_EXACT_MATCH_INDEX.get(key, ())) for key in keys)


def person_table_match_is_authoritative_identity(evidence_type):
    """Return whether an exact person-table hit is strong enough to identify the row/scope.

    A row/scope may contain several weak contextual values.  We only use the
    person-table row's own names as authoritative Name evidence when the match
    is a clear identity anchor: an email, a configured strong anchor, an ID-like
    value, or a full-name exact match from the person table.  First-name and
    last-name columns are deliberately not indexed as exact Name anchors, so
    partial values such as ``Jane`` cannot by themselves trigger this path.
    """
    evidence_type = safe_cell(evidence_type)
    if not evidence_type:
        return False
    if evidence_type == "Name":
        return True
    if evidence_type in EMAIL_EVIDENCE_TYPES:
        return True
    if evidence_type in PERSON_CLUSTER_STRONG_ANCHORS:
        return True
    if evidence_type in ID_EVIDENCE_TYPES:
        return True
    if evidence_type.startswith("Known Person Identifier"):
        return True
    if any(role in {"id", "email"} for role in EVIDENCE_RISK_ROLES.get(evidence_type, set())):
        return True
    return False


def authoritative_known_person_name_matches_from_exact_matches(exact_matches):
    """Return Name matches supplied by the matched person-table rows themselves.

    This is the scanner-stage authority override for known-person rows/scopes:
    when a strong person-table value identifies a person, their known composite
    names are emitted as Name evidence instead of relying on weak row assembly
    that can accidentally pair first names with countries/addresses.
    """
    refs = set()
    for exact_match in exact_matches or []:
        if not person_table_match_is_authoritative_identity(exact_match.get("evidence_type", "")):
            continue
        refs.update(exact_match.get("person_table_refs", set()) or set())

    matches = []
    seen = set()
    for person_ref in sorted(refs):
        for name in PERSON_TABLE_REF_NAME_INDEX.get(person_ref, ()):
            matched_text = safe_cell(name.get("matched_text", ""))
            normalized = normalize_name_value(matched_text)
            if not matched_text or not normalized or normalized in seen:
                continue
            if not valid_name_value(matched_text, require_full_name=True):
                continue
            seen.add(normalized)
            matches.append({
                "matched_text": matched_text,
                "normalized_value": normalized,
                "confidence": name.get("confidence", "high"),
                "source": "person_table_authoritative",
            })
    return matches


def explicit_full_name_matches_from_labelled_fields(labelled_fields):
    """Return additional explicit full-name fields from a row/scope.

    Used only after an authoritative person-table match.  We do not pair inferred
    first/last columns in this mode, because that is exactly how mixed values
    such as ``Jane England`` can be created.  Explicit full-name style fields
    such as birth name, maiden name, legal name, preferred name, or previous full
    name can still contribute additional Name evidence.
    """
    matches = []
    seen = set()
    for header, value in labelled_fields or []:
        header = safe_cell(header)
        if not header or is_non_person_name_header(header):
            continue
        if not is_full_name_header(header):
            continue
        for full_name in split_name_values(value, require_full_name=True):
            match = name_match(full_name)
            if not match:
                continue
            normalized = match["normalized_value"]
            if normalized in seen:
                continue
            seen.add(normalized)
            matches.append(match)
    return matches


def merge_name_match_rows(primary_matches, additional_matches):
    merged = []
    seen = set()
    for match in list(primary_matches or []) + list(additional_matches or []):
        matched_text = safe_cell(match.get("matched_text", ""))
        normalized = match.get("normalized_value") or normalize_name_value(matched_text)
        if not matched_text or not normalized or normalized in seen:
            continue
        seen.add(normalized)
        row = dict(match)
        row["matched_text"] = matched_text
        row["normalized_value"] = normalized
        row.setdefault("confidence", "high")
        merged.append(row)
    return merged


def person_refs_to_table_stems(refs):
    stems = set()
    for ref in refs or []:
        stem = safe_cell(str(ref).split(":", 1)[0])
        if stem:
            stems.add(stem)
    return sorted(stems)


def person_table_exact_candidates_from_line(line, labelled_fields):
    if not PERSON_TABLE_EXACT_MATCH_INDEX:
        return []

    candidates = []
    seen = {}

    def add_candidate(raw_value, start_pos=None, free_text=False):
        raw_value = safe_cell(raw_value)
        if not raw_value:
            return
        keys = person_table_exact_keys_for_value(raw_value)
        specs = []
        for key in keys:
            specs.extend(PERSON_TABLE_EXACT_MATCH_INDEX.get(key, ()))
        if not specs:
            return
        if start_pos is None:
            start_pos = line.find(raw_value)
            if start_pos < 0:
                start_pos = 0
        for spec in specs:
            evidence_type = spec.get("evidence_type", "")
            if not evidence_type:
                continue
            if free_text and not person_table_match_is_authoritative_identity(evidence_type):
                continue
            normalized = normalize_value(evidence_type, raw_value)
            dedupe_key = (evidence_type, normalized, start_pos)
            person_ref = f"{spec.get('source_table', '')}:{spec.get('source_row_number', '')}"
            if dedupe_key in seen:
                candidates[seen[dedupe_key]].setdefault("person_table_refs", set()).add(person_ref)
                continue
            seen[dedupe_key] = len(candidates)
            candidates.append({
                "evidence_type": evidence_type,
                "matched_text": raw_value,
                "normalized_value": normalized,
                "start": start_pos,
                "end": start_pos + len(raw_value),
                "confidence": "high",
                "pattern_name": PERSON_TABLE_EXACT_PATTERN_NAME,
                "person_table_refs": {person_ref},
            })

    # Exact whole-cell matching is the safest and most useful path for tables,
    # XML_SCOPE rows, and structured records because the value boundary is known.
    for _header, value in labelled_fields or []:
        add_candidate(value)
        for value_part in split_person_cell_values(value):
            if value_part != value:
                add_candidate(value_part)

    # Free-text fallback: look up candidate identifier-like tokens only.
    for match in PERSON_TABLE_EXACT_TOKEN_RE.finditer(line):
        add_candidate(match.group(0), match.start(), free_text=True)

    return candidates


def split_person_cell_values(value):
    value = safe_cell(value)
    if not value:
        return []
    return [part.strip() for part in re.split(r"\s*[|;]\s*", value) if part.strip()]


def is_person_table_primary_id_header(header):
    return safe_cell(header).lower() == "id"


def evidence_types_for_person_column(header):
    if is_person_table_primary_id_header(header):
        return [person_table_dynamic_identifier_evidence_type("ID")]

    metadata = resolve_table_header_metadata(header)
    evidence_types = set(configured_evidence_types_from_header_metadata(metadata))

    resolved_header = resolve_table_header(header) or safe_cell(header)
    header_slug = rule_slug(resolved_header)
    if not header_slug:
        return sorted(evidence_types)

    for evidence_type in EVIDENCE_COUNT_TYPES:
        evidence_slug = rule_slug(evidence_type)
        if header_slug == evidence_slug:
            evidence_types.add(evidence_type)

    return sorted(evidence_types)


def person_column_regex_matches(header, value):
    cleaned = safe_cell(value)
    if not cleaned:
        return []

    context_header = resolve_table_header(header) or safe_cell(header)
    if not context_header:
        return []

    matches = []
    seen = set()
    for value_part in split_person_cell_values(cleaned):
        line = f"{context_header}: {value_part}"
        lower_line = line.lower()
        for pattern in PATTERNS:
            line_triggers = pattern.get("line_triggers") or ()
            if line_triggers and not any(token in lower_line for token in line_triggers):
                continue
            for match in pattern["regex"].finditer(line):
                matched_text, _, _ = extract_match_value(match)
                if not validate_pattern_match(pattern, matched_text):
                    continue
                key = (pattern["evidence_type"], normalize_value(pattern["evidence_type"], matched_text))
                if key in seen:
                    continue
                seen.add(key)
                matches.append((pattern["evidence_type"], matched_text))
    return matches


def person_key_for_row(row, row_number):
    for header, value in row.items():
        if is_person_table_primary_id_header(header) and safe_cell(value):
            return safe_cell(value)
    for header, value in row.items():
        if set(evidence_types_for_person_column(header)) & PERSON_CLUSTER_STRONG_ANCHORS and safe_cell(value):
            return safe_cell(value)
    for value in row.values():
        emails = EMAIL_ANCHOR_RE.findall(safe_cell(value))
        if emails:
            return emails[0].lower()
    for value in row.values():
        cleaned = safe_cell(value)
        if cleaned:
            return cleaned
    return f"person_table_row_{row_number}"


def make_unique_person_key(base_key, people):
    person_key = base_key
    suffix = 2
    while person_key in people:
        person_key = f"{base_key}#{suffix}"
        suffix += 1
    return person_key


def add_person_anchor(anchor_to_people, person_key, evidence_type, value, source_field):
    pairs = email_lookup_pairs(evidence_type, value)
    if not pairs:
        normalized = normalize_value(evidence_type, value)
        pairs = ((evidence_type, normalized),) if normalized else ()
    for pair_evidence_type, normalized in pairs:
        if normalized:
            anchor_to_people[(pair_evidence_type, normalized)][person_key].add(source_field)


def add_person_cell_anchors(anchor_to_people, person_key, header, value):
    cleaned = safe_cell(value)
    if not cleaned:
        return

    header_metadata = resolve_table_header_metadata(header)
    evidence_types = evidence_types_for_person_column(header)
    exact_evidence_types = person_table_exact_evidence_types_for_header(header)
    for email_value in EMAIL_ANCHOR_RE.findall(cleaned):
        add_person_anchor(anchor_to_people, person_key, email_evidence_type(email_value), email_value, header)

    for evidence_type in sorted(set(exact_evidence_types) | set(evidence_types)):
        if evidence_type == "Name" and header_metadata.get("name_part") in {"first", "last"}:
            continue
        if evidence_type in EMAIL_EVIDENCE_TYPES:
            continue
        for value_part in split_person_cell_values(cleaned):
            add_person_anchor(anchor_to_people, person_key, evidence_type, value_part, header)

    for evidence_type, matched_text in person_column_regex_matches(header, cleaned):
        if evidence_type == "Name" and header_metadata.get("name_part") in {"first", "last"}:
            continue
        if evidence_type in EMAIL_EVIDENCE_TYPES:
            continue
        add_person_anchor(anchor_to_people, person_key, evidence_type, matched_text, header)


def add_composite_name_anchor(anchor_to_people, person_key, row):
    fields = [
        (header, safe_cell(value), resolve_table_header_metadata(header))
        for header, value in row.items()
    ]
    for name in assembled_names_from_fields(fields):
        add_person_anchor(anchor_to_people, person_key, "Name", name["matched_text"], "composite_name")


def merge_pipe_values(left, right):
    values = []
    seen = set()
    for value in list(split_pipe_values(left)) + list(split_pipe_values(right)):
        value = safe_cell(value)
        if not value or value in seen:
            continue
        seen.add(value)
        values.append(value)
    return " | ".join(values)


def merge_person_table_row(existing_source, row, headers):
    for header in headers:
        existing_source[header] = merge_pipe_values(existing_source.get(header, ""), row.get(header, ""))


def load_person_table(person_table_path):
    people = {}
    anchor_to_people = defaultdict(lambda: defaultdict(set))

    with open(person_table_path, "rb") as f:
        text = decode_person_table_bytes(f.read())

    reader = csv.DictReader(io.StringIO(text, newline=""))
    headers = reader.fieldnames or []
    for row_number, row in enumerate(reader, start=1):
        base_key = person_key_for_row(row, row_number)
        person_key = base_key
        if person_key in people:
            people[person_key]["person_table_row_number"] = merge_pipe_values(
                str(people[person_key].get("person_table_row_number", "")),
                str(row_number),
            )
            merge_person_table_row(people[person_key]["source"], row, headers)
        else:
            people[person_key] = {
                "person_key": person_key,
                "person_table_row_number": row_number,
                "source": dict(row),
            }

        for header in headers:
            add_person_cell_anchors(anchor_to_people, person_key, header, row.get(header, ""))
        add_composite_name_anchor(anchor_to_people, person_key, row)

    return people, anchor_to_people, headers


def person_output_fields(person_headers, extra_fields):
    return ["person_key", "person_table_row_number"] + list(person_headers) + list(extra_fields)


def person_output_row(person):
    row = {
        "person_key": person["person_key"],
        "person_table_row_number": person["person_table_row_number"],
    }
    row.update(person["source"])
    return row


def parse_linked_evidence_values(evidence_values):
    parsed = []
    for part in split_pipe_values(evidence_values):
        if "=" not in part:
            continue
        evidence_type, value = part.split("=", 1)
        parsed.append((evidence_type.strip(), value.strip()))
    return parsed


def exposure_risk(categories):
    categories = set(categories)
    has_email = has_email_evidence(categories)
    has_id = has_id_evidence(categories)
    has_dob = has_risk_role(categories, "dob")
    if categories & HIGH_RISK_STANDALONE:
        return "high"
    if (categories & SENSITIVE_CONTEXT) and (categories & IDENTIFIABLE_EVIDENCE):
        return "high"
    if (has_email and has_dob) or (has_email and has_id):
        return "high"
    if categories & IDENTIFIABLE_EVIDENCE:
        return "medium"
    if categories:
        return "low"
    return ""


def exposure_risk_score(categories):
    risk_level = exposure_risk(categories)
    return {
        "": 0,
        "low": 25,
        "medium": 60,
        "high": 90,
    }[risk_level], risk_level or "none"


def write_known_person_risk_matrix(people, person_headers, exposure, risk_matrix_path):
    fieldnames = person_output_fields(
        person_headers,
        ["overall_risk_score", "overall_risk_level"] + EVIDENCE_FLAG_COLUMNS,
    )
    with open(risk_matrix_path, "w", encoding="utf-8", newline="", buffering=OUTPUT_BUFFER_SIZE) as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for person_id in sorted(people):
            source = people[person_id]
            person = exposure[person_id]
            risk_score, risk_level = exposure_risk_score(person["categories"])
            row = person_output_row(source)
            row["overall_risk_score"] = risk_score
            row["overall_risk_level"] = risk_level
            for evidence_type, column in zip(EVIDENCE_COUNT_TYPES, EVIDENCE_FLAG_COLUMNS):
                row[column] = "yes" if evidence_type in person["categories"] else "no"
            writer.writerow(row)


def add_pii_matrix_value(values_by_type, evidence_type, value):
    evidence_type = safe_cell(evidence_type)
    value = safe_cell(value)
    if not evidence_type or not value:
        return
    if value.startswith("...(+") and value.endswith(" more)"):
        return
    values_by_type[evidence_type].add(value)


def add_pii_matrix_pairs(values_by_type, pairs):
    for evidence_type, value in pairs:
        add_pii_matrix_value(values_by_type, evidence_type, value)


def id_like_reference_header(header):
    slug = rule_slug(header)
    if not slug:
        return False
    id_terms = {
        "id", "identifier", "number", "no", "num", "ref", "reference",
        "person", "person_id", "person_number", "staff", "staff_id", "staff_number",
        "student", "student_id", "student_number", "employee", "employee_id",
        "assignment", "assignment_id", "assignment_number", "username", "user_name",
        "user_id", "applicant", "applicant_id", "applicant_number",
    }
    if slug in id_terms:
        return True
    return any(
        slug == term or slug.startswith(term + "_") or slug.endswith("_" + term)
        for term in id_terms
    )


def include_reference_evidence_value(evidence_type, header, detected_categories):
    """Return True when a known-person table value should be copied into the value matrix.

    The value matrix is evidence-led, but exposed-known rows are easier to use if
    they carry the reference identifiers that explain how the person was linked.
    To avoid copying broad contextual fields such as School/Course/Department
    into has_* columns, this allows core identity values by default and allows
    other known-table values only when that evidence type was actually detected
    for the person.
    """
    evidence_type = safe_cell(evidence_type)
    if not evidence_type:
        return False
    if evidence_type == "Name" or evidence_type in EMAIL_EVIDENCE_TYPES:
        return True
    if evidence_type in detected_categories:
        return True
    if id_like_reference_header(header):
        return True
    if any(role in {"id", "dob", "phone", "address", "payment_card", "application_reference"}
           for role in EVIDENCE_RISK_ROLES.get(evidence_type, set())):
        return True
    return False


def known_person_reference_name_map(person, person_headers):
    """Return the valid known-person names from the source person-table row.

    This is deliberately stricter than the general table Name detector. The
    value matrix is for known people, so a Name value should only be shown when
    it validates against the known person's own first/last/full-name columns.
    This prevents cluster-level false positives such as addresses, schools,
    courses, countries, or organisational names from carrying into has_name.
    """
    row = person.get("source", {})
    fields = []
    for header in person_headers:
        if is_non_person_name_header(header):
            continue
        value = safe_cell(row.get(header, ""))
        if not value:
            continue
        metadata = resolve_table_header_metadata(header)
        name_part = name_part_for_header(header, metadata)
        full_name_header = is_full_name_header(header)
        # Accept explicit first/last/surname/forename fields and clear subject
        # full-name fields. Do not use contextual non-name columns.
        if name_part in {"first", "last"} or full_name_header or is_subject_person_name_header(header):
            fields.append((header, value, table_header_assembly_metadata(header)))

    names = {}
    for name in assembled_names_from_fields(fields):
        matched = safe_cell(name.get("matched_text", ""))
        if not matched or not valid_name_value(matched, require_full_name=True):
            continue
        names[normalize_name_value(matched)] = matched
    return names


def validated_known_person_name_values(person, person_headers, values):
    reference_names = known_person_reference_name_map(person, person_headers)
    if not reference_names:
        return set()

    validated = set()
    for value in values or []:
        value = safe_cell(value)
        if not value:
            continue
        normalized = normalize_name_value(value)
        if normalized in reference_names:
            # Prefer the person-table spelling/capitalisation rather than a
            # cluster-normalised lowercase value.
            validated.add(reference_names[normalized])
    return validated


def person_reference_pii_values(person, person_headers, detected_categories):
    values_by_type = defaultdict(set)
    row = person.get("source", {})

    for header in person_headers:
        raw_value = row.get(header, "")
        cleaned = safe_cell(raw_value)
        if not cleaned:
            continue

        header_metadata = resolve_table_header_metadata(header)
        for email_value in EMAIL_ANCHOR_RE.findall(cleaned):
            evidence_type = email_evidence_type(email_value)
            if include_reference_evidence_value(evidence_type, header, detected_categories):
                add_pii_matrix_value(values_by_type, evidence_type, email_value)

        evidence_types = sorted(
            set(evidence_types_for_person_column(header))
            | set(person_table_exact_evidence_types_for_header(header))
        )
        for evidence_type in evidence_types:
            if evidence_type == "Name" and header_metadata.get("name_part") in {"first", "last"}:
                continue
            if evidence_type in EMAIL_EVIDENCE_TYPES:
                continue
            if not include_reference_evidence_value(evidence_type, header, detected_categories):
                continue
            for value_part in split_person_cell_values(cleaned):
                add_pii_matrix_value(values_by_type, evidence_type, value_part)

        for evidence_type, matched_text in person_column_regex_matches(header, cleaned):
            if evidence_type == "Name" and header_metadata.get("name_part") in {"first", "last"}:
                continue
            if evidence_type in EMAIL_EVIDENCE_TYPES:
                continue
            if not include_reference_evidence_value(evidence_type, header, detected_categories):
                continue
            add_pii_matrix_value(values_by_type, evidence_type, matched_text)

    # For known-person value matrices, only carry the known subject person's
    # validated reference name. Do not use arbitrary cluster/table Name values
    # here; those are filtered again at write time.
    for name in known_person_reference_name_map(person, person_headers).values():
        add_pii_matrix_value(values_by_type, "Name", name)

    return values_by_type


def collect_assignment_pii_values(assignment):
    values_by_type = defaultdict(set)
    for cluster in assignment.get("clusters", []):
        add_pii_matrix_pairs(values_by_type, parse_linked_evidence_values(cluster.get("evidence_values", "")))
    for linked_row in assignment.get("unclustered_linked_rows", []):
        add_pii_matrix_pairs(values_by_type, parse_linked_evidence_values(linked_row.get("evidence_values", "")))
    for raw_row in assignment.get("direct_raw_evidence_rows", []):
        add_pii_matrix_value(
            values_by_type,
            raw_row.get("evidence_type", ""),
            raw_row.get("matched_text") or raw_row.get("normalized_value", ""),
        )
    return values_by_type


def merge_pii_value_maps(*maps):
    merged = defaultdict(set)
    for value_map in maps:
        for evidence_type, values in (value_map or {}).items():
            for value in values:
                add_pii_matrix_value(merged, evidence_type, value)
    return merged


def format_pii_matrix_values(values, limit=50):
    best_by_key = {}
    for value in values:
        value = safe_cell(value)
        if not value:
            continue
        key = re.sub(r"\s+", " ", value).casefold().strip()
        if not key:
            continue
        # Prefer human-readable mixed/lowercase values over normalised all-caps
        # forms when the scanner has both for the same evidence value.
        score = (0 if any(char.islower() for char in value) else 1, len(value), value)
        existing = best_by_key.get(key)
        if existing is None or score < existing[0]:
            best_by_key[key] = (score, value)
    values = sorted((value for _score, value in best_by_key.values()), key=lambda item: item.casefold())
    if len(values) <= limit:
        return " | ".join(values)
    return " | ".join(values[:limit]) + f" | ...(+{len(values) - limit} more)"


def write_known_person_pii_value_risk_matrix(
    people,
    person_headers,
    exposure,
    known_evidence_assignments,
    pii_value_risk_matrix_path,
):
    if not pii_value_risk_matrix_path:
        return

    fieldnames = person_output_fields(
        person_headers,
        ["overall_risk_score", "overall_risk_level"] + EVIDENCE_FLAG_COLUMNS,
    )
    with open(pii_value_risk_matrix_path, "w", encoding="utf-8", newline="", buffering=OUTPUT_BUFFER_SIZE) as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for person_id in sorted(people):
            source = people[person_id]
            person = exposure[person_id]
            risk_score, risk_level = exposure_risk_score(person["categories"])
            row = person_output_row(source)
            row["overall_risk_score"] = risk_score
            row["overall_risk_level"] = risk_level

            value_map = defaultdict(set)
            if person["clusters"] or person["unclustered_count"] or person["raw_evidence_count"]:
                reference_values = person_reference_pii_values(source, person_headers, person["categories"])
                assignment_values = collect_assignment_pii_values(known_evidence_assignments.get(person_id, {}))
                value_map = merge_pii_value_maps(reference_values, assignment_values)

            for evidence_type, column in zip(EVIDENCE_COUNT_TYPES, EVIDENCE_FLAG_COLUMNS):
                values = value_map.get(evidence_type, set())
                if evidence_type == "Name":
                    values = validated_known_person_name_values(source, person_headers, values)
                if values:
                    row[column] = format_pii_matrix_values(values)
                elif evidence_type in person["categories"]:
                    # Preserve the fact that the risk category was seen even if the
                    # source row did not carry a parseable value string. For Name,
                    # do not echo unvalidated cluster values into the value matrix;
                    # the binary risk matrix still records the presence flag.
                    row[column] = "yes"
                else:
                    row[column] = ""
            writer.writerow(row)


def write_unknown_person_risk_matrix(rows, risk_matrix_path):
    fieldnames = [
        "unknown_person_key",
        "person_cluster_id",
        "overall_risk_score",
        "overall_risk_level",
    ] + EVIDENCE_FLAG_COLUMNS
    with open(risk_matrix_path, "w", encoding="utf-8", newline="", buffering=OUTPUT_BUFFER_SIZE) as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            categories = set(split_pipe_values(row.get("evidence_types", "")))
            risk_score, risk_level = exposure_risk_score(categories)
            output_row = {
                "unknown_person_key": row.get("unknown_person_key", ""),
                "person_cluster_id": row.get("person_cluster_id", ""),
                "overall_risk_score": risk_score,
                "overall_risk_level": risk_level,
            }
            for evidence_type, column in zip(EVIDENCE_COUNT_TYPES, EVIDENCE_FLAG_COLUMNS):
                output_row[column] = "yes" if evidence_type in categories else "no"
            writer.writerow(output_row)


def record_link_pairs(record):
    pairs = []
    pairs.extend(parse_linked_evidence_values(record.get("anchor_values", "")))
    anchor_type = record.get("anchor_type", "")
    anchor_value = record.get("anchor_value", "")
    if anchor_type and anchor_value:
        pairs.append((anchor_type, anchor_value))
    pairs.extend(parse_linked_evidence_values(record.get("evidence_values", "")))
    return pairs


def strong_anchor_pairs_for_record(record):
    """Return configured strong identity anchors present in a row or cluster.

    This is intentionally stricter than ``record_link_pairs``. It only returns
    pairs whose evidence type is currently configured as a strong person-cluster
    anchor, for example Email / Institutional Email / Personal Email when the
    identity-anchor configuration declares Email as strong.
    """
    pairs = []
    seen = set()

    for evidence_type, value in record_link_pairs(record):
        evidence_type = safe_cell(evidence_type)
        value = safe_cell(value)
        if not evidence_type or not value:
            continue
        if evidence_type not in PERSON_CLUSTER_STRONG_ANCHORS:
            continue
        lookup_pairs = email_lookup_pairs(evidence_type, value)
        if not lookup_pairs:
            normalized = normalize_value(evidence_type, value)
            lookup_pairs = ((evidence_type, normalized),) if normalized else ()
        for key in lookup_pairs:
            if key in seen:
                continue
            seen.add(key)
            pairs.append(key)

    return pairs


def unknown_strong_anchor_key(evidence_type, evidence_value):
    """Stable non-disclosing key for an unknown unclustered strong anchor."""
    digest = hashlib.md5(
        f"{evidence_type}:{evidence_value}".encode("utf-8", errors="ignore")
    ).hexdigest()[:12]
    return f"unknown_unclustered_strong:{rule_slug(evidence_type)}:{digest}"


def linked_people_for_record(record, anchor_to_people):
    pairs = record_link_pairs(record)

    linked_people = set()
    link_anchor_types = set()
    link_anchor_fields = set()

    for evidence_type, value in pairs:
        lookup_pairs = email_lookup_pairs(evidence_type, value)
        if not lookup_pairs:
            value_normalized = normalize_value(evidence_type, value)
            lookup_pairs = ((evidence_type, value_normalized),) if value_normalized else ()

        people_for_pair = {}
        for pair in lookup_pairs:
            for person_key, fields in anchor_to_people.get(pair, {}).items():
                people_for_pair[person_key] = fields

        if people_for_pair:
            linked_people.update(people_for_pair)
            link_anchor_types.update(pair[0] for pair in lookup_pairs)
            for person_fields in people_for_pair.values():
                link_anchor_fields.update(person_fields)

    return linked_people, link_anchor_types, link_anchor_fields


def linked_people_for_raw_evidence(row, anchor_to_people):
    evidence_type = row.get("evidence_type", "")
    value = row.get("normalized_value") or row.get("matched_text", "")
    if not evidence_type or not value:
        return set(), set(), set()

    lookup_pairs = email_lookup_pairs(evidence_type, value)
    if not lookup_pairs:
        normalized = normalize_value(evidence_type, value)
        lookup_pairs = ((evidence_type, normalized),) if normalized else ()

    people_for_pair = {}
    for pair in lookup_pairs:
        for person_key, fields in anchor_to_people.get(pair, {}).items():
            people_for_pair[person_key] = fields
    if not people_for_pair:
        return set(), set(), set()

    link_anchor_fields = set()
    for person_fields in people_for_pair.values():
        link_anchor_fields.update(person_fields)
    return set(people_for_pair), {pair[0] for pair in lookup_pairs}, link_anchor_fields


def known_output_progress(label, **counts):
    print(
        "\rStage 6/7: "
        + label
        + " | "
        + " | ".join(f"{name.replace('_', ' ')} {value:,}" for name, value in counts.items()),
        end="",
        flush=True,
    )


def write_individuals_not_in_known_person_exposure(people, person_headers, exposure, output_path):
    with open(output_path, "w", encoding="utf-8", newline="", buffering=OUTPUT_BUFFER_SIZE) as f:
        writer = csv.DictWriter(f, fieldnames=person_output_fields(person_headers, ["reason"]))
        writer.writeheader()
        for person_id in sorted(people):
            if (
                exposure[person_id]["clusters"]
                or exposure[person_id]["unclustered_count"]
                or exposure[person_id]["raw_evidence_count"]
            ):
                continue
            row = person_output_row(people[person_id])
            row["reason"] = "No person cluster, cluster-excluded linked evidence, or raw evidence matched this person table row."
            writer.writerow(row)


def write_unknown_person_clusters(rows, output_path):
    with open(output_path, "w", encoding="utf-8", newline="", buffering=OUTPUT_BUFFER_SIZE) as f:
        writer = csv.DictWriter(f, fieldnames=UNKNOWN_PERSON_IN_DATASET_CLUSTER_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def write_unknown_person_in_dataset(rows, output_path):
    with open(output_path, "w", encoding="utf-8", newline="", buffering=OUTPUT_BUFFER_SIZE) as f:
        writer = csv.DictWriter(f, fieldnames=UNKNOWN_PERSON_IN_DATASET_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def linked_row_key(row):
    return row.get("file_path", ""), str(row.get("row_number", ""))


def raw_evidence_key(row):
    return (
        row.get("file_path", ""),
        str(row.get("row_number", "")),
        row.get("evidence_type", ""),
        row.get("normalized_value") or row.get("matched_text", ""),
        row.get("pattern_name", ""),
        str(row.get("start", "")),
        str(row.get("end", "")),
    )


def iter_atomic_evidence_rows(evidence_dir):
    if not os.path.isdir(evidence_dir):
        return
    for entry in sorted(os.scandir(evidence_dir), key=lambda item: item.name):
        if not entry.is_file() or not entry.name.lower().endswith(".csv") or entry.name == "errors.csv":
            continue
        with open(entry.path, "r", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as f:
            for row in csv.DictReader(f):
                if row.get("evidence_tier") == "metadata" or row.get("pattern_name") == "max_findings_per_file":
                    continue
                yield row


def collect_atomic_evidence_for_linked_rows(evidence_dir, linked_rows):
    wanted_keys = {linked_row_key(row) for row in linked_rows if row.get("file_path")}
    raw_by_key = defaultdict(list)
    if not wanted_keys:
        return raw_by_key

    for row in iter_atomic_evidence_rows(evidence_dir):
        key = linked_row_key(row)
        if key in wanted_keys:
            raw_by_key[key].append(row)
    return raw_by_key


def matched_evidence_count(linked_rows, raw_by_key):
    keys = {linked_row_key(row) for row in linked_rows if row.get("file_path")}
    return sum(len(raw_by_key.get(key, [])) for key in keys)


def add_raw_evidence_keys_to_entry(entry, rows):
    for row in rows:
        entry["matched_evidence_keys"].add(raw_evidence_key(row))


def safe_person_evidence_filename(person_key, fallback_prefix):
    slug = rule_slug(person_key)[:80] or fallback_prefix
    digest = hashlib.md5(str(person_key).encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"{slug}__{digest}.csv"


def clean_output_folder(folder):
    os.makedirs(folder, exist_ok=True)
    for entry in os.scandir(folder):
        if entry.is_file() and entry.name.lower().endswith(".csv"):
            os.remove(entry.path)


def write_person_evidence_file(folder, person_key, person_type, assignment, raw_by_key):
    path = os.path.join(folder, safe_person_evidence_filename(person_key, person_type))
    with open(path, "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as f:
        writer = csv.DictWriter(f, fieldnames=PERSON_EVIDENCE_DETAIL_FIELDS)
        writer.writeheader()

        for cluster in assignment.get("clusters", []):
            writer.writerow(
                {
                    "person_type": person_type,
                    "person_key": person_key,
                    "person_table_row_number": assignment.get("person_table_row_number", ""),
                    "person_cluster_id": cluster.get("person_cluster_id", ""),
                    "record_type": "person_cluster",
                    "source_scope": "clustered",
                    "cluster_confidence": cluster.get("cluster_confidence", ""),
                    "risk_level": cluster.get("risk_level", ""),
                    "linked_evidence_key": "",
                    "linked_evidence_count": cluster.get("linked_evidence_count", ""),
                    "file_count": cluster.get("file_count", ""),
                    "evidence_types": cluster.get("evidence_types", ""),
                    "evidence_values": cluster.get("evidence_values", ""),
                    "cluster_anchor_types": cluster.get("anchor_types", ""),
                    "cluster_anchor_values": cluster.get("anchor_values", ""),
                    "cluster_merge_keys": cluster.get("cluster_merge_keys", ""),
                    "risk_reasons": cluster.get("risk_reasons", ""),
                    "source_row": cluster.get("source_rows", ""),
                }
            )

        for scope, rows in (
            ("clustered", assignment.get("clustered_linked_rows", [])),
            ("unclustered", assignment.get("unclustered_linked_rows", [])),
        ):
            for linked_row in rows:
                cluster_id = linked_row.get("_person_cluster_id", "")
                base = {
                    "person_type": person_type,
                    "person_key": person_key,
                    "person_table_row_number": assignment.get("person_table_row_number", ""),
                    "person_cluster_id": cluster_id,
                    "record_type": "linked_evidence",
                    "source_scope": scope,
                    "linked_evidence_key": linked_row.get("linked_evidence_key", ""),
                    "file_path": linked_row.get("file_path", ""),
                    "file_name": linked_row.get("file_name", ""),
                    "extension": linked_row.get("extension", ""),
                    "row_number": linked_row.get("row_number", ""),
                    "anchor_type": linked_row.get("anchor_type", ""),
                    "anchor_value": linked_row.get("anchor_value", ""),
                    "evidence_types": linked_row.get("evidence_types", ""),
                    "evidence_values": linked_row.get("evidence_values", ""),
                    "confidence": linked_row.get("confidence", ""),
                    "risk_level": linked_row.get("risk_level", ""),
                    "risk_reasons": linked_row.get("risk_reasons", ""),
                    "cluster_eligible": linked_row.get("cluster_eligible", ""),
                    "cluster_exclusion_reason": linked_row.get("cluster_exclusion_reason", ""),
                    "source_row": linked_row.get("source_row", ""),
                }
                writer.writerow(base)

                for raw_row in raw_by_key.get(linked_row_key(linked_row), []):
                    raw_output = dict(base)
                    raw_output.update(
                        {
                            "record_type": "raw_evidence",
                            "raw_evidence_type": raw_row.get("evidence_type", ""),
                            "raw_matched_text": raw_row.get("matched_text", ""),
                            "raw_normalized_value": raw_row.get("normalized_value", ""),
                            "raw_pattern_name": raw_row.get("pattern_name", ""),
                            "raw_confidence": raw_row.get("confidence", ""),
                            "raw_evidence_tier": raw_row.get("evidence_tier", ""),
                            "raw_start": raw_row.get("start", ""),
                            "raw_end": raw_row.get("end", ""),
                            "raw_context": raw_row.get("context", ""),
                        }
                    )
                    writer.writerow(raw_output)

        for raw_row in assignment.get("direct_raw_evidence_rows", []):
            writer.writerow(
                {
                    "person_type": person_type,
                    "person_key": person_key,
                    "person_table_row_number": assignment.get("person_table_row_number", ""),
                    "record_type": "raw_evidence",
                    "source_scope": "direct_raw_evidence",
                    "file_path": raw_row.get("file_path", ""),
                    "file_name": raw_row.get("file_name", ""),
                    "extension": raw_row.get("extension", ""),
                    "row_number": raw_row.get("row_number", ""),
                    "raw_evidence_type": raw_row.get("evidence_type", ""),
                    "raw_matched_text": raw_row.get("matched_text", ""),
                    "raw_normalized_value": raw_row.get("normalized_value", ""),
                    "raw_pattern_name": raw_row.get("pattern_name", ""),
                    "raw_confidence": raw_row.get("confidence", ""),
                    "raw_evidence_tier": raw_row.get("evidence_tier", ""),
                    "raw_start": raw_row.get("start", ""),
                    "raw_end": raw_row.get("end", ""),
                    "raw_context": raw_row.get("context", ""),
                }
            )


def write_person_evidence_folders(known_assignments, unknown_assignments, raw_by_key, known_folder, unknown_folder):
    clean_output_folder(known_folder)
    clean_output_folder(unknown_folder)

    for person_key, assignment in sorted(known_assignments.items()):
        write_person_evidence_file(known_folder, person_key, "known_person", assignment, raw_by_key)

    for person_key, assignment in sorted(unknown_assignments.items()):
        write_person_evidence_file(unknown_folder, person_key, "unknown_person", assignment, raw_by_key)


def known_exposure_entry(exposure_by_person, person_id):
    return exposure_by_person.setdefault(
        person_id,
        {
            "person_cluster_ids": set(),
            "cluster_confidences": [],
            "risk_levels": [],
            "linked_evidence_count": 0,
            "unclustered_linked_evidence_count": 0,
            "file_paths": set(),
            "evidence_types": set(),
            "link_anchor_types": set(),
            "link_person_table_fields": set(),
            "matched_evidence_count": 0,
            "matched_evidence_keys": set(),
        },
    )


def update_known_person_exposure(
    exposure,
    exposure_by_person,
    person_id,
    evidence_types,
    file_paths,
    link_anchor_types,
    link_anchor_fields,
    linked_evidence_count=1,
    cluster_id="",
    cluster_confidence="",
    risk_level="",
    unclustered=False,
    raw_evidence_count=0,
):
    person = exposure[person_id]
    if cluster_id:
        person["clusters"].add(cluster_id)
    if unclustered:
        person["unclustered_count"] += linked_evidence_count
    if raw_evidence_count:
        person["raw_evidence_count"] += raw_evidence_count
    person["categories"].update(evidence_types)
    person["files"].update(file_paths)
    person["anchors"].update(link_anchor_types)
    person["count"] += linked_evidence_count

    entry = known_exposure_entry(exposure_by_person, person_id)
    if cluster_id:
        entry["person_cluster_ids"].add(cluster_id)
    if cluster_confidence:
        entry["cluster_confidences"].append(cluster_confidence)
    if risk_level:
        entry["risk_levels"].append(risk_level)
    entry["linked_evidence_count"] += linked_evidence_count
    if unclustered:
        entry["unclustered_linked_evidence_count"] += linked_evidence_count
    entry["file_paths"].update(file_paths)
    entry["evidence_types"].update(evidence_types)
    entry["link_anchor_types"].update(link_anchor_types)
    entry["link_person_table_fields"].update(link_anchor_fields)


def build_known_person_outputs_from_clusters(
    person_table_path,
    clusters_path,
    linked_evidence_path,
    evidence_dir,
    known_person_exposure_path,
    risk_matrix_path,
    not_in_exposure_path,
    unknown_person_in_dataset_clusters_path,
    unknown_person_in_dataset_path,
    unknown_person_risk_matrix_path,
    known_person_evidence_dir,
    unknown_person_evidence_dir,
    build_unknown_outputs,
    cluster_members,
    pii_value_risk_matrix_path=None,
    progress_every=1.0,
    write_person_evidence=False,
    cluster_total=None,
    linked_evidence_total=None,
    raw_evidence_total=None,
):
    # Backward-compatible positional API: older callers passed
    # cluster_members, progress_every, write_person_evidence, cluster_total,
    # linked_evidence_total, raw_evidence_total immediately after the two
    # evidence-folder paths.
    if not isinstance(build_unknown_outputs, bool):
        old_cluster_members = build_unknown_outputs
        old_progress_every = cluster_members
        old_write_person_evidence = pii_value_risk_matrix_path
        old_cluster_total = progress_every
        old_linked_evidence_total = write_person_evidence
        old_raw_evidence_total = cluster_total
        build_unknown_outputs = True
        cluster_members = old_cluster_members
        pii_value_risk_matrix_path = None
        progress_every = old_progress_every
        write_person_evidence = bool(old_write_person_evidence)
        cluster_total = old_cluster_total
        linked_evidence_total = old_linked_evidence_total
        raw_evidence_total = old_raw_evidence_total

    people, anchor_to_people, person_headers = load_person_table(person_table_path)
    exposure = {
        person_id: {
            "files": set(),
            "categories": set(),
            "anchors": set(),
            "clusters": set(),
            "unclustered_count": 0,
            "raw_evidence_count": 0,
            "count": 0,
        }
        for person_id in people
    }
    exposure_rows = []
    exposure_by_person = {}
    unknown_cluster_rows = []
    unknown_summary_rows = []
    unknown_summary_states = {}
    unknown_identity_by_strong_anchor = {}
    unknown_unclustered_strong_seen = set()
    known_evidence_assignments = {}
    unknown_evidence_assignments = {}
    cluster_rows_seen = 0
    cluster_rows_matched = 0
    excluded_linked_rows_seen = 0
    excluded_linked_rows_matched = 0
    linked_rows_seen = 0
    raw_evidence_rows_seen = 0
    raw_evidence_rows_matched = 0
    last_progress = time.time()
    if cluster_total is None:
        cluster_total = count_csv_rows(clusters_path)
    if linked_evidence_total is None:
        linked_evidence_total = count_csv_rows(linked_evidence_path)
    if raw_evidence_total is None:
        raw_evidence_total = 0

    with open(clusters_path, "r", encoding="utf-8", newline="", buffering=OUTPUT_BUFFER_SIZE) as f:
        for cluster in csv.DictReader(f):
            cluster_rows_seen += 1
            cluster_id = cluster.get("person_cluster_id", "")
            clustered_linked_rows = []
            if isinstance(cluster_members, dict):
                for linked_row in cluster_members.get(cluster_id, []):
                    linked_row = dict(linked_row)
                    linked_row["_person_cluster_id"] = cluster_id
                    clustered_linked_rows.append(linked_row)

            linked_people, link_anchor_types, link_anchor_fields = linked_people_for_record(
                cluster,
                anchor_to_people,
            )
            if not linked_people:
                if not build_unknown_outputs:
                    now = time.time()
                    if progress_every > 0 and now - last_progress >= progress_every:
                        known_output_progress(
                            "matching clusters",
                            processed=cluster_rows_seen,
                            total=cluster_total,
                            matched_clusters=cluster_rows_matched,
                            unknown_identities=len(unknown_cluster_rows),
                        )
                        last_progress = now
                    continue
                if not cluster_meets_identity_anchor(cluster):
                    continue

                unknown_cluster_row = {
                    "unknown_person_key": cluster_id,
                    "person_cluster_id": cluster_id,
                    "cluster_confidence": cluster.get("cluster_confidence", ""),
                    "risk_level": cluster.get("risk_level", ""),
                    "linked_evidence_count": cluster.get("linked_evidence_count", ""),
                    "matched_evidence_count": "",
                    "file_count": cluster.get("file_count", ""),
                    "evidence_types": cluster.get("evidence_types", ""),
                    "cluster_anchor_types": cluster.get("anchor_types", ""),
                    "identity_anchor_basis": cluster_identity_anchor_basis(cluster),
                    "cluster_anchor_values": cluster.get("anchor_values", ""),
                    "cluster_merge_keys": cluster.get("cluster_merge_keys", ""),
                    "file_paths": cluster.get("file_paths", ""),
                    "reason": "Person cluster met identity-anchor rules but did not match any configured known-person table anchor.",
                }
                unknown_cluster_rows.append(unknown_cluster_row)
                unknown_evidence_assignments[cluster_id] = {
                    "clusters": [cluster],
                    "clustered_linked_rows": clustered_linked_rows,
                    "unclustered_linked_rows": [],
                    "direct_raw_evidence_rows": [],
                }
                unknown_summary_states[cluster_id] = {
                    "unknown_person_key": cluster_id,
                    "person_cluster_id": cluster_id,
                    "cluster_confidence": cluster.get("cluster_confidence", ""),
                    "risk_level": cluster.get("risk_level", ""),
                    "linked_evidence_count": int(cluster.get("linked_evidence_count", "0") or 0),
                    "matched_evidence_count": "",
                    "file_count": int(cluster.get("file_count", "0") or 0),
                    "evidence_types": set(split_pipe_values(cluster.get("evidence_types", ""))),
                    "cluster_anchor_types": set(split_pipe_values(cluster.get("anchor_types", ""))),
                    "identity_anchor_basis": set(split_pipe_values(cluster_identity_anchor_basis(cluster))),
                    "file_paths": set(split_pipe_values(cluster.get("file_paths", ""))),
                    "reason": "Person cluster met identity-anchor rules but did not match any configured known-person table anchor.",
                }
                for strong_pair in strong_anchor_pairs_for_record(cluster):
                    unknown_identity_by_strong_anchor.setdefault(strong_pair, cluster_id)
                now = time.time()
                if progress_every > 0 and now - last_progress >= progress_every:
                    known_output_progress(
                        "matching clusters",
                        processed=cluster_rows_seen,
                        total=cluster_total,
                        matched_clusters=cluster_rows_matched,
                        unknown_identities=len(unknown_cluster_rows),
                    )
                    last_progress = now
                continue

            cluster_rows_matched += 1
            evidence_types = set(split_pipe_values(cluster.get("evidence_types", "")))
            file_paths = set(split_pipe_values(cluster.get("file_paths", "")))

            for person_id in sorted(linked_people):
                update_known_person_exposure(
                    exposure,
                    exposure_by_person,
                    person_id,
                    evidence_types,
                    file_paths,
                    link_anchor_types,
                    link_anchor_fields,
                    linked_evidence_count=int(cluster.get("linked_evidence_count", "0") or 0),
                    cluster_id=cluster_id,
                    cluster_confidence=cluster.get("cluster_confidence", ""),
                    risk_level=cluster.get("risk_level", ""),
                )
                assignment = known_evidence_assignments.setdefault(
                    person_id,
                    {
                        "person_table_row_number": people[person_id]["person_table_row_number"],
                        "clusters": [],
                        "clustered_linked_rows": [],
                        "unclustered_linked_rows": [],
                        "direct_raw_evidence_rows": [],
                    },
                )
                assignment["clusters"].append(cluster)
                assignment["clustered_linked_rows"].extend(clustered_linked_rows)

            now = time.time()
            if progress_every > 0 and now - last_progress >= progress_every:
                known_output_progress(
                    "matching clusters",
                    processed=cluster_rows_seen,
                    total=cluster_total,
                    matched_clusters=cluster_rows_matched,
                    unknown_identities=len(unknown_cluster_rows),
                )
                last_progress = now

    known_output_progress(
        "matching clusters",
        processed=cluster_rows_seen,
        total=cluster_total,
        matched_clusters=cluster_rows_matched,
        unknown_identities=len(unknown_cluster_rows),
    )
    print()
    last_progress = time.time()

    with open(linked_evidence_path, "r", encoding="utf-8", newline="", buffering=OUTPUT_BUFFER_SIZE) as f:
        for row in csv.DictReader(f):
            linked_rows_seen += 1
            if row.get("cluster_eligible") != "no":
                now = time.time()
                if progress_every > 0 and now - last_progress >= progress_every:
                    known_output_progress(
                        "reviewing linked evidence",
                        processed=linked_rows_seen,
                        total=linked_evidence_total,
                        excluded_rows=excluded_linked_rows_seen,
                        matched_rows=excluded_linked_rows_matched,
                    )
                    last_progress = now
                continue
            excluded_linked_rows_seen += 1
            linked_people, link_anchor_types, link_anchor_fields = linked_people_for_record(
                row,
                anchor_to_people,
            )
            if not linked_people:
                if not build_unknown_outputs:
                    continue
                strong_pairs = strong_anchor_pairs_for_record(row)
                if not strong_pairs:
                    continue

                linked_row = dict(row)
                row_file_path = row.get("file_path", "")
                row_evidence_types = set(split_pipe_values(row.get("evidence_types", "")))
                row_risk_level = row.get("risk_level", "")

                for evidence_type, evidence_value in strong_pairs:
                    unknown_key = unknown_identity_by_strong_anchor.get((evidence_type, evidence_value))
                    if not unknown_key:
                        unknown_key = unknown_strong_anchor_key(evidence_type, evidence_value)
                        unknown_identity_by_strong_anchor[(evidence_type, evidence_value)] = unknown_key

                    dedupe_key = (unknown_key, row_file_path, str(row.get("row_number", "")))
                    if dedupe_key in unknown_unclustered_strong_seen:
                        continue
                    unknown_unclustered_strong_seen.add(dedupe_key)

                    assignment = unknown_evidence_assignments.setdefault(
                        unknown_key,
                        {
                            "clusters": [],
                            "clustered_linked_rows": [],
                            "unclustered_linked_rows": [],
                            "direct_raw_evidence_rows": [],
                        },
                    )
                    assignment["unclustered_linked_rows"].append(linked_row)

                    state = unknown_summary_states.setdefault(
                        unknown_key,
                        {
                            "unknown_person_key": unknown_key,
                            "person_cluster_id": "",
                            "cluster_confidence": "high",
                            "risk_level": "",
                            "linked_evidence_count": 0,
                            "matched_evidence_count": "",
                            "file_count": 0,
                            "evidence_types": set(),
                            "cluster_anchor_types": set(),
                            "identity_anchor_basis": set(),
                            "file_paths": set(),
                            "reason": (
                                "Cluster-excluded linked evidence contains a configured strong identity anchor "
                                "but did not match any known-person table anchor."
                            ),
                        },
                    )
                    state["linked_evidence_count"] = int(state.get("linked_evidence_count", 0) or 0) + 1
                    if row_file_path:
                        state["file_paths"].add(row_file_path)
                    state["file_count"] = len(state["file_paths"])
                    state["evidence_types"].update(row_evidence_types)
                    state["cluster_anchor_types"].add(evidence_type)
                    state["identity_anchor_basis"].add(f"strong:{evidence_type}")
                    state["risk_level"] = strongest_risk([state.get("risk_level", ""), row_risk_level])

                continue

            excluded_linked_rows_matched += 1
            evidence_types = set(split_pipe_values(row.get("evidence_types", "")))
            file_paths = {row["file_path"]} if row.get("file_path") else set()
            for person_id in sorted(linked_people):
                update_known_person_exposure(
                    exposure,
                    exposure_by_person,
                    person_id,
                    evidence_types,
                    file_paths,
                    link_anchor_types,
                    link_anchor_fields,
                    linked_evidence_count=1,
                    risk_level=row.get("risk_level", ""),
                    unclustered=True,
                )
                assignment = known_evidence_assignments.setdefault(
                    person_id,
                    {
                        "person_table_row_number": people[person_id]["person_table_row_number"],
                        "clusters": [],
                        "clustered_linked_rows": [],
                        "unclustered_linked_rows": [],
                        "direct_raw_evidence_rows": [],
                    },
                )
                assignment["unclustered_linked_rows"].append(dict(row))

            now = time.time()
            if progress_every > 0 and now - last_progress >= progress_every:
                known_output_progress(
                    "reviewing linked evidence",
                    processed=linked_rows_seen,
                    total=linked_evidence_total,
                    excluded_rows=excluded_linked_rows_seen,
                    matched_rows=excluded_linked_rows_matched,
                )
                last_progress = now

    known_output_progress(
        "reviewing linked evidence",
        processed=linked_rows_seen,
        total=linked_evidence_total,
        excluded_rows=excluded_linked_rows_seen,
        matched_rows=excluded_linked_rows_matched,
    )
    print()
    last_progress = time.time()

    all_linked_rows = []
    for assignment in known_evidence_assignments.values():
        all_linked_rows.extend(assignment.get("clustered_linked_rows", []))
        all_linked_rows.extend(assignment.get("unclustered_linked_rows", []))
    for assignment in unknown_evidence_assignments.values():
        all_linked_rows.extend(assignment.get("clustered_linked_rows", []))
        all_linked_rows.extend(assignment.get("unclustered_linked_rows", []))

    raw_by_key = collect_atomic_evidence_for_linked_rows(evidence_dir, all_linked_rows)

    for person_id, assignment in known_evidence_assignments.items():
        entry = known_exposure_entry(exposure_by_person, person_id)
        for linked_row in assignment.get("clustered_linked_rows", []) + assignment.get("unclustered_linked_rows", []):
            add_raw_evidence_keys_to_entry(entry, raw_by_key.get(linked_row_key(linked_row), []))

    for row in iter_atomic_evidence_rows(evidence_dir):
        raw_evidence_rows_seen += 1
        linked_people, link_anchor_types, link_anchor_fields = linked_people_for_raw_evidence(row, anchor_to_people)
        if not linked_people:
            now = time.time()
            if progress_every > 0 and now - last_progress >= progress_every:
                known_output_progress(
                    "matching raw evidence",
                    processed=raw_evidence_rows_seen,
                    total=raw_evidence_total,
                    matched_rows=raw_evidence_rows_matched,
                    known_people=len(exposure_by_person),
                )
                last_progress = now
            continue

        raw_evidence_rows_matched += 1
        evidence_type = row.get("evidence_type", "")
        evidence_types = {evidence_type} if evidence_type else set()
        file_paths = {row["file_path"]} if row.get("file_path") else set()
        risk_level = exposure_risk(evidence_types)
        raw_key = raw_evidence_key(row)

        for person_id in sorted(linked_people):
            entry = known_exposure_entry(exposure_by_person, person_id)
            if raw_key in entry["matched_evidence_keys"]:
                continue
            update_known_person_exposure(
                exposure,
                exposure_by_person,
                person_id,
                evidence_types,
                file_paths,
                link_anchor_types,
                link_anchor_fields,
                linked_evidence_count=0,
                risk_level=risk_level,
                raw_evidence_count=1,
            )
            known_exposure_entry(exposure_by_person, person_id)["matched_evidence_keys"].add(raw_key)
            assignment = known_evidence_assignments.setdefault(
                person_id,
                {
                    "person_table_row_number": people[person_id]["person_table_row_number"],
                    "clusters": [],
                    "clustered_linked_rows": [],
                    "unclustered_linked_rows": [],
                    "direct_raw_evidence_rows": [],
                },
            )
            assignment.setdefault("direct_raw_evidence_rows", []).append(dict(row))

        now = time.time()
        if progress_every > 0 and now - last_progress >= progress_every:
            known_output_progress(
                "matching raw evidence",
                processed=raw_evidence_rows_seen,
                total=raw_evidence_total,
                matched_rows=raw_evidence_rows_matched,
                known_people=len(exposure_by_person),
            )
            last_progress = now

    known_output_progress(
        "matching raw evidence",
        processed=raw_evidence_rows_seen,
        total=raw_evidence_total,
        matched_rows=raw_evidence_rows_matched,
        known_people=len(exposure_by_person),
    )
    print()

    for person_id in known_evidence_assignments:
        entry = known_exposure_entry(exposure_by_person, person_id)
        # In low-memory mode cluster-member rows are not kept in RAM. Use the
        # linked evidence count as the floor, then add any direct raw-evidence
        # matches that were found by streaming the atomic evidence files.
        entry["matched_evidence_count"] = max(
            len(entry["matched_evidence_keys"]),
            int(entry.get("linked_evidence_count", 0) or 0) + int(exposure.get(person_id, {}).get("raw_evidence_count", 0) or 0),
        )

    for unknown_key in sorted(unknown_summary_states):
        state = unknown_summary_states[unknown_key]
        assignment = unknown_evidence_assignments.get(unknown_key, {})
        linked_rows = (
            assignment.get("clustered_linked_rows", [])
            + assignment.get("unclustered_linked_rows", [])
        )
        unknown_summary_rows.append(
            {
                "unknown_person_key": state.get("unknown_person_key", ""),
                "person_cluster_id": state.get("person_cluster_id", ""),
                "cluster_confidence": state.get("cluster_confidence", ""),
                "risk_level": state.get("risk_level", ""),
                "linked_evidence_count": state.get("linked_evidence_count", ""),
                "matched_evidence_count": matched_evidence_count(linked_rows, raw_by_key) if linked_rows else state.get("linked_evidence_count", ""),
                "file_count": state.get("file_count", ""),
                "evidence_types": capped_join(state.get("evidence_types", set())),
                "cluster_anchor_types": capped_join(state.get("cluster_anchor_types", set())),
                "identity_anchor_basis": capped_join(state.get("identity_anchor_basis", set())),
                "reason": state.get("reason", ""),
            }
        )

    for person_id, assignment in known_evidence_assignments.items():
        assignment.setdefault("direct_raw_evidence_rows", [])

    for person_id, assignment in unknown_evidence_assignments.items():
        assignment.setdefault("direct_raw_evidence_rows", [])

    for person_id in sorted(exposure_by_person):
        entry = exposure_by_person[person_id]
        row = person_output_row(people[person_id])
        row.update(
            {
                "person_cluster_ids": capped_join(entry["person_cluster_ids"], limit=50),
                "matched_cluster_count": len(entry["person_cluster_ids"]),
                "unclustered_linked_evidence_count": entry["unclustered_linked_evidence_count"],
                "matched_evidence_count": entry["matched_evidence_count"],
                "direct_raw_evidence_count": exposure[person_id]["raw_evidence_count"],
                "cluster_confidence": strongest_risk(entry["cluster_confidences"]),
                "risk_level": strongest_risk(entry["risk_levels"]),
                "linked_evidence_count": entry["linked_evidence_count"],
                "file_count": len(entry["file_paths"]),
                "evidence_types": capped_join(entry["evidence_types"], limit=50),
                "link_anchor_types": capped_join(entry["link_anchor_types"], limit=50),
                "link_person_table_fields": capped_join(entry["link_person_table_fields"], limit=50),
            }
        )
        exposure_rows.append(row)

    with open(known_person_exposure_path, "w", encoding="utf-8", newline="", buffering=OUTPUT_BUFFER_SIZE) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=person_output_fields(
                person_headers,
                [
                    "person_cluster_ids",
                    "matched_cluster_count",
                    "unclustered_linked_evidence_count",
                    "matched_evidence_count",
                    "direct_raw_evidence_count",
                    "cluster_confidence",
                    "risk_level",
                    "linked_evidence_count",
                    "file_count",
                    "evidence_types",
                    "link_anchor_types",
                    "link_person_table_fields",
                ],
            ),
        )
        writer.writeheader()
        writer.writerows(exposure_rows)

    write_known_person_risk_matrix(people, person_headers, exposure, risk_matrix_path)
    write_known_person_pii_value_risk_matrix(
        people,
        person_headers,
        exposure,
        known_evidence_assignments,
        pii_value_risk_matrix_path,
    )
    write_individuals_not_in_known_person_exposure(people, person_headers, exposure, not_in_exposure_path)
    if build_unknown_outputs:
        write_unknown_person_clusters(unknown_cluster_rows, unknown_person_in_dataset_clusters_path)
        write_unknown_person_in_dataset(unknown_summary_rows, unknown_person_in_dataset_path)
        write_unknown_person_risk_matrix(unknown_summary_rows, unknown_person_risk_matrix_path)
    if write_person_evidence:
        if build_unknown_outputs:
            write_person_evidence_folders(
                known_evidence_assignments,
                unknown_evidence_assignments,
                raw_by_key,
                known_person_evidence_dir,
                unknown_person_evidence_dir,
            )
        else:
            write_person_evidence_folders(
                known_evidence_assignments,
                {},
                raw_by_key,
                known_person_evidence_dir,
                unknown_person_evidence_dir,
            )

    linked_people_count = sum(
        1
        for row in exposure.values()
        if row["clusters"] or row["unclustered_count"] or row["raw_evidence_count"]
    )
    unmatched_count = len(people) - linked_people_count
    return linked_people_count, len(exposure_rows), unmatched_count, len(unknown_summary_rows), len(unknown_cluster_rows)



# =============================================================================
# Direct-streaming pipeline: no SQLite, no dedupe, no resume/rerun.
# =============================================================================

PIPELINE_FORMAT_VERSION = "streaming-1"
DEFAULT_AUTO_WORKERS = 8
LARGE_FILE_BYTES = 50 * 1024 * 1024
DEFAULT_SCAN_UNIT_RECORDS = 1000
