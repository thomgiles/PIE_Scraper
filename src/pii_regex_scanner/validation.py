"""Validation, normalisation, email suffix handling, name/address assembly helpers.

This module is loaded into pii_regex_scanner.pipeline's shared namespace.
"""


@dataclass
class ExtractedText:
    text: str
    extraction_method: str


def digits_only(value):
    return re.sub(r"\D", "", value or "")


def numeric_identifier_has_plain_shape(value):
    """Reject numbers rendered as floats/scientific notation or phone-like groups."""
    text = safe_cell(value)
    if re.search(r"[A-Za-z]", text):
        return False
    if re.search(r"\d\s*[eE]\s*[+-]?\s*\d", text):
        return False
    if "." in text or "," in text or "|" in text:
        return False
    if re.search(r"^\s*\+", text):
        return False
    if re.search(r"^\s*0\d{1,3}\s+0?\d", text):
        return False
    return True


def date_within_last_100_years(year, month, day):
    try:
        candidate = date(int(year), int(month), int(day))
    except (TypeError, ValueError):
        return False

    today = date.today()
    try:
        earliest = today.replace(year=today.year - 100)
    except ValueError:
        earliest = today.replace(year=today.year - 100, day=28)
    return earliest <= candidate <= today


def valid_luhn(value):
    if not numeric_identifier_has_plain_shape(value):
        return False
    digits = digits_only(value)
    if not 13 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:
        return False

    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        digit = int(char)
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def valid_nhs_number(value):
    if not numeric_identifier_has_plain_shape(value):
        return False
    digits = digits_only(value)
    if len(digits) != 10 or len(set(digits)) == 1:
        return False

    total = sum(int(digit) * weight for digit, weight in zip(digits[:9], range(10, 1, -1)))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    if check == 10:
        return False
    return check == int(digits[-1])


def valid_ucas_personal_id(value):
    if not numeric_identifier_has_plain_shape(value):
        return False
    return len(digits_only(value)) == 10


def valid_saturn_id(value):
    if not numeric_identifier_has_plain_shape(value):
        return False
    digits = digits_only(value)
    return len(digits) in {7, 8} and len(set(digits)) > 1


def valid_cas_number(value):
    value = str(value or "").strip()
    return bool(
        re.fullmatch(r"[A-Z0-9]{14}", value)
        and re.search(r"[A-Z]", value)
        and re.search(r"\d", value)
    )


def valid_husid_entry_year(value):
    if not numeric_identifier_has_plain_shape(value):
        return False
    digits = digits_only(value)
    if len(digits) != 13:
        return False

    two_digit_year = int(digits[:2])
    current_year = date.today().year
    candidate_years = (1900 + two_digit_year, 2000 + two_digit_year)
    return any(current_year - 100 <= year <= current_year for year in candidate_years)


def valid_uk_driving_licence(value):
    compact = re.sub(r"\s+", "", value or "").upper()
    if not re.fullmatch(r"[A-Z9]{5}\d{6}[A-Z9]{2}[A-Z0-9]{3}", compact):
        return False

    year = compact[5] + compact[10]
    encoded_month = int(compact[6:8])
    if 51 <= encoded_month <= 62:
        month = encoded_month - 50
    elif 1 <= encoded_month <= 12:
        month = encoded_month
    else:
        return False
    day = int(compact[8:10])

    return any(
        date_within_last_100_years(century + int(year), month, day)
        for century in (1900, 2000)
    )


def valid_bare_8_digit_id(value):
    digits = digits_only(value)
    if len(digits) != 8 or len(set(digits)) == 1:
        return False

    year_first = int(digits[:4])
    year_last = int(digits[-4:])
    month_mid = int(digits[4:6])
    day_last = int(digits[6:8])
    day_first = int(digits[:2])
    month_second = int(digits[2:4])

    if 1900 <= year_first <= 2099 and 1 <= month_mid <= 12 and 1 <= day_last <= 31:
        return False
    if 1900 <= year_last <= 2099 and 1 <= month_second <= 12 and 1 <= day_first <= 31:
        return False
    if digits in {"12345678", "87654321"}:
        return False
    return True


def valid_uk_postcode(value):
    compact = re.sub(r"\s+", "", value or "").upper()
    return bool(
        re.fullmatch(
            r"(?:GIR0AA|[A-PR-UWYZ][A-HK-Y]?\d[A-HJKPSTUW\d]?\d[ABD-HJLNP-UW-Z]{2})",
            compact,
        )
    )


UK_POSTCODE_RE = re.compile(
    r"\b(?:GIR\s?0AA|[A-PR-UWYZ][A-HK-Y]?\d[A-HJKPSTUW\d]?\s?\d[ABD-HJLNP-UW-Z]{2})\b",
    re.IGNORECASE,
)

ADDRESS_STREET_TERMS = {
    "avenue",
    "av",
    "boulevard",
    "bvd",
    "close",
    "court",
    "crescent",
    "cres",
    "drive",
    "dr",
    "gardens",
    "gate",
    "grove",
    "lane",
    "ln",
    "mews",
    "park",
    "place",
    "pl",
    "road",
    "rd",
    "row",
    "square",
    "sq",
    "street",
    "st",
    "terrace",
    "way",
}


def canonical_uk_postcode(value):
    compact = re.sub(r"\s+", "", value or "").upper()
    if not valid_uk_postcode(compact):
        return ""
    return f"{compact[:-3]} {compact[-3:]}"


def normalize_address_value(value):
    return re.sub(r"[^A-Z0-9]+", "", value or "", flags=re.IGNORECASE).upper()


NAME_TITLES_RE = re.compile(
    r"^(?:(?:mr|mrs|ms|miss|mx|dr|prof|professor|sir|dame|lord|lady)\.?\s+)+",
    re.IGNORECASE,
)
INVALID_NAME_VALUES = {"", "n/a", "na", "none", "null", "not known", "unknown"}


# Headers/values that contain the word "name" but do not describe the
# subject person's own name. This stops school/course/department/etc. names
# from being emitted as Name evidence by the code-derived name assembler.
NON_PERSON_NAME_HEADER_TOKENS = {
    "school", "course", "programme", "program", "module", "subject",
    "country", "nationality", "citizenship", "domicile", "nation",
    "faculty", "department", "college", "university", "institution",
    "institute", "organisation", "organization", "org", "company",
    "business", "service", "services", "team", "unit", "division",
    "directorate", "centre", "center", "campus", "site", "location",
    "building", "room", "role", "job", "title", "position", "post",
    "pool", "panel", "committee", "category", "type", "status",
    "code", "description", "project", "research", "study", "award",
    "qualification", "degree", "class", "route", "pathway", "plan",
    "scheme", "manager", "supervisor", "tutor", "mentor", "reviewer",
    "assessor", "lead", "dean", "head", "coordinator", "contact",
    "emergency", "next", "kin",
    "address", "addr", "postcode", "postal", "street", "road",
    "avenue", "lane", "drive", "flat", "house", "building",
}

PERSON_SUBJECT_NAME_HEADER_TOKENS = {
    "person", "individual", "applicant", "candidate", "student",
    "pupil", "learner", "staff", "employee", "worker", "user",
    "patient", "resident", "customer", "client", "participant",
}

GENERIC_FULL_NAME_SLUGS = {
    "name", "full_name", "fullname", "person_name", "individual_name",
    "applicant_name", "candidate_name", "student_name", "pupil_name",
    "learner_name", "staff_name", "employee_name", "worker_name",
    "user_name", "patient_name", "resident_name", "customer_name",
    "client_name", "participant_name", "preferred_name", "known_as",
    "legal_name", "legalname", "birth_name", "birthname", "maiden_name", "maidenname",
    "previous_name", "previousname", "former_name", "formername", "display_name", "displayname",
}

# These can appear as the final component of a structured/XML path, e.g.
# records.record.birthName -> records_record_birthname.  Deliberately exclude
# the bare suffix "name", otherwise fields such as first_name/last_name would
# be misclassified as full-name fields.
GENERIC_FULL_NAME_SUFFIX_SLUGS = {
    slug for slug in GENERIC_FULL_NAME_SLUGS if slug not in {"name"}
}

PERSON_CONTEXT_HEADER_TOKENS = {
    "email", "mail", "e_mail", "dob", "birth", "date_of_birth",
    "student", "staff", "employee", "person", "individual",
    "applicant", "candidate", "user", "patient", "pupil", "learner",
    "passport", "phone", "telephone", "mobile", "nhs", "national",
    "insurance", "ni", "cas", "husid", "slc", "ssn", "id",
    "identifier", "number",
}

NON_PERSON_NAME_VALUE_TERMS = {
    "school", "course", "programme", "program", "module", "faculty",
    "country", "nationality", "citizenship", "domicile", "nation",
    "department", "university", "college", "institution", "institute",
    "centre", "center", "campus", "service", "services", "team",
    "unit", "division", "directorate", "office", "committee", "panel",
    "project", "research", "study", "degree", "qualification",
    "certificate", "diploma", "pathway", "route", "award", "role",
    "job", "position", "group", "address", "postcode", "postal",
    "street", "road", "avenue", "lane", "drive", "flat", "house",
    "building",
}


def header_slug_tokens(header):
    slug = rule_slug(header)
    return [token for token in slug.split("_") if token]


def is_non_person_name_header(header):
    tokens = set(header_slug_tokens(header))
    if not tokens:
        return False
    if not ({"name", "fullname"} & tokens or str(header or "").casefold().strip() == "name"):
        return False
    return bool(tokens & NON_PERSON_NAME_HEADER_TOKENS)


def header_label_looks_like_free_text(header):
    """Return True when a supposed header is probably a data value or prompt.

    Real source-system labels can be long when they are structured paths, for
    example `Root.Person.Contact.EMAIL_ADDR`. Those should still be resolved.
    This guard is aimed at malformed/headerless CSVs where an essay sentence or
    questionnaire prompt has been promoted to "header" and then accidentally
    triggers words such as gender, religion, country, or student.
    """
    header = safe_cell(header)
    if not header:
        return False
    if "." in header and not re.search(r"\s", header):
        return False
    words = re.findall(r"[A-Za-z]{2,}", header)
    if len(header) >= 80 and len(words) >= 10:
        return True
    if len(header) >= 120 and len(words) >= 14:
        return True
    if "?" in header and len(header) >= 60 and len(words) >= 8:
        return True
    if "?" in header and len(words) >= 5:
        return True
    sentence_marks = sum(header.count(mark) for mark in ".!?;:")
    if sentence_marks >= 2 and len(words) >= 12:
        return True
    return False


def is_subject_person_name_header(header):
    slug = rule_slug(header)
    tokens = set(header_slug_tokens(header))
    if not slug:
        return False
    if slug in GENERIC_FULL_NAME_SLUGS:
        return True
    return bool(tokens & PERSON_SUBJECT_NAME_HEADER_TOKENS)


def is_generic_full_name_header(header):
    slug = rule_slug(header)
    return slug in {"name", "full_name", "fullname", "display_name", "preferred_name", "known_as"}


def row_has_person_name_context(fields):
    for header, value, metadata in fields:
        header = safe_cell(header)
        value = safe_cell(value)
        if not header and not value:
            continue
        if is_non_person_name_header(header):
            continue
        slug = rule_slug(header)
        tokens = set(header_slug_tokens(header))
        resolved = resolve_table_header(header)
        if resolved in {"email", "DOB", "student id", "passport", "phone"}:
            return True
        if tokens & PERSON_CONTEXT_HEADER_TOKENS:
            return True
        if "@" in value:
            return True
    return False


def looks_like_non_person_name_value(value):
    value = clean_name_value(value)
    if not value:
        return False
    lower = value.casefold()
    if UK_POSTCODE_RE.search(value):
        return True
    if has_searchable_address_component(value) and re.search(
        r"\b(?:flat|house|building|room|street|st|road|rd|avenue|ave|drive|dr|lane|ln|close|court|crescent|grove|mews|terrace|way|postcode|address)\b",
        lower,
    ):
        return True
    if re.search(r"\b(?:school|faculty|department|college|university|institute|institution|centre|center)\s+of\b", lower):
        return True
    if re.search(r"\b(?:country|nationality|citizenship|domicile|course|programme|program|module|degree|qualification|certificate|diploma|pathway|route)\b", lower):
        return True
    words = set(re.findall(r"[a-z][a-z']+", lower))
    return bool(words & NON_PERSON_NAME_VALUE_TERMS)



def clean_name_value(value):
    value = safe_cell(value).strip(" ,;|/")
    value = NAME_TITLES_RE.sub("", value)
    if value.count(",") == 1:
        last, first = (part.strip() for part in value.split(",", 1))
        if first and last:
            value = f"{first} {last}"
    return safe_cell(value)


def normalize_name_value(value, already_clean=False):
    value = (value if already_clean else clean_name_value(value)).casefold()
    value = value.replace("\u2019", "'").replace("\u2018", "'")
    return re.sub(r"\s+", " ", value).strip()


def valid_name_value(value, require_full_name=True, already_clean=False):
    value = value if already_clean else clean_name_value(value)
    if value.casefold() in INVALID_NAME_VALUES or len(value) > 120:
        return False
    if looks_like_non_person_name_value(value):
        return False
    if any(char.isdigit() for char in value) or "@" in value:
        return False
    if any(not (char.isalpha() or char in " .'-") for char in value):
        return False
    words = [word for word in value.split() if any(char.isalpha() for char in word)]
    return len(words) >= (2 if require_full_name else 1)


def split_name_values(value, require_full_name=False):
    parts = re.split(r"\s*(?:;|\||\s/\s)\s*", safe_cell(value))
    values = []
    seen = set()
    for part in parts:
        cleaned = clean_name_value(part)
        normalized = normalize_name_value(cleaned, already_clean=True)
        if not normalized or normalized in seen or not valid_name_value(
            cleaned, require_full_name, already_clean=True
        ):
            continue
        seen.add(normalized)
        values.append(cleaned)
    return values


def pair_name_parts(first_names, last_names):
    first_names = [name for value in first_names for name in split_name_values(value)]
    last_names = [name for value in last_names for name in split_name_values(value)]
    if not first_names or not last_names:
        return []
    if len(first_names) == len(last_names):
        pairs = zip(first_names, last_names)
    elif len(last_names) == 1:
        pairs = ((first, last_names[0]) for first in first_names)
    elif len(first_names) == 1:
        pairs = ((first_names[0], last) for last in last_names)
    else:
        return []
    return [f"{first} {last}" for first, last in pairs]


def name_match(value, confidence="high"):
    value = clean_name_value(value)
    if not valid_name_value(value, require_full_name=True, already_clean=True):
        return None
    return {
        "matched_text": value,
        "normalized_value": normalize_name_value(value, already_clean=True),
        "confidence": confidence,
    }


def name_header_group(header, name_part):
    slug = rule_slug(header)
    suffixes = {
        "first": ("first_name", "firstname", "forename", "given_name", "givenname"),
        "last": ("last_name", "lastname", "surname", "family_name", "familyname"),
    }
    for suffix in suffixes.get(name_part, ()):
        if slug == suffix:
            return "default"
        if slug.endswith("_" + suffix):
            return slug[: -(len(suffix) + 1)] or "default"
    return "default"


def name_part_for_header(header, metadata=None):
    metadata = metadata or {}
    if is_non_person_name_header(header):
        return ""
    if metadata.get("name_part") in {"first", "last"}:
        return metadata["name_part"]
    slug = rule_slug(header)
    if slug.endswith(("first_name", "firstname", "forename", "given_name", "givenname")):
        return "first"
    if slug.endswith(("last_name", "lastname", "surname", "family_name", "familyname")):
        return "last"
    return ""


def is_full_name_header(header):
    if is_non_person_name_header(header):
        return False
    resolved = resolve_table_header(header)
    slug = rule_slug(header)
    if slug in GENERIC_FULL_NAME_SLUGS:
        return True
    if any(slug.endswith("_" + generic_slug) for generic_slug in GENERIC_FULL_NAME_SUFFIX_SLUGS):
        return True
    if resolved == "full name":
        return is_subject_person_name_header(header) or is_generic_full_name_header(header)
    return slug.endswith(("full_name", "fullname")) and is_subject_person_name_header(header)


def assembled_names_from_fields(fields):
    names = []
    seen = set()
    grouped_parts = defaultdict(lambda: {"first": [], "last": []})
    allow_generic_full_names = row_has_person_name_context(fields)

    for header, value, metadata in fields:
        if is_non_person_name_header(header):
            continue
        name_part = metadata.get("_name_part") or name_part_for_header(header, metadata)
        is_full_name = metadata.get("_is_full_name")
        if is_full_name is None:
            is_full_name = is_full_name_header(header)
        if is_full_name:
            if is_generic_full_name_header(header) and not allow_generic_full_names:
                continue
            for full_name in split_name_values(value, require_full_name=True):
                match = name_match(full_name)
                if match and match["normalized_value"] not in seen:
                    seen.add(match["normalized_value"])
                    names.append(match)
        elif name_part in {"first", "last"}:
            group = metadata.get("_name_group") or name_header_group(header, name_part)
            grouped_parts[group][name_part].append(value)

    for parts in grouped_parts.values():
        for full_name in pair_name_parts(parts["first"], parts["last"]):
            match = name_match(full_name)
            if match and match["normalized_value"] not in seen:
                seen.add(match["normalized_value"])
                names.append(match)
    return names


def assembled_names_from_labelled_line(line, labelled_fields=None):
    labelled_fields = labelled_fields if labelled_fields is not None else labelled_fields_from_line(line)
    fields = [
        (header, value, table_header_assembly_metadata(header))
        for header, value in labelled_fields
    ]
    return assembled_names_from_fields(fields)


def address_header_role(header):
    slug = rule_slug(header)
    if not slug:
        return ""
    if slug in {"postcode", "post_code", "postal_code", "zip", "zip_code"}:
        return "postcode"
    if "postcode" in slug or "postal_code" in slug or "post_code" in slug:
        return "postcode"
    if slug in {"town", "city", "county", "locality"} or slug.endswith(("_town", "_city", "_county", "_locality")):
        return "locality"
    if (
        slug.startswith("address")
        or slug.startswith("addr")
        or slug in {"street", "road", "avenue"}
        or slug.endswith("_address")
        or slug.endswith("_addr")
    ):
        return "address"
    return ""


def table_header_assembly_metadata(header):
    """Return cached name/address classification for a labelled field header."""
    header = safe_cell(header)
    cached = TABLE_HEADER_ASSEMBLY_CACHE.get(header)
    if cached is not None:
        return cached

    metadata = resolve_table_header_metadata(header)
    name_part = name_part_for_header(header, metadata)
    metadata.update({
        "_name_part": name_part,
        "_is_full_name": is_full_name_header(header),
        "_name_group": name_header_group(header, name_part) if name_part else "",
        "_address_role": address_header_role(header),
    })
    if len(TABLE_HEADER_ASSEMBLY_CACHE) >= 1024:
        TABLE_HEADER_ASSEMBLY_CACHE.clear()
    TABLE_HEADER_ASSEMBLY_CACHE[header] = metadata
    return metadata


def has_searchable_address_component(value):
    value = safe_cell(value)
    if not value:
        return False
    lower = value.lower()
    if any(re.search(rf"\b{re.escape(term)}\b", lower) for term in ADDRESS_STREET_TERMS):
        return True
    if re.search(r"\b\d{1,5}\s+[A-Za-z][A-Za-z'.-]{2,}", value):
        return True
    words = re.findall(r"[A-Za-z][A-Za-z'.-]{2,}", value)
    return len(words) >= 2


def clean_address_component(value):
    value = safe_cell(value)
    value = UK_POSTCODE_RE.sub("", value)
    value = re.sub(r"\b(?:address|addr|postcode|postal\s*code|post\s*code)\b\s*[:=#-]?", "", value, flags=re.IGNORECASE)
    value = re.sub(r"\s*,\s*", ", ", value)
    return safe_cell(value.strip(" ,;-"))


def assembled_address_from_components(components, postcodes):
    components = [clean_address_component(component) for component in components]
    components = [component for component in components if component]
    postcodes = [canonical_uk_postcode(postcode) for postcode in postcodes]
    postcodes = [postcode for postcode in postcodes if postcode]
    if not postcodes or not components:
        return None
    if not any(has_searchable_address_component(component) for component in components):
        return None

    deduped_components = []
    seen = set()
    for component in components:
        key = normalize_address_value(component)
        if key and key not in seen:
            seen.add(key)
            deduped_components.append(component)

    postcode = postcodes[0]
    matched_text = ", ".join(deduped_components + [postcode])
    confidence = "high" if any(has_searchable_address_component(component) for component in deduped_components) else "medium"
    return {
        "matched_text": matched_text,
        "normalized_value": normalize_address_value(matched_text),
        "postcode": postcode,
        "confidence": confidence,
    }


def labelled_fields_from_line(line):
    fields = []
    for part in line.split("|"):
        if ":" not in part:
            continue
        header, value = part.split(":", 1)
        header = re.sub(r"^TABLE_ROW\s+.*?#\d+\s*", "", header).strip()
        header = re.sub(r"^-+\s*TABLE:.*?-+\s*", "", header).strip()
        header = safe_cell(header)
        value = safe_cell(value)
        if header and value:
            fields.append((header, value))
    return fields


def add_assembled_address(addresses, seen, components, postcode):
    address = assembled_address_from_components(components, [postcode])
    if address is None:
        return
    key = address["normalized_value"]
    if key in seen:
        return
    seen.add(key)
    addresses.append(address)


def assembled_addresses_from_labelled_line(line, labelled_fields=None):
    """Return separately assembled addresses from a labelled table/record line.

    The scanner converts tables, Excel sheets, CSV/TSV rows, and structured
    JSON/XML/YAML records into pipe-delimited `label: value` lines. Older
    versions collapsed every address-looking field and every postcode in a line
    into one synthetic address. That produced misleading composite addresses
    when a row contained both home and term-time/current addresses.

    This function keeps the row-level linkage but emits one Address evidence
    record per address/postcode group. A postcode closes the current group; the
    next address-like field starts a new group. Rows with several addresses
    therefore become several evidence values attached to the same source row,
    rather than one merged address that never existed in the source data.
    """
    addresses = []
    seen = set()
    components = []

    labelled_fields = labelled_fields if labelled_fields is not None else labelled_fields_from_line(line)
    for header, value in labelled_fields:
        role = table_header_assembly_metadata(header)["_address_role"]
        if role not in {"address", "locality", "postcode"}:
            continue

        value_postcodes = UK_POSTCODE_RE.findall(value)

        if role in {"address", "locality"}:
            components.append(value)
            if value_postcodes:
                for postcode in value_postcodes:
                    add_assembled_address(addresses, seen, components, postcode)
                components = []
            continue

        if role == "postcode" and value_postcodes:
            for postcode in value_postcodes:
                add_assembled_address(addresses, seen, components, postcode)
            components = []

    return addresses



def valid_contextual_date(value):
    value = (value or "").strip()
    cached = VALID_CONTEXTUAL_DATE_CACHE.get(value)
    if cached is not None:
        return cached

    for pattern in ("%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d/%m/%y", "%d-%m-%y"):
        try:
            parsed = time.strptime(value, pattern)
        except ValueError:
            continue
        result = date_within_last_100_years(parsed.tm_year, parsed.tm_mon, parsed.tm_mday)
        break
    else:
        result = False

    if len(VALID_CONTEXTUAL_DATE_CACHE) >= 4096:
        VALID_CONTEXTUAL_DATE_CACHE.clear()
    VALID_CONTEXTUAL_DATE_CACHE[value] = result
    return result


def valid_passport_like(value):
    compact = re.sub(r"[^A-Z0-9]", "", value or "", flags=re.IGNORECASE).upper()
    if not 6 <= len(compact) <= 12:
        return False
    if compact in {"APPROVED", "PENDING", "UPLOADED", "REJECTED", "EXPIRED", "REQUIRED"}:
        return False
    return any(char.isdigit() for char in compact)


def valid_china_national_id(value):
    compact = re.sub(r"\s+", "", value or "").upper()
    if not re.fullmatch(r"[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dX]", compact):
        return False

    # Validate embedded date.
    date_part = compact[6:14]
    try:
        parsed_date = time.strptime(date_part, "%Y%m%d")
    except ValueError:
        return False
    if not date_within_last_100_years(parsed_date.tm_year, parsed_date.tm_mon, parsed_date.tm_mday):
        return False

    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    checks = "10X98765432"
    total = sum(int(digit) * weight for digit, weight in zip(compact[:17], weights))
    return compact[-1] == checks[total % 11]


def valid_orcid(value):
    compact = re.sub(r"[^0-9X]", "", value or "", flags=re.IGNORECASE).upper()
    if len(compact) != 16:
        return False
    total = 0
    for char in compact[:15]:
        total = (total + int(char)) * 2
    remainder = total % 11
    result = (12 - remainder) % 11
    check = "X" if result == 10 else str(result)
    return compact[-1] == check


def valid_uk_phone_rough(value):
    digits = digits_only(value)
    if digits.startswith("44"):
        digits = "0" + digits[2:]
    if len(digits) not in {10, 11}:
        return False
    if len(set(digits)) == 1:
        return False
    return digits.startswith("0")


def valid_uk_national_insurance_number(value):
    compact = re.sub(r"\s+", "", value or "").upper()
    if not re.fullmatch(
        r"(?!BG|GB|KN|NK|NT|TN|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\d{6}[A-D]",
        compact,
    ):
        return False
    digits = compact[2:8]
    return len(set(digits)) > 1


SENSITIVE_VALUE_FALSE_MARKERS = {
    "n", "no", "false", "0", "none", "nil", "not disabled",
    "no disability", "no disabilities", "no known disability",
    "no known disabilities", "not applicable", "n/a", "na",
    "not specified", "not known", "unknown", "missing",
}

SENSITIVE_VALUE_TRUE_MARKERS = {
    "y", "yes", "true", "1", "disabled", "declared",
    "declared disability", "has disability", "disability declared",
}

SENSITIVE_VALUE_BAD_TERMS = {
    "address", "appointment", "assessment", "bank", "building", "campus",
    "cas", "city", "comment", "course", "department", "email", "evidence",
    "faculty", "fee", "finance", "module", "note", "passport", "payment",
    "phone", "postcode", "programme", "program", "record", "reference",
    "school", "staff", "student", "support plan", "telephone", "visa",
}

RELIGION_VALUE_TERMS = {
    "agnostic",
    "atheist",
    "buddhist",
    "buddhism",
    "christian",
    "christianity",
    "hindu",
    "hinduism",
    "jewish",
    "judaism",
    "muslim",
    "islam",
    "no religion",
    "none",
    "other religion",
    "any other religion",
    "pagan",
    "sikh",
    "sikhism",
}

SUPPORT_NEGATIVE_MARKERS = {
    "n", "no", "false", "0", "0.0", "none", "nil", "not applicable",
    "n/a", "na", "not known", "unknown", "missing",
}

SUPPORT_POSITIVE_MARKERS = {
    "y", "yes", "true", "1", "approved", "declared", "eligible", "received", "awarded",
}


def valid_positive_indicator_value(value):
    folded = sensitive_value_clean_text(value).casefold()
    return folded in SUPPORT_POSITIVE_MARKERS


def valid_positive_amount_value(value):
    cleaned = sensitive_value_clean_text(value)
    folded = cleaned.casefold()
    if folded in SUPPORT_NEGATIVE_MARKERS:
        return False
    if folded in SUPPORT_POSITIVE_MARKERS:
        return True
    if "|" in cleaned:
        return any(valid_positive_amount_value(part) for part in cleaned.split("|"))
    numeric = re.sub(r"[£$,\s]", "", cleaned)
    if re.fullmatch(r"\d+(?:\.\d+)?", numeric):
        try:
            return float(numeric) > 0
        except ValueError:
            return False
    return False


def valid_positive_count_value(value):
    cleaned = sensitive_value_clean_text(value)
    folded = cleaned.casefold()
    if folded in SUPPORT_NEGATIVE_MARKERS:
        return False
    if "|" in cleaned:
        return any(valid_positive_count_value(part) for part in cleaned.split("|"))
    if re.fullmatch(r"\d+", cleaned):
        return int(cleaned) > 0
    return False

DISABILITY_VALUE_TERMS = {
    "adhd",
    "adjustment",
    "asperger",
    "attention deficit",
    "autism",
    "autistic",
    "blind",
    "deaf",
    "disab",
    "dyslexia",
    "dyspraxia",
    "hearing impairment",
    "impairment",
    "learning difficulty",
    "learning disability",
    "medical condition",
    "mental health",
    "mobility",
    "neurodiv",
    "physical impairment",
    "reasonable adjustment",
    "social communication",
    "specific learning",
    "visual impairment",
    "wheelchair",
}


def sensitive_value_clean_text(value):
    return re.sub(r"\s+", " ", safe_cell(value)).strip()


def sensitive_value_has_bad_shape(value, max_length=80, max_words=8):
    cleaned = sensitive_value_clean_text(value)
    folded = cleaned.casefold()
    if not cleaned or len(cleaned) > max_length:
        return True
    if "@" in cleaned or re.search(r"https?://|www\.", cleaned, re.IGNORECASE):
        return True
    if re.search(r"[{}\[\]<>]", cleaned):
        return True
    if len(re.findall(r"\d", cleaned)) > 2:
        return True
    if len(re.findall(r"[A-Za-z]+", cleaned)) > max_words:
        return True
    if any(term in folded for term in SENSITIVE_VALUE_BAD_TERMS):
        return True
    return False


def valid_religion_value(value):
    cleaned = sensitive_value_clean_text(value)
    folded = cleaned.casefold()
    if folded in SENSITIVE_VALUE_TRUE_MARKERS:
        return False
    if folded in SENSITIVE_VALUE_FALSE_MARKERS:
        return folded in RELIGION_VALUE_TERMS
    if sensitive_value_has_bad_shape(cleaned, max_length=60, max_words=6):
        return False
    if not re.search(r"[A-Za-z]", cleaned):
        return False
    return folded in RELIGION_VALUE_TERMS


def valid_ethnicity_value(value):
    cleaned = sensitive_value_clean_text(value)
    folded = cleaned.casefold()
    if folded in SENSITIVE_VALUE_FALSE_MARKERS or folded in SENSITIVE_VALUE_TRUE_MARKERS:
        return False
    if sensitive_value_has_bad_shape(cleaned, max_length=80, max_words=10):
        return False
    if not re.search(r"[A-Za-z]", cleaned):
        return False
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z '&,/()\-]{1,79}", cleaned))


def valid_citizenship_country_value(value):
    cleaned = sensitive_value_clean_text(value)
    folded = cleaned.casefold()
    if folded in SENSITIVE_VALUE_FALSE_MARKERS or folded in SENSITIVE_VALUE_TRUE_MARKERS:
        return False
    if folded in {
        "uk - home",
        "uk-home",
        "uk home",
        "uk - international",
        "uk-international",
        "uk international",
        "home",
        "international",
        "homuk",
        "class enrolment",
        "europe",
        "european",
        "eu",
        "england",
        "wales",
        "scotland",
        "northern ireland",
    }:
        return False
    if re.search(r"\b(?:home|international|enrolment|enrollment|fee|fees|tuition|class)\b", folded):
        return False
    if " | " in cleaned or "|" in cleaned:
        return False
    if sensitive_value_has_bad_shape(cleaned, max_length=60, max_words=5):
        return False
    if not re.search(r"[A-Za-z]", cleaned):
        return False
    return bool(re.fullmatch(r"[A-Za-z][A-Za-z .,'()\-]{1,59}", cleaned))


@lru_cache(maxsize=1)
def citizenship_country_aliases():
    """Return local country/nationality aliases keyed to canonical country names."""
    aliases = {}

    def add_alias(raw_value, canonical):
        raw_value = sensitive_value_clean_text(raw_value)
        canonical = sensitive_value_clean_text(canonical)
        if not raw_value or not canonical:
            return
        aliases[profile_vocab_term_text(raw_value) if "profile_vocab_term_text" in globals() else raw_value.casefold()] = canonical
        aliases[raw_value.casefold()] = canonical

    resources_dir = SCRIPT_DIR / "resources" / "vocabularies"
    seed_path = resources_dir / "country_name_and_nationality_seed.json"
    try:
        with open(seed_path, "r", encoding="utf-8") as handle:
            seed = json.load(handle)
    except Exception:
        seed = {}
    for entry in seed.get("entries", []):
        canonical = entry.get("country", "")
        add_alias(canonical, canonical)
        for alias in entry.get("aliases", []):
            add_alias(alias, canonical)

    names_path = resources_dir / "country_names_babel_en.json"
    try:
        with open(names_path, "r", encoding="utf-8") as handle:
            names = json.load(handle)
    except Exception:
        names = {}
    for entry in names.get("entries", []):
        name = entry.get("name", "")
        add_alias(name, name)
        code = entry.get("alpha_2") or entry.get("alpha2") or entry.get("code")
        if code:
            add_alias(code, name)
        code = entry.get("alpha_3") or entry.get("alpha3")
        if code:
            add_alias(code, name)

    # Common aliases/codes seen in education exports.  These are only
    # normalization aliases; validation still rejects regional/admin values.
    for alias, canonical in {
        "UK": "United Kingdom",
        "GB": "United Kingdom",
        "GBR": "United Kingdom",
        "U.K.": "United Kingdom",
        "PRC": "China",
        "CHN": "China",
        "KOR": "South Korea",
        "ROK": "South Korea",
        "USA": "United States",
        "US": "United States",
    }.items():
        add_alias(alias, canonical)
    return aliases


def normalize_citizenship_country_value(value):
    """Canonicalize accepted country/nationality values when a local alias exists."""
    cleaned = sensitive_value_clean_text(value)
    if not valid_citizenship_country_value(cleaned):
        return ""
    aliases = citizenship_country_aliases()
    lookup_keys = [cleaned.casefold()]
    if "profile_vocab_term_text" in globals():
        lookup_keys.insert(0, profile_vocab_term_text(cleaned))
    for key in lookup_keys:
        canonical = aliases.get(key)
        if canonical and valid_citizenship_country_value(canonical):
            return canonical
    return cleaned


IDENTITY_DOCUMENT_FILENAME_RE = re.compile(
    r"(?:passport|travel[\s_-]*document|visa|\bbrp\b|"
    r"biometric[\s_-]*residence[\s_-]*permit|residence[\s_-]*permit|"
    r"national[\s_-]*id|identity[\s_-]*card|\bid[\s_-]*card|"
    r"driv(?:ing|er)[\s_-]*licen[cs]e|birth[\s_-]*certificate)",
    re.IGNORECASE,
)

IDENTITY_DOCUMENT_FILENAME_STOPWORDS = {
    "and", "back", "birth", "brp", "card", "certificate", "copy", "document",
    "documents", "driver", "driving", "front", "id", "identity", "licence",
    "license", "national", "nric", "of", "page", "passport", "permit", "photo",
    "residence", "scan", "travel", "visa",
}

IDENTITY_DOCUMENT_RELATIONSHIP_TERMS = {
    "father", "mother", "parent", "guardian", "sponsor", "spouse", "husband",
    "wife", "partner", "son", "daughter", "brother", "sister",
}


def valid_identity_document_file_reference(value):
    """Return True for document filenames/metadata that carry owner-name context.

    A filename such as ``passport.pdf`` says only that a document-like file is
    present.  It should not be linked to a person without OCR text or another
    person anchor.  For filename/metadata-only evidence, require a document cue
    and at least two plausible owner-name tokens in the same value.
    """
    cleaned = safe_cell(value)
    if not cleaned or not IDENTITY_DOCUMENT_FILENAME_RE.search(cleaned):
        return False
    if re.search(r"@", cleaned):
        return False

    filename = re.split(r"[\\/]", cleaned)[-1]
    filename = re.sub(r"\.[A-Za-z0-9]{1,5}$", "", filename)
    filename = re.sub(r"(?<=[a-z])(?=[A-Z])", " ", filename)
    tokens = [
        token.casefold()
        for token in re.findall(r"[A-Za-z][A-Za-z'\-]{1,}", filename)
    ]
    name_tokens = [
        token
        for token in tokens
        if token not in IDENTITY_DOCUMENT_FILENAME_STOPWORDS
        and token not in IDENTITY_DOCUMENT_RELATIONSHIP_TERMS
        and len(token) >= 2
    ]
    return len(name_tokens) >= 2


def valid_disability_value(value):
    cleaned = sensitive_value_clean_text(value)
    folded = cleaned.casefold()
    if folded in SENSITIVE_VALUE_FALSE_MARKERS:
        return False
    if folded in SENSITIVE_VALUE_TRUE_MARKERS:
        return True
    if sensitive_value_has_bad_shape(cleaned, max_length=80, max_words=8):
        return False
    if not re.search(r"[A-Za-z]", cleaned):
        return False
    if not re.fullmatch(r"[A-Za-z][A-Za-z '&,/()\-]{1,79}", cleaned):
        return False
    return any(term in folded for term in DISABILITY_VALUE_TERMS)


MARITAL_STATUS_VALUE_TERMS = {
    "single",
    "never married",
    "not married",
    "unmarried",
    "married",
    "civil partnership",
    "civil partner",
    "in a civil partnership",
    "separated",
    "married but separated",
    "divorced",
    "widowed",
    "surviving civil partner",
    "cohabiting",
    "living with partner",
    "partnered",
    "living as married",
}


def valid_marital_status_value(value):
    cleaned = sensitive_value_clean_text(value)
    folded = cleaned.casefold()
    if folded in SENSITIVE_VALUE_FALSE_MARKERS:
        return False
    if sensitive_value_has_bad_shape(cleaned, max_length=60, max_words=6):
        return False
    return folded in MARITAL_STATUS_VALUE_TERMS


CONTEXT_GUARD_KEYS = (
    "required_tokens",
    "required_phrases",
    "forbidden_tokens",
    "forbidden_phrases",
)


def semantic_label_text(label):
    text = safe_cell(label).replace(".", " ")
    text = text.replace("_", " ").replace("-", " ")
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    formatter = globals().get("nlp_header_label_text")
    if callable(formatter):
        formatted = safe_cell(formatter(text))
        if formatted:
            text = formatted
    return re.sub(r"\s+", " ", text).strip().casefold()


def semantic_label_tokens(label):
    text = semantic_label_text(label)
    slug_fn = globals().get("rule_slug")
    if callable(slug_fn):
        slug = safe_cell(slug_fn(text))
    else:
        slug = re.sub(r"[^a-z0-9]+", "_", text).strip("_")
    tokens = {token for token in slug.split("_") if token}
    if "dob" in tokens:
        tokens.update({"date", "birth"})
    return tokens


def normalize_context_guard_config(config):
    if not isinstance(config, dict):
        return {}
    normalized = {}
    for key in CONTEXT_GUARD_KEYS:
        values = config.get(key, [])
        if isinstance(values, str):
            values = [values]
        elif not isinstance(values, (list, tuple, set)):
            values = []
        cleaned = []
        seen = set()
        for value in values:
            if key.endswith("_tokens"):
                normalized_value = safe_cell(value).casefold()
            else:
                normalized_value = semantic_label_text(value)
            if not normalized_value or normalized_value in seen:
                continue
            seen.add(normalized_value)
            cleaned.append(normalized_value)
        if cleaned:
            normalized[key] = tuple(cleaned)
    return normalized


def context_guard_payload(config):
    normalized = normalize_context_guard_config(config)
    if not normalized:
        return {}
    return {
        key: list(normalized.get(key, ()))
        for key in CONTEXT_GUARD_KEYS
        if normalized.get(key)
    }


def context_guard_enabled(config):
    return bool(normalize_context_guard_config(config))


def header_context_supports_guard(header, config):
    config = normalize_context_guard_config(config)
    if not config:
        return True

    header_text = semantic_label_text(header)
    header_tokens = semantic_label_tokens(header)
    if not header_text and not header_tokens:
        return False

    for phrase in config.get("forbidden_phrases", ()):
        if phrase in header_text:
            return False
    if header_tokens & set(config.get("forbidden_tokens", ())):
        return False

    if any(phrase in header_text for phrase in config.get("required_phrases", ())):
        return True
    if header_tokens & set(config.get("required_tokens", ())):
        return True

    if globals().get("SCAN_NLP_ENABLED"):
        suggestion_fn = globals().get("nlp_header_suggestion")
        if callable(suggestion_fn):
            suggested_header, _confidence = suggestion_fn(header_text)
            suggested_tokens = semantic_label_tokens(suggested_header)
            required_tokens = set(config.get("required_tokens", ()))
            for phrase in config.get("required_phrases", ()):
                required_tokens.update(semantic_label_tokens(phrase))
            if suggested_tokens and required_tokens and suggested_tokens & required_tokens:
                return True

    return False


def normalize_email_suffix(value):
    suffix = (value or "").strip().lower()
    if suffix.startswith("@"):
        suffix = suffix[1:]
    return suffix.strip(".")


def normalize_email_suffixes(value):
    if value is None:
        return ()
    raw_values = []
    if isinstance(value, (list, tuple, set)):
        raw_values.extend(value)
    else:
        raw_values.append(value)

    suffixes = []
    seen = set()
    for raw_value in raw_values:
        for part in re.split(r"[,;]", str(raw_value or "")):
            suffix = normalize_email_suffix(part)
            if not suffix or suffix in seen:
                continue
            seen.add(suffix)
            suffixes.append(suffix)
    return tuple(suffixes)


def set_email_suffix(value):
    global EMAIL_SUFFIX
    EMAIL_SUFFIX = normalize_email_suffixes(value)


def normalize_email_wildcard_side(value):
    side = (value or "").strip().lower()
    if side.startswith("@"):
        side = side[1:]
    return side.strip(".")


def normalize_email_wildcard_rules(value):
    """Parse bidirectional email-domain equivalence rules.

    A rule such as ``@nottingham == @exmail.nottingham`` maps the same local
    part across matching domains.  Short domain prefixes are allowed, so
    ``a@nottingham.ac.uk`` is equivalent to ``a@exmail.nottingham.ac.uk``.
    """
    if value is None:
        return ()
    raw_values = []
    if isinstance(value, (list, tuple, set)):
        raw_values.extend(value)
    else:
        raw_values.append(value)

    rules = []
    seen = set()
    for raw_value in raw_values:
        for part in re.split(r"[,;]", str(raw_value or "")):
            if "==" in part:
                left, right = part.split("==", 1)
            elif "=" in part:
                left, right = part.split("=", 1)
            else:
                continue
            left = normalize_email_wildcard_side(left)
            right = normalize_email_wildcard_side(right)
            if not left or not right or left == right:
                continue
            key = tuple(sorted((left, right)))
            if key in seen:
                continue
            seen.add(key)
            rules.append((left, right))
    return tuple(rules)


def set_email_wildcards(value):
    global EMAIL_WILDCARDS
    EMAIL_WILDCARDS = normalize_email_wildcard_rules(value)


def email_domain(value):
    value = (value or "").strip().lower()
    if "@" not in value:
        return ""
    return value.rsplit("@", 1)[1].strip(".")


def email_suffix_pattern_matches_domain(pattern, domain):
    pattern = normalize_email_suffix(pattern)
    domain = normalize_email_suffix(domain)
    if not pattern or not domain:
        return False

    if "*" not in pattern:
        return domain == pattern or domain.endswith("." + pattern)

    # Wildcard suffixes are domain-boundary aware.  ``nottingham.*`` matches
    # nottingham.ac.uk and mail.nottingham.ac.uk; ``*.nottingham.ac.uk``
    # requires at least one label before nottingham.ac.uk.
    regex = re.escape(pattern).replace(r"\*", r".+")
    return bool(re.fullmatch(rf"(?:.+\.)?{regex}", domain))


def email_domain_matches_suffixes(domain, suffixes=None):
    suffixes = EMAIL_SUFFIX if suffixes is None else normalize_email_suffixes(suffixes)
    return any(email_suffix_pattern_matches_domain(suffix, domain) for suffix in suffixes)


def email_alias_domain(domain, source, target):
    domain = normalize_email_suffix(domain)
    source = normalize_email_wildcard_side(source)
    target = normalize_email_wildcard_side(target)
    if not domain or not source or not target:
        return ""
    if domain == source:
        return target
    if domain.startswith(source + "."):
        return target + domain[len(source):]
    return ""


def email_equivalent_domains(domain):
    domains = []
    seen = set()
    for candidate in [normalize_email_suffix(domain)]:
        if candidate and candidate not in seen:
            seen.add(candidate)
            domains.append(candidate)
    for left, right in globals().get("EMAIL_WILDCARDS", ()):
        for source, target in ((left, right), (right, left)):
            candidate = email_alias_domain(domain, source, target)
            if candidate and candidate not in seen:
                seen.add(candidate)
                domains.append(candidate)
    return tuple(domains)


def email_equivalent_values(value):
    value = (value or "").strip().lower()
    if "@" not in value:
        return (value,) if value else ()
    local, domain = value.rsplit("@", 1)
    local = local.strip()
    if not local:
        return ()
    values = []
    seen = set()
    for candidate_domain in email_equivalent_domains(domain):
        candidate = f"{local}@{candidate_domain}"
        if candidate not in seen:
            seen.add(candidate)
            values.append(candidate)
    return tuple(values)


def email_lookup_pairs(evidence_type, value):
    """Return all evidence-type/value lookup pairs equivalent to an email."""
    evidence_type = safe_cell(evidence_type)
    if evidence_type not in EMAIL_EVIDENCE_TYPES and evidence_type != "Email":
        normalized = normalize_value(evidence_type, value) if "normalize_value" in globals() else safe_cell(value)
        return ((evidence_type, normalized),) if evidence_type and normalized else ()

    pairs = []
    seen = set()
    for email_value in email_equivalent_values(value):
        normalized = email_value.lower()
        candidate_types = {evidence_type}
        if EMAIL_SUFFIX:
            candidate_types.add(email_evidence_type(email_value))
        else:
            candidate_types.add("Email")
        for candidate_type in candidate_types:
            if not candidate_type:
                continue
            key = (candidate_type, normalized)
            if key not in seen:
                seen.add(key)
                pairs.append(key)
    return tuple(pairs)


def email_evidence_type(value):
    if not EMAIL_SUFFIX:
        return "Email"
    if email_domain_matches_suffixes(email_domain(value)):
        return "Institutional Email"
    return "Personal Email"
