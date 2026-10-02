#!/usr/bin/env python3
"""Non-disclosive row/value overlap report for Stage 4 scanner outputs.

The email-overlap report is deliberately email-specific. This tool is broader:
it reads known-person ``*_pii_value_risk_matrix.csv`` files plus
``*not_in_list*.csv`` outputs from a scanner output directory, extracts typed
evidence values where present, builds non-raw row signatures for redacted/risk
tables, hashes these in memory, and writes count-only overlap reports.

No raw PII values are written. The hashes are used only internally unless
``--write-hash-audit`` is supplied.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import re
from collections import Counter, defaultdict
from itertools import product
from pathlib import Path


TRUNCATED_MARKER_RE = re.compile(r"^\s*\.\.\.\(\+\d+\s+more\)\s*$")
LABELLED_VALUE_RE = re.compile(r"(?P<label>[A-Za-z][A-Za-z0-9 _/()\\.-]{1,80})\s*=\s*(?P<value>[^|]+)")

KNOWN_VALUE_PREFIXES = ("has_",)
UNKNOWN_VALUE_FIELDS = (
    "cluster_anchor_values",
    "cluster_merge_keys",
    "evidence_values",
    "source_rows",
)
SIGNATURE_LIST_FIELDS = {
    "evidence_types",
    "cluster_anchor_types",
    "identity_anchor_basis",
    "link_anchor_types",
    "link_person_table_fields",
}
SIGNATURE_SCALAR_FIELDS = {
    "overall_risk_level",
    "risk_level",
    "cluster_confidence",
    "reason",
}
IGNORE_VALUES = {"", "yes", "no", "none", "null", "nan", "0"}
IGNORE_FIELDS = {
    "person_key",
    "person_table_row_number",
    "overall_risk_score",
    "overall_risk_level",
    "unknown_person_key",
    "person_cluster_id",
    "cluster_confidence",
    "risk_level",
    "linked_evidence_count",
    "matched_evidence_count",
    "file_count",
}

DEFAULT_IDENTITY_ANCHORS = {
    "strong_anchor_types": ["Email"],
    "compound_anchor_sets": [],
}


def safe_name(path: Path) -> str:
    name = path.name
    for suffix in (
        "_pii_value_risk_matrix.csv",
        "_in_dataset.csv",
        "_risk_matrix.csv",
        "_not_in_dataset.csv",
        ".csv",
    ):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name or path.stem


def normalize_label(label: str) -> str:
    label = str(label or "").strip()
    if label.startswith("has_"):
        label = label[4:]
    label = label.replace("_", " ")
    label = re.sub(r"[^A-Za-z0-9]+", " ", label)
    return re.sub(r"\s+", " ", label).strip().casefold()


def normalize_value(value: str) -> str:
    value = str(value or "").strip()
    value = value.strip("\"'")
    value = re.sub(r"\s+", " ", value)
    return value.casefold()


def token_hash(label: str, value: str) -> str:
    payload = f"{normalize_label(label)}={normalize_value(value)}"
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()


def token_category(label: str) -> str:
    category = normalize_label(label)
    aliases = {
        "email": "Email",
        "institutional email": "Institutional Email",
        "personal email": "Personal Email",
        "phone": "Phone",
        "dob": "DOB",
        "date of birth": "DOB",
        "name": "Name",
        "address": "Address",
        "passport": "Passport",
        "nhs number": "NHS Number",
        "national insurance number": "National Insurance Number",
        "cas number": "CAS Number",
        "husid": "HUSID",
        "saturn id": "Saturn ID",
        "known person identifier person id": "Known Person Identifier: Person ID",
    }
    return aliases.get(category, category.title())


def default_identity_anchors_path() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "rules" / "person_identity_anchors.json"
        if candidate.exists():
            return candidate
    return here.parents[1] / "rules" / "person_identity_anchors.json"


def load_identity_anchors(path: str | Path | None):
    path = Path(path) if path else default_identity_anchors_path()
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        payload = DEFAULT_IDENTITY_ANCHORS
    strong = payload.get("strong_anchor_types") if isinstance(payload, dict) else None
    compounds = payload.get("compound_anchor_sets") if isinstance(payload, dict) else None
    return {
        "path": str(path),
        "strong_anchor_types": [
            str(item)
            for item in (strong if isinstance(strong, list) else DEFAULT_IDENTITY_ANCHORS["strong_anchor_types"])
            if str(item).strip()
        ],
        "compound_anchor_sets": [
            [str(part) for part in item if str(part).strip()]
            for item in (compounds if isinstance(compounds, list) else [])
            if isinstance(item, list) and item
        ],
    }


def expanded_anchor_categories(anchor: str) -> list[str]:
    category = token_category(anchor)
    if category == "Email":
        return ["Email", "Institutional Email", "Personal Email"]
    return [category]


def tokens_for_anchor(by_category: dict[str, set[str]], anchor: str) -> set[str]:
    tokens = set()
    for category in expanded_anchor_categories(anchor):
        tokens.update(by_category.get(category, set()))
    return tokens


def build_person_anchor_tokens(by_category: dict[str, set[str]], identity_anchors: dict, max_compound_tokens: int) -> set[str]:
    """Build row-level person tokens from configured strong/compound anchors."""
    person_tokens = set()
    for anchor in identity_anchors.get("strong_anchor_types", []):
        person_tokens.update(tokens_for_anchor(by_category, anchor))

    max_compound_tokens = max(0, int(max_compound_tokens or 0))
    for anchor_set in identity_anchors.get("compound_anchor_sets", []):
        if max_compound_tokens == 0:
            continue
        token_lists = []
        product_size = 1
        for anchor in anchor_set:
            anchor_tokens = sorted(tokens_for_anchor(by_category, anchor))
            if not anchor_tokens:
                token_lists = []
                break
            token_lists.append(anchor_tokens)
            product_size *= len(anchor_tokens)
            if max_compound_tokens and product_size > max_compound_tokens:
                token_lists = []
                break
        if not token_lists:
            continue
        for combo in product(*token_lists):
            payload = "compound:" + "|".join(combo)
            person_tokens.add(hashlib.sha256(payload.encode("ascii")).hexdigest())
    return person_tokens


def row_hash(tokens: set[str]) -> str:
    payload = "\n".join(sorted(tokens))
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def split_cell_values(value: str) -> list[str]:
    parts = []
    for raw in str(value or "").split("|"):
        raw = raw.strip()
        if not raw or TRUNCATED_MARKER_RE.match(raw):
            continue
        normalized = normalize_value(raw)
        if normalized in IGNORE_VALUES:
            continue
        parts.append(raw)
    return parts


def extract_known_value_tokens(row: dict[str, str]) -> tuple[set[str], dict[str, set[str]]]:
    tokens = set()
    by_category: dict[str, set[str]] = defaultdict(set)
    for field, value in row.items():
        if not field or field in IGNORE_FIELDS:
            continue
        if not field.startswith(KNOWN_VALUE_PREFIXES):
            continue
        for part in split_cell_values(value):
            token = token_hash(field, part)
            tokens.add(token)
            by_category[token_category(field)].add(token)
    return tokens, by_category


def extract_labelled_tokens(text: str) -> tuple[set[str], dict[str, set[str]]]:
    tokens = set()
    by_category: dict[str, set[str]] = defaultdict(set)
    for match in LABELLED_VALUE_RE.finditer(str(text or "")):
        label = match.group("label")
        value = match.group("value")
        for part in split_cell_values(value):
            token = token_hash(label, part)
            tokens.add(token)
            by_category[token_category(label)].add(token)
    return tokens, by_category


def extract_unknown_value_tokens(row: dict[str, str]) -> tuple[set[str], dict[str, set[str]]]:
    tokens = set()
    by_category: dict[str, set[str]] = defaultdict(set)
    for field in UNKNOWN_VALUE_FIELDS:
        field_tokens, field_by_category = extract_labelled_tokens(row.get(field, ""))
        tokens.update(field_tokens)
        for category, category_tokens in field_by_category.items():
            by_category[category].update(category_tokens)
    return tokens, by_category


def extract_signature_tokens(row: dict[str, str]) -> set[str]:
    """Return non-raw row-category tokens for exact row-signature overlap."""
    tokens = set()
    for field, value in row.items():
        if not field or field in IGNORE_FIELDS:
            continue
        normalized_field = normalize_label(field)
        normalized_value = normalize_value(value)
        if not normalized_value:
            continue
        if field.startswith("has_"):
            if normalized_value in {"yes", "true", "1"}:
                tokens.add(token_hash("flag", normalized_field))
            elif normalized_value not in {"no", "false", "0"} and TRUNCATED_MARKER_RE.match(str(value or "")) is None:
                # Value-bearing has_* fields get a category token here; the
                # actual values are handled by value-token extraction.
                tokens.add(token_hash("flag", normalized_field))
            continue
        if normalized_value in IGNORE_VALUES:
            continue
        if field in SIGNATURE_LIST_FIELDS:
            for part in split_cell_values(value):
                tokens.add(token_hash(field, part))
            continue
        if field in SIGNATURE_SCALAR_FIELDS:
            tokens.add(token_hash(field, value))
    return tokens


def find_input_tables(root: Path) -> list[tuple[str, Path, str]]:
    known = sorted(
        path for path in root.rglob("*_pii_value_risk_matrix.csv")
        if path.is_file() and not path.name.startswith("clusters_not_in_list")
    )
    unknown = sorted(
        path for path in root.rglob("*not_in_list*.csv")
        if path.is_file()
        and "evidence" not in {part.casefold() for part in path.parts}
    )
    tables: list[tuple[str, Path, str]] = []

    def unique_source_name(base: str, path: Path) -> str:
        existing = {source for source, _path, _kind in tables}
        if base not in existing:
            return base
        try:
            rel_parts = path.relative_to(root).parts
        except ValueError:
            rel_parts = path.parts
        parent_bits = [
            re.sub(r"[^A-Za-z0-9]+", "_", part).strip("_")
            for part in rel_parts[:-1]
            if part and part not in {"4.Reidentification", "outputs"}
        ]
        candidate = f"{'_'.join(parent_bits[-2:])}_{base}" if parent_bits else base
        candidate = candidate.strip("_") or base
        suffix = 2
        unique = candidate
        while unique in existing:
            suffix += 1
            unique = f"{candidate}_{suffix}"
        return unique

    for path in known:
        source = unique_source_name(safe_name(path), path)
        tables.append((source, path, "known_pii_value_risk_matrix"))
    for path in unknown:
        name = path.name
        if name == "clusters_not_in_list.csv":
            source = "UNKNOWN_NOT_IN_LIST"
            table_kind = "unknown_clusters_not_in_list"
        elif name == "clusters_not_in_list_redacted.csv":
            source = "UNKNOWN_NOT_IN_LIST_REDACTED"
            table_kind = "unknown_clusters_not_in_list_redacted"
        elif name == "clusters_not_in_list_risk_matrix.csv":
            source = "UNKNOWN_NOT_IN_LIST_RISK_MATRIX"
            table_kind = "unknown_clusters_not_in_list_risk_matrix"
        else:
            source = safe_name(path).upper()
            table_kind = "unknown_not_in_list_other"
        source = unique_source_name(source, path)
        tables.append((source, path, table_kind))
    return tables


def read_source(source: str, path: Path, table_kind: str, identity_anchors: dict, max_compound_tokens: int):
    value_token_to_rows: dict[str, set[int]] = defaultdict(set)
    person_token_to_rows: dict[str, set[int]] = defaultdict(set)
    category_token_to_rows: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
    row_signature_counts: Counter[str] = Counter()
    rows_seen = 0
    rows_with_values = 0
    rows_with_person_tokens = 0
    rows_with_signatures = 0

    with path.open("r", newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        for row_index, row in enumerate(reader, start=1):
            rows_seen += 1
            if table_kind.startswith("unknown_"):
                value_tokens, by_category = extract_unknown_value_tokens(row)
            else:
                value_tokens, by_category = extract_known_value_tokens(row)
            signature_tokens = extract_signature_tokens(row) | value_tokens
            person_tokens = build_person_anchor_tokens(by_category, identity_anchors, max_compound_tokens)
            if value_tokens:
                rows_with_values += 1
                for token in value_tokens:
                    value_token_to_rows[token].add(row_index)
                for category, category_tokens in by_category.items():
                    for token in category_tokens:
                        category_token_to_rows[category][token].add(row_index)
            if person_tokens:
                rows_with_person_tokens += 1
                for token in person_tokens:
                    person_token_to_rows[token].add(row_index)
            if signature_tokens:
                rows_with_signatures += 1
                row_signature_counts[row_hash(signature_tokens)] += 1

    return {
        "source": source,
        "path": str(path),
        "table_kind": table_kind,
        "rows_seen": rows_seen,
        "rows_with_values": rows_with_values,
        "rows_with_person_tokens": rows_with_person_tokens,
        "rows_with_signatures": rows_with_signatures,
        "tokens": set(value_token_to_rows),
        "token_to_rows": value_token_to_rows,
        "person_tokens": set(person_token_to_rows),
        "person_token_to_rows": person_token_to_rows,
        "category_tokens": {
            category: set(token_rows)
            for category, token_rows in category_token_to_rows.items()
        },
        "category_token_to_rows": category_token_to_rows,
        "row_signature_counts": row_signature_counts,
    }


def write_matrix(path: Path, sources: dict[str, dict], metric_name: str, value_func):
    names = sorted(sources)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["metric", "source"] + names)
        writer.writeheader()
        for left in names:
            row = {"metric": metric_name, "source": left}
            for right in names:
                row[right] = value_func(sources[left], sources[right])
            writer.writerow(row)


def shared_value_count(left: dict, right: dict) -> int:
    return len(left["tokens"] & right["tokens"])


def rows_with_shared_values(left: dict, right: dict) -> int:
    shared = left["tokens"] & right["tokens"]
    row_ids = set()
    for token in shared:
        row_ids.update(left["token_to_rows"].get(token, set()))
    return len(row_ids)


def exact_row_signature_overlap(left: dict, right: dict) -> int:
    total = 0
    for signature in set(left["row_signature_counts"]) & set(right["row_signature_counts"]):
        total += min(left["row_signature_counts"][signature], right["row_signature_counts"][signature])
    return total


def write_pairwise(path: Path, sources: dict[str, dict]):
    names = sorted(sources)
    fields = [
        "left_source",
        "right_source",
        "shared_value_tokens",
        "left_rows_with_shared_values",
        "right_rows_with_shared_values",
        "exact_row_signature_overlap",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for i, left in enumerate(names):
            for right in names[i + 1:]:
                writer.writerow({
                    "left_source": left,
                    "right_source": right,
                    "shared_value_tokens": shared_value_count(sources[left], sources[right]),
                    "left_rows_with_shared_values": rows_with_shared_values(sources[left], sources[right]),
                    "right_rows_with_shared_values": rows_with_shared_values(sources[right], sources[left]),
                    "exact_row_signature_overlap": exact_row_signature_overlap(sources[left], sources[right]),
                })


def known_source_names(sources: dict[str, dict]) -> list[str]:
    return sorted(
        name for name, source in sources.items()
        if source["table_kind"] == "known_pii_value_risk_matrix"
    )


def primary_unknown_source(sources: dict[str, dict]):
    for name, source in sorted(sources.items()):
        if source["table_kind"] == "unknown_clusters_not_in_list":
            return name, source
    for name, source in sorted(sources.items()):
        if source["table_kind"].startswith("unknown_"):
            return name, source
    return "", None


def category_tokens(source: dict, category: str) -> set[str]:
    if category == "Persons":
        return set(source["person_tokens"])
    return set(source.get("category_tokens", {}).get(category, set()))


def category_rows_with_tokens(source: dict, tokens: set[str], category: str) -> int:
    row_ids = set()
    if category == "Persons":
        token_to_rows = source["person_token_to_rows"]
    else:
        token_to_rows = source.get("category_token_to_rows", {}).get(category, {})
    for token in tokens:
        row_ids.update(token_to_rows.get(token, set()))
    return len(row_ids)


def category_row_denominator(source: dict, category: str) -> int:
    if category == "Persons":
        return int(source.get("rows_with_person_tokens", 0) or 0)
    tokens = category_tokens(source, category)
    return category_rows_with_tokens(source, tokens, category)


def rows_without_shared_values(source: dict, other_tokens: set[str]) -> int:
    shared_rows = set()
    for token in source["person_tokens"] & other_tokens:
        shared_rows.update(source["person_token_to_rows"].get(token, set()))
    return max(0, int(source.get("rows_with_person_tokens", 0) or 0) - len(shared_rows))


def write_membership_summary(path: Path, sources: dict[str, dict]):
    known_names = known_source_names(sources)
    unknown_name, unknown = primary_unknown_source(sources)
    categories = {"Persons"}
    for name in known_names:
        categories.update(sources[name].get("category_tokens", {}).keys())
    if unknown:
        categories.update(unknown.get("category_tokens", {}).keys())

    preferred_order = [
        "Persons",
        "Personal Email",
        "Institutional Email",
        "Email",
        "Phone",
        "DOB",
        "Name",
        "Address",
        "Passport",
        "NHS Number",
        "National Insurance Number",
        "HUSID",
        "CAS Number",
        "Saturn ID",
        "Known Person Identifier: Person ID",
    ]
    category_order = [item for item in preferred_order if item in categories]
    category_order.extend(sorted(categories - set(category_order)))

    fields = [
        "left_source",
        "right_source",
        "neither_source",
        "metric",
        "left_only",
        "right_only",
        "both",
        "neither",
        "left_total",
        "right_total",
        "neither_total",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for left_index, left_name in enumerate(known_names):
            for right_name in known_names[left_index + 1:]:
                left = sources[left_name]
                right = sources[right_name]
                for category in category_order:
                    left_tokens = category_tokens(left, category)
                    right_tokens = category_tokens(right, category)
                    both_tokens = left_tokens & right_tokens
                    left_only_tokens = left_tokens - right_tokens
                    right_only_tokens = right_tokens - left_tokens
                    if unknown:
                        unknown_tokens = category_tokens(unknown, category)
                        neither_tokens = unknown_tokens - left_tokens - right_tokens
                        neither_count = rows_without_shared_values(unknown, left_tokens | right_tokens) if category == "Persons" else len(neither_tokens)
                        neither_total = (
                            category_row_denominator(unknown, category)
                            if category == "Persons"
                            else len(unknown_tokens)
                        )
                    else:
                        neither_count = ""
                        neither_total = ""

                    writer.writerow({
                        "left_source": left_name,
                        "right_source": right_name,
                        "neither_source": unknown_name,
                        "metric": category,
                        "left_only": (
                            rows_without_shared_values(left, right_tokens)
                            if category == "Persons"
                            else len(left_only_tokens)
                        ),
                        "right_only": (
                            rows_without_shared_values(right, left_tokens)
                            if category == "Persons"
                            else len(right_only_tokens)
                        ),
                        "both": (
                            min(
                                category_rows_with_tokens(left, both_tokens, category),
                                category_rows_with_tokens(right, both_tokens, category),
                            )
                            if category == "Persons"
                            else len(both_tokens)
                        ),
                        "neither": neither_count,
                        "left_total": category_row_denominator(left, category) if category == "Persons" else len(left_tokens),
                        "right_total": category_row_denominator(right, category) if category == "Persons" else len(right_tokens),
                        "neither_total": neither_total,
                    })


def presentation_rows_from_sources(sources: dict[str, dict]):
    known_names = known_source_names(sources)
    unknown_name, unknown = primary_unknown_source(sources)
    categories = {"Persons"}
    for name in known_names:
        categories.update(sources[name].get("category_tokens", {}).keys())
    if unknown:
        categories.update(unknown.get("category_tokens", {}).keys())

    preferred_order = [
        "Persons",
        "Personal Email",
        "Institutional Email",
        "Email",
        "Phone",
        "DOB",
        "Name",
        "Address",
        "Passport",
        "National Insurance Number",
        "NHS Number",
        "HUSID",
        "CAS Number",
        "Saturn ID",
        "Known Person Identifier: Person ID",
    ]
    category_order = [item for item in preferred_order if item in categories]
    category_order.extend(sorted(categories - set(category_order)))

    rows = []
    for left_index, left_name in enumerate(known_names):
        for right_name in known_names[left_index + 1:]:
            left = sources[left_name]
            right = sources[right_name]
            for category in category_order:
                left_tokens = category_tokens(left, category)
                right_tokens = category_tokens(right, category)
                both_tokens = left_tokens & right_tokens
                left_only_tokens = left_tokens - right_tokens
                right_only_tokens = right_tokens - left_tokens
                if unknown:
                    unknown_tokens = category_tokens(unknown, category)
                    neither_tokens = unknown_tokens - left_tokens - right_tokens
                    neither_count = rows_without_shared_values(unknown, left_tokens | right_tokens) if category == "Persons" else len(neither_tokens)
                else:
                    neither_count = 0
                if category == "Persons":
                    left_only = rows_without_shared_values(left, right_tokens)
                    right_only = rows_without_shared_values(right, left_tokens)
                    both = min(
                        category_rows_with_tokens(left, both_tokens, category),
                        category_rows_with_tokens(right, both_tokens, category),
                    )
                else:
                    left_only = len(left_only_tokens)
                    right_only = len(right_only_tokens)
                    both = len(both_tokens)
                total_verified = left_only + right_only + both
                total_found = total_verified + int(neither_count or 0)
                percentage_verified = (100.0 * total_verified / total_found) if total_found else 0.0
                rows.append({
                    "left_source": left_name,
                    "right_source": right_name,
                    "neither_source": unknown_name,
                    "metric": category,
                    "left_only": left_only,
                    "right_only": right_only,
                    "both": both,
                    "neither": neither_count,
                    "total_verified": total_verified,
                    "total_found": total_found,
                    "percentage_verified": f"{percentage_verified:.6f}".rstrip("0").rstrip("."),
                })
    return rows


def write_presentation_csv(path: Path, rows: list[dict]):
    fields = [
        "left_source",
        "right_source",
        "neither_source",
        "metric",
        "left_only",
        "right_only",
        "both",
        "neither",
        "total_verified",
        "total_found",
        "percentage_verified",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def html_number(value):
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return html.escape(str(value or ""))


def write_html_report(path: Path, rows: list[dict], manifest: dict):
    by_pair: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for row in rows:
        by_pair[(row["left_source"], row["right_source"])].append(row)

    style = """
    body { font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 2rem; color: #1f2933; }
    h1, h2 { margin-bottom: 0.4rem; }
    .note { color: #52606d; margin-bottom: 1.4rem; }
    table { border-collapse: collapse; width: 100%; margin: 1rem 0 2rem 0; font-size: 0.92rem; }
    th, td { border: 1px solid #d9e2ec; padding: 0.38rem 0.5rem; text-align: right; }
    th { background: #f0f4f8; font-weight: 700; }
    td.metric, th.metric { text-align: left; min-width: 12rem; }
    .barcell { min-width: 9rem; }
    .barwrap { background: #e4e7eb; border-radius: 999px; overflow: hidden; height: 0.75rem; }
    .bar { background: #2f80ed; height: 0.75rem; }
    .pct { white-space: nowrap; }
    .meta { background: #f8fafc; border: 1px solid #d9e2ec; padding: 0.8rem; border-radius: 0.4rem; }
    """

    parts = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<title>PII row overlap report</title>",
        f"<style>{style}</style>",
        "</head><body>",
        "<h1>PII row overlap report</h1>",
        "<p class='note'>Count-only report. Raw PII values are not written. The Persons metric uses the configured person identity anchors.</p>",
        "<div class='meta'>",
        f"<div><strong>Identity anchors:</strong> {html.escape(str(manifest.get('identity_anchors_path', '')))}</div>",
        f"<div><strong>Strong anchors:</strong> {html.escape(', '.join(manifest.get('strong_anchor_types', [])))}</div>",
        f"<div><strong>Compound anchor sets:</strong> {html.escape(str(manifest.get('compound_anchor_sets', [])))}</div>",
        "</div>",
    ]
    for (left, right), pair_rows in sorted(by_pair.items()):
        parts.append(f"<h2>{html.escape(left)} vs {html.escape(right)}</h2>")
        parts.append("<table>")
        parts.append(
            "<thead><tr>"
            "<th class='metric'>metric</th>"
            f"<th>{html.escape(left)}</th>"
            f"<th>{html.escape(right)}</th>"
            "<th>both</th><th>neither</th><th>Total Verified</th><th>Total Found</th><th>% Verified</th><th class='barcell'>figure</th>"
            "</tr></thead><tbody>"
        )
        for row in pair_rows:
            pct = float(row.get("percentage_verified") or 0)
            pct = max(0.0, min(100.0, pct))
            parts.append(
                "<tr>"
                f"<td class='metric'>{html.escape(str(row['metric']))}</td>"
                f"<td>{html_number(row['left_only'])}</td>"
                f"<td>{html_number(row['right_only'])}</td>"
                f"<td>{html_number(row['both'])}</td>"
                f"<td>{html_number(row['neither'])}</td>"
                f"<td>{html_number(row['total_verified'])}</td>"
                f"<td>{html_number(row['total_found'])}</td>"
                f"<td class='pct'>{html.escape(str(row['percentage_verified']))}%</td>"
                f"<td class='barcell'><div class='barwrap'><div class='bar' style='width:{pct:.2f}%'></div></div></td>"
                "</tr>"
            )
        parts.append("</tbody></table>")
    parts.append("</body></html>")
    path.write_text("\n".join(parts), encoding="utf-8")


def write_source_frequency(path: Path, sources: dict[str, dict]):
    known_names = known_source_names(sources)
    categories = set()
    token_sources_by_category: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for name in known_names:
        source = sources[name]
        source_categories = {"Persons": set(source["person_tokens"])}
        source_categories.update(source.get("category_tokens", {}))
        for category, tokens in source_categories.items():
            categories.add(category)
            for token in tokens:
                token_sources_by_category[category][token].add(name)

    fields = ["metric", "source_count", "unique_typed_values"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for category in sorted(categories):
            counts = Counter(len(source_names) for source_names in token_sources_by_category[category].values())
            for source_count in sorted(counts):
                writer.writerow({
                    "metric": category,
                    "source_count": source_count,
                    "unique_typed_values": counts[source_count],
                })


def write_summary(path: Path, sources: dict[str, dict]):
    all_names = sorted(sources)
    fields = [
        "source",
        "table_kind",
        "input_path",
        "rows_seen",
        "rows_with_typed_values",
        "rows_with_person_anchor_values",
        "rows_with_row_signatures",
        "unique_typed_values",
        "unique_exact_row_signatures",
        "typed_values_also_in_any_other_source",
        "typed_values_unique_to_source",
        "rows_with_values_also_in_any_other_source",
        "rows_with_values_not_seen_in_other_sources",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for name in all_names:
            source = sources[name]
            other_tokens = set()
            for other_name in all_names:
                if other_name != name:
                    other_tokens.update(sources[other_name]["tokens"])
            overlapping_tokens = source["tokens"] & other_tokens
            overlapping_rows = rows_with_shared_values(source, {"tokens": other_tokens, "token_to_rows": {}})
            writer.writerow({
                "source": name,
                "table_kind": source["table_kind"],
                "input_path": source["path"],
                "rows_seen": source["rows_seen"],
                "rows_with_typed_values": source["rows_with_values"],
                "rows_with_person_anchor_values": source["rows_with_person_tokens"],
                "rows_with_row_signatures": source["rows_with_signatures"],
                "unique_typed_values": len(source["tokens"]),
                "unique_exact_row_signatures": len(source["row_signature_counts"]),
                "typed_values_also_in_any_other_source": len(overlapping_tokens),
                "typed_values_unique_to_source": len(source["tokens"] - other_tokens),
                "rows_with_values_also_in_any_other_source": overlapping_rows,
                "rows_with_values_not_seen_in_other_sources": max(0, source["rows_with_values"] - overlapping_rows),
            })


def write_hash_audit(path: Path, sources: dict[str, dict]):
    fields = ["source", "token_hash", "row_count"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for source_name, source in sorted(sources.items()):
            for token, rows in sorted(source["token_to_rows"].items()):
                writer.writerow({
                    "source": source_name,
                    "token_hash": token,
                    "row_count": len(rows),
                })


def build_report(
    root: Path,
    output_dir: Path,
    write_hash_audit_flag: bool = False,
    identity_anchors_path: str | Path | None = None,
    max_compound_tokens: int = 5000,
):
    tables = find_input_tables(root)
    output_dir.mkdir(parents=True, exist_ok=True)
    identity_anchors = load_identity_anchors(identity_anchors_path)
    sources = {
        source: read_source(source, path, table_kind, identity_anchors, max_compound_tokens)
        for source, path, table_kind in tables
    }

    presentation_rows = presentation_rows_from_sources(sources)
    manifest = {
        "input_root": str(root),
        "source_count": len(sources),
        "identity_anchors_path": identity_anchors.get("path", ""),
        "strong_anchor_types": identity_anchors.get("strong_anchor_types", []),
        "compound_anchor_sets": identity_anchors.get("compound_anchor_sets", []),
        "max_compound_person_tokens_per_row": max_compound_tokens,
        "person_metric": "rows linked by configured strong/compound person_identity_anchors",
    }

    write_summary(output_dir / "row_overlap_summary.csv", sources)
    write_pairwise(output_dir / "row_overlap_pairwise.csv", sources)
    write_membership_summary(output_dir / "row_overlap_membership_summary.csv", sources)
    write_presentation_csv(output_dir / "row_overlap_presentation.csv", presentation_rows)
    write_html_report(output_dir / "row_overlap_report.html", presentation_rows, manifest)
    write_source_frequency(output_dir / "row_overlap_source_frequency.csv", sources)
    write_matrix(output_dir / "row_overlap_value_matrix.csv", sources, "shared_value_tokens", shared_value_count)
    write_matrix(output_dir / "row_overlap_row_matrix.csv", sources, "rows_with_shared_values", rows_with_shared_values)
    write_matrix(output_dir / "row_overlap_exact_row_matrix.csv", sources, "exact_row_signature_overlap", exact_row_signature_overlap)
    if write_hash_audit_flag:
        write_hash_audit(output_dir / "row_overlap_hash_audit.csv", sources)
    with (output_dir / "row_overlap_manifest.json").open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return output_dir, len(sources)


def write_row_overlap_report(output_root, report_dir=None, identity_anchors_path=None):
    """Package/runtime wrapper for the general overlap report."""
    root = Path(output_root).resolve()
    if report_dir:
        output_dir = Path(report_dir).resolve()
    elif (root / "4.Reidentification").is_dir():
        output_dir = root / "4.Reidentification" / "row_overlap_report"
    else:
        output_dir = root / "row_overlap_report"
    report_dir, source_count = build_report(
        root,
        output_dir,
        write_hash_audit_flag=False,
        identity_anchors_path=identity_anchors_path,
    )
    return {
        "report_dir": str(report_dir),
        "source_count": source_count,
        "html_report": str(report_dir / "row_overlap_report.html"),
        "presentation_csv": str(report_dir / "row_overlap_presentation.csv"),
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Write a non-disclosive general row/value overlap report for PII scanner Stage 4 outputs.")
    parser.add_argument("output_root", help="Scanner output directory, or its 4.Reidentification subdirectory.")
    parser.add_argument("--output-dir", default="", help="Report output directory. Default: <output_root>/row_overlap_report or <output_root>/4.Reidentification/row_overlap_report.")
    parser.add_argument("--identity-anchors", default="", help="Path to person_identity_anchors.json. Default: ../rules/person_identity_anchors.json beside this tool.")
    parser.add_argument("--max-compound-person-tokens-per-row", type=int, default=5000, help="Safety cap for compound person-anchor token products per row. Default: 5000; 0 disables compound anchors.")
    parser.add_argument("--write-hash-audit", action="store_true", help="Also write token hashes and row counts. Hashes are non-raw but can still aid linkage, so this is off by default.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    root = Path(args.output_root).resolve()
    if args.output_dir:
        output_dir = Path(args.output_dir).resolve()
    elif (root / "4.Reidentification").is_dir():
        output_dir = root / "4.Reidentification" / "row_overlap_report"
    else:
        output_dir = root / "row_overlap_report"
    report_dir, source_count = build_report(
        root,
        output_dir,
        args.write_hash_audit,
        identity_anchors_path=args.identity_anchors or None,
        max_compound_tokens=args.max_compound_person_tokens_per_row,
    )
    print(f"Wrote row overlap report for {source_count} source table(s): {report_dir}")


if __name__ == "__main__":
    main()
