#!/usr/bin/env python3
"""Shared runtime namespace for the package and standalone scanner.

Historically this project had a separate monolithic script and a package
implementation. The current codebase keeps the functional implementation in
source modules such as `rules.py`, `extraction.py`, `scanning.py`,
`clustering.py`, `people.py`, and `runtime.py`, then loads them into this shared
namespace so both entry points behave the same way.

Operationally this is the direct-streaming scanner:

- no SQLite working evidence store;
- discovery writes atomic evidence directly to CSV;
- resume modes rebuild from those CSV artefacts;
- XML can be scanned in `fast` or `structured` mode;
- Stage 5 clusters from linked evidence rather than from a database layer.
"""

from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
import multiprocessing as mp
import queue as queue_module



# =============================================================================
# Shared state, constants, and implementations loaded from the functional
# modules. The section banners make it easier to navigate the merged namespace
# during debugging, but the real source of truth remains the individual module
# files under src/pii_regex_scanner/.
# =============================================================================

"""Rules, validation, normalisation, table-header inference, and shared scanner configuration."""

import argparse
import csv
import hashlib
import io
import json
import os
import re
import sys
import time
import warnings
from collections import Counter, defaultdict
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import date, datetime
from functools import lru_cache
from itertools import chain, islice
from pathlib import Path
from html import unescape


PACKAGE_DIR = Path(__file__).resolve().parent
SCRIPT_DIR = PACKAGE_DIR.parents[1]
DEFAULT_ROOT = str(SCRIPT_DIR / "tests" / "synthetic_data" / "inputs" / "breach_dump")
DEFAULT_OUTPUT_DIR = str(SCRIPT_DIR / "tests" / "synthetic_data" / "outputs")
DEFAULT_RULES_PATH = ""
LOADED_RULES_PATH = None
LOADED_TABLE_COLUMN_RULES_PATH = None
LOADED_IDENTITY_ANCHORS_PATH = None
EMAIL_SUFFIX = ()
EMAIL_WILDCARDS = ()
VALID_CONTEXTUAL_DATE_CACHE = {}
TABLE_HEADER_MATCH_CACHE = {}
TABLE_HEADER_PATTERN_CACHE = {}
TABLE_HEADER_ASSEMBLY_CACHE = {}
XML_STREAMING_STRUCTURED_BYTES = 10 * 1024 * 1024


def configure_csv_field_size_limit():
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return limit
        except OverflowError:
            limit //= 10


CSV_FIELD_SIZE_LIMIT = configure_csv_field_size_limit()

BUILTIN_EMAIL_RULE = {
    "evidence_type": "Email",
    "pattern_name": "email",
    "confidence": "high",
    "regex": r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b",
    "flags": ["IGNORECASE"],
    "risk_tier": "tier_1_strong_identifier",
    "normalization": "lower",
    "is_identifiable": True,
    "anchor_priority": 10,
    "max_per_cluster": 4,
    "max_per_cluster_by_evidence_type": {
        "Institutional Email": 1,
        "Personal Email": 3,
    },
}

CODE_DERIVED_EVIDENCE_RULES = [
    {
        "evidence_type": "Address",
        "pattern_name": "assembled_address",
        "risk_tier": "tier_3_supporting_evidence",
        "normalization": "address_compact",
        "risk_roles": ["address"],
        "max_per_cluster": 10,
    },
    {
        "evidence_type": "Name",
        "pattern_name": "assembled_name",
        "risk_tier": "tier_3_supporting_evidence",
        "normalization": "name_casefold",
        "risk_roles": ["name"],
        "max_per_cluster": 10,
        "is_identifiable": True,
    },
]

CODE_DERIVED_EVIDENCE_TYPES = {
    rule["evidence_type"] for rule in CODE_DERIVED_EVIDENCE_RULES
}

HEADER_CONFIRMED_ONLY_EVIDENCE_TYPES = {
    "Citizenship Country",
    "Citizenship/Country",
    "Religion",
    "Ethnicity",
    "Disability",
    "Marital Status",
}

DEFAULT_TABLE_COLUMN_RULES = {
    "min_non_empty_headers": 2,
    "rules": [
        {
            "canonical_header": "first name",
            "name_part": "first",
            "header_patterns": [r"\bfirst\s*name\b", r"\bforename\b", r"\bgiven\s*name\b"],
        },
        {
            "canonical_header": "last name",
            "name_part": "last",
            "header_patterns": [r"\blast\s*name\b", r"\bfamily\s*name\b", r"\bsurname\b"],
        },
        {"canonical_header": "full name", "header_patterns": [r"\bfull\s*name\b", r"\bname\b"]},
        {"canonical_header": "email", "header_patterns": [r"\be-?mail\b", r"\bmail\b"]},
        {"canonical_header": "DOB", "header_patterns": [r"\bdob\b", r"\bdate\s*of\s*birth\b", r"\bbirth\s*date\b"]},
        {"canonical_header": "student id", "header_patterns": [r"\bstudent\s*(?:id|number|no)\b"]},
        {"canonical_header": "passport", "header_patterns": [r"\bpassport\b"]},
        {"canonical_header": "phone", "header_patterns": [r"\bphone\b", r"\btelephone\b", r"\bmobile\b"]},
        {"canonical_header": "postcode", "header_patterns": [r"\bpost\s*code\b", r"\bpostcode\b", r"\bpostal\s*code\b"]},
        {
            "canonical_header": "address",
            "header_patterns": [
                r"\baddress\s*(?:line\s*)?\d*\b",
                r"\baddr\s*\d*\b",
                r"\bstreet\b",
                r"\broad\b",
                r"\bavenue\b",
            ],
        },
    ],
}
TABLE_COLUMN_RULES = dict(DEFAULT_TABLE_COLUMN_RULES)
TABLE_CELL_VALUE_EMIT_RULES = []

READ_CHUNK_SIZE = 1024 * 1024
HASH_CHUNK_SIZE = 1024 * 1024
OUTPUT_BUFFER_SIZE = 1024 * 1024
TEXT_EXTENSIONS = {
    ".bat",
    ".cfg",
    ".conf",
    ".csv",
    ".dat",
    ".env",
    ".htm",
    ".html",
    ".ini",
    ".json",
    ".jsonl",
    ".log",
    ".md",
    ".properties",
    ".ps1",
    ".sh",
    ".sql",
    ".tsv",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

EXCEL_EXTENSIONS = {".xlsx", ".xlsm", ".xls", ".xlsb", ".ods"}
WORD_EXTENSIONS = {".docx"}
PDF_EXTENSIONS = {".pdf"}
RTF_EXTENSIONS = {".rtf"}
EMAIL_EXTENSIONS = {".eml", ".msg"}
LEGACY_UNSUPPORTED_DOCUMENT_EXTENSIONS = {".doc", ".odt", ".odp", ".ppt", ".pptx"}

IMAGE_EXTENSIONS = {
    ".bmp",
    ".gif",
    ".heic",
    ".jpeg",
    ".jpg",
    ".png",
    ".tif",
    ".tiff",
    ".webp",
}

PARSER_DOCUMENT_EXTENSIONS = (
    EXCEL_EXTENSIONS
    | WORD_EXTENSIONS
    | PDF_EXTENSIONS
    | RTF_EXTENSIONS
    | EMAIL_EXTENSIONS
)
DOCUMENT_SIGNAL_EXTENSIONS = PARSER_DOCUMENT_EXTENSIONS | LEGACY_UNSUPPORTED_DOCUMENT_EXTENSIONS
SCAN_EXTRACTABLE_EXTENSIONS = TEXT_EXTENSIONS | PARSER_DOCUMENT_EXTENSIONS | IMAGE_EXTENSIONS

FINDING_FIELDS = [
    "file_path",
    "file_name",
    "extension",
    "size_bytes",
    "md5",
    "row_number",
    "evidence_type",
    "matched_text",
    "normalized_value",
    "start",
    "end",
    "context",
    "pattern_name",
    "confidence",
    "evidence_tier",
    "matched_person_tables",
]

FILE_SUMMARY_FIELDS = [
    "file_path",
    "file_name",
    "extension",
    "detected_extension",
    "size_bytes",
    "md5",
    "sha256",
    "duplicate_content_group",
    "duplicate_content_index",
    "duplicate_of",
    "duplicate_path_count",
    "duplicate_paths",
    "duplicate_content_action",
    "status",
    "text_chars_scanned",
    "finding_count",
    "cluster_excluded_linked_evidence_count",
    "cluster_exclusion_reasons",
    "error",
]
BASE_FILE_SUMMARY_FIELDS = FILE_SUMMARY_FIELDS[:]

ERROR_FIELDS = [
    "file_path",
    "file_name",
    "extension",
    "size_bytes",
    "status",
    "error",
]

LINKED_EVIDENCE_FIELDS = [
    "linked_evidence_key",
    "file_path",
    "file_name",
    "extension",
    "row_number",
    "anchor_type",
    "anchor_value",
    "evidence_types",
    "evidence_values",
    "confidence",
    "risk_level",
    "risk_reasons",
    "cluster_eligible",
    "cluster_exclusion_reason",
    "source_row",
    "duplicate_evidence_group",
    "duplicate_evidence_index",
    "duplicate_evidence_count",
    "duplicate_evidence_paths",
    "duplicate_evidence_locators",
    "duplicate_evidence_action",
]

ENTITY_SUMMARY_FIELDS = [
    "evidence_type",
    "finding_count",
    "file_count",
]

REGEX_SUMMARY_FIELDS = [
    "evidence_type",
    "pattern_name",
    "finding_count",
    "unique_value_count",
    "file_count",
    "confidence",
    "evidence_tier",
    "not_matched",
]

PERSON_CLUSTER_FIELDS = [
    "person_cluster_id",
    "cluster_confidence",
    "risk_level",
    "linked_evidence_count",
    "file_count",
    "row_count",
    "anchor_types",
    "anchor_values",
    "cluster_merge_keys",
    "identity_anchor_basis",
    "evidence_types",
    "evidence_values",
    "risk_reasons",
    "file_paths",
    "file_names",
    "source_rows",
]

UNKNOWN_PERSON_IN_DATASET_CLUSTER_FIELDS = [
    "unknown_person_key",
    "person_cluster_id",
    "cluster_confidence",
    "risk_level",
    "linked_evidence_count",
    "matched_evidence_count",
    "file_count",
    "evidence_types",
    "cluster_anchor_types",
    "identity_anchor_basis",
    "cluster_anchor_values",
    "cluster_merge_keys",
    "file_paths",
    "reason",
]

UNKNOWN_PERSON_IN_DATASET_FIELDS = [
    "unknown_person_key",
    "person_cluster_id",
    "cluster_confidence",
    "risk_level",
    "linked_evidence_count",
    "matched_evidence_count",
    "file_count",
    "evidence_types",
    "cluster_anchor_types",
    "identity_anchor_basis",
    "reason",
]

PERSON_EVIDENCE_DETAIL_FIELDS = [
    "person_type",
    "person_key",
    "person_table_row_number",
    "person_cluster_id",
    "record_type",
    "source_scope",
    "linked_evidence_key",
    "file_path",
    "file_name",
    "extension",
    "row_number",
    "anchor_type",
    "anchor_value",
    "evidence_types",
    "evidence_values",
    "confidence",
    "risk_level",
    "risk_reasons",
    "cluster_eligible",
    "cluster_exclusion_reason",
    "source_row",
    "cluster_confidence",
    "linked_evidence_count",
    "file_count",
    "cluster_anchor_types",
    "cluster_anchor_values",
    "cluster_merge_keys",
    "raw_evidence_type",
    "raw_matched_text",
    "raw_normalized_value",
    "raw_pattern_name",
    "raw_confidence",
    "raw_evidence_tier",
    "raw_start",
    "raw_end",
    "raw_context",
]

BASE_KNOWN_PERSON_RISK_MATRIX_FIELDS = [
    "person_key",
    "person_table_row_number",
    "overall_risk_score",
    "overall_risk_level",
]
KNOWN_PERSON_RISK_MATRIX_FIELDS = BASE_KNOWN_PERSON_RISK_MATRIX_FIELDS[:]

# Rule-derived fields are rebuilt by load_rules(). The bootstrap values
# support the built-in email-only default before external JSON rules are loaded.
EVIDENCE_COUNT_TYPES = [BUILTIN_EMAIL_RULE["evidence_type"]]
EVIDENCE_COUNT_COLUMNS = [
    "count_" + re.sub(r"[^a-z0-9]+", "_", evidence_type.lower()).strip("_")
    for evidence_type in EVIDENCE_COUNT_TYPES
]
EVIDENCE_FLAG_COLUMNS = [
    "has_" + re.sub(r"[^a-z0-9]+", "_", evidence_type.lower()).strip("_")
    for evidence_type in EVIDENCE_COUNT_TYPES
]
EVIDENCE_NORMALIZATION = {"Email": "lower"}
EVIDENCE_RISK_ROLES = {"Email": {"email"}}
FILE_SUMMARY_FIELDS = FILE_SUMMARY_FIELDS + ["highest_file_risk", "evidence_type_counts"] + EVIDENCE_COUNT_COLUMNS

TIER_1_EVIDENCE = {"Email"}
TIER_2_EVIDENCE = set()
TIER_3_EVIDENCE = set()

_COMPONENT_MODULES = (
    "validation.py",
    "rules.py",
    "extraction.py",
    "scanning.py",
    "profiling.py",
    "summaries.py",
    "clustering.py",
    "people.py",
    "row_overlap.py",
    "runtime.py",
)


def _load_component_module(filename):
    path = PACKAGE_DIR / filename
    source = path.read_text(encoding="utf-8")
    exec(compile(source, str(path), "exec"), globals())


for _component_module in _COMPONENT_MODULES:
    _load_component_module(_component_module)

del _component_module
