import argparse
import csv
import hashlib
import io
import os
import re
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from pathlib import Path


def configure_csv_field_size_limit():
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return limit
        except OverflowError:
            limit //= 10


CSV_FIELD_SIZE_LIMIT = configure_csv_field_size_limit()
OUTPUT_BUFFER_SIZE = 1024 * 1024


OUTPUT_FILE_CANDIDATES = {
    "known": "known_person_in_dataset.csv",
    "known_risk": "known_person_individual_risk_matrix.csv",
    "clusters": "person_clusters.csv",
    "linked": "pii_regex_evidence_linked.csv",
}

UNKNOWN_OUTPUT_CANDIDATES = (
    "unknown_person_in_dataset_clusters.csv",
    "unknown_person_in_dataset.csv",
)


def safe_cell(value):
    if value is None:
        return ""
    value = str(value).replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return re.sub(r"\s+", " ", value).strip()


def rule_slug(value):
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").lower()).strip("_")


def looks_like_utf16_text(raw):
    sample = raw[:4096]
    if sample.startswith((b"\xff\xfe", b"\xfe\xff")):
        return True
    if len(sample) < 8:
        return False
    even_nulls = sample[0::2].count(0)
    odd_nulls = sample[1::2].count(0)
    half_length = max(1, len(sample) // 2)
    return even_nulls / half_length > 0.25 or odd_nulls / half_length > 0.25


def detect_encoding(path):
    path = Path(path)
    try:
        with open(path, "rb") as f:
            raw = f.read(8192)
    except OSError:
        return "utf-8"

    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if looks_like_utf16_text(raw):
        even_nulls = raw[:4096][0::2].count(0)
        odd_nulls = raw[:4096][1::2].count(0)
        return "utf-16-be" if even_nulls > odd_nulls else "utf-16-le"
    return "utf-8-sig"


@contextmanager
def csv_dict_reader(path):
    path = Path(path)
    if not path.exists():
        yield [], iter(())
        return

    encoding = detect_encoding(path)
    raw_fh = open(path, "rb", buffering=OUTPUT_BUFFER_SIZE)
    try:
        text_fh = io.TextIOWrapper(raw_fh, encoding=encoding, errors="replace", newline="")
        reader = csv.DictReader(text_fh)
        fieldnames = reader.fieldnames or []
        yield fieldnames, reader
    finally:
        raw_fh.close()


def read_csv_rows(path):
    """Read smaller CSV outputs into memory.

    Atomic evidence CSVs are intentionally not read through this helper; they are
    streamed by load_evidence_keys().
    """
    with csv_dict_reader(path) as (fieldnames, reader):
        rows = list(reader)
    return fieldnames, rows


def split_pipe_values(value):
    if not value:
        return []
    return [part.strip() for part in str(value).split("|") if part.strip()]


def percent(numerator, denominator):
    if not denominator:
        return "n/a"
    return f"{(numerator / denominator) * 100:.2f}%"


def dataset_label(path, override=""):
    return override or Path(path).resolve().name


def digest_key(value):
    """Compact stable key to reduce RAM.

    The report compares counts/overlap rather than printing the literal term
    values, so storing a 128-bit digest avoids retaining very large strings from
    evidence_values, context, file_paths, etc.
    """
    value = safe_cell(value)
    return hashlib.blake2b(value.encode("utf-8", errors="replace"), digest_size=16).digest()


def evidence_key_digest(row):
    evidence_type = safe_cell(row.get("evidence_type", ""))
    value = safe_cell(row.get("normalized_value") or row.get("matched_text") or "")
    if not evidence_type or not value:
        return b""
    return digest_key(f"{evidence_type}={value}")


def identity_key_digests(values):
    return {digest_key(value) for value in values if safe_cell(value)}


def maybe_progress(label, count, last_time, progress_every):
    if progress_every <= 0:
        return last_time
    now = time.time()
    if now - last_time >= progress_every:
        print(f"\r{label}: {count:,}", end="", flush=True)
        return now
    return last_time


def merge_counter(target, source):
    for key, value in source.items():
        target[key] += value


def merge_by_type(target, source):
    for evidence_type, keys in source.items():
        target[evidence_type].update(keys)


def load_evidence_file_summary(path):
    keys = set()
    by_type = defaultdict(set)
    pattern_counts = Counter()
    row_count = 0

    with csv_dict_reader(path) as (_, reader):
        for row in reader:
            if row.get("evidence_tier") == "metadata" or row.get("pattern_name") == "max_findings_per_file":
                continue

            key = evidence_key_digest(row)
            if not key:
                continue

            row_count += 1
            keys.add(key)
            by_type[row.get("evidence_type", "")].add(key)
            pattern_counts[(row.get("evidence_type", ""), row.get("pattern_name", ""))] += 1

    return {
        "path": str(path),
        "keys": keys,
        "by_type": dict(by_type),
        "pattern_counts": pattern_counts,
        "row_count": row_count,
    }


def load_evidence_keys_single_thread(evidence_files, label="", progress_every=2.0):
    keys = set()
    by_type = defaultdict(set)
    pattern_counts = Counter()
    row_count = 0
    file_count = 0
    total_files = len(evidence_files)
    last_progress = 0
    progress_label = f"Streaming atomic evidence {label}".strip()

    for path in evidence_files:
        file_count += 1
        with csv_dict_reader(path) as (_, reader):
            for row in reader:
                if row.get("evidence_tier") == "metadata" or row.get("pattern_name") == "max_findings_per_file":
                    continue

                key = evidence_key_digest(row)
                if not key:
                    continue

                row_count += 1
                keys.add(key)
                by_type[row.get("evidence_type", "")].add(key)
                pattern_counts[(row.get("evidence_type", ""), row.get("pattern_name", ""))] += 1

                last_progress = maybe_progress(
                    f"{progress_label} [{file_count:,}/{total_files:,} files]",
                    row_count,
                    last_progress,
                    progress_every,
                )

    if progress_every > 0:
        print(
            f"\r{progress_label} [{file_count:,}/{total_files:,} files]: {row_count:,} rows",
            flush=True,
        )

    return {
        "keys": keys,
        "by_type": by_type,
        "pattern_counts": pattern_counts,
        "row_count": row_count,
    }


def load_evidence_keys_multi_thread(evidence_files, label="", workers=2, progress_every=2.0):
    keys = set()
    by_type = defaultdict(set)
    pattern_counts = Counter()
    row_count = 0
    completed_files = 0
    total_files = len(evidence_files)
    last_progress = 0
    progress_label = f"Streaming atomic evidence {label}".strip()

    # Threads are only used across files. This can help when there are many small
    # evidence CSVs or a latency-heavy network share. It may not help one giant
    # CSV and can increase peak memory during result merging, so default workers=1.
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_path = {
            executor.submit(load_evidence_file_summary, path): path
            for path in evidence_files
        }

        for future in as_completed(future_to_path):
            result = future.result()
            completed_files += 1
            row_count += result["row_count"]
            keys.update(result["keys"])
            merge_by_type(by_type, result["by_type"])
            merge_counter(pattern_counts, result["pattern_counts"])

            last_progress = maybe_progress(
                f"{progress_label} [{completed_files:,}/{total_files:,} files]",
                row_count,
                last_progress,
                progress_every,
            )

    if progress_every > 0:
        print(
            f"\r{progress_label} [{completed_files:,}/{total_files:,} files]: {row_count:,} rows",
            flush=True,
        )

    return {
        "keys": keys,
        "by_type": by_type,
        "pattern_counts": pattern_counts,
        "row_count": row_count,
    }


def load_evidence_keys(output_dir, label="", workers=1, progress_every=2.0):
    evidence_dir = Path(output_dir) / "pii_regex_evidence"

    if not evidence_dir.is_dir():
        return {
            "keys": set(),
            "by_type": defaultdict(set),
            "pattern_counts": Counter(),
            "row_count": 0,
        }

    evidence_files = [
        path
        for path in sorted(evidence_dir.glob("*.csv"))
        if path.name != "errors.csv"
    ]

    if workers <= 1 or len(evidence_files) <= 1:
        return load_evidence_keys_single_thread(evidence_files, label, progress_every)

    return load_evidence_keys_multi_thread(evidence_files, label, workers, progress_every)


def load_known_people(output_dir):
    known = set()
    path = Path(output_dir) / OUTPUT_FILE_CANDIDATES["known"]
    with csv_dict_reader(path) as (_, reader):
        for row in reader:
            person_key = safe_cell(row.get("person_key"))
            if person_key:
                known.add(person_key)
    return known, []


def evidence_label_from_flag_column(column):
    slug = column.removeprefix("has_")
    words = []
    acronyms = {
        "cas": "CAS",
        "dob": "DOB",
        "husid": "HUSID",
        "id": "ID",
        "ip": "IP",
        "nid": "NID",
        "nhs": "NHS",
        "orcid": "ORCID",
        "slc": "SLC",
        "ssn": "SSN",
    }
    for word in slug.split("_"):
        words.append(acronyms.get(word, word.capitalize()))
    return " ".join(words)


def load_known_risk_matrix(output_dir):
    path = Path(output_dir) / OUTPUT_FILE_CANDIDATES["known_risk"]
    with csv_dict_reader(path) as (fieldnames, reader):
        flag_columns = [field for field in fieldnames if field.startswith("has_")]
        by_person = {}
        for row in reader:
            person_key = safe_cell(row.get("person_key"))
            if person_key:
                by_person[person_key] = row
    return flag_columns, by_person


def person_table_key(row, row_number):
    if safe_cell(row.get("ID")):
        return safe_cell(row.get("ID"))
    for value in row.values():
        match = re.search(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", safe_cell(value), re.IGNORECASE)
        if match:
            return match.group(0).lower()
    for value in row.values():
        cleaned = safe_cell(value)
        if cleaned:
            return cleaned
    return f"person_table_row_{row_number}"


def load_person_universe(person_table_path):
    people = []
    seen = Counter()
    with csv_dict_reader(person_table_path) as (headers, reader):
        for row_number, row in enumerate(reader, start=1):
            key = person_table_key(row, row_number)
            seen[key] += 1
            if seen[key] > 1:
                key = f"{key}#{seen[key]}"
            people.append((key, row))
    return headers, people


def known_person_groups(person_universe, left_label, right_label, left_known, right_known):
    universe = {person_key for person_key, _ in person_universe}
    return [
        ("known_in_both_datasets", "Known in both datasets", universe & left_known & right_known),
        (f"known_only_in_{rule_slug(left_label)}", f"Known only in {left_label}", universe & left_known - right_known),
        (f"known_only_in_{rule_slug(right_label)}", f"Known only in {right_label}", universe & right_known - left_known),
        ("known_in_neither_dataset", "Known in neither dataset", universe - left_known - right_known),
    ]


def evidence_presence_value(person_key, flag_column, left_label, right_label, left_risk, right_risk):
    left_has = safe_cell(left_risk.get(person_key, {}).get(flag_column, "")).lower() == "yes"
    right_has = safe_cell(right_risk.get(person_key, {}).get(flag_column, "")).lower() == "yes"
    if left_has and right_has:
        return "both"
    if left_has:
        return left_label
    if right_has:
        return right_label
    return ""


def known_group_file_name(group_name):
    return f"{group_name}.csv"


def write_known_group_files(
    output_dir,
    person_headers,
    person_universe,
    groups,
    left_label,
    right_label,
    left_flag_columns,
    right_flag_columns,
    left_risk,
    right_risk,
):
    person_lookup = dict(person_universe)
    all_flag_columns = sorted(set(left_flag_columns) | set(right_flag_columns))
    used_columns = {"person_key", *person_headers}
    evidence_columns = []
    for flag_column in all_flag_columns:
        evidence_column = evidence_label_from_flag_column(flag_column)
        if evidence_column in used_columns:
            evidence_column = f"{evidence_column} evidence"
        used_columns.add(evidence_column)
        evidence_columns.append(evidence_column)
    fieldnames = ["person_key"] + list(person_headers) + evidence_columns
    written = {}

    for group_name, _, people in groups:
        path = Path(output_dir) / known_group_file_name(group_name)
        with open(path, "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for person_key in sorted(people):
                source = person_lookup.get(person_key, {})
                row = {"person_key": person_key}
                for header in person_headers:
                    row[header] = source.get(header, "")
                for flag_column, evidence_column in zip(all_flag_columns, evidence_columns):
                    row[evidence_column] = evidence_presence_value(
                        person_key,
                        flag_column,
                        left_label,
                        right_label,
                        left_risk,
                        right_risk,
                    )
                writer.writerow(row)
        written[group_name] = path

    return written


def cluster_identity_key_values(row):
    keys = {
        value
        for value in split_pipe_values(row.get("cluster_merge_keys", ""))
        if value and not value.startswith("singleton:")
    }
    if keys:
        return keys
    keys = set(split_pipe_values(row.get("anchor_values", "")))
    if keys:
        return keys
    return set(split_pipe_values(row.get("evidence_values", "")))


def load_clusters(output_dir, label="", progress_every=2.0):
    path = Path(output_dir) / OUTPUT_FILE_CANDIDATES["clusters"]
    cluster_rows = []
    keys_by_cluster_id = {}
    all_keys = set()
    count = 0
    last_progress = 0

    with csv_dict_reader(path) as (_, reader):
        for row in reader:
            count += 1
            cluster_id = row.get("person_cluster_id", "")
            keys = identity_key_digests(cluster_identity_key_values(row))
            cluster_rows.append((cluster_id, keys))
            if cluster_id:
                keys_by_cluster_id[cluster_id] = keys
            all_keys.update(keys)
            last_progress = maybe_progress(f"Streaming clusters {label}".strip(), count, last_progress, progress_every)

    if count and progress_every > 0:
        print(f"\rStreaming clusters {label}: {count:,} rows", flush=True)

    return {
        "rows": cluster_rows,
        "keys": all_keys,
        "keys_by_cluster_id": keys_by_cluster_id,
    }


def matched_cluster_count(left_clusters, right_clusters):
    right_keys = right_clusters["keys"]
    return sum(1 for _, keys in left_clusters["rows"] if keys & right_keys)


def unknown_signature_key_values(row):
    keys = {
        value
        for value in split_pipe_values(row.get("cluster_merge_keys", ""))
        if value and not value.startswith("singleton:")
    }
    if keys:
        return keys
    keys = set(split_pipe_values(row.get("cluster_anchor_values", "")))
    keys.update(split_pipe_values(row.get("anchor_values", "")))
    if keys:
        return keys
    return set(split_pipe_values(row.get("evidence_values", "")))


def unknown_output_path(output_dir):
    output_dir = Path(output_dir)
    for file_name in UNKNOWN_OUTPUT_CANDIDATES:
        path = output_dir / file_name
        if path.exists():
            return path
    return output_dir / UNKNOWN_OUTPUT_CANDIDATES[0]


def load_unknown_people(output_dir, clusters, label="", progress_every=2.0):
    path = unknown_output_path(output_dir)
    unknown_rows = []
    keys = set()
    count = 0
    resolved_from_clusters = 0
    rows_without_keys = 0
    last_progress = 0

    with csv_dict_reader(path) as (_, reader):
        for row in reader:
            count += 1
            signature = identity_key_digests(unknown_signature_key_values(row))
            cluster_id = safe_cell(row.get("person_cluster_id") or row.get("unknown_person_key"))
            if not signature and cluster_id:
                signature = clusters["keys_by_cluster_id"].get(cluster_id, set())
                if signature:
                    resolved_from_clusters += 1
            if not signature:
                rows_without_keys += 1
            unknown_rows.append((row.get("unknown_person_key", "") or cluster_id, signature))
            keys.update(signature)
            last_progress = maybe_progress(f"Streaming unknown people {label}".strip(), count, last_progress, progress_every)

    if count and progress_every > 0:
        print(f"\rStreaming unknown people {label}: {count:,} rows", flush=True)

    return {
        "rows": unknown_rows,
        "keys": keys,
        "source_file": path.name,
        "resolved_from_clusters": resolved_from_clusters,
        "rows_without_keys": rows_without_keys,
    }


def matched_unknown_count(left_unknown, right_unknown):
    right_keys = right_unknown["keys"]
    return sum(1 for _, keys in left_unknown["rows"] if keys & right_keys)


def compare_sets(left, right):
    overlap = left & right
    return {
        "left_count": len(left),
        "right_count": len(right),
        "overlap": len(overlap),
        "left_only": len(left - right),
        "right_only": len(right - left),
        "left_conserved": percent(len(overlap), len(left)),
        "right_conserved": percent(len(overlap), len(right)),
        "jaccard": percent(len(overlap), len(left | right)),
    }


def append_set_summary(lines, title, left_label, right_label, left_set, right_set):
    stats = compare_sets(left_set, right_set)
    lines.extend(
        [
            f"{title}",
            "-" * len(title),
            f"{left_label} unique terms: {stats['left_count']:,}",
            f"{right_label} unique terms: {stats['right_count']:,}",
            f"Shared terms: {stats['overlap']:,}",
            f"{left_label}-only terms: {stats['left_only']:,}",
            f"{right_label}-only terms: {stats['right_only']:,}",
            f"{left_label} conserved in {right_label}: {stats['left_conserved']}",
            f"{right_label} conserved in {left_label}: {stats['right_conserved']}",
            f"Jaccard overlap: {stats['jaccard']}",
            "",
        ]
    )


def append_evidence_by_type(lines, left_label, right_label, left_by_type, right_by_type):
    evidence_types = sorted(set(left_by_type) | set(right_by_type))
    lines.extend(["Evidence Conservation By Type", "-----------------------------"])
    lines.append(
        f"{'evidence_type':35} {left_label:>12} {right_label:>12} {'shared':>12} "
        f"{left_label + ' conserved':>18} {right_label + ' conserved':>18}"
    )
    for evidence_type in evidence_types:
        left = left_by_type.get(evidence_type, set())
        right = right_by_type.get(evidence_type, set())
        shared = len(left & right)
        lines.append(
            f"{evidence_type[:35]:35} {len(left):12,} {len(right):12,} {shared:12,} "
            f"{percent(shared, len(left)):>18} {percent(shared, len(right)):>18}"
        )
    lines.append("")


def append_known_group_counts(lines, groups, group_files, universe_count):
    lines.extend(["Known Person Group Counts", "-------------------------"])
    lines.append(f"{'group':35} {'count':>10} {'person table %':>15} detail_file")
    for group_name, title, people in groups:
        detail_file = Path(group_files[group_name]).name if group_name in group_files else ""
        lines.append(f"{title[:35]:35} {len(people):10,} {percent(len(people), universe_count):>15} {detail_file}")
    lines.append("")


def append_known_person_matrix(lines, person_universe, left_label, right_label, groups, group_files):
    universe = {person_key for person_key, _ in person_universe}
    group_lookup = {group_name: people for group_name, _, people in groups}
    both_in = group_lookup["known_in_both_datasets"]
    left_only = group_lookup[f"known_only_in_{rule_slug(left_label)}"]
    right_only = group_lookup[f"known_only_in_{rule_slug(right_label)}"]
    both_out = group_lookup["known_in_neither_dataset"]

    lines.extend(
        [
            "Known Person Matrix",
            "-------------------",
            f"Person-table universe: {len(universe):,}",
            "",
            f"{'':22} {right_label + ' in':>16} {right_label + ' out':>16}",
            f"{left_label + ' in':22} {len(both_in):16,} {len(left_only):16,}",
            f"{left_label + ' out':22} {len(right_only):16,} {len(both_out):16,}",
            "",
            f"Both in: {percent(len(both_in), len(universe))}",
            f"{left_label} only: {percent(len(left_only), len(universe))}",
            f"{right_label} only: {percent(len(right_only), len(universe))}",
            f"Both out: {percent(len(both_out), len(universe))}",
            "",
        ]
    )
    append_known_group_counts(lines, groups, group_files, len(universe))


def append_cluster_summary(lines, left_label, right_label, left_clusters, right_clusters):
    left_matched = matched_cluster_count(left_clusters, right_clusters)
    right_matched = matched_cluster_count(right_clusters, left_clusters)
    lines.extend(
        [
            "Person Cluster Conservation",
            "---------------------------",
            f"{left_label} cluster rows: {len(left_clusters['rows']):,}",
            f"{right_label} cluster rows: {len(right_clusters['rows']):,}",
            f"{left_label} clusters with at least one identity term seen in {right_label}: {left_matched:,} ({percent(left_matched, len(left_clusters['rows']))})",
            f"{right_label} clusters with at least one identity term seen in {left_label}: {right_matched:,} ({percent(right_matched, len(right_clusters['rows']))})",
            "",
        ]
    )
    append_set_summary(
        lines,
        "Person Cluster Identity Term Conservation",
        left_label,
        right_label,
        left_clusters["keys"],
        right_clusters["keys"],
    )


def append_unknown_summary(lines, left_label, right_label, left_unknown, right_unknown):
    left_matched = matched_unknown_count(left_unknown, right_unknown)
    right_matched = matched_unknown_count(right_unknown, left_unknown)
    lines.extend(
        [
            "Unknown Person Comparison",
            "-------------------------",
            f"{left_label} unknown rows: {len(left_unknown['rows']):,}",
            f"{right_label} unknown rows: {len(right_unknown['rows']):,}",
            f"{left_label} unknown source: {left_unknown['source_file']}",
            f"{right_label} unknown source: {right_unknown['source_file']}",
            f"{left_label} unknown rows resolved through person_clusters.csv: {left_unknown['resolved_from_clusters']:,}",
            f"{right_label} unknown rows resolved through person_clusters.csv: {right_unknown['resolved_from_clusters']:,}",
            f"{left_label} unknown rows without comparable identity terms: {left_unknown['rows_without_keys']:,}",
            f"{right_label} unknown rows without comparable identity terms: {right_unknown['rows_without_keys']:,}",
            f"{left_label} unknown rows with at least one signature term seen in {right_label}: {left_matched:,} ({percent(left_matched, len(left_unknown['rows']))})",
            f"{right_label} unknown rows with at least one signature term seen in {left_label}: {right_matched:,} ({percent(right_matched, len(right_unknown['rows']))})",
            "",
        ]
    )
    append_set_summary(
        lines,
        "Unknown Person Signature Term Conservation",
        left_label,
        right_label,
        left_unknown["keys"],
        right_unknown["keys"],
    )


def default_report_path(left_dir, right_dir):
    left = Path(left_dir).resolve()
    right = Path(right_dir).resolve()
    parent = left.parent if left.parent == right.parent else Path.cwd()
    comparison_dir = parent / f"{left.name}_vs_{right.name}"
    return comparison_dir / "report.txt"


def report_path_from_args(args):
    if args.output_dir:
        return Path(args.output_dir) / "report.txt"
    return default_report_path(args.left_output_dir, args.right_output_dir)


def build_report(args):
    left_label = dataset_label(args.left_output_dir, args.left_label)
    right_label = dataset_label(args.right_output_dir, args.right_label)
    report_path = report_path_from_args(args)

    report_path.parent.mkdir(parents=True, exist_ok=True)

    left_evidence = load_evidence_keys(args.left_output_dir, left_label, args.workers, args.progress_every)
    right_evidence = load_evidence_keys(args.right_output_dir, right_label, args.workers, args.progress_every)
    left_known, _ = load_known_people(args.left_output_dir)
    right_known, _ = load_known_people(args.right_output_dir)
    left_flag_columns, left_risk = load_known_risk_matrix(args.left_output_dir)
    right_flag_columns, right_risk = load_known_risk_matrix(args.right_output_dir)
    person_headers, person_universe = load_person_universe(args.person_table)
    left_clusters = load_clusters(args.left_output_dir, left_label, args.progress_every)
    right_clusters = load_clusters(args.right_output_dir, right_label, args.progress_every)
    left_unknown = load_unknown_people(args.left_output_dir, left_clusters, left_label, args.progress_every)
    right_unknown = load_unknown_people(args.right_output_dir, right_clusters, right_label, args.progress_every)
    known_groups = known_person_groups(person_universe, left_label, right_label, left_known, right_known)

    known_group_files = write_known_group_files(
        report_path.parent,
        person_headers,
        person_universe,
        known_groups,
        left_label,
        right_label,
        left_flag_columns,
        right_flag_columns,
        left_risk,
        right_risk,
    )

    lines = [
        "PII Regex Output Comparison",
        "===========================",
        "",
        f"Left dataset:  {left_label}",
        f"Left folder:   {Path(args.left_output_dir).resolve()}",
        f"Right dataset: {right_label}",
        f"Right folder:  {Path(args.right_output_dir).resolve()}",
        f"Person table:  {Path(args.person_table).resolve()}",
        f"Workers:       {args.workers}",
        "",
        "Definitions",
        "-----------",
        "Evidence conservation compares evidence terms (evidence_type=normalized_value) and ignores file path, row number, and source context.",
        "Large evidence terms are compared using stable 128-bit digests to reduce RAM use; counts/overlap are unaffected for practical purposes.",
        "Cluster conservation compares configured cluster merge terms where present, falling back to anchor/evidence values for singleton-like clusters.",
        "Known-person comparison uses person_key column values derived from the supplied person table, with an exact ID column treated as the primary identifier.",
        "Unknown-person comparison prefers identity terms from unknown_person_in_dataset_clusters.csv. When only the non-disclosive unknown_person_in_dataset.csv exists, rows are resolved to person_clusters.csv by person_cluster_id.",
        "",
    ]

    append_set_summary(
        lines,
        "Evidence Term Conservation",
        left_label,
        right_label,
        left_evidence["keys"],
        right_evidence["keys"],
    )
    lines.extend(
        [
            f"{left_label} atomic evidence rows scanned into comparison: {left_evidence['row_count']:,}",
            f"{right_label} atomic evidence rows scanned into comparison: {right_evidence['row_count']:,}",
            "",
        ]
    )
    append_evidence_by_type(lines, left_label, right_label, left_evidence["by_type"], right_evidence["by_type"])
    append_cluster_summary(lines, left_label, right_label, left_clusters, right_clusters)
    append_known_person_matrix(lines, person_universe, left_label, right_label, known_groups, known_group_files)
    append_unknown_summary(lines, left_label, right_label, left_unknown, right_unknown)

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def parse_args():
    parser = argparse.ArgumentParser(
        description="Compare two pii_regex_scanner output folders and write a text report."
    )
    parser.add_argument(
        "left_output_dir",
        help="First pii_regex output folder, e.g. tests/synthetic_data/outputs/breach_dump",
    )
    parser.add_argument(
        "right_output_dir",
        help="Second pii_regex output folder, e.g. tests/synthetic_data/outputs/exposed_dump",
    )
    parser.add_argument("--person-table", required=True, help="Known-person CSV used as the primary reference universe.")
    parser.add_argument(
        "--output-dir",
        default="",
        help=(
            "Folder for report.txt and comparison CSVs. Default: "
            "<left_folder_name>_vs_<right_folder_name> beside the compared output folders."
        ),
    )
    parser.add_argument("--left-label", default="", help="Optional display label for the first folder. Default: folder name.")
    parser.add_argument("--right-label", default="", help="Optional display label for the second folder. Default: folder name.")
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help=(
            "Number of worker threads for reading atomic evidence CSV files. "
            "Use 1 for lowest RAM. Try 2-4 for many small files or network latency. Default: 1"
        ),
    )
    parser.add_argument(
        "--progress-every",
        type=float,
        default=2.0,
        help="Print progress every N seconds while streaming large CSVs. Use 0 to disable. Default: 2.0",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    if args.workers < 1:
        raise SystemExit("--workers must be >= 1")
    report_path = build_report(args)
    print(f"Wrote comparison report: {report_path}")


if __name__ == "__main__":
    main()
