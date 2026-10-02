"""Top-level run orchestration for the direct-streaming scanner.

This module is responsible for:

- turning CLI arguments into runtime behaviour;
- deciding which files or scan chunks to submit to workers;
- coordinating the linear seven-stage run: file preprocessing, discovery
  preprocessing, profiling/schema planning, regex scanning, clustering,
  reidentification, and reporting;
- writing run metadata such as `run_info.txt`, `run_manifest.json`, and the
  process timing log.

The implementation is loaded into the shared pipeline namespace so the package
and standalone forms use the same runtime behaviour.
"""

PROFILE_MODE_ALIASES = {
    "columns": "standalone",
}

PROFILE_ONLY_MODES = {
    "standalone",
    "create_rules",
}

PREPROCESSING_MODES = {
    "standalone",
    "disabled",
    "integrated",
}


def canonical_profile_mode(value):
    return PROFILE_MODE_ALIASES.get(safe_cell(value), safe_cell(value))


def is_profile_only_mode(value):
    return canonical_profile_mode(value) in PROFILE_ONLY_MODES


def run_mode_label(profile_mode):
    profile_mode = canonical_profile_mode(profile_mode)
    if profile_mode == "integrated":
        return "direct_csv_streaming_with_integrated_profile_schema_plan"
    if profile_mode:
        return "column_profiling"
    return "direct_csv_streaming_no_sqlite"


def is_stage1_profile_mode(value):
    return canonical_profile_mode(value) == "integrated"


def file_preprocessing_mode(args):
    value = safe_cell(getattr(args, "file_preprocessing", "integrated") or "integrated").casefold()
    return value if value in PREPROCESSING_MODES else "integrated"


def discovery_preprocessing_mode(args):
    value = safe_cell(getattr(args, "discovery_preprocessing", "integrated") or "integrated").casefold()
    return value if value in PREPROCESSING_MODES else "integrated"

def format_elapsed(seconds):
    """Format a duration for progress logs using compact human units."""
    seconds = max(0.0, float(seconds or 0.0))
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours = minutes // 60
    minutes = minutes % 60
    return f"{hours}h {minutes}m {secs}s"


def format_hms(seconds):
    """Format a duration as HH:MM:SS for summaries and manifests."""
    seconds = max(0, int(float(seconds or 0)))
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def iso_timestamp(ts=None):
    """Return a local ISO timestamp for logs and manifest rows."""
    return datetime.fromtimestamp(ts or time.time()).isoformat(timespec="seconds")


def progress_percent(value):
    """Clamp worker progress into the 0-100 range expected by the UI/logs."""
    if value is None:
        return None
    try:
        return max(0.0, min(100.0, float(value)))
    except (TypeError, ValueError):
        return None


def target_progress_key(target):
    """Build a stable progress key for a file or chunk submission target."""
    target_type, value = target
    if target_type == "scan_chunk" and isinstance(value, dict):
        return "chunk:" + "|".join([
            str(value.get("file_path", "")),
            str(value.get("chunk_index", "")),
            str(value.get("start_line", "")),
            str(value.get("row_number_offset", "")),
        ])
    return f"{target_type}:{value}"


def target_progress_path(target):
    """Return the underlying file path for a file or chunk target."""
    target_type, value = target
    if target_type == "scan_chunk" and isinstance(value, dict):
        return str(value.get("file_path", ""))
    return str(value)


def emit_worker_progress(args, task_key, file_path, stage, percent=None, message=""):
    """Best-effort worker heartbeat emission.

    Workers push lightweight progress messages onto the shared queue. The parent
    process can then print aggregated progress without blocking the actual scan.
    Queue failures are intentionally ignored so progress reporting never breaks a
    scan.
    """
    queue = getattr(args, "progress_queue", None)
    if queue is None:
        return
    try:
        queue.put({
            "event": "progress",
            "task_key": task_key,
            "file_path": file_path,
            "pid": os.getpid(),
            "stage": stage,
            "percent": progress_percent(percent),
            "message": message,
            "timestamp": time.time(),
        })
    except Exception:
        pass


PROCESS_TIMING_FIELDS = [
    "timestamp", "pid", "task_key", "result_kind", "chunk_index", "final_chunk",
    "file_path", "file_name", "extension", "size_bytes", "status",
    "elapsed_seconds", "hash_seconds", "extraction_seconds", "regex_seconds",
    "xml_evidence_scope_seconds", "worker_total_seconds", "text_chars_scanned",
    "finding_count", "candidate_count", "error",
]


def process_timing_row(result):
    """Flatten one worker result into a process_timing.log row."""
    summary = result.get("summary", {})
    timings = result.get("timings", {})
    process_info = result.get("process_info", {})
    return {
        "timestamp": iso_timestamp(process_info.get("finished_at_epoch")),
        "pid": process_info.get("pid", ""),
        "task_key": process_info.get("task_key", ""),
        "result_kind": result.get("result_kind", "file"),
        "chunk_index": result.get("chunk_index", ""),
        "final_chunk": result.get("final_chunk", ""),
        "file_path": summary.get("file_path", process_info.get("file_path", "")),
        "file_name": summary.get("file_name", ""),
        "extension": summary.get("extension", ""),
        "size_bytes": summary.get("size_bytes", ""),
        "status": summary.get("status", ""),
        "elapsed_seconds": f"{float(process_info.get('elapsed_seconds') or timings.get('worker_total_seconds') or 0):.6f}",
        "hash_seconds": f"{float(timings.get('hash_seconds') or 0):.6f}",
        "extraction_seconds": f"{float(timings.get('extraction_seconds') or 0):.6f}",
        "regex_seconds": f"{float(timings.get('regex_seconds') or 0):.6f}",
        "xml_evidence_scope_seconds": f"{float(timings.get('xml_evidence_scope_seconds') or 0):.6f}",
        "worker_total_seconds": f"{float(timings.get('worker_total_seconds') or 0):.6f}",
        "text_chars_scanned": summary.get("text_chars_scanned", ""),
        "finding_count": summary.get("finding_count", ""),
        "candidate_count": summary.get("candidate_count", ""),
        "error": summary.get("error", ""),
    }


def output_paths(output_dir):
    """Return the canonical output file/folder layout for one scanner run."""
    file_preprocessing_dir = os.path.join(output_dir, "1.File_Preprocessing")
    discovery_preprocessing_dir = os.path.join(output_dir, "2.Discovery_Preprocessing")
    profiling_dir = os.path.join(output_dir, "3.Profiling")
    regex_dir = os.path.join(output_dir, "4.Regex_Scanning")
    clustering_dir = os.path.join(output_dir, "5.Clustering")
    reidentification_dir = os.path.join(output_dir, "6.Reidentification")
    reporting_dir = os.path.join(output_dir, "7.Reporting")
    metadata_dir = os.path.join(reporting_dir, "metadata")
    index_dir = os.path.join(reporting_dir, "indexes")
    return {
        "output_dir": output_dir,
        "file_preprocessing_dir": file_preprocessing_dir,
        "discovery_preprocessing_dir": discovery_preprocessing_dir,
        "profiling_dir": profiling_dir,
        "regex_dir": regex_dir,
        "clustering_dir": clustering_dir,
        "reidentification_dir": reidentification_dir,
        "reporting_dir": reporting_dir,
        "metadata_dir": metadata_dir,
        "findings": os.path.join(regex_dir, "pii_regex_evidence"),
        "file_summary": os.path.join(regex_dir, "file_summary.csv"),
        "errors": os.path.join(regex_dir, "pii_regex_evidence", "errors.csv"),
        "linked_evidence": os.path.join(regex_dir, "linked_evidence.csv"),
        "entity_summary": os.path.join(regex_dir, "entity_summary.csv"),
        "regex_summary": os.path.join(regex_dir, "regex_summary.csv"),
        "person_clusters": os.path.join(clustering_dir, "clusters.csv"),
        "no_list_clusters": os.path.join(reidentification_dir, "clusters_not_in_list.csv"),
        "no_list_summary": os.path.join(reidentification_dir, "clusters_not_in_list_redacted.csv"),
        "no_list_risk": os.path.join(reidentification_dir, "clusters_not_in_list_risk_matrix.csv"),
        "no_list_evidence": os.path.join(reidentification_dir, "Clusters_not_in_list_evidence"),
        "run_info": os.path.join(reporting_dir, "run_info.txt"),
        "process_timing_log": os.path.join(metadata_dir, "process_timing.log"),
        "run_manifest": os.path.join(reporting_dir, "run_manifest.json"),
        "index_dir": index_dir,
        "discovery_index": os.path.join(discovery_preprocessing_dir, "discovery.json"),
        "file_index": os.path.join(file_preprocessing_dir, "file.index.json"),
        "person_tables_index": os.path.join(discovery_preprocessing_dir, "person-tables.index.json"),
        "cluster_members": os.path.join(clustering_dir, "cluster_members.csv"),
        "columns_all_profiles": os.path.join(profiling_dir, "columns_all_profiles.csv"),
        "unknown_column_profiles": os.path.join(profiling_dir, "columns_unknown_profiles.csv"),
        "column_rule_candidates": os.path.join(profiling_dir, "columns_rule_candidates.csv"),
        "review_only_column_candidates": os.path.join(profiling_dir, "columns_review_candidates.csv"),
        "schema_plan": os.path.join(profiling_dir, "schema_plan.csv"),
        "table_sketches": os.path.join(profiling_dir, "table_sketches.csv"),
        "table_families": os.path.join(profiling_dir, "table_families.csv"),
        "value_type_candidates": os.path.join(profiling_dir, "value_type_candidates.csv"),
        "rule_coverage": os.path.join(profiling_dir, "rule_coverage.csv"),
        "draft_table_column_rules": os.path.join(profiling_dir, "draft_table_column_rules"),
        "draft_rule_manifest": os.path.join(profiling_dir, "draft_table_column_rules", "draft_rule_manifest.csv"),
    }


def ensure_output_parent(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def ensure_clustering_output_dirs(paths):
    for key in ("person_clusters", "cluster_members"):
        if paths.get(key):
            ensure_output_parent(paths[key])


def ensure_reidentification_output_dirs(paths, write_person_evidence=False):
    for key in ("no_list_clusters", "no_list_summary", "no_list_risk"):
        if paths.get(key):
            ensure_output_parent(paths[key])
    if write_person_evidence and paths.get("no_list_evidence"):
        Path(paths["no_list_evidence"]).mkdir(parents=True, exist_ok=True)


def initialize_rules(args, progress_callback=None):
    """Load regex, table-header, and identity-anchor configuration for a run."""
    def report(message):
        if callable(progress_callback):
            progress_callback(message)

    report("applying email suffix configuration")
    set_email_suffix(args.email_suffix)
    report("applying email wildcard configuration")
    set_email_wildcards(getattr(args, "email_wildcard", []))
    # In standalone profile mode, NLP is used by the profiling suggestion layer
    # rather than by the live scanner header resolver. That keeps profile
    # outputs auditable: labels remain visible as candidates/review rows instead
    # of being silently upgraded into resolved headers by the scan path itself.
    report("configuring NLP-assisted header resolution")
    set_nlp_mode(bool(
        getattr(args, "nlp", False)
        and not is_profile_only_mode(getattr(args, "profile", ""))
    ))
    report("loading person identity anchor rules")
    load_identity_anchor_config(args.rules)
    report("loading regex search rules")
    load_rules(args.rules)
    report("loading table column rules")
    load_table_column_rules(args.rules)
    person_mode = discovery_preprocessing_mode(args)
    if getattr(args, "person_tables", None) and person_mode in {"integrated", "standalone"}:
        report("building person-table exact-match index")
        ensure_person_table_exact_match_index(args, progress_callback=report)
    elif getattr(args, "person_tables", None):
        report(f"person-table exact-match index deferred; discovery-preprocessing={person_mode}")
    else:
        report("no person tables supplied; clearing person-table exact-match index")
        ensure_person_table_exact_match_index(args, progress_callback=report)
    report("synchronising runtime state")
    sync_runtime_state()


def resolve_worker_count(requested_workers, targets):
    """Choose the worker count for Stage 1.

    `--workers N` is always respected when N > 0.

    With `--workers 0`, the scanner uses a conservative auto mode:

    - one fewer than logical CPU count;
    - never fewer than 1;
    - never more workers than there are file targets to scan.
    """
    if requested_workers and requested_workers > 0:
        return requested_workers

    cpu_count = os.cpu_count() or DEFAULT_AUTO_WORKERS
    auto_workers = max(1, cpu_count - 1)

    file_sizes = []
    for target_type, path in targets:
        if target_type != "file":
            continue
        try:
            file_sizes.append(os.path.getsize(path))
        except OSError:
            continue
    total_files = len(file_sizes)
    if total_files <= 1:
        return 1
    return min(auto_workers, max(1, total_files))


def resolve_streaming_worker_count(requested_workers):
    """Choose Stage 1 workers when discovery is streamed and target count is unknown."""
    if requested_workers and requested_workers > 0:
        return requested_workers
    cpu_count = os.cpu_count() or DEFAULT_AUTO_WORKERS
    return max(1, cpu_count - 1)


def resolve_hash_worker_count(requested_hash_workers, requested_scan_workers, hash_target_count):
    """Choose bounded process count for Stage 1 content hashing."""
    if hash_target_count <= 0:
        return 1
    try:
        requested_hash_workers = int(requested_hash_workers or 0)
    except (TypeError, ValueError):
        requested_hash_workers = 0
    if requested_hash_workers > 0:
        return min(requested_hash_workers, hash_target_count)
    try:
        requested_scan_workers = int(requested_scan_workers or 0)
    except (TypeError, ValueError):
        requested_scan_workers = 0
    if requested_scan_workers > 0:
        base = requested_scan_workers
    else:
        base = max(1, (os.cpu_count() or DEFAULT_AUTO_WORKERS) - 1)
    return min(max(1, base * 2), 16, hash_target_count)


def resolve_hash_batch_size(hash_target_count, hash_worker_count):
    """Choose a small batch size so process-pool hashing avoids per-file churn."""
    if hash_target_count <= 0:
        return 1
    hash_worker_count = max(1, int(hash_worker_count or 1))
    # Aim for several waves per worker so progress remains visible, but avoid
    # submitting tens of thousands of one-file futures for many small files.
    return max(1, min(64, (hash_target_count + (hash_worker_count * 8) - 1) // (hash_worker_count * 8)))


def batched_sequence(values, batch_size):
    """Yield lists of values in fixed-size batches."""
    batch_size = max(1, int(batch_size or 1))
    for start in range(0, len(values), batch_size):
        yield values[start:start + batch_size]


def large_file_threshold_bytes(args):
    """Convert the large-file split threshold from MB to bytes."""
    value = float(getattr(args, "large_file_cutoff_mb", 100) or 0)
    return max(0, int(value * 1024 * 1024))


def should_split_large_file(path, args, metadata):
    """Return whether this file should be turned into intra-file scan chunks.

    Large-file chunking is only used where rows/records can be scanned
    independently without changing the evidence semantics.
    """
    if getattr(args, "max_findings_per_file", 0):
        return False
    if getattr(args, "structured_max_records_per_file", 0):
        return False
    threshold = large_file_threshold_bytes(args)
    if threshold <= 0:
        return False
    try:
        size_bytes = metadata.get("size_bytes") or os.path.getsize(path)
    except OSError:
        return False
    if size_bytes < threshold:
        return False
    extension = (metadata.get("detected_extension") or Path(path).suffix).casefold()
    if extension == ".xml":
        return getattr(args, "xml_scan", "fast") == "structured"
    return extension in {".jsonl", ".csv", ".tsv"}


def duplicate_content_group_id(args, digest):
    digest = safe_cell(digest)
    if not digest:
        return ""
    return f"{selected_file_hash_algorithm(args)}:{digest}"


def index_dir_path(args, paths):
    """Return the reusable index directory for file/discovery/person caches."""
    return os.path.abspath(getattr(args, "index_dir", "") or paths["index_dir"])


def file_index_path(args, paths):
    """Return the reusable preprocessing index path for this run."""
    if not getattr(args, "index_dir", ""):
        return os.path.abspath(paths["file_index"])
    return os.path.join(index_dir_path(args, paths), "file.index.json")


def person_tables_index_path(args, paths):
    """Return the reusable known-person table index path for this run."""
    if not getattr(args, "index_dir", ""):
        return os.path.abspath(paths["person_tables_index"])
    return os.path.join(index_dir_path(args, paths), "person-tables.index.json")


def discovery_index_path(args, paths):
    """Return the reusable worker discovery bundle path for this run."""
    if not getattr(args, "index_dir", ""):
        return os.path.abspath(paths["discovery_index"])
    return os.path.join(index_dir_path(args, paths), "discovery.json")


def indexed_mtime_ns(path):
    try:
        return os.stat(path).st_mtime_ns
    except OSError:
        return None


def metadata_current_for_path(path, metadata):
    """Return whether a cached metadata row still describes the current file."""
    if not metadata:
        return False
    try:
        stat = os.stat(path)
    except OSError:
        return False
    try:
        indexed_size = int(metadata.get("size_bytes") or -1)
    except (TypeError, ValueError):
        indexed_size = -1
    try:
        indexed_mtime = int(metadata.get("mtime_ns") or -1)
    except (TypeError, ValueError):
        indexed_mtime = -1
    return indexed_size == stat.st_size and indexed_mtime == stat.st_mtime_ns


def file_index_payload_compatible(payload, args=None):
    """Return whether a reusable file index belongs to the current run setup."""
    if args is None:
        return True, ""
    if not isinstance(payload, dict):
        return False, "index payload is not an object"
    indexed_root = os.path.abspath(safe_cell(payload.get("root")))
    current_root = os.path.abspath(safe_cell(getattr(args, "root", "")))
    if indexed_root and current_root and os.path.normcase(indexed_root) != os.path.normcase(current_root):
        return False, f"root mismatch: index={indexed_root}; current={current_root}"
    indexed_hash_mode = safe_cell(payload.get("hash_mode"))
    current_hash_mode = safe_cell(getattr(args, "hash_mode", ""))
    if indexed_hash_mode and current_hash_mode and indexed_hash_mode != current_hash_mode:
        return False, f"hash-mode mismatch: index={indexed_hash_mode}; current={current_hash_mode}"
    indexed_file_hash = safe_cell(payload.get("file_hash"))
    current_file_hash = safe_cell(getattr(args, "file_hash", ""))
    if indexed_file_hash and current_file_hash and indexed_file_hash.casefold() != current_file_hash.casefold():
        return False, f"file-hash mismatch: index={indexed_file_hash}; current={current_file_hash}"
    indexed_duplicate_files = safe_cell(payload.get("duplicate_files"))
    current_duplicate_files = safe_cell(getattr(args, "duplicate_files", getattr(args, "duplicate_content", "")))
    if indexed_duplicate_files and current_duplicate_files and indexed_duplicate_files != current_duplicate_files:
        return False, f"duplicate-files mismatch: index={indexed_duplicate_files}; current={current_duplicate_files}"
    return True, ""


def load_file_index(index_path, trust=False, args=None):
    """Load reusable preprocessing metadata.

    With ``trust=True`` (used for explicit --index-dir), rows are accepted
    without per-file stat/mtime validation, but the index-level root/hash/
    duplicate options must still match the current run.
    """
    if not index_path or not os.path.exists(index_path):
        return {}
    try:
        with open(index_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        return {}
    rows = payload.get("files") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return {}
    compatible, reason = file_index_payload_compatible(payload, args=args)
    if not compatible:
        print(f"File index ignored: {index_path}; {reason}", flush=True)
        return {}
    metadata_by_path = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        path = os.path.abspath(safe_cell(row.get("file_path") or row.get("path")))
        if not path or (not trust and not metadata_current_for_path(path, row)):
            continue
        metadata_by_path[path] = {
            "size_bytes": int(row.get("size_bytes") or 0),
            "mtime_ns": int(row.get("mtime_ns") or 0),
            "detected_extension": safe_cell(row.get("detected_extension")),
            "md5": safe_cell(row.get("md5")),
            "sha256": safe_cell(row.get("sha256")),
            "duplicate_content_group": safe_cell(row.get("duplicate_content_group")),
            "duplicate_content_index": safe_cell(row.get("duplicate_content_index")),
            "duplicate_of": safe_cell(row.get("duplicate_of")),
            "duplicate_path_count": safe_cell(row.get("duplicate_path_count")),
            "duplicate_paths": safe_cell(row.get("duplicate_paths")),
            "duplicate_content_action": safe_cell(row.get("duplicate_content_action")),
        }
    return metadata_by_path


def file_index_row(path, metadata):
    path = os.path.abspath(path)
    row = {
        "file_path": path,
        "file_name": os.path.basename(path),
        "extension": Path(path).suffix.casefold().lstrip("."),
        "size_bytes": metadata.get("size_bytes", ""),
        "mtime_ns": metadata.get("mtime_ns") or indexed_mtime_ns(path) or "",
        "detected_extension": safe_cell(metadata.get("detected_extension")),
        "md5": safe_cell(metadata.get("md5")),
        "sha256": safe_cell(metadata.get("sha256")),
        "duplicate_content_group": safe_cell(metadata.get("duplicate_content_group")),
        "duplicate_content_index": safe_cell(metadata.get("duplicate_content_index")),
        "duplicate_of": safe_cell(metadata.get("duplicate_of")),
        "duplicate_path_count": safe_cell(metadata.get("duplicate_path_count")),
        "duplicate_paths": safe_cell(metadata.get("duplicate_paths")),
        "duplicate_content_action": safe_cell(metadata.get("duplicate_content_action")),
    }
    if not row["size_bytes"]:
        try:
            row["size_bytes"] = os.path.getsize(path)
        except OSError:
            row["size_bytes"] = ""
    return row


def write_file_index(index_path, metadata_by_path, args, mode="integrated"):
    """Write reusable preprocessing/file metadata for future runs."""
    if not index_path:
        return 0
    ensure_output_parent(index_path)
    rows = [
        file_index_row(path, metadata)
        for path, metadata in sorted(metadata_by_path.items(), key=lambda item: os.path.normcase(item[0]).casefold())
        if path
    ]
    payload = {
        "schema_version": 1,
        "created_at": iso_timestamp(),
        "mode": mode,
        "root": os.path.abspath(getattr(args, "root", "") or ""),
        "rules": os.path.abspath(getattr(args, "rules", "") or ""),
        "hash_mode": getattr(args, "hash_mode", ""),
        "file_hash": getattr(args, "file_hash", ""),
        "duplicate_files": getattr(args, "duplicate_files", getattr(args, "duplicate_content", "")),
        "files": rows,
    }
    with open(index_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return len(rows)


def targets_from_file_index(metadata_by_path):
    """Return scan targets represented by a loaded file index."""
    return [("file", path) for path in metadata_by_path.keys()]


def rules_path_fingerprint(path):
    """Return a stable fingerprint for the configured rules tree/file."""
    if not safe_cell(path):
        return ""
    path = Path(path)
    payload = []
    try:
        if path.is_file():
            payload.append((str(path.resolve()), hashlib.sha256(path.read_bytes()).hexdigest()))
        elif path.is_dir():
            for rule_file in sorted(path.rglob("*.json")):
                try:
                    payload.append((str(rule_file.relative_to(path)), hashlib.sha256(rule_file.read_bytes()).hexdigest()))
                except OSError:
                    continue
        else:
            return ""
    except OSError:
        return ""
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def write_discovery_index(index_path, args, paths, run_info, mode="integrated"):
    """Write a worker-readable discovery bundle for rules/config/reference indexes."""
    if not index_path:
        return ""
    ensure_output_parent(index_path)
    evidence_metadata = current_evidence_output_metadata()
    payload = {
        "schema_version": 1,
        "created_at": iso_timestamp(),
        "mode": mode,
        "root": os.path.abspath(getattr(args, "root", "") or ""),
        "rules": os.path.abspath(getattr(args, "rules", "") or ""),
        "rules_fingerprint": rules_path_fingerprint(getattr(args, "rules", "")),
        "regex_rule_count": len(PATTERNS),
        "regex_rule_fingerprints": current_rule_fingerprints(),
        "expected_evidence_outputs": evidence_metadata,
        "table_column_rules_loaded": bool(TABLE_COLUMN_RULES),
        "identity_anchor_strong_types": sorted(PERSON_CLUSTER_STRONG_ANCHORS),
        "email_suffix": list(normalize_email_suffixes(getattr(args, "email_suffix", ""))),
        "nlp": bool(getattr(args, "nlp", False)),
        "xml_scan": getattr(args, "xml_scan", ""),
        "index_dir": index_dir_path(args, paths),
        "file_index": file_index_path(args, paths),
        "person_tables": [os.path.abspath(path) for path in getattr(args, "person_tables", []) or []],
        "person_tables_index": person_tables_index_path(args, paths),
        "person_tables_index_rows": len(PERSON_TABLE_EXACT_MATCH_INDEX),
        "person_table_summary_stems": list(PERSON_TABLE_SUMMARY_STEMS),
    }
    with open(index_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    run_info["discovery_index"] = index_path
    run_info["discovery_index_regex_rules"] = len(PATTERNS)
    run_info["discovery_index_evidence_outputs"] = len(evidence_metadata)
    run_info["discovery_index_person_table_keys"] = len(PERSON_TABLE_EXACT_MATCH_INDEX)
    return index_path


def discover_targets_for_preprocessing(args, paths):
    """Discover and prioritise filesystem targets for source-file preprocessing."""
    root_path = os.path.abspath(args.root)
    output_dir = os.path.abspath(args.output_dir)
    output_files = paths.values()
    targets = list(iter_targets(
        root_path,
        output_dir,
        output_files,
        args.include_hidden,
        args.exclude,
    ))
    return prioritize_targets(targets, args.priority)


def hash_metadata_batch_worker(batch, options):
    """Hash a batch of files inside a process-pool worker."""
    worker_args = argparse.Namespace(**dict(options or {}))
    results = []
    hash_mode = getattr(worker_args, "hash_mode", "duplicate-candidates")
    for path, metadata, scan_extension in batch:
        metadata = dict(metadata or {})
        try:
            metadata.update(hash_metadata_for_file(
                path,
                worker_args,
                scan_extension,
                progress_callback=None,
                total_size=metadata.get("size_bytes") or None,
                progress_base=0.0,
                progress_span=100.0,
                force=(hash_mode == "duplicate-candidates"),
            ))
            results.append((path, metadata, ""))
        except OSError as exc:
            results.append((path, metadata, safe_cell(exc)))
    return results


def precompute_hash_metadata_for_targets(targets, args, progress_callback=None, existing_metadata_by_path=None):
    """Build per-file metadata and duplicate groups before Stage 1 dispatch."""
    metadata_by_path = {}
    digest_groups = {}
    existing_metadata_by_path = existing_metadata_by_path or {}
    file_targets = [path for target_type, path in targets if target_type == "file"]
    size_groups = {}
    total_files = len(file_targets)
    processed_files = 0
    hashed_files = 0
    duplicate_group_count = 0
    duplicate_file_count = 0

    def emit(status, path="", file_percent=None, force=False):
        if callable(progress_callback):
            progress_callback({
                "status": status,
                "path": path,
                "processed_files": processed_files,
                "total_files": total_files,
                "hashed_files": hashed_files,
                "duplicate_groups": duplicate_group_count,
                "duplicate_files": duplicate_file_count,
                "file_percent": file_percent,
                "force": force,
            })

    def add_digest_path(digest, path):
        nonlocal duplicate_group_count, duplicate_file_count
        if not digest:
            return
        group_paths = digest_groups.setdefault(digest, [])
        previous_count = len(group_paths)
        group_paths.append(path)
        if previous_count == 1:
            duplicate_group_count += 1
            duplicate_file_count += 1
        elif previous_count > 1:
            duplicate_file_count += 1

    emit("collecting file metadata", force=True)
    for target_type, path in targets:
        if target_type != "file":
            continue
        extension = Path(path).suffix.casefold()
        metadata = {
            "size_bytes": "",
            "mtime_ns": "",
            "detected_extension": extension,
            "md5": "",
            "sha256": "",
        }
        existing = existing_metadata_by_path.get(os.path.abspath(path)) or existing_metadata_by_path.get(path)
        if existing:
            metadata.update(existing)
            metadata_by_path[path] = metadata
            try:
                size_groups.setdefault(metadata.get("size_bytes") or "", []).append(path)
            except TypeError:
                pass
            digest = selected_content_hash(metadata, args)
            if digest:
                add_digest_path(digest, path)
            processed_files += 1
            emit("reused file-index metadata", path=path)
            continue
        try:
            emit("detecting content type", path=path)
            metadata["size_bytes"] = os.path.getsize(path)
            metadata["mtime_ns"] = indexed_mtime_ns(path) or ""
            metadata["detected_extension"] = detect_extension_from_content(path, extension)
            size_groups.setdefault(metadata["size_bytes"], []).append(path)
        except OSError:
            pass
        metadata_by_path[path] = metadata
        processed_files += 1
        emit("file metadata ready", path=path)

    hash_mode = getattr(args, "hash_mode", "duplicate-candidates")
    if hash_mode == "duplicate-candidates":
        hash_paths = {
            path
            for group_paths in size_groups.values()
            if len(group_paths) > 1
            for path in group_paths
            if not selected_content_hash(metadata_by_path.get(path, {}), args)
            if processed_hash_eligible(
                args,
                metadata_by_path.get(path, {}).get("detected_extension") or Path(path).suffix.casefold(),
            )
        }
        emit(f"hashing duplicate-size candidates ({len(hash_paths):,} files)", force=True)
    else:
        hash_paths = {
            path
            for path in file_targets
            if not selected_content_hash(metadata_by_path.get(path, {}), args)
            if should_hash_file(
                args,
                metadata_by_path.get(path, {}).get("detected_extension") or Path(path).suffix.casefold(),
            )
        }
        if hash_paths:
            emit(f"hashing files ({len(hash_paths):,} files)", force=True)

    hash_path_list = [path for path in file_targets if path in hash_paths]
    hash_worker_count = resolve_hash_worker_count(getattr(args, "hash_workers", 0), getattr(args, "workers", 0), len(hash_path_list))

    if hash_path_list:
        batch_size = resolve_hash_batch_size(len(hash_path_list), hash_worker_count)
        emit(
            f"hashing with {hash_worker_count:,} process(es), batch size {batch_size:,}",
            force=True,
        )
    if hash_path_list and hash_worker_count > 1:
        hash_options = {
            "hash_mode": getattr(args, "hash_mode", "duplicate-candidates"),
            "file_hash": selected_file_hash_algorithm(args),
            "scan_images": bool(getattr(args, "scan_images", False)),
        }
        hash_batches = [
            [
                (
                    path,
                    metadata_by_path.get(path, {}),
                    metadata_by_path.get(path, {}).get("detected_extension") or Path(path).suffix.casefold(),
                )
                for path in batch
            ]
            for batch in batched_sequence(hash_path_list, batch_size)
        ]
        with ProcessPoolExecutor(max_workers=hash_worker_count) as pool:
            pending = {pool.submit(hash_metadata_batch_worker, batch, hash_options) for batch in hash_batches}
            while pending:
                progress_every = getattr(args, "progress_every", 0)
                done, pending = wait(pending, timeout=progress_every if progress_every > 0 else None, return_when=FIRST_COMPLETED)
                if not done:
                    emit("hashing", force=True)
                    continue
                for future in done:
                    try:
                        batch_results = future.result()
                    except OSError:
                        continue
                    for path, metadata, error in batch_results:
                        if error:
                            emit(f"hash error: {error}", path=path)
                            continue
                        metadata_by_path[path].update(metadata)
                        hashed_files += 1
                        digest = selected_content_hash(metadata, args)
                        add_digest_path(digest, path)
                        emit("file hash ready", path=path)
    else:
        for path in hash_path_list:
            try:
                batch_results = hash_metadata_batch_worker([
                    (
                        path,
                        metadata_by_path.get(path, {}),
                        metadata_by_path.get(path, {}).get("detected_extension") or Path(path).suffix.casefold(),
                    )
                ], {
                    "hash_mode": getattr(args, "hash_mode", "duplicate-candidates"),
                    "file_hash": selected_file_hash_algorithm(args),
                    "scan_images": bool(getattr(args, "scan_images", False)),
                })
            except OSError:
                continue
            if not batch_results:
                continue
            path, metadata, error = batch_results[0]
            if error:
                emit(f"hash error: {error}", path=path)
                continue
            metadata_by_path[path].update(metadata)
            hashed_files += 1
            digest = selected_content_hash(metadata, args)
            add_digest_path(digest, path)
            emit("file hash ready", path=path)

    emit("grouping duplicates", force=True)
    for digest, group_paths in digest_groups.items():
        action_by_index = {}
        for index, path in enumerate(group_paths):
            if index == 0:
                action_by_index[path] = "scanned"
            elif args.duplicate_content == "scan":
                action_by_index[path] = "scanned_duplicate"
            elif args.duplicate_content == "collapse":
                action_by_index[path] = "duplicate_collapsed"
            else:
                action_by_index[path] = "duplicate_reported"
        for index, path in enumerate(group_paths):
            metadata_by_path[path].update({
                "duplicate_content_group": duplicate_content_group_id(args, digest),
                "duplicate_content_index": str(index + 1),
                "duplicate_of": group_paths[0] if index > 0 else "",
                "duplicate_path_count": str(len(group_paths)),
                "duplicate_paths": " | ".join(group_paths),
                "duplicate_content_action": action_by_index[path],
            })
    emit("complete", force=True)
    return metadata_by_path, digest_groups


def duplicate_filtered_targets(targets, args, metadata_by_path, digest_groups):
    if args.duplicate_content == "scan":
        return targets, {}
    duplicate_paths = {
        path
        for group_paths in digest_groups.values()
        for path in group_paths[1:]
    }
    duplicates_by_canonical = {}
    for group_paths in digest_groups.values():
        if len(group_paths) > 1:
            duplicates_by_canonical.setdefault(group_paths[0], []).extend(group_paths[1:])
    filtered = [
        (target_type, path)
        for target_type, path in targets
        if target_type != "file" or path not in duplicate_paths
    ]
    return filtered, duplicates_by_canonical


def duplicate_summary_result(path, metadata, args):
    file_name = os.path.basename(path)
    extension = Path(path).suffix.casefold()
    status = "duplicate_reported"
    message = f"Duplicate content; first copy scanned at {metadata.get('duplicate_of', '')}."
    summary = summary_row(
        path,
        file_name,
        extension,
        metadata.get("size_bytes") or "",
        metadata.get("md5") or "",
        status,
        0,
        0,
        0,
        message,
        detected_extension=metadata.get("detected_extension") or extension,
        sha256=metadata.get("sha256") or "",
        duplicate_content_group=metadata.get("duplicate_content_group", ""),
        duplicate_content_index=metadata.get("duplicate_content_index", ""),
        duplicate_of=metadata.get("duplicate_of", ""),
        duplicate_path_count=metadata.get("duplicate_path_count", ""),
        duplicate_paths=metadata.get("duplicate_paths", ""),
        duplicate_content_action=metadata.get("duplicate_content_action", "duplicate_reported"),
    )
    return {
        "summary": summary,
        "errors": [],
        "findings": [],
        "candidates": [],
        "candidate_count": 0,
        "entity_counts": Counter(),
        "entity_files": set(),
        "timings": {"hash_seconds": 0.0, "extraction_seconds": 0.0, "regex_seconds": 0.0, "worker_total_seconds": 0.0},
        "process_info": {
            "pid": os.getpid(),
            "task_key": f"duplicate:{path}",
            "file_path": path,
            "elapsed_seconds": 0.0,
        },
    }


def rewrite_duplicate_row(row, metadata):
    rewritten = dict(row)
    path = metadata.get("file_path")
    file_name = metadata.get("file_name") or os.path.basename(path)
    extension = (metadata.get("extension") or Path(path).suffix).lstrip(".")
    rewritten.update({
        "file_path": path,
        "file_name": file_name,
        "extension": extension,
        "size_bytes": metadata.get("size_bytes", rewritten.get("size_bytes", "")),
        "md5": metadata.get("md5", rewritten.get("md5", "")),
    })
    return rewritten


def clone_result_for_duplicate(result, duplicate_path, metadata):
    metadata = dict(metadata)
    metadata["file_path"] = duplicate_path
    metadata["file_name"] = os.path.basename(duplicate_path)
    metadata["extension"] = Path(duplicate_path).suffix.lstrip(".").casefold()
    scan_extension = (metadata.get("detected_extension") or Path(duplicate_path).suffix).casefold()
    duplicate_file_info = {
        "file_path": duplicate_path,
        "file_name": metadata["file_name"],
        "extension": metadata["extension"],
        "size_bytes": metadata.get("size_bytes", ""),
        "md5": metadata.get("md5", ""),
        "sha256": metadata.get("sha256", ""),
    }
    duplicate_signal_findings = file_signal_findings(duplicate_file_info, scan_extension)
    findings = duplicate_signal_findings + [
        rewrite_duplicate_row(finding, metadata)
        for finding in result.get("findings", [])
        if finding.get("pattern_name") not in FILE_SIGNAL_PATTERN_NAMES
    ]
    candidates = [
        rewrite_duplicate_row(candidate, metadata)
        for candidate in result.get("candidates", [])
    ]
    errors = [
        rewrite_duplicate_row(error, metadata)
        for error in result.get("errors", [])
    ]
    entity_counts = Counter(finding.get("evidence_type", "") for finding in findings if finding.get("evidence_type"))
    summary = dict(result.get("summary") or {})
    summary.update({
        "file_path": duplicate_path,
        "file_name": metadata["file_name"],
        "extension": metadata["extension"],
        "detected_extension": (metadata.get("detected_extension") or summary.get("detected_extension") or metadata["extension"]).lstrip("."),
        "size_bytes": metadata.get("size_bytes", summary.get("size_bytes", "")),
        "md5": metadata.get("md5", summary.get("md5", "")),
        "sha256": metadata.get("sha256", summary.get("sha256", "")),
        "status": "duplicate_collapsed",
        "finding_count": len(findings),
        "candidate_count": len(candidates),
        "error": f"Reused content-derived scan results from {metadata.get('duplicate_of', '')}.",
        "duplicate_content_group": metadata.get("duplicate_content_group", ""),
        "duplicate_content_index": metadata.get("duplicate_content_index", ""),
        "duplicate_of": metadata.get("duplicate_of", ""),
        "duplicate_path_count": metadata.get("duplicate_path_count", ""),
        "duplicate_paths": metadata.get("duplicate_paths", ""),
        "duplicate_content_action": metadata.get("duplicate_content_action", "duplicate_collapsed"),
    })
    add_summary_evidence_counts(summary, entity_counts)
    return {
        "summary": summary,
        "errors": errors,
        "findings": findings,
        "candidates": candidates,
        "candidate_count": len(candidates),
        "entity_counts": entity_counts,
        "entity_files": set(entity_counts),
        "timings": {"hash_seconds": 0.0, "extraction_seconds": 0.0, "regex_seconds": 0.0, "worker_total_seconds": 0.0},
        "process_info": {
            "pid": os.getpid(),
            "task_key": f"duplicate:{duplicate_path}",
            "file_path": duplicate_path,
            "elapsed_seconds": 0.0,
        },
        "result_kind": result.get("result_kind", "file"),
        "chunk_index": result.get("chunk_index", ""),
        "final_chunk": result.get("final_chunk", ""),
    }


def duplicate_evidence_mode(args):
    value = safe_cell(getattr(args, "duplicate_evidence", "collapse") or "collapse").casefold()
    return value if value in {"scan", "report", "collapse"} else "collapse"


def split_evidence_values(value):
    """Return stable evidence type/value pairs from a linked-evidence string."""
    pairs = []
    for item in safe_cell(value).split("|"):
        item = item.strip()
        if not item or "=" not in item:
            continue
        evidence_type, evidence_value = item.split("=", 1)
        evidence_type = safe_cell(evidence_type).casefold()
        evidence_value = " ".join(safe_cell(evidence_value).split()).casefold()
        if evidence_type and evidence_value:
            pairs.append((evidence_type, evidence_value))
    return sorted(set(pairs))


def linked_evidence_duplicate_signature(row):
    """Hash the semantic evidence payload used for duplicate row collapse.

    The signature intentionally ignores file path and row number so the same
    table row copied between non-identical files can be grouped while still
    retaining all paths/locators in provenance columns.
    """
    pairs = split_evidence_values(row.get("evidence_values", ""))
    if not pairs:
        return ""
    payload = {
        "evidence": pairs,
        "anchor_type": safe_cell(row.get("anchor_type", "")).casefold(),
        "anchor_value": " ".join(safe_cell(row.get("anchor_value", "")).split()).casefold(),
        "cluster_eligible": safe_cell(row.get("cluster_eligible", "")).casefold(),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def linked_evidence_locator(row):
    path = safe_cell(row.get("file_path", ""))
    locator = safe_cell(row.get("row_number", ""))
    if path and locator:
        return f"{path}:{locator}"
    return path or locator


def annotate_duplicate_evidence_row(row, group_key="", index="", count="", paths="", locators="", action=""):
    row = dict(row)
    row.update({
        "duplicate_evidence_group": group_key,
        "duplicate_evidence_index": index,
        "duplicate_evidence_count": count,
        "duplicate_evidence_paths": paths,
        "duplicate_evidence_locators": locators,
        "duplicate_evidence_action": action,
    })
    return row


def materialize_duplicate_evidence_rows(rows, mode):
    """Apply duplicate-evidence scan/report/collapse semantics to linked rows."""
    mode = mode if mode in {"scan", "report", "collapse"} else "collapse"
    if mode == "scan":
        return [annotate_duplicate_evidence_row(row, action="scanned") for row in rows], 0, 0

    groups = {}
    sequence = 0
    for row in rows:
        signature = linked_evidence_duplicate_signature(row)
        if signature:
            group_key = f"sha256:{signature}"
        else:
            sequence += 1
            group_key = f"unique:{sequence}"
        groups.setdefault(group_key, []).append(row)

    output_rows = []
    duplicate_groups = 0
    duplicate_rows = 0
    for group_key, grouped_rows in groups.items():
        duplicate_count = len(grouped_rows)
        is_duplicate = duplicate_count > 1 and not group_key.startswith("unique:")
        paths = sorted({safe_cell(row.get("file_path", "")) for row in grouped_rows if row.get("file_path")})
        locators = []
        seen_locators = set()
        for row in grouped_rows:
            locator = linked_evidence_locator(row)
            if locator and locator not in seen_locators:
                seen_locators.add(locator)
                locators.append(locator)
        rows_to_write = grouped_rows if mode == "report" else grouped_rows[:1]
        for index, row in enumerate(rows_to_write, start=1):
            if is_duplicate:
                action = "duplicate_collapsed" if mode == "collapse" else "duplicate_reported"
            else:
                action = "scanned"
            output_rows.append(annotate_duplicate_evidence_row(
                row,
                group_key=group_key if is_duplicate else "",
                index=str(index) if is_duplicate else "",
                count=str(duplicate_count) if is_duplicate else "",
                paths=" | ".join(paths) if is_duplicate else "",
                locators=" | ".join(locators) if is_duplicate else "",
                action=action,
            ))
        if is_duplicate:
            duplicate_groups += 1
            duplicate_rows += duplicate_count - 1
    return output_rows, duplicate_groups, duplicate_rows


def chunk_base(path, args, metadata, chunk_type, chunk_index, final_chunk=False):
    """Build the common metadata block shared by every emitted scan chunk."""
    extension = Path(path).suffix.casefold()
    detected_extension = metadata.get("detected_extension") or extension
    chunk = {
        "file_path": path,
        "file_name": os.path.basename(path),
        "extension": extension.lstrip("."),
        "detected_extension": detected_extension.lstrip("."),
        "size_bytes": metadata.get("size_bytes") or os.path.getsize(path),
        "md5": metadata.get("md5") or "",
        "sha256": metadata.get("sha256") or "",
        "duplicate_content_group": metadata.get("duplicate_content_group") or "",
        "duplicate_content_index": metadata.get("duplicate_content_index") or "",
        "duplicate_of": metadata.get("duplicate_of") or "",
        "duplicate_path_count": metadata.get("duplicate_path_count") or "",
        "duplicate_paths": metadata.get("duplicate_paths") or "",
        "duplicate_content_action": metadata.get("duplicate_content_action") or "",
        "chunk_type": chunk_type,
        "chunk_index": chunk_index,
        "final_chunk": final_chunk,
    }
    if final_chunk:
        chunk["expected_chunk_count"] = chunk_index + 1
    return chunk


def iter_jsonl_scan_chunks(path, args, metadata):
    """Yield JSONL record batches as independent scan units."""
    batch_size = max(1, int(getattr(args, "scan_unit_records", DEFAULT_SCAN_UNIT_RECORDS) or DEFAULT_SCAN_UNIT_RECORDS))
    chunk_index = 0
    start_line = 1
    batch = []
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not batch:
                start_line = line_number
            batch.append(line)
            if len(batch) >= batch_size:
                chunk = chunk_base(path, args, metadata, "jsonl", chunk_index)
                chunk.update({"lines": batch, "start_line": start_line, "row_number_offset": start_line - 1})
                yield "scan_chunk", chunk
                chunk_index += 1
                batch = []
        if batch:
            chunk = chunk_base(path, args, metadata, "jsonl", chunk_index, final_chunk=True)
            chunk.update({"lines": batch, "start_line": start_line, "row_number_offset": start_line - 1})
            yield "scan_chunk", chunk


def iter_delimited_scan_chunks(path, args, metadata):
    """Yield CSV/TSV row batches as independent scan units.

    The original header row is repeated into every chunk so downstream scanning
    behaves the same way as a whole-file table scan.
    """
    batch_size = max(1, int(getattr(args, "scan_unit_records", DEFAULT_SCAN_UNIT_RECORDS) or DEFAULT_SCAN_UNIT_RECORDS))
    extension = Path(path).suffix.casefold()
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
            return
        chunk_index = 0
        start_row = 2
        batch = []
        for source_row_number, row in enumerate(reader, start=2):
            if not batch:
                start_row = source_row_number
            batch.append(row)
            if len(batch) >= batch_size:
                chunk = chunk_base(path, args, metadata, "delimited", chunk_index)
                chunk.update({"headers": headers, "rows": batch, "table_name": Path(path).name, "row_number_offset": start_row - 1, "delimiter": getattr(dialect, "delimiter", "")})
                yield "scan_chunk", chunk
                chunk_index += 1
                batch = []
        if batch:
            chunk = chunk_base(path, args, metadata, "delimited", chunk_index, final_chunk=True)
            chunk.update({"headers": headers, "rows": batch, "table_name": Path(path).name, "row_number_offset": start_row - 1, "delimiter": getattr(dialect, "delimiter", "")})
            yield "scan_chunk", chunk


def iter_xml_scan_chunks(path, args, metadata):
    import xml.etree.ElementTree as ET

    batch_size = max(1, int(getattr(args, "scan_unit_records", DEFAULT_SCAN_UNIT_RECORDS) or DEFAULT_SCAN_UNIT_RECORDS))
    chunk_index = 0
    start_element = 1
    batch = []
    stack = []
    root_tag = None
    element_index = 0
    context = ET.iterparse(path, events=("start", "end"))
    for event, element in context:
        if event == "start":
            stack.append(element.tag)
            if root_tag is None:
                root_tag = element.tag
            continue
        is_direct_root_child = root_tag is not None and len(stack) == 2
        if is_direct_root_child:
            element_index += 1
            if not batch:
                start_element = element_index
            batch.append((element.tag, xml_element_to_structured_data(element)))
            element.clear()
            if len(batch) >= batch_size:
                chunk = chunk_base(path, args, metadata, "xml", chunk_index)
                chunk.update({"root_tag": root_tag, "records": batch, "row_locator_prefix": f"xml:{start_element}:"})
                yield "scan_chunk", chunk
                chunk_index += 1
                batch = []
        if stack:
            stack.pop()
    if batch:
        chunk = chunk_base(path, args, metadata, "xml", chunk_index, final_chunk=True)
        chunk.update({"root_tag": root_tag, "records": batch, "row_locator_prefix": f"xml:{start_element}:"})
        yield "scan_chunk", chunk


def iter_scan_tasks(targets, args, metadata_by_path):
    for target_type, path in targets:
        if target_type != "file":
            yield target_type, path
            continue
        metadata = dict(metadata_by_path.get(path, {}))
        if not should_split_large_file(path, args, metadata):
            yield target_type, path
            continue
        extension = (metadata.get("detected_extension") or Path(path).suffix).casefold()
        metadata.setdefault("detected_extension", extension)
        metadata.setdefault("size_bytes", os.path.getsize(path))
        if not selected_content_hash(metadata, args) and should_hash_file(args, extension):
            metadata.update(hash_metadata_for_file(path, args, extension))
        extension = (metadata.get("detected_extension") or Path(path).suffix).casefold()
        yielded = False
        try:
            if extension == ".jsonl":
                chunk_iter = iter_jsonl_scan_chunks(path, args, metadata)
            elif extension in {".csv", ".tsv"}:
                chunk_iter = iter_delimited_scan_chunks(path, args, metadata)
            elif extension == ".xml":
                chunk_iter = iter_xml_scan_chunks(path, args, metadata)
            else:
                chunk_iter = ()
            for chunk_target in chunk_iter:
                yielded = True
                yield chunk_target
        except Exception:
            if not yielded:
                yield target_type, path
            else:
                raise
        if not yielded:
            yield target_type, path


def task_display(target):
    target_type, value = target
    if target_type == "scan_chunk":
        return value.get("file_name") or os.path.basename(value.get("file_path", "")), "scanning chunk"
    if target_type == "empty_folder":
        return os.path.basename(value), "recording empty folder"
    return os.path.basename(value), "scanning file"



def evidence_output_name(evidence_type, pattern_name):
    return f"{rule_slug(evidence_type)}_{rule_slug(pattern_name)}.csv"

def current_evidence_output_metadata():
    """Return the atomic evidence CSVs expected for the currently loaded rules."""
    metadata = {}
    for pattern in PATTERNS:
        name = evidence_output_name(pattern.get("evidence_type", ""), pattern.get("pattern_name", ""))
        metadata[name] = {
            "evidence_type": pattern.get("evidence_type", ""),
            "pattern_name": pattern.get("pattern_name", ""),
            "fingerprint": pattern_fingerprint(pattern),
            "kind": "regex_rule",
        }
    derived_rules = list(CODE_DERIVED_EVIDENCE_RULES) + [
        {
            "evidence_type": "Name",
            "pattern_name": "assembled_table_name",
            "risk_tier": "tier_3_supporting_evidence",
            "normalization": "name_casefold",
            "risk_roles": ["name"],
        },
        {
            "evidence_type": "Name",
            "pattern_name": "person_table_authoritative_name",
            "risk_tier": "tier_3_supporting_evidence",
            "normalization": "name_casefold",
            "risk_roles": ["name"],
        },
        {
            "evidence_type": "Name",
            "pattern_name": PERSON_TABLE_EXACT_PATTERN_NAME,
            "risk_tier": "tier_3_supporting_evidence",
            "normalization": "name_casefold",
            "risk_roles": ["name"],
        },
        {
            "evidence_type": "Address",
            "pattern_name": "assembled_table_address",
            "risk_tier": "tier_3_supporting_evidence",
            "normalization": "address_compact",
            "risk_roles": ["address"],
        },
        {
            "evidence_type": "SCAN_LIMIT",
            "pattern_name": "max_findings_per_file",
            "risk_tier": "metadata",
            "normalization": "none",
            "risk_roles": [],
        },
    ]
    for rule in derived_rules:
        name = evidence_output_name(rule.get("evidence_type", ""), rule.get("pattern_name", ""))
        payload = json.dumps(rule, sort_keys=True, default=str)
        metadata.setdefault(name, {
            "evidence_type": rule.get("evidence_type", ""),
            "pattern_name": rule.get("pattern_name", ""),
            "fingerprint": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "kind": "code_derived",
        })
    for rule in TABLE_CELL_VALUE_EMIT_RULES:
        name = evidence_output_name(rule.get("evidence_type", ""), rule.get("pattern_name", ""))
        payload = json.dumps(rule, sort_keys=True, default=str)
        metadata.setdefault(name, {
            "evidence_type": rule.get("evidence_type", ""),
            "pattern_name": rule.get("pattern_name", ""),
            "fingerprint": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "kind": "table_cell_value",
        })
    for evidence_type in sorted(PERSON_TABLE_EXACT_EVIDENCE_TYPES):
        name = evidence_output_name(evidence_type, PERSON_TABLE_EXACT_PATTERN_NAME)
        payload = json.dumps({
            "evidence_type": evidence_type,
            "pattern_name": PERSON_TABLE_EXACT_PATTERN_NAME,
            "kind": "person_table_exact_match",
        }, sort_keys=True)
        metadata.setdefault(name, {
            "evidence_type": evidence_type,
            "pattern_name": PERSON_TABLE_EXACT_PATTERN_NAME,
            "fingerprint": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
            "kind": "person_table_exact_match",
        })
    return metadata


def atomic_evidence_csv_files(evidence_dir):
    if not os.path.isdir(evidence_dir):
        return []
    return [
        entry.path
        for entry in sorted(os.scandir(evidence_dir), key=lambda item: item.name)
        if entry.is_file() and entry.name.lower().endswith(".csv") and entry.name != "errors.csv"
    ]


def ensure_atomic_evidence_file(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with open(path, "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
            csv.DictWriter(handle, fieldnames=FINDING_FIELDS).writeheader()


class EvidenceOnlyWriter:
    """Append/replace atomic evidence CSVs for selected rule outputs only."""

    def __init__(self, paths, target_output_names):
        self.paths = paths
        self.evidence_dir = Path(paths["findings"])
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.target_output_names = set(target_output_names)
        self.handles = {}
        self.writers = {}
        self.finding_rows = 0
        self.csv_write_seconds = 0.0
        for name in sorted(self.target_output_names):
            path = self.evidence_dir / name
            handle = open(path, "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE)
            writer = csv.DictWriter(handle, fieldnames=FINDING_FIELDS)
            writer.writeheader()
            self.handles[name] = handle
            self.writers[name] = writer

    def write_result(self, result):
        started = time.perf_counter()
        unit_text = {}
        for finding in result.get("findings", []):
            locator = str(finding.get("row_number", ""))
            context = finding.get("context", "")
            if len(context) > len(unit_text.get(locator, "")):
                unit_text[locator] = context
        for candidate in result.get("candidates", []):
            locator = str(candidate.get("row_number", ""))
            source_row = candidate.get("source_row", "")
            if len(source_row) > len(unit_text.get(locator, "")):
                unit_text[locator] = source_row
        for finding in result.get("findings", []):
            name = evidence_output_name(finding.get("evidence_type", ""), finding.get("pattern_name", ""))
            if name not in self.target_output_names:
                continue
            row = {field: finding.get(field, "") for field in FINDING_FIELDS}
            locator = str(finding.get("row_number", ""))
            if locator in unit_text:
                row["context"] = unit_text[locator]
            self.writers[name].writerow(row)
            self.finding_rows += 1
        self.csv_write_seconds += time.perf_counter() - started

    def close(self):
        for handle in self.handles.values():
            handle.close()


def scan_selected_rule_outputs(args, paths, selected_patterns, selected_output_names, run_info):
    """Rescan the source tree for selected regex rules and write only their atomic evidence CSVs."""
    if not selected_patterns:
        for name in selected_output_names:
            ensure_atomic_evidence_file(Path(paths["findings"]) / name)
        return 0

    global PATTERNS
    original_patterns = PATTERNS
    try:
        PATTERNS = list(selected_patterns)
        configure_pattern_line_triggers()

        targets = list(iter_targets(
            os.path.abspath(args.root),
            os.path.abspath(args.output_dir),
            paths.values(),
            args.include_hidden,
            args.exclude,
        ))
        targets = prioritize_targets(targets, args.priority)
        total_files = sum(1 for target_type, _path in targets if target_type == "file")
        worker_count = resolve_worker_count(args.workers, targets)
        iterator = iter(iter_scan_tasks(targets, args, {}))
        writer = EvidenceOnlyWriter(paths, selected_output_names)
        active = {}
        phase_seconds = Counter()
        processed = 0
        last_progress = time.monotonic()

        def report(force=False):
            nonlocal last_progress
            now = time.monotonic()
            if not force and (args.progress_every <= 0 or now - last_progress < args.progress_every):
                return
            if active:
                _future, state = min(active.items(), key=lambda item: item[1]["started"])
                label = state["file"]
                elapsed = now - state["started"]
            else:
                label = "not applicable"
                elapsed = 0.0
            print(
                f"\rResume rules: rescanning selected outputs | "
                f"file {min(processed + 1, total_files):,} of {total_files:,} files | "
                f"current file: {label} | selected-rule scan: {format_elapsed(elapsed)} | "
                f"new evidence rows {writer.finding_rows:,}",
                end="\n" if force else "",
                flush=True,
            )
            last_progress = now

        def submit_next(pool, pending):
            try:
                target = next(iterator)
            except StopIteration:
                return False
            file_display, process_label = task_display(target)
            future = pool.submit(process_target, target, args)
            active[future] = {"file": file_display, "process": process_label, "started": time.monotonic()}
            pending.add(future)
            return True

        def consume(future):
            nonlocal processed
            active.pop(future, None)
            result = future.result()
            for name, seconds in result.get("timings", {}).items():
                phase_seconds[name] += seconds
            writer.write_result(result)
            is_chunk = result.get("result_kind") == "scan_chunk"
            if result["summary"].get("status") != "empty_folder" and (not is_chunk or result.get("final_chunk")):
                processed += 1
            report()

        pool = ProcessPoolExecutor(max_workers=max(1, worker_count))
        try:
            with pool:
                pending = set()
                for _ in range(max(1, worker_count)):
                    if not submit_next(pool, pending):
                        break
                report(force=True)
                while pending:
                    timeout = args.progress_every if args.progress_every > 0 else None
                    done, pending = wait(pending, timeout=timeout, return_when=FIRST_COMPLETED)
                    if not done:
                        report()
                        continue
                    for future in done:
                        consume(future)
                        submit_next(pool, pending)
        finally:
            writer.close()

        report(force=True)
        run_info["resume_rules_scanned_outputs"] = len(selected_output_names)
        run_info["resume_rules_new_finding_rows"] = writer.finding_rows
        run_info["resume_rules_csv_write_seconds"] = round(writer.csv_write_seconds, 6)
        for name, seconds in phase_seconds.items():
            run_info[f"resume_rules_{name}"] = round(seconds, 6)
        return writer.finding_rows
    finally:
        PATTERNS = original_patterns
        configure_pattern_line_triggers()


def rebuild_file_summary_from_atomic_evidence(paths):
    counts_by_file = defaultdict(Counter)
    linked_excluded_by_file = Counter()
    linked_reasons_by_file = defaultdict(Counter)
    file_metadata = {}

    for csv_path in atomic_evidence_csv_files(paths["findings"]):
        with open(csv_path, "r", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
            for row in csv.DictReader(handle):
                file_path = row.get("file_path", "")
                if not file_path:
                    continue
                evidence_type = row.get("evidence_type", "")
                if evidence_type:
                    counts_by_file[file_path][evidence_type] += 1
                file_metadata.setdefault(file_path, {
                    "file_path": file_path,
                    "file_name": row.get("file_name", ""),
                    "extension": row.get("extension", ""),
                    "detected_extension": row.get("extension", ""),
                    "size_bytes": row.get("size_bytes", ""),
                    "md5": row.get("md5", ""),
                    "status": "scanned_from_atomic_evidence",
                    "text_chars_scanned": "",
                    "error": "",
                })

    if os.path.exists(paths["linked_evidence"]):
        with open(paths["linked_evidence"], "r", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
            for row in csv.DictReader(handle):
                if row.get("cluster_eligible") != "no" and not row.get("cluster_exclusion_reason"):
                    continue
                file_path = row.get("file_path", "")
                if not file_path:
                    continue
                linked_excluded_by_file[file_path] += 1
                for reason in split_pipe_values(row.get("cluster_exclusion_reason", "")):
                    linked_reasons_by_file[file_path][reason] += 1

    rows = []
    seen = set()
    if os.path.exists(paths["file_summary"]):
        with open(paths["file_summary"], "r", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
            for row in csv.DictReader(handle):
                file_path = row.get("file_path", "")
                if not file_path:
                    continue
                seen.add(file_path)
                row = {field: row.get(field, "") for field in FILE_SUMMARY_FIELDS}
                entity_counts = counts_by_file.get(file_path, Counter())
                row["finding_count"] = sum(entity_counts.values())
                add_summary_evidence_counts(row, entity_counts)
                add_summary_cluster_exclusion_counts(row, linked_excluded_by_file.get(file_path, 0), linked_reasons_by_file.get(file_path, Counter()))
                rows.append(row)

    for file_path, meta in sorted(file_metadata.items()):
        if file_path in seen:
            continue
        entity_counts = counts_by_file.get(file_path, Counter())
        row = {field: meta.get(field, "") for field in FILE_SUMMARY_FIELDS}
        row["finding_count"] = sum(entity_counts.values())
        add_summary_evidence_counts(row, entity_counts)
        add_summary_cluster_exclusion_counts(row, linked_excluded_by_file.get(file_path, 0), linked_reasons_by_file.get(file_path, Counter()))
        rows.append(row)

    with open(paths["file_summary"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
        writer = csv.DictWriter(handle, fieldnames=FILE_SUMMARY_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def rebuild_linked_evidence_from_atomic(paths, args=None):
    grouped = {}
    for csv_path in atomic_evidence_csv_files(paths["findings"]):
        with open(csv_path, "r", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
            for row in csv.DictReader(handle):
                if row.get("evidence_tier") == "metadata" or row.get("pattern_name") == "max_findings_per_file":
                    continue
                file_path = row.get("file_path", "")
                row_number = str(row.get("row_number", ""))
                if not file_path:
                    continue
                key = (file_path, row_number)
                state = grouped.setdefault(key, {"findings": [], "source_row": ""})
                finding = {field: row.get(field, "") for field in FINDING_FIELDS}
                state["findings"].append(finding)
                context = row.get("context", "")
                if len(context) > len(state["source_row"]):
                    state["source_row"] = context

    linked_rows = []
    for (file_path, row_number), state in grouped.items():
        findings = state["findings"]
        first = findings[0]
        file_info = {
            "file_path": file_path,
            "file_name": first.get("file_name", ""),
            "extension": first.get("extension", ""),
            "size_bytes": first.get("size_bytes", ""),
            "md5": first.get("md5", ""),
        }
        candidate = build_candidate(file_info, row_number, state.get("source_row", ""), findings)
        if candidate is not None:
            linked_rows.append(candidate)

    linked_rows.sort(key=lambda row: (row.get("file_path", ""), str(row.get("row_number", "")), row.get("anchor_type", ""), row.get("anchor_value", "")))
    linked_rows, _, _ = materialize_duplicate_evidence_rows(linked_rows, duplicate_evidence_mode(args or argparse.Namespace()))
    with open(paths["linked_evidence"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as handle:
        writer = csv.DictWriter(handle, fieldnames=LINKED_EVIDENCE_FIELDS)
        writer.writeheader()
        writer.writerows({field: row.get(field, "") for field in LINKED_EVIDENCE_FIELDS} for row in linked_rows)
    return len(linked_rows)


def rebuild_downstream_from_atomic(paths, args=None):
    linked_total = rebuild_linked_evidence_from_atomic(paths, args)
    file_summary_rows = rebuild_file_summary_from_atomic_evidence(paths)
    build_entity_summary_from_file_summary(paths["file_summary"], paths["entity_summary"])
    build_regex_summary(paths["findings"], paths["regex_summary"])
    return linked_total, file_summary_rows


def resume_rules(args, paths, run_info):
    """Resume rule outputs by inspecting existing atomic evidence CSV files only.

    This intentionally does not use a manifest, so it works with output folders
    produced by earlier direct-streaming runs. Current rule outputs are inferred
    from the loaded rules. Missing regex-rule CSVs are rescanned. CSVs whose
    filename no longer corresponds to any current rule/code-derived output are
    removed. Empty existing CSVs are treated as valid completed outputs.
    """
    evidence_dir = Path(paths["findings"])
    evidence_dir.mkdir(parents=True, exist_ok=True)

    current = current_evidence_output_metadata()
    current_names = set(current)
    manifest = read_run_manifest(paths)
    if manifest_has_capped_atomic_outputs(manifest):
        raise SystemExit(
            "Cannot --resume rules from capped atomic evidence outputs. "
            "Rerun discovery with --max-findings-per-file 0 so downstream clustering can be rebuilt completely."
        )
    current_fingerprints = current_regex_output_fingerprints()

    removed_names = []
    manifest_outputs = read_run_manifest(paths).get("rule_outputs", {}) if read_run_manifest(paths) else {}
    for entry in evidence_dir.glob("*.csv"):
        if entry.name == "errors.csv":
            continue
        if entry.name not in current_names:
            previous_kind = (manifest_outputs.get(entry.name) or {}).get("kind", "")
            # Only regex-rule CSVs can safely be declared obsolete from rule metadata alone.
            # Runtime code-derived outputs may not have an independently runnable regex rule.
            if previous_kind in {"regex_rule", "regex"}:
                print(f"Resume rules: removing obsolete evidence output {entry.name}")
                entry.unlink()
                removed_names.append(entry.name)

    missing_patterns = []
    missing_names = []
    for pattern in PATTERNS:
        name = evidence_output_name(pattern.get("evidence_type", ""), pattern.get("pattern_name", ""))
        path = evidence_dir / name
        fingerprint = current_fingerprints.get(name, "")
        if manifest_output_is_valid(manifest, name, fingerprint, path):
            continue
        if path.exists():
            print(f"Resume rules: rescanning stale or incomplete evidence output {name}")
            path.unlink()
        missing_patterns.append(pattern)
        missing_names.append(name)

    # Code-derived outputs are emitted as part of normal source-unit scanning and
    # cannot be independently rescanned from a single regex pattern. For resume,
    # ensure their files exist so downstream rebuilds can consume a complete set.
    for name, meta in current.items():
        if meta.get("kind") in {"code_derived", "table_cell_value"}:
            ensure_atomic_evidence_file(evidence_dir / name)

    if missing_names:
        print(f"Resume rules: rescanning {len(missing_names):,} missing rule output file(s)")
        scan_selected_rule_outputs(args, paths, missing_patterns, missing_names, run_info)
    else:
        print("Resume rules: all current regex rule output files are present")

    # Ensure that every current output file exists before downstream rebuilds.
    for name in current_names:
        ensure_atomic_evidence_file(evidence_dir / name)

    linked_total, file_summary_rows = rebuild_downstream_from_atomic(paths, args)
    run_info["resume_rules_removed_outputs"] = len(removed_names)
    run_info["resume_rules_missing_outputs"] = len(missing_names)
    run_info["resume_rules_removed_output_files"] = "|".join(sorted(removed_names))
    run_info["resume_rules_missing_output_files"] = "|".join(sorted(missing_names))
    run_info["linked_evidence_rows"] = linked_total
    run_info["file_summary_rows"] = file_summary_rows
    run_info["finding_rows"] = count_atomic_evidence_rows(paths["findings"])
    return linked_total

def run_clustering_and_optionally_identification(args, paths, run_info, rebuild_linked=True):
    if rebuild_linked:
        linked_total, file_summary_rows = rebuild_downstream_from_atomic(paths, args)
    else:
        linked_total = count_csv_rows(paths["linked_evidence"])
        file_summary_rows = count_csv_rows(paths["file_summary"])
        build_entity_summary_from_file_summary(paths["file_summary"], paths["entity_summary"])
        build_regex_summary(paths["findings"], paths["regex_summary"])
    raw_evidence_total = count_atomic_evidence_rows(paths["findings"])
    run_info["linked_evidence_rows"] = linked_total
    run_info["finding_rows"] = raw_evidence_total
    run_info["file_summary_rows"] = file_summary_rows

    print("Stage 5/7: reclustering linked evidence")
    started = time.perf_counter()
    ensure_clustering_output_dirs(paths)
    cluster_count, cluster_members = build_person_clusters(
        paths["linked_evidence"],
        paths["person_clusters"],
        args.progress_every,
        linked_total,
        paths.get("cluster_members"),
    )
    run_info["stage2_clustering_seconds"] = round(time.perf_counter() - started, 6)
    run_info["cluster_count"] = cluster_count

    if args.person_tables:
        print("Stage 6/7: recalculating list/no-list identification")
        started = time.perf_counter()
        ensure_reidentification_output_dirs(paths, args.write_person_evidence)
        result = run_person_search(args, paths, None, cluster_count, linked_total, raw_evidence_total)
        run_info["stage3_reidentification_seconds"] = round(time.perf_counter() - started, 6)
        run_info["person_list_count"] = len(args.person_tables)
        run_info["person_tables"] = "|".join(args.person_tables)
        run_info["known_people_matched"] = result["known_people_matched_total"]
        run_info["known_people_output_rows"] = result["known_people_output_rows_total"]
        run_info["known_people_missing"] = result["known_people_missing_total"]
        run_info["no_list_people_summarised"] = result["no_list_people_summarised"]
        run_info["no_list_cluster_rows"] = result["no_list_cluster_rows"]
        for table_result in result["tables"]:
            stem = table_result["stem"]
            run_info[f"person_list_{stem}_matched"] = table_result["matched"]
            run_info[f"person_list_{stem}_output_rows"] = table_result["output_rows"]
            run_info[f"person_list_{stem}_missing"] = table_result["missing"]
        write_stage3_row_overlap_report(paths, run_info)
    else:
        run_info["stage3_reidentification_seconds"] = 0.0
    return cluster_count


def resume_identification(args, paths, run_info):
    linked_total = count_csv_rows(paths["linked_evidence"])
    raw_evidence_total = count_atomic_evidence_rows(paths["findings"])
    cluster_members = None
    cluster_total = count_csv_rows(paths["person_clusters"]) if os.path.exists(paths["person_clusters"]) else 0
    run_info["linked_evidence_rows"] = linked_total
    run_info["finding_rows"] = raw_evidence_total
    run_info["cluster_count"] = cluster_total
    if args.person_tables:
        print("Stage 6/7: recalculating list/no-list identification")
        started = time.perf_counter()
        result = run_person_search(args, paths, cluster_members, cluster_total, linked_total, raw_evidence_total)
        run_info["stage3_reidentification_seconds"] = round(time.perf_counter() - started, 6)
        run_info["person_list_count"] = len(args.person_tables)
        run_info["person_tables"] = "|".join(args.person_tables)
        run_info["known_people_matched"] = result["known_people_matched_total"]
        run_info["known_people_output_rows"] = result["known_people_output_rows_total"]
        run_info["known_people_missing"] = result["known_people_missing_total"]
        run_info["no_list_people_summarised"] = result["no_list_people_summarised"]
        run_info["no_list_cluster_rows"] = result["no_list_cluster_rows"]
        for table_result in result["tables"]:
            stem = table_result["stem"]
            run_info[f"person_list_{stem}_matched"] = table_result["matched"]
            run_info[f"person_list_{stem}_output_rows"] = table_result["output_rows"]
            run_info[f"person_list_{stem}_missing"] = table_result["missing"]
        write_stage3_row_overlap_report(paths, run_info)
    else:
        print("Stage 6/7: no --person-tables supplied; identification resume has nothing to do")
        run_info["stage3_reidentification_seconds"] = 0.0
    return cluster_total


def resume_reporting(args, paths, run_info):
    """Rebuild Stage 7 reports from existing Stage 6 outputs."""
    print("Stage 7/7: rebuilding reports from existing reidentification outputs")
    write_stage3_row_overlap_report(paths, run_info)
    return True


class DirectCSVWriter:
    """Write scan results directly to CSV, with no SQLite working store."""

    def __init__(self, paths, args=None):
        self.paths = paths
        self.duplicate_evidence = duplicate_evidence_mode(args or argparse.Namespace())
        self.evidence_dir = Path(paths["findings"])
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        for path in self.evidence_dir.glob("*.csv"):
            path.unlink()
        Path(paths["file_summary"]).parent.mkdir(parents=True, exist_ok=True)
        Path(paths["linked_evidence"]).parent.mkdir(parents=True, exist_ok=True)

        self.file_summary_handle = open(paths["file_summary"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE)
        self.file_summary_writer = csv.DictWriter(self.file_summary_handle, fieldnames=FILE_SUMMARY_FIELDS)
        self.file_summary_writer.writeheader()

        self.errors_handle = open(paths["errors"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE)
        self.errors_writer = csv.DictWriter(self.errors_handle, fieldnames=ERROR_FIELDS)
        self.errors_writer.writeheader()

        self.linked_handle = open(paths["linked_evidence"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE)
        self.linked_writer = csv.DictWriter(self.linked_handle, fieldnames=LINKED_EVIDENCE_FIELDS)
        self.linked_writer.writeheader()

        self.evidence_handles = {}
        self.evidence_writers = {}
        self._precreate_current_rule_outputs()
        self.csv_write_seconds = 0.0
        self.file_rows = 0
        self.error_rows = 0
        self.finding_rows = 0
        self.linked_rows = 0
        self.linked_groups = {}
        self.linked_group_sequence = 0
        self.linked_groups_flushed = False
        self.duplicate_evidence_groups = 0
        self.duplicate_evidence_duplicate_rows = 0
        self.file_index_metadata = {}

    def _evidence_writer_for_rule(self, evidence_type, pattern_name):
        name = evidence_output_name(evidence_type, pattern_name)
        writer = self.evidence_writers.get(name)
        if writer is not None:
            return writer
        handle = open(self.evidence_dir / name, "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE)
        self.evidence_handles[name] = handle
        writer = csv.DictWriter(handle, fieldnames=FINDING_FIELDS)
        writer.writeheader()
        self.evidence_writers[name] = writer
        return writer

    def _precreate_current_rule_outputs(self):
        for output_name, meta in current_evidence_output_metadata().items():
            self._evidence_writer_for_rule(meta["evidence_type"], meta["pattern_name"])

    def _evidence_writer(self, finding):
        return self._evidence_writer_for_rule(
            finding.get("evidence_type", ""),
            finding.get("pattern_name", ""),
        )

    def _write_linked_row(self, row):
        self.linked_writer.writerow({field: row.get(field, "") for field in LINKED_EVIDENCE_FIELDS})
        self.linked_rows += 1

    def _record_linked_candidate(self, candidate):
        row = {field: candidate.get(field, "") for field in LINKED_EVIDENCE_FIELDS}
        if self.duplicate_evidence == "scan":
            row = annotate_duplicate_evidence_row(row, action="scanned")
            self._write_linked_row(row)
            return

        signature = linked_evidence_duplicate_signature(row)
        if signature:
            group_key = f"sha256:{signature}"
        else:
            self.linked_group_sequence += 1
            group_key = f"unique:{self.linked_group_sequence}"
        group = self.linked_groups.setdefault(group_key, {"rows": []})
        group["rows"].append(row)

    def _flush_linked_groups(self):
        if self.linked_groups_flushed:
            return
        self.linked_groups_flushed = True
        if self.duplicate_evidence == "scan":
            return
        grouped_rows = []
        for group in self.linked_groups.values():
            grouped_rows.extend(group.get("rows", []))
        output_rows, duplicate_groups, duplicate_rows = materialize_duplicate_evidence_rows(grouped_rows, self.duplicate_evidence)
        for row in output_rows:
            self._write_linked_row(row)
        self.duplicate_evidence_groups = duplicate_groups
        self.duplicate_evidence_duplicate_rows = duplicate_rows

    def write_result(self, result):
        started = time.perf_counter()
        summary = dict(result.get("summary") or {})
        add_summary_evidence_counts(summary, result.get("entity_counts", Counter()))
        self.file_summary_writer.writerow({field: summary.get(field, "") for field in FILE_SUMMARY_FIELDS})
        self.file_rows += 1
        file_path = safe_cell(summary.get("file_path"))
        if file_path and summary.get("status") != "empty_folder":
            self.file_index_metadata[file_path] = {
                "size_bytes": summary.get("size_bytes", ""),
                "mtime_ns": indexed_mtime_ns(file_path) or "",
                "detected_extension": summary.get("detected_extension", "") or summary.get("extension", ""),
                "md5": summary.get("md5", ""),
                "sha256": summary.get("sha256", ""),
                "duplicate_content_group": summary.get("duplicate_content_group", ""),
                "duplicate_content_index": summary.get("duplicate_content_index", ""),
                "duplicate_of": summary.get("duplicate_of", ""),
                "duplicate_path_count": summary.get("duplicate_path_count", ""),
                "duplicate_paths": summary.get("duplicate_paths", ""),
                "duplicate_content_action": summary.get("duplicate_content_action", ""),
            }

        for error in result.get("errors", []):
            self.errors_writer.writerow({field: error.get(field, "") for field in ERROR_FIELDS})
            self.error_rows += 1

        findings = result.get("findings", [])
        candidates = result.get("candidates", [])

        # Match the SQLite exporter's context behaviour: each source unit uses
        # the longest available context/source row for that locator, then every
        # finding from that locator carries the same source-unit context.
        unit_text = {}
        for finding in findings:
            locator = str(finding.get("row_number", ""))
            context = finding.get("context", "")
            if len(context) > len(unit_text.get(locator, "")):
                unit_text[locator] = context
        for candidate in candidates:
            locator = str(candidate.get("row_number", ""))
            source_row = candidate.get("source_row", "")
            if len(source_row) > len(unit_text.get(locator, "")):
                unit_text[locator] = source_row

        for finding in findings:
            writer = self._evidence_writer(finding)
            row = {field: finding.get(field, "") for field in FINDING_FIELDS}
            locator = str(finding.get("row_number", ""))
            if locator in unit_text:
                row["context"] = unit_text[locator]
            writer.writerow(row)
            self.finding_rows += 1

        for candidate in candidates:
            self._record_linked_candidate(candidate)

        self.csv_write_seconds += time.perf_counter() - started

    def close(self):
        self._flush_linked_groups()
        for handle in self.evidence_handles.values():
            handle.close()
        self.linked_handle.close()
        self.errors_handle.close()
        self.file_summary_handle.close()


def discover_streaming(args, paths, run_info):
    root_path = os.path.abspath(args.root)
    output_dir = os.path.abspath(args.output_dir)
    output_files = paths.values()
    preprocess_mode = file_preprocessing_mode(args)
    explicit_index_dir = bool(getattr(args, "index_dir", ""))
    index_path = file_index_path(args, paths)
    indexed_metadata = load_file_index(index_path, trust=explicit_index_dir, args=args)
    skip_duplicate_precompute = preprocess_mode == "disabled"
    use_index_targets = bool(indexed_metadata)
    stream_discovery_to_stage1 = (
        not use_index_targets
        and skip_duplicate_precompute
        and getattr(args, "priority", "discovery") == "discovery"
    )

    print("Discovery: finding files", flush=True)
    preprocessing_started_wall = time.time()
    last_preprocessing_progress = 0.0
    last_preprocessing_hash_report = 0
    last_preprocessing_duplicate_report = (0, 0)

    def report_preprocessing_progress(event):
        nonlocal last_preprocessing_progress, last_preprocessing_hash_report, last_preprocessing_duplicate_report
        if args.progress_every <= 0:
            return
        now = time.monotonic()
        total_files = int(event.get("total_files") or 0)
        processed_files = int(event.get("processed_files") or 0)
        hashed_files = int(event.get("hashed_files") or 0)
        duplicate_groups = int(event.get("duplicate_groups") or 0)
        duplicate_files = int(event.get("duplicate_files") or 0)
        duplicate_snapshot = (duplicate_groups, duplicate_files)
        hash_step = max(1, min(100, max(1, total_files) // 20))
        duplicate_changed = duplicate_snapshot != last_preprocessing_duplicate_report
        hash_milestone = (
            hashed_files
            and hashed_files != last_preprocessing_hash_report
            and (hashed_files % hash_step == 0 or hashed_files == total_files)
        )
        if (
            not event.get("force")
            and not duplicate_changed
            and not hash_milestone
            and now - last_preprocessing_progress < args.progress_every
        ):
            return
        status = event.get("status") or "duplicate pre-processing"
        path = event.get("path") or ""
        file_percent = event.get("file_percent")
        if total_files:
            overall_percent = 100.0 * min(1.0, processed_files / max(1, total_files))
            count_text = f"{processed_files:,} / {total_files:,} files ({overall_percent:.0f}%)"
        else:
            count_text = "0 / 0 files"
        lines = [
            (
                f"Pre-processing | {count_text} | hashed {hashed_files:,} | "
                f"duplicate groups {duplicate_groups:,} | duplicate files {duplicate_files:,} | "
                f"elapsed {format_hms(time.time() - preprocessing_started_wall)}"
            )
        ]
        if path:
            if file_percent is None:
                lines.append(f"Current: {path}: {status}")
            else:
                lines.append(f"Current: {path}: {file_percent:.0f}% ({status})")
        else:
            lines.append(f"Current: {status}")
        print("\n".join(lines), flush=True)
        last_preprocessing_progress = now
        if hash_milestone or event.get("force"):
            last_preprocessing_hash_report = hashed_files
        last_preprocessing_duplicate_report = duplicate_snapshot

    if use_index_targets:
        print(
            f"Discovery: using reusable file index {index_path}; "
            f"{len(indexed_metadata):,} indexed files",
            flush=True,
        )
        targets = targets_from_file_index(indexed_metadata)
        metadata_by_path = dict(indexed_metadata)
        digest_groups = {}
        for path, metadata in metadata_by_path.items():
            digest = selected_content_hash(metadata, args)
            if digest:
                digest_groups.setdefault(digest, []).append(path)
        scan_targets, duplicates_by_canonical = duplicate_filtered_targets(targets, args, metadata_by_path, digest_groups)
        duplicate_group_count = sum(1 for group_paths in digest_groups.values() if len(group_paths) > 1)
        duplicate_file_count = sum(max(0, len(group_paths) - 1) for group_paths in digest_groups.values())
        total_files = len(targets)
        worker_count = resolve_worker_count(args.workers, scan_targets)
    elif stream_discovery_to_stage1:
        print(
            "Discovery: streaming targets directly to Stage 4 scanning; "
            "file count will be known when the scan completes",
            flush=True,
        )
        targets = iter_targets(
            root_path,
            output_dir,
            output_files,
            args.include_hidden,
            args.exclude,
        )
        metadata_by_path = {}
        digest_groups = {}
        scan_targets = targets
        duplicates_by_canonical = {}
        duplicate_group_count = 0
        duplicate_file_count = 0
        total_files = None
        worker_count = resolve_streaming_worker_count(args.workers)
        print(
            "Duplicate pre-processing: content hashing and duplicate-file handling disabled; "
            "skipping file metadata precompute",
            flush=True,
        )
    else:
        targets = discover_targets_for_preprocessing(args, paths)
        discovered_file_count = sum(1 for target_type, _path in targets if target_type == "file")
        discovered_empty_folder_count = sum(1 for target_type, _path in targets if target_type == "empty_folder")
        print(
            "Discovery: discovered "
            f"{discovered_file_count:,} files"
            + (f" and {discovered_empty_folder_count:,} empty folders" if discovered_empty_folder_count else "")
            + f"; priority={args.priority}",
            flush=True,
        )
        print("Discovery: prioritising targets", flush=True)
        targets = prioritize_targets(targets, args.priority)
        if skip_duplicate_precompute:
            print(
                "Duplicate pre-processing: content hashing and duplicate-file handling disabled; "
                "skipping file metadata precompute",
                flush=True,
            )
            metadata_by_path = {}
            digest_groups = {}
            scan_targets = targets
            duplicates_by_canonical = {}
        else:
            print("Duplicate pre-processing: detecting content signatures, hashing files, and grouping duplicates", flush=True)
            metadata_by_path, digest_groups = precompute_hash_metadata_for_targets(
                targets,
                args,
                progress_callback=report_preprocessing_progress,
                existing_metadata_by_path=indexed_metadata,
            )
            scan_targets, duplicates_by_canonical = duplicate_filtered_targets(targets, args, metadata_by_path, digest_groups)
        duplicate_group_count = sum(1 for group_paths in digest_groups.values() if len(group_paths) > 1)
        duplicate_file_count = sum(max(0, len(group_paths) - 1) for group_paths in digest_groups.values())
        current_file_paths = [path for target_type, path in targets if target_type == "file"]
        total_files = len(current_file_paths)
        worker_count = resolve_worker_count(args.workers, scan_targets)
    args.precomputed_file_metadata = metadata_by_path
    print(
        "Duplicate pre-processing complete: "
        f"{len(metadata_by_path):,} file metadata rows, "
        f"{duplicate_group_count:,} duplicate groups, "
        f"{duplicate_file_count:,} duplicate files; "
        f"duplicate mode={args.duplicate_content}",
        flush=True,
    )
    iterator = iter(iter_scan_tasks(scan_targets, args, metadata_by_path))
    processed_files = 0
    regex_terms = 0
    phase_seconds = Counter()
    # Profiling is now a linear Stage 3. Stage 4 should consume the schema plan
    # but must not regenerate/overwrite profiling outputs as a sidecar.
    worker_profile_enabled = False
    integrated_profiles = {}
    integrated_rule_coverage = initialize_rule_coverage() if worker_profile_enabled else None
    integrated_schema_plan = []
    integrated_profiled_files = set()
    last_progress = time.monotonic()
    stage_started_wall = time.time()
    writer = DirectCSVWriter(paths, args)
    active = {}
    active_by_key = {}
    if os.name == "nt" and bool(getattr(args, "person_tables", None)):
        print(
            "Stage 4/7 scanning: using process workers; each Windows worker may warm its "
            "own person-table index on its first file.",
            flush=True,
        )
    progress_manager = None
    progress_queue = None
    if args.progress_every > 0 and worker_count > 1:
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

    Path(paths["process_timing_log"]).parent.mkdir(parents=True, exist_ok=True)
    timing_handle = open(paths["process_timing_log"], "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE)
    timing_writer = csv.DictWriter(timing_handle, fieldnames=PROCESS_TIMING_FIELDS)
    timing_writer.writeheader()

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
        if not force and (args.progress_every <= 0 or now - last_progress < args.progress_every):
            return
        if total_files is None:
            file_progress_text = f"{processed_files:,} files complete"
        else:
            file_progress_text = f"{processed_files:,} / {total_files:,} files complete"
        header = (
            f"Stage 4/7 scanning | {file_progress_text} | {len(active):,} active | "
            f"elapsed {format_hms(now_wall - stage_started_wall)} | regex terms {regex_terms:,}"
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
                lines.append(f"[pid {pid}] {elapsed}  {file_path}: {progress_text}")
        else:
            lines.append("none")
        print("\n".join(lines), flush=True)
        last_progress = now

    def task_args_for_target(target):
        task_args = argparse.Namespace(**vars(args))
        if target[0] == "file":
            task_args.precomputed_file_metadata = {target[1]: metadata_by_path.get(target[1], {})}
        else:
            task_args.precomputed_file_metadata = {}
        return task_args

    def submit_next(pool, pending):
        try:
            target = next(iterator)
        except StopIteration:
            return False
        file_display, process_label = task_display(target)
        task_key = target_progress_key(target)
        state = {
            "task_key": task_key,
            "file": file_display,
            "path": target_progress_path(target),
            "process": process_label,
            "status": "queued",
            "percent": None,
            "pid": "",
            "started_wall": time.time(),
        }
        future = pool.submit(process_target, target, task_args_for_target(target))
        active[future] = state
        active_by_key[task_key] = state
        pending.add(future)
        return True

    def consume(future):
        nonlocal processed_files, regex_terms
        drain_progress_queue()
        state = active.pop(future, None)
        if state:
            active_by_key.pop(state.get("task_key"), None)
        result = future.result()
        timing_writer.writerow(process_timing_row(result))
        for name, seconds in result.get("timings", {}).items():
            phase_seconds[name] += seconds
        writer.write_result(result)
        canonical_path = result.get("process_info", {}).get("file_path") or result.get("summary", {}).get("file_path", "")
        duplicate_paths = duplicates_by_canonical.get(canonical_path, [])
        is_chunk = result.get("result_kind") == "scan_chunk"
        should_emit_duplicate_rows = duplicate_paths and (not is_chunk or result.get("final_chunk"))
        if args.duplicate_content == "collapse" and duplicate_paths:
            for duplicate_path in duplicate_paths:
                duplicate_metadata = metadata_by_path.get(duplicate_path, {})
                cloned = clone_result_for_duplicate(result, duplicate_path, duplicate_metadata)
                writer.write_result(cloned)
                regex_terms += int(cloned["summary"].get("finding_count", 0) or 0)
                if worker_profile_enabled:
                    pass
        elif args.duplicate_content == "report" and should_emit_duplicate_rows:
            for duplicate_path in duplicate_paths:
                duplicate_result = duplicate_summary_result(duplicate_path, metadata_by_path.get(duplicate_path, {}), args)
                writer.write_result(duplicate_result)
        if worker_profile_enabled:
            merge_local_profile_result(integrated_profiles, integrated_rule_coverage, result, schema_plan=integrated_schema_plan)
            if result.get("profiled"):
                profiled_path = (
                    result.get("summary", {}).get("file_path")
                    or result.get("process_info", {}).get("file_path")
                    or ""
                )
                if profiled_path:
                    integrated_profiled_files.add(profiled_path)
        if result["summary"].get("status") != "empty_folder" and (not is_chunk or result.get("final_chunk")):
            processed_files += 1
            if should_emit_duplicate_rows:
                processed_files += len(duplicate_paths)
        regex_terms += int(result["summary"].get("finding_count", 0) or 0)
        report_progress()

    class ImmediateFuture:
        def __init__(self, result):
            self._result = result

        def result(self):
            return self._result

    completed_normally = False
    try:
        if worker_count <= 1:
            report_progress(force=True)
            for target in iterator:
                file_display, process_label = task_display(target)
                task_key = target_progress_key(target)
                future = ImmediateFuture(None)
                active[future] = {
                    "task_key": task_key,
                    "file": file_display,
                    "path": target_progress_path(target),
                    "process": process_label,
                    "status": "queued",
                    "percent": None,
                    "pid": os.getpid(),
                    "started_wall": time.time(),
                }
                active_by_key[task_key] = active[future]
                report_progress(force=True)
                future._result = process_target(target, task_args_for_target(target))
                consume(future)
        else:
            with ProcessPoolExecutor(max_workers=worker_count) as pool:
                pending = set()
                for _ in range(worker_count):
                    if not submit_next(pool, pending):
                        break
                report_progress(force=True)
                while pending:
                    timeout = args.progress_every if args.progress_every > 0 else None
                    done, pending = wait(pending, timeout=timeout, return_when=FIRST_COMPLETED)
                    if not done:
                        report_progress()
                        continue
                    for future in done:
                        consume(future)
                        submit_next(pool, pending)
        completed_normally = True
    finally:
        drain_progress_queue()
        writer.close()
        timing_handle.close()
        if progress_manager is not None:
            try:
                progress_manager.shutdown()
            except Exception:
                pass

    if completed_normally and total_files is not None:
        processed_files = total_files
    report_progress(force=True)

    if completed_normally and preprocess_mode != "disabled" and not use_index_targets:
        index_metadata = {}
        index_metadata.update(metadata_by_path or {})
        index_metadata.update(writer.file_index_metadata or {})
        if index_metadata:
            try:
                written_index_rows = write_file_index(index_path, index_metadata, args, mode=preprocess_mode)
                run_info["file_index"] = index_path
                run_info["file_index_rows"] = written_index_rows
                print(f"Pre-processing index written: {index_path} ({written_index_rows:,} files)", flush=True)
            except OSError as exc:
                run_info["file_index_error"] = str(exc)
                print(f"Pre-processing index could not be written: {exc}", flush=True)
    elif use_index_targets:
        run_info["file_index"] = index_path
        run_info["file_index_rows"] = len(indexed_metadata)
        run_info["file_index_reused"] = "true"

    if worker_profile_enabled:
        profile_started = time.perf_counter()
        (
            profile_count,
            candidate_count,
            review_only_candidate_count,
            value_type_candidate_count,
            rule_coverage_count,
            schema_plan_count,
        ) = write_profile_outputs(args.output_dir, integrated_profiles, integrated_rule_coverage, schema_plan=integrated_schema_plan)
        run_info["profile"] = args.profile
        run_info["profiled_files"] = len(integrated_profiled_files)
        run_info["unknown_column_profile_rows"] = profile_count
        run_info["column_rule_candidate_rows"] = candidate_count
        run_info["review_only_candidate_rows"] = review_only_candidate_count
        run_info["value_type_candidate_rows"] = value_type_candidate_count
        run_info["rule_coverage_rows"] = rule_coverage_count
        run_info["schema_plan_rows"] = schema_plan_count
        run_info["profile_seconds"] = round(time.perf_counter() - profile_started, 6)
        print(
            f"Stage 3/7 profiling: "
            f"{profile_count:,} column/field profiles, "
            f"{candidate_count:,} candidate rule rows, "
            f"{review_only_candidate_count:,} review-only grouped suggestions, "
            f"{value_type_candidate_count:,} value-type candidate rows, "
            f"{rule_coverage_count:,} rule coverage rows, "
            f"{schema_plan_count:,} schema-plan rows"
        )

    run_info.update({
        "worker_count": worker_count,
        "files_discovered": total_files if total_files is not None else processed_files,
        "files_processed": processed_files,
        "file_hash_algorithm": selected_file_hash_algorithm(args),
        "duplicate_files_mode": args.duplicate_files,
        "duplicate_file_groups": duplicate_group_count,
        "duplicate_files": duplicate_file_count,
        "duplicate_evidence_mode": args.duplicate_evidence,
        "duplicate_evidence_groups": writer.duplicate_evidence_groups,
        "duplicate_evidence_duplicate_rows": writer.duplicate_evidence_duplicate_rows,
        "finding_rows": writer.finding_rows,
        "linked_evidence_rows": writer.linked_rows,
        "file_summary_rows": writer.file_rows,
        "error_rows": writer.error_rows,
        "csv_write_seconds": writer.csv_write_seconds,
        "process_timing_log": paths["process_timing_log"],
    })
    for name, seconds in phase_seconds.items():
        run_info[name] = seconds

    print(
        "Stage 4/7 cumulative process time: "
        f"hash={phase_seconds['hash_seconds']:.2f}s, "
        f"extraction={phase_seconds['extraction_seconds']:.2f}s, "
        f"regex={phase_seconds['regex_seconds']:.2f}s, "
        f"csv={writer.csv_write_seconds:.2f}s, "
        f"workers={worker_count}"
    )
    return processed_files


def run_source_preprocessing(args, paths, run_info):
    """Build or reuse the standalone source-file preprocessing index."""
    mode_label = "standalone" if file_preprocessing_mode(args) == "standalone" else "integrated"
    progress_label = f"File pre-processing {mode_label}"
    index_path = file_index_path(args, paths)
    explicit_index_dir = bool(getattr(args, "index_dir", ""))
    indexed_metadata = load_file_index(index_path, trust=explicit_index_dir, args=args)
    if explicit_index_dir and indexed_metadata:
        print(
            f"{progress_label}: using reusable file index {index_path}; "
            f"{len(indexed_metadata):,} indexed files",
            flush=True,
        )
        run_info["file_index"] = index_path
        run_info["file_index_rows"] = len(indexed_metadata)
        run_info["file_index_reused"] = "true"
        run_info["files_discovered"] = len(indexed_metadata)
        run_info["files_processed"] = 0
        return len(indexed_metadata)

    print(f"{progress_label}: discovering files", flush=True)
    targets = discover_targets_for_preprocessing(args, paths)
    file_count = sum(1 for target_type, _path in targets if target_type == "file")
    empty_folder_count = sum(1 for target_type, _path in targets if target_type == "empty_folder")
    print(
        f"{progress_label}: discovered "
        f"{file_count:,} files"
        + (f" and {empty_folder_count:,} empty folders" if empty_folder_count else ""),
        flush=True,
    )

    started_wall = time.time()
    last_progress = 0.0
    last_hash_report = 0
    last_duplicate_report = (0, 0)

    def report(event):
        nonlocal last_progress, last_hash_report, last_duplicate_report
        if args.progress_every <= 0:
            return
        now = time.monotonic()
        total_files = int(event.get("total_files") or 0)
        processed_files = int(event.get("processed_files") or 0)
        hashed_files = int(event.get("hashed_files") or 0)
        duplicate_groups = int(event.get("duplicate_groups") or 0)
        duplicate_files = int(event.get("duplicate_files") or 0)
        duplicate_snapshot = (duplicate_groups, duplicate_files)
        hash_step = max(1, min(100, max(1, total_files) // 20))
        duplicate_changed = duplicate_snapshot != last_duplicate_report
        hash_milestone = (
            hashed_files
            and hashed_files != last_hash_report
            and (hashed_files % hash_step == 0 or hashed_files == total_files)
        )
        if (
            not event.get("force")
            and not duplicate_changed
            and not hash_milestone
            and now - last_progress < args.progress_every
        ):
            return
        status = event.get("status") or "pre-processing"
        path = event.get("path") or ""
        file_percent = event.get("file_percent")
        percent = 100.0 * min(1.0, processed_files / max(1, total_files)) if total_files else 0.0
        lines = [
            (
                f"{progress_label} | {processed_files:,} / {total_files:,} files "
                f"({percent:.0f}%) | hashed {hashed_files:,} | duplicate groups {duplicate_groups:,} | "
                f"duplicate files {duplicate_files:,} | elapsed {format_hms(time.time() - started_wall)}"
            )
        ]
        if path:
            if file_percent is None:
                lines.append(f"Current: {path}: {status}")
            else:
                lines.append(f"Current: {path}: {file_percent:.0f}% ({status})")
        else:
            lines.append(f"Current: {status}")
        print("\n".join(lines), flush=True)
        last_progress = now
        if hash_milestone or event.get("force"):
            last_hash_report = hashed_files
        last_duplicate_report = duplicate_snapshot

    metadata_by_path, digest_groups = precompute_hash_metadata_for_targets(
        targets,
        args,
        progress_callback=report,
        existing_metadata_by_path=indexed_metadata,
    )
    duplicate_group_count = sum(1 for group_paths in digest_groups.values() if len(group_paths) > 1)
    duplicate_file_count = sum(max(0, len(group_paths) - 1) for group_paths in digest_groups.values())
    written_index_rows = write_file_index(index_path, metadata_by_path, args, mode=mode_label)
    print(f"{progress_label} complete: wrote {written_index_rows:,} file rows to {index_path}", flush=True)
    run_info["file_index"] = index_path
    run_info["file_index_rows"] = written_index_rows
    run_info["files_discovered"] = file_count
    run_info["files_processed"] = 0
    run_info["file_hash_algorithm"] = selected_file_hash_algorithm(args)
    run_info["duplicate_files_mode"] = args.duplicate_files
    run_info["duplicate_file_groups"] = duplicate_group_count
    run_info["duplicate_files"] = duplicate_file_count
    return file_count


def run_discovery_preprocessing(args, paths, run_info):
    """Build or reuse discovery/reference artefacts for process workers."""
    print("Discovery pre-processing: preparing worker-ready discovery artefacts", flush=True)
    index_path = person_tables_index_path(args, paths)
    args.person_tables_index = index_path
    original_mode = getattr(args, "discovery_preprocessing", "integrated")
    if discovery_preprocessing_mode(args) == "standalone":
        args.discovery_preprocessing = "integrated"
    try:
        if getattr(args, "person_tables", None):
            print(f"Discovery pre-processing: building/reusing person-table index {index_path}", flush=True)
            ensure_person_table_exact_match_index(
                args,
                progress_callback=lambda message: print(f"Discovery pre-processing: {message}", flush=True),
            )
        else:
            print("Discovery pre-processing: no --person-tables supplied", flush=True)
    finally:
        args.discovery_preprocessing = original_mode
    row_count = len(PERSON_TABLE_EXACT_MATCH_INDEX)
    run_info["person_tables_index"] = index_path
    run_info["person_tables_index_rows"] = row_count
    run_info["discovery_preprocessing"] = discovery_preprocessing_mode(args)
    discovery_path = discovery_index_path(args, paths)
    write_discovery_index(discovery_path, args, paths, run_info, mode=discovery_preprocessing_mode(args))
    print(
        f"Discovery pre-processing complete: {row_count:,} person-table exact-match keys; "
        f"bundle={discovery_path}",
        flush=True,
    )
    return row_count


def load_schema_plan_decisions_from_csv(schema_plan_path):
    """Load a profiling schema plan and return Stage-4 routing decisions."""
    if not schema_plan_path or not os.path.exists(schema_plan_path):
        return None
    rows = []
    with open(schema_plan_path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append(dict(row))
    return actionable_schema_plan_decisions(rows)


def safe_output_stem(path):
    stem = Path(path).stem.strip() or "person_list"
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", stem).strip("._-")
    return stem or "person_list"


def person_table_output_paths(output_dir, person_table_path):
    stem = safe_output_stem(person_table_path)
    return {
        "stem": stem,
        "exposure": os.path.join(output_dir, f"{stem}_in_dataset.csv"),
        "risk": os.path.join(output_dir, f"{stem}_risk_matrix.csv"),
        "pii_value_risk": os.path.join(output_dir, f"{stem}_pii_value_risk_matrix.csv"),
        "missing": os.path.join(output_dir, f"{stem}_not_in_dataset.csv"),
        "evidence": os.path.join(output_dir, f"{stem}_evidence"),
    }


def temp_person_output_paths(temp_dir, stem):
    return {
        "exposure": os.path.join(temp_dir, f"{stem}_in_dataset.csv"),
        "risk": os.path.join(temp_dir, f"{stem}_risk_matrix.csv"),
        "missing": os.path.join(temp_dir, f"{stem}_not_in_dataset.csv"),
        "clusters": os.path.join(temp_dir, f"{stem}_clusters_not_in_list.csv"),
        "summary": os.path.join(temp_dir, f"{stem}_clusters_not_in_list_redacted.csv"),
        "unknown_risk": os.path.join(temp_dir, f"{stem}_clusters_not_in_list_risk_matrix.csv"),
        "known_evidence": os.path.join(temp_dir, f"{stem}_evidence"),
        "unknown_evidence": os.path.join(temp_dir, f"{stem}-Clusters_not_in_list_evidence"),
    }


def write_stage3_row_overlap_report(paths, run_info=None):
    """Write built-in row/person overlap diagnostics from Stage 6 outputs."""
    output_root = paths.get("reidentification_dir") or paths["output_dir"]
    try:
        result = write_row_overlap_report(output_root)
    except Exception as exc:
        print(f"Stage 7/7: row overlap report failed: {exc}")
        if run_info is not None:
            run_info["row_overlap_report_error"] = str(exc)
        return None
    if run_info is not None:
        run_info["row_overlap_report_dir"] = result.get("report_dir", "")
        run_info["row_overlap_source_count"] = result.get("source_count", 0)
    print(f"Stage 7/7: row overlap report written: {result.get('report_dir', '')}")
    return result


def read_person_table_rows(person_table_path):
    with open(person_table_path, "rb") as f:
        text = decode_person_table_bytes(f.read())
    reader = csv.DictReader(io.StringIO(text, newline=""))
    headers = reader.fieldnames or []
    rows = [dict(row) for row in reader]
    return headers, rows


def write_combined_person_table(person_table_paths, combined_path):
    all_headers = []
    seen_headers = set()
    table_rows = []

    for table_path in person_table_paths:
        headers, rows = read_person_table_rows(table_path)
        for header in headers:
            if header not in seen_headers:
                all_headers.append(header)
                seen_headers.add(header)
        table_rows.append((table_path, headers, rows))

    combined_headers = ["__person_list"] + all_headers
    ensure_output_parent(combined_path)
    with open(combined_path, "w", encoding="utf-8", newline="", buffering=OUTPUT_BUFFER_SIZE) as f:
        writer = csv.DictWriter(f, fieldnames=combined_headers)
        writer.writeheader()
        for table_path, headers, rows in table_rows:
            list_name = safe_output_stem(table_path)
            for row in rows:
                out = {header: row.get(header, "") for header in all_headers}
                out["__person_list"] = list_name
                writer.writerow(out)

    return combined_path


def run_person_search(args, paths, cluster_members, cluster_total, linked_total, raw_evidence_total):
    import tempfile

    output_dir = paths["reidentification_dir"]
    person_tables = [os.path.abspath(path) for path in args.person_tables]
    results = {
        "tables": [],
        "known_people_matched_total": 0,
        "known_people_output_rows_total": 0,
        "known_people_missing_total": 0,
        "no_list_people_summarised": 0,
        "no_list_cluster_rows": 0,
    }

    with tempfile.TemporaryDirectory(prefix="pii_person_lists_") as temp_dir:
        for person_table in person_tables:
            table_paths = person_table_output_paths(output_dir, person_table)
            tmp = temp_person_output_paths(temp_dir, table_paths["stem"])
            print(f"Stage 6/7: matching person list '{table_paths['stem']}'")
            result = build_known_person_outputs_from_clusters(
                person_table,
                paths["person_clusters"],
                paths["linked_evidence"],
                paths["findings"],
                table_paths["exposure"],
                table_paths["risk"],
                table_paths["missing"],
                tmp["clusters"],
                tmp["summary"],
                tmp["unknown_risk"],
                table_paths["evidence"],
                tmp["unknown_evidence"],
                False,
                cluster_members,
                table_paths["pii_value_risk"],
                args.progress_every,
                args.write_person_evidence,
                cluster_total,
                linked_total,
                raw_evidence_total,
            )
            results["tables"].append({
                "table": person_table,
                "stem": table_paths["stem"],
                "matched": result[0],
                "output_rows": result[1],
                "missing": result[2],
            })
            results["known_people_matched_total"] += result[0]
            results["known_people_output_rows_total"] += result[1]
            results["known_people_missing_total"] += result[2]

        combined_path = os.path.join(temp_dir, "all_person_lists_combined.csv")
        write_combined_person_table(person_tables, combined_path)
        tmp = temp_person_output_paths(temp_dir, "all_lists")
        print("Stage 6/7: summarising no-list identities")
        no_list_result = build_known_person_outputs_from_clusters(
            combined_path,
            paths["person_clusters"],
            paths["linked_evidence"],
            paths["findings"],
            tmp["exposure"],
            tmp["risk"],
            tmp["missing"],
            paths["no_list_clusters"],
            paths["no_list_summary"],
            paths["no_list_risk"],
            tmp["known_evidence"],
            paths["no_list_evidence"],
            True,
            cluster_members,
            None,
            args.progress_every,
            args.write_person_evidence,
            cluster_total,
            linked_total,
            raw_evidence_total,
        )
        results["no_list_people_summarised"] = no_list_result[3]
        results["no_list_cluster_rows"] = no_list_result[4]

    return results


def count_atomic_evidence_rows(evidence_dir):
    total = 0
    if not os.path.isdir(evidence_dir):
        return 0
    for entry in os.scandir(evidence_dir):
        if not entry.is_file() or not entry.name.lower().endswith(".csv") or entry.name == "errors.csv":
            continue
        total += count_csv_rows(entry.path)
    return total


def current_regex_output_fingerprints():
    return {
        evidence_output_name(pattern.get("evidence_type", ""), pattern.get("pattern_name", "")): pattern_fingerprint(pattern)
        for pattern in PATTERNS
    }


def atomic_output_manifest(paths):
    evidence_dir = Path(paths["findings"])
    outputs = {}
    if not evidence_dir.is_dir():
        return outputs
    fingerprints = current_regex_output_fingerprints()
    metadata = current_evidence_output_metadata()
    for name, meta in sorted(metadata.items()):
        path = evidence_dir / name
        outputs[name] = {
            "evidence_type": meta.get("evidence_type", ""),
            "pattern_name": meta.get("pattern_name", ""),
            "kind": meta.get("kind", ""),
            "fingerprint": fingerprints.get(name, ""),
            "exists": path.exists(),
            "size_bytes": path.stat().st_size if path.exists() else 0,
            "row_count": count_csv_rows(path) if path.exists() else 0,
            "completed": bool(path.exists()),
        }
    return outputs


def read_run_manifest(paths):
    path = paths.get("run_manifest")
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            loaded = json.load(handle)
        return loaded if isinstance(loaded, dict) else {}
    except Exception:
        return {}


def write_run_manifest(paths, args, run_info):
    manifest = {
        "schema_version": 1,
        "mode": run_mode_label(getattr(args, "profile", "")),
        "root": getattr(args, "root", ""),
        "output_dir": getattr(args, "output_dir", ""),
        "rules": os.path.abspath(getattr(args, "rules", "") or ""),
        "nlp": bool(getattr(args, "nlp", False)),
        "nlp_backend": run_info.get("nlp_backend", ""),
        "email_suffix": list(normalize_email_suffixes(getattr(args, "email_suffix", ""))),
        "email_wildcard": [" == ".join(pair) for pair in normalize_email_wildcard_rules(getattr(args, "email_wildcard", ""))],
        "xml_scan": getattr(args, "xml_scan", ""),
        "profile": getattr(args, "profile", ""),
        "file_preprocessing": file_preprocessing_mode(args),
        "discovery_preprocessing": discovery_preprocessing_mode(args),
        "index_dir": index_dir_path(args, paths),
        "file_index": file_index_path(args, paths),
        "discovery_index": discovery_index_path(args, paths),
        "person_tables_index": person_tables_index_path(args, paths),
        "large_file_cutoff_mb": getattr(args, "large_file_cutoff_mb", ""),
        "scan_unit_records": getattr(args, "scan_unit_records", ""),
        "file_hash": getattr(args, "file_hash", ""),
        "duplicate_files": getattr(args, "duplicate_files", getattr(args, "duplicate_content", "")),
        "duplicate_evidence": getattr(args, "duplicate_evidence", ""),
        "person_tables": list(getattr(args, "person_tables", []) or []),
        "rule_outputs": atomic_output_manifest(paths),
        "run_info": dict(run_info),
    }
    with open(paths["run_manifest"], "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")


def normalize_profile_mode_args(args):
    """Trim runtime options down to the subset that matters in profile mode.

    Standalone profile mode is a separate pass over files for schema discovery.
    It does not perform atomic evidence writing, clustering, identification,
    OCR, resume, or large-file scan-unit scheduling. Traversal/profile controls
    such as root, output-dir, rules, workers, hash-mode, file-hash,
    exclude/include-hidden, priority, progress interval, XML scan mode, and NLP
    remain meaningful. Scanning-only controls such as email suffixes, OCR,
    person tables, duplicate-file collapse, large-file split units, and custom
    structured field/depth caps are normalized back to a deterministic baseline.
    """
    args.resume = ""
    args.email_suffix = []
    args.email_wildcard = []
    args.scan_images = False
    args.max_findings_per_file = 0
    args.person_tables = []
    args.write_person_evidence = False
    args.duplicate_files = "report"
    args.duplicate_content = "report"
    args.duplicate_evidence = "collapse"
    args.large_file_cutoff_mb = 0.0
    args.scan_unit_records = DEFAULT_SCAN_UNIT_RECORDS
    args.structured_max_depth = 12
    args.xml_max_fields = 200
    if args.profile == "create_rules":
        args.exclude = []
        args.priority = "discovery"
        args.include_hidden = False
    return args


def manifest_has_capped_atomic_outputs(manifest):
    run_info = manifest.get("run_info") or {}
    try:
        if int(run_info.get("max_findings_per_file") or 0) > 0:
            return True
    except (TypeError, ValueError):
        pass
    for name, entry in (manifest.get("rule_outputs") or {}).items():
        if name == evidence_output_name("SCAN_LIMIT", "max_findings_per_file") and int(entry.get("row_count") or 0) > 0:
            return True
    return False


def manifest_output_is_valid(manifest, output_name, current_fingerprint, output_path):
    if not manifest:
        return False
    entry = (manifest.get("rule_outputs") or {}).get(output_name)
    if not isinstance(entry, dict):
        return False
    if entry.get("fingerprint", "") != current_fingerprint:
        return False
    if not output_path.exists():
        return False
    try:
        actual_rows = count_csv_rows(output_path)
    except Exception:
        return False
    return int(entry.get("row_count", -1)) == actual_rows and bool(entry.get("completed"))


def write_run_info(paths, run_info):
    ordered_keys = [
        "started_at",
        "finished_at",
        "root",
        "output_dir",
        "workers_requested",
        "hash_workers_requested",
        "worker_count",
        "nlp",
        "nlp_backend",
        "xml_scan",
        "profile",
        "file_preprocessing",
        "discovery_preprocessing",
        "file_preprocessing_seconds",
        "discovery_preprocessing_seconds",
        "file_index",
        "file_index_rows",
        "file_index_reused",
        "file_index_error",
        "discovery_index",
        "discovery_index_regex_rules",
        "discovery_index_evidence_outputs",
        "discovery_index_person_table_keys",
        "person_tables_index",
        "person_tables_index_rows",
        "resume",
        "max_findings_per_file",
        "files_discovered",
        "files_processed",
        "profiled_files",
        "draft_rule_rows",
        "review_only_candidate_rows",
        "file_summary_rows",
        "finding_rows",
        "linked_evidence_rows",
        "cluster_count",
        "person_list_count",
        "person_tables",
        "known_people_matched",
        "known_people_output_rows",
        "known_people_missing",
        "no_list_people_summarised",
        "no_list_cluster_rows",
        "overall_seconds",
        "stage1_seconds",
        "hash_seconds",
        "extraction_seconds",
        "regex_seconds",
        "xml_evidence_scope_seconds",
        "worker_total_seconds",
        "csv_write_seconds",
        "entity_summary_seconds",
        "regex_summary_seconds",
        "profile_seconds",
        "value_type_candidate_rows",
        "rule_coverage_rows",
        "stage2_clustering_seconds",
        "stage3_reidentification_seconds",
    ]
    with open(paths["run_info"], "w", encoding="utf-8") as handle:
        handle.write("PII regex scanner run information\n")
        handle.write("=================================\n")
        handle.write(f"mode={run_mode_label(run_info.get('profile', ''))}\n")
        for key in ordered_keys:
            if key in run_info:
                handle.write(f"{key}={run_info[key]}\n")
        for key in sorted(run_info):
            if key not in ordered_keys:
                handle.write(f"{key}={run_info[key]}\n")


def compact_list_preview(values, limit=4):
    """Return a compact human-readable preview of a CLI list value."""
    values = [safe_cell(value) for value in (values or []) if safe_cell(value)]
    if not values:
        return "none"
    shown = values[:limit]
    suffix = "" if len(values) <= limit else f" +{len(values) - limit} more"
    return ", ".join(shown) + suffix


def print_launch_summary(args):
    """Print the effective run parameters in a readable terminal block."""
    profile = getattr(args, "profile", "") or "off"
    resume = getattr(args, "resume", "") or "off"
    person_tables = getattr(args, "person_tables", []) or []
    preprocessing = file_preprocessing_mode(args)
    person_preprocessing = discovery_preprocessing_mode(args)
    index_dir = getattr(args, "index_dir", "") or "default stage output folders"
    exclude = [
        item
        for group in (getattr(args, "exclude", []) or [])
        for item in (group if isinstance(group, list) else [group])
    ]
    lines = [
        "Run configuration",
        f"  root: {args.root}",
        f"  output: {args.output_dir}",
        f"  rules: {getattr(args, 'rules', '')}",
        f"  workers: {getattr(args, 'workers', 0)} requested (0 = auto)",
        "  worker backend: process",
        f"  hash workers: {getattr(args, 'hash_workers', 0)} requested (0 = auto)",
        f"  progress interval: {getattr(args, 'progress_every', 0)}s",
        f"  profile: {profile}",
        f"  file preprocessing: {preprocessing}",
        f"  discovery preprocessing: {person_preprocessing}",
        f"  index dir: {index_dir}",
        f"  resume: {resume}",
        f"  NLP: {'on' if getattr(args, 'nlp', False) else 'off'}",
        f"  XML scan: {getattr(args, 'xml_scan', '')}",
        f"  hash mode: {getattr(args, 'hash_mode', '')} ({getattr(args, 'file_hash', '')})",
        f"  duplicate files: {getattr(args, 'duplicate_files', getattr(args, 'duplicate_content', ''))}",
        f"  duplicate evidence: {getattr(args, 'duplicate_evidence', '')}",
        f"  large-file cutoff: {getattr(args, 'large_file_cutoff_mb', 0)} MB",
        f"  scan unit records: {getattr(args, 'scan_unit_records', '')}",
        f"  image/OCR scan: {'on' if getattr(args, 'scan_images', False) else 'off'}",
        f"  max findings per file: {getattr(args, 'max_findings_per_file', 0) or 'unlimited'}",
        f"  email suffixes: {compact_list_preview(getattr(args, 'email_suffix', []))}",
        f"  email wildcards: {compact_list_preview(getattr(args, 'email_wildcard', []))}",
        f"  person tables: {compact_list_preview(person_tables)}",
        f"  exclude paths: {compact_list_preview(exclude)}",
        f"  include hidden: {'yes' if getattr(args, 'include_hidden', False) else 'no'}",
        f"  priority: {getattr(args, 'priority', '')}",
    ]
    print("\n".join(lines), flush=True)


def run(args):
    print("PiiScraper startup: preparing run configuration", flush=True)
    args.root = os.path.abspath(args.root)
    args.output_dir = os.path.abspath(args.output_dir)
    print("PiiScraper startup: preparing output directories", flush=True)
    os.makedirs(args.output_dir, exist_ok=True)
    paths = output_paths(args.output_dir)
    args.index_dir = index_dir_path(args, paths)
    print_launch_summary(args)
    print("PiiScraper startup: loading rule configuration", flush=True)
    rules_started = time.perf_counter()
    last_rule_step = {"message": "", "time": rules_started}

    def report_rule_step(message):
        now = time.perf_counter()
        previous = last_rule_step["message"]
        if previous:
            print(
                f"PiiScraper startup: completed {previous} in {format_elapsed(now - last_rule_step['time'])}",
                flush=True,
            )
        print(f"PiiScraper startup: {message}", flush=True)
        last_rule_step["message"] = message
        last_rule_step["time"] = now

    initialize_rules(args, progress_callback=report_rule_step)
    if last_rule_step["message"]:
        now = time.perf_counter()
        print(
            f"PiiScraper startup: completed {last_rule_step['message']} in {format_elapsed(now - last_rule_step['time'])}",
            flush=True,
        )
    print(f"PiiScraper startup: rules loaded in {format_elapsed(time.perf_counter() - rules_started)}", flush=True)
    args.precomputed_file_metadata = {}
    run_started = time.perf_counter()
    run_info = {
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S %z"),
        "root": args.root,
        "output_dir": args.output_dir,
        "workers_requested": args.workers,
        "hash_workers_requested": args.hash_workers,
        "nlp": "true" if getattr(args, "nlp", False) else "false",
        "nlp_backend": current_nlp_backend() or ("lazy_loaded" if getattr(args, "nlp", False) else ""),
        "xml_scan": args.xml_scan,
        "profile": args.profile or "",
        "file_preprocessing": file_preprocessing_mode(args),
        "discovery_preprocessing": discovery_preprocessing_mode(args),
        "index_dir": index_dir_path(args, paths),
        "file_index": file_index_path(args, paths),
        "discovery_index": discovery_index_path(args, paths),
        "person_tables_index": person_tables_index_path(args, paths),
        "resume": args.resume or "",
        "max_findings_per_file": args.max_findings_per_file,
    }
    standalone_preprocessing_requested = (
        file_preprocessing_mode(args) == "standalone"
        or discovery_preprocessing_mode(args) == "standalone"
    )

    if (
        file_preprocessing_mode(args) == "integrated"
        and not standalone_preprocessing_requested
        and args.resume == ""
    ):
        print("Stage 1/7: file pre-processing")
        stage_started = time.perf_counter()
        run_source_preprocessing(args, paths, run_info)
        run_info["file_preprocessing_seconds"] = round(time.perf_counter() - stage_started, 6)

    if (
        discovery_preprocessing_mode(args) == "integrated"
        and not standalone_preprocessing_requested
        and args.resume in {"", "discovery"}
    ):
        print("Stage 2/7: discovery pre-processing")
        stage_started = time.perf_counter()
        run_discovery_preprocessing(args, paths, run_info)
        run_info["discovery_preprocessing_seconds"] = round(time.perf_counter() - stage_started, 6)

    if standalone_preprocessing_requested:
        if file_preprocessing_mode(args) == "standalone":
            print("Stage 1/7: file pre-processing standalone")
            stage_started = time.perf_counter()
            run_source_preprocessing(args, paths, run_info)
            run_info["file_preprocessing_seconds"] = round(time.perf_counter() - stage_started, 6)
        if discovery_preprocessing_mode(args) == "standalone":
            print("Stage 2/7: discovery pre-processing standalone")
            stage_started = time.perf_counter()
            run_discovery_preprocessing(args, paths, run_info)
            run_info["discovery_preprocessing_seconds"] = round(time.perf_counter() - stage_started, 6)
    elif args.profile == "standalone":
        print("Stage 3/7: profiling standalone")
        stage_started = time.perf_counter()
        profile_count, candidate_count, review_only_candidate_count, value_type_candidate_count, rule_coverage_count, schema_plan_count = run_profile_scan(args, paths, run_info)
        run_info["profile_seconds"] = round(time.perf_counter() - stage_started, 6)
        print(
            "Profiling complete: "
            f"{profile_count:,} column/field profiles, "
            f"{candidate_count:,} candidate rule rows, "
            f"{review_only_candidate_count:,} review-only grouped suggestions, "
            f"{value_type_candidate_count:,} value-type candidate rows, "
            f"{rule_coverage_count:,} rule coverage rows, "
            f"{schema_plan_count:,} schema-plan rows"
        )
    elif args.profile == "create_rules":
        print("Stage 3/7: create draft rules from profiling outputs")
        stage_started = time.perf_counter()
        draft_rule_count = create_rule_drafts_from_profile(args, paths, run_info)
        run_info["profile_seconds"] = round(time.perf_counter() - stage_started, 6)
        print(
            "Draft rule generation complete: "
            f"{draft_rule_count:,} review-stage JSON rule files written"
        )
    else:
        if args.profile == "integrated" and args.resume in {"", "discovery", "profiling"}:
            print("Stage 3/7: profiling and schema planning")
            stage_started = time.perf_counter()
            profile_count, candidate_count, review_only_candidate_count, value_type_candidate_count, rule_coverage_count, schema_plan_count = run_profile_scan(args, paths, run_info)
            run_info["profile_seconds"] = round(time.perf_counter() - stage_started, 6)
            args.schema_plan_decisions = load_schema_plan_decisions_from_csv(paths["schema_plan"])
            run_info["schema_plan_rows"] = schema_plan_count
            run_info["schema_plan_actionable"] = "true" if args.schema_plan_decisions else "false"
            print(
                "Stage 3/7 complete: "
                f"{profile_count:,} column/field profiles, "
                f"{candidate_count:,} candidate rule rows, "
                f"{review_only_candidate_count:,} review-only grouped suggestions, "
                f"{value_type_candidate_count:,} value-type candidate rows, "
                f"{rule_coverage_count:,} rule coverage rows, "
                f"{schema_plan_count:,} schema-plan rows"
            )
        elif args.profile == "integrated" and args.resume == "scanning":
            args.schema_plan_decisions = load_schema_plan_decisions_from_csv(paths["schema_plan"])
            run_info["schema_plan_reused"] = "true" if args.schema_plan_decisions else "false"
            run_info["schema_plan_actionable"] = "true" if args.schema_plan_decisions else "false"
            if args.schema_plan_decisions:
                print("Stage 3/7: using existing schema plan for resumed Stage 4 scanning")
            else:
                print("Stage 3/7: no reusable schema plan found; resumed Stage 4 scanning will use normal rule routing")

        if args.resume == "clustering":
            print("Resume mode: Stage 5 clustering")
            run_clustering_and_optionally_identification(args, paths, run_info, rebuild_linked=True)
        elif args.resume == "reidentification":
            print("Resume mode: Stage 6 reidentification")
            resume_identification(args, paths, run_info)
        elif args.resume == "reporting":
            print("Resume mode: Stage 7 reporting")
            resume_reporting(args, paths, run_info)
        else:
            if args.profile == "integrated":
                print("Stage 4/7: discovery and regex scanning using Stage 3 schema plan")
            else:
                print("Stage 4/7: discovery and regex scanning")
            stage_started = time.perf_counter()
            count = discover_streaming(args, paths, run_info)
            run_info["stage1_seconds"] = round(time.perf_counter() - stage_started, 6)
            print(f"Stage 4/7 complete: {count:,} files")

            stage_started = time.perf_counter()
            print("Stage 4/7: building entity summary from streamed file summary")
            build_entity_summary_from_file_summary(paths["file_summary"], paths["entity_summary"])
            run_info["entity_summary_seconds"] = round(time.perf_counter() - stage_started, 6)

            stage_started = time.perf_counter()
            print("Stage 4/7: building regex summary from streamed atomic evidence")
            build_regex_summary(paths["findings"], paths["regex_summary"])
            run_info["regex_summary_seconds"] = round(time.perf_counter() - stage_started, 6)

            linked_total = count_csv_rows(paths["linked_evidence"])
            raw_evidence_total = count_atomic_evidence_rows(paths["findings"])
            run_info["linked_evidence_rows"] = linked_total
            run_info["finding_rows"] = raw_evidence_total

            print("Stage 5/7: linking extracted evidence and building person clusters")
            stage_started = time.perf_counter()
            ensure_clustering_output_dirs(paths)
            cluster_count, cluster_members = build_person_clusters(
                paths["linked_evidence"],
                paths["person_clusters"],
                args.progress_every,
                linked_total,
                paths.get("cluster_members"),
            )
            run_info["stage2_clustering_seconds"] = round(time.perf_counter() - stage_started, 6)
            run_info["cluster_count"] = cluster_count
            print(f"Stage 5/7 complete: {linked_total:,} linked evidence rows, {cluster_count:,} clusters")

            if args.person_tables:
                print("Stage 6/7: reidentification using person-list information")
                stage_started = time.perf_counter()
                ensure_reidentification_output_dirs(paths, args.write_person_evidence)
                result = run_person_search(
                    args,
                    paths,
                    None,
                    cluster_count,
                    linked_total,
                    raw_evidence_total,
                )
                run_info["stage3_reidentification_seconds"] = round(time.perf_counter() - stage_started, 6)
                run_info["person_list_count"] = len(args.person_tables)
                run_info["person_tables"] = "|".join(args.person_tables)
                run_info["known_people_matched"] = result["known_people_matched_total"]
                run_info["known_people_output_rows"] = result["known_people_output_rows_total"]
                run_info["known_people_missing"] = result["known_people_missing_total"]
                run_info["no_list_people_summarised"] = result["no_list_people_summarised"]
                run_info["no_list_cluster_rows"] = result["no_list_cluster_rows"]
                for table_result in result["tables"]:
                    stem = table_result["stem"]
                    run_info[f"person_list_{stem}_matched"] = table_result["matched"]
                    run_info[f"person_list_{stem}_output_rows"] = table_result["output_rows"]
                    run_info[f"person_list_{stem}_missing"] = table_result["missing"]
                write_stage3_row_overlap_report(paths, run_info)
                print(
                    "Stage 6/7 complete: "
                    f"{result['known_people_matched_total']:,} list matches across {len(args.person_tables):,} lists, "
                    f"{result['no_list_people_summarised']:,} no-list summaries"
                )
            else:
                run_info["stage3_reidentification_seconds"] = 0.0
                print("Stage 6/7: skipped; no --person-tables supplied")

    print("Stage 7/7: writing final run metadata and reports", flush=True)
    run_info["finished_at"] = time.strftime("%Y-%m-%d %H:%M:%S %z")
    run_info["overall_seconds"] = round(time.perf_counter() - run_started, 6)
    for key in ["hash_seconds", "extraction_seconds", "regex_seconds", "worker_total_seconds", "csv_write_seconds"]:
        if key in run_info:
            run_info[key] = round(float(run_info[key]), 6)
    write_run_info(paths, run_info)
    write_run_manifest(paths, args, run_info)
    print(f"Run info: {paths['run_info']}")
    print("SQLite evidence store: not used; direct CSV streaming mode")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Standalone direct-streaming PII regex scanner; no SQLite evidence store; XML supports fast evidence-scope or structured scan modes.",
        allow_abbrev=False,
    )
    parser.add_argument("--root", default=DEFAULT_ROOT)
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--rules", default=DEFAULT_RULES_PATH)
    parser.add_argument(
        "--profile",
        choices=["standalone", "integrated", "create_rules", "columns"],
        default="",
        help=(
            "Profiling mode. 'standalone' rescans table/structured sources and writes "
            "non-disclosive profiling outputs and exits. 'integrated' runs profiling/schema planning "
            "as the linear Stage 3 before Stage 4 discovery/searching. 'create_rules' reads an existing profile output "
            "directory and writes draft table-column JSON rules for review. "
            "'columns' is accepted as a backward-compatible alias for 'standalone'."
        ),
    )
    parser.add_argument("--nlp", type=parse_bool, nargs="?", const=True, default=False, help="Enable optional NLP-assisted header/context heuristics for profiling and structured/header-aware scanning.")
    parser.add_argument("--email-suffix", action="append", default=[], help="Institutional email domain suffix/pattern. Repeat or comma-separate values; * is supported, e.g. nottingham.*")
    parser.add_argument(
        "--email-wildcard",
        action="append",
        default=[],
        help=(
            "Bidirectional email-domain equivalence rule for matching, e.g. "
            "'@nottingham == @exmail.nottingham'. Repeat or comma-separate rules."
        ),
    )
    parser.add_argument("--scan-images", type=parse_bool, nargs="?", const=True, default=False)
    parser.add_argument("--workers", type=int, default=0, help="Worker count; 0 selects logical CPU count minus 1, with a minimum of 1.")
    parser.add_argument(
        "--file-preprocessing",
        dest="file_preprocessing",
        choices=["standalone", "disabled", "integrated"],
        default="integrated",
        help=(
            "Source-file preprocessing mode. 'integrated' discovers/hashes/groups files before Stage 1; "
            "'disabled' skips this pass entirely; 'standalone' builds the reusable file index and exits."
        ),
    )
    parser.add_argument(
        "--discovery-preprocessing",
        choices=["standalone", "disabled", "integrated"],
        default="integrated",
        help=(
            "Discovery/reference-data preprocessing mode. 'integrated' prepares worker-ready discovery artefacts "
            "before discovery/searching; 'disabled' leaves workers to load raw rules/person tables; "
            "'standalone' builds reusable discovery artefacts and exits."
        ),
    )
    parser.add_argument(
        "--index-dir",
        default="",
        help=(
            "Reusable index directory. If present, existing indexes in this folder are trusted and reused; "
            "missing indexes are recreated by the relevant preprocessing mode. Contains file.index.json, "
            "discovery.json, person-tables.index.json, and future profile/schema indexes."
        ),
    )
    parser.add_argument(
        "--hash-workers",
        type=int,
        default=0,
        help=(
            "Process count for Stage 1 content hashing; 0 uses up to twice the scan worker count, capped at 16 "
            "and never above the number of files being hashed."
        ),
    )
    parser.add_argument("--max-findings-per-file", type=int, default=0)
    parser.add_argument(
        "--hash-mode",
        choices=["duplicate-candidates", "processed", "all", "none"],
        default="duplicate-candidates",
        help=(
            "Controls content hashing. 'duplicate-candidates' hashes only files whose byte size is shared "
            "with another processable file, then collapses exact selected-hash matches. 'processed' hashes "
            "all processable files before Stage 1. 'all' hashes every discovered file. 'none' disables "
            "content hashing and duplicate-file collapse."
        ),
    )
    parser.add_argument(
        "--file-hash",
        type=lambda value: safe_cell(value).casefold(),
        choices=["sha256", "md5"],
        default="sha256",
        help="Content hash algorithm used when --hash-mode hashes files. Default is sha256; md5 is retained for compatibility.",
    )
    parser.add_argument(
        "--duplicate-files",
        "--duplicate-content",
        dest="duplicate_files",
        choices=["scan", "report", "collapse", "reuse"],
        default="collapse",
        help=(
            "How to handle byte-identical files with the same selected content hash. "
            "'scan' scans every copy and annotates duplicate groups; 'report' scans the first copy and writes "
            "duplicate file_summary rows only; 'collapse' scans the first copy and reuses content-derived "
            "evidence for duplicate paths. The older value/name 'reuse' is accepted as an alias for 'collapse'."
        ),
    )
    parser.add_argument(
        "--duplicate-evidence",
        choices=["scan", "report", "collapse"],
        default="collapse",
        help=(
            "How to handle semantically identical linked-evidence units after scanning. "
            "'scan' writes every linked-evidence row; 'report' writes all rows with duplicate provenance; "
            "'collapse' writes one linked-evidence row per duplicate group with provenance. "
            "Atomic evidence CSVs are not collapsed."
        ),
    )
    parser.add_argument(
        "--large-file-cutoff-mb",
        "--large-file-cuttoff-mb",
        "--large-file-threshold-mb",
        dest="large_file_cutoff_mb",
        type=float,
        default=100.0,
        help="Split XML/JSONL/CSV/TSV files into parallel scan units only at or above this size in MB. Use 0 to disable.",
    )
    parser.add_argument("--scan-unit-records", type=int, default=DEFAULT_SCAN_UNIT_RECORDS)
    parser.add_argument("--progress-every", type=float, default=1.0)
    parser.add_argument("--person-tables", nargs="+", default=[], help="One or more person reference CSV files. Outputs are named from each input filename stem; no-list outputs contain identities not matched to any supplied table.")
    parser.add_argument("--write-person-evidence", type=parse_bool, nargs="?", const=True, default=False)
    parser.add_argument(
        "--xml-scan",
        choices=["fast", "structured"],
        default="fast",
        help=(
            "XML scan mode. 'fast' uses raw in-RAM XML evidence scopes and retains all regex evidence; "
            "'structured' uses the structured XML extraction/chunking path."
        ),
    )
    parser.add_argument(
        "--resume",
        choices=["discovery", "profiling", "scanning", "clustering", "reidentification", "reporting"],
        default="",
        help=(
            "Resume a linear stage from previous outputs: discovery starts at Stage 2 discovery preprocessing; "
            "profiling starts at Stage 3 profiling/schema planning; scanning starts at Stage 4 regex scanning; "
            "clustering starts at Stage 5; reidentification starts at Stage 6; reporting starts at Stage 7."
        ),
    )
    parser.add_argument("--structured-max-depth", type=int, default=12)
    parser.add_argument(
        "--xml-max-fields",
        type=int,
        default=200,
        help=(
            "Maximum labelled fields retained per XML evidence scope or structured record. "
            "Applies to --xml-scan fast scopes and the structured extraction path."
        ),
    )
    parser.add_argument("--exclude", nargs="+", action="append", default=[], metavar="PATH")
    parser.add_argument("--priority", choices=["discovery", "alphabetical", "size", "type"], default="discovery")
    parser.add_argument("--include-hidden", action="store_true")
    args = parser.parse_args(argv)
    args.profile = canonical_profile_mode(args.profile)
    if args.duplicate_files == "reuse":
        args.duplicate_files = "collapse"
    # Internal compatibility name used by the existing duplicate-file helpers.
    args.duplicate_content = args.duplicate_files

    if is_profile_only_mode(args.profile) and args.resume:
        parser.error("--profile standalone/create_rules cannot be combined with --resume")
    if args.resume == "profiling" and not args.profile:
        args.profile = "integrated"
    if args.resume == "profiling" and args.profile != "integrated":
        parser.error("--resume profiling requires --profile integrated or no --profile flag")

    if is_profile_only_mode(args.profile):
        args = normalize_profile_mode_args(args)

    # Structured records are always enabled in this direct-streaming scanner.
    # The former --structured-records flag has been removed.
    args.structured_records = True

    # Structured record emission is intentionally not tied to --max-findings-per-file;
    # that flag limits output findings, not extraction coverage.
    args.structured_max_records_per_file = 0

    # Internal compatibility name used by the merged extraction helpers.
    # The public flags --structured-max-record-fields and --xml-scope-max-fields
    # have been merged into --xml-max-fields.
    args.structured_max_record_fields = max(1, int(args.xml_max_fields or 200))

    return args


def main(argv=None):
    print("PiiScraper startup: parsing command-line arguments", flush=True)
    args = parse_args(argv)
    print("PiiScraper startup: arguments parsed", flush=True)
    run(args)


if __name__ == "__main__":
    main()
