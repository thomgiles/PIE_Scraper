"""Linked-evidence candidate parsing and person-cluster construction.

This module is loaded into pii_regex_scanner.pipeline's shared namespace.
"""

def sync_runtime_state():
    return None


def split_pipe_values(value):
    if not value:
        return []
    return [part for part in str(value).split("|") if part]


def parse_cluster_evidence_values(evidence_values):
    parsed = {}
    for part in split_pipe_values(evidence_values):
        if "=" not in part:
            continue
        evidence_type, evidence_value = part.split("=", 1)
        evidence_type = evidence_type.strip()
        evidence_value = evidence_value.strip()
        if not evidence_type or not evidence_value:
            continue
        parsed.setdefault(evidence_type, set()).add(evidence_value)
    return parsed


class UnionFind:
    def __init__(self):
        self.parent = []
        self.rank = []

    def add(self):
        index = len(self.parent)
        self.parent.append(index)
        self.rank.append(0)
        return index

    def find(self, item):
        parent = self.parent[item]
        if parent != item:
            self.parent[item] = self.find(parent)
        return self.parent[item]

    def union(self, left, right):
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return left_root
        if self.rank[left_root] < self.rank[right_root]:
            left_root, right_root = right_root, left_root
        self.parent[right_root] = left_root
        if self.rank[left_root] == self.rank[right_root]:
            self.rank[left_root] += 1
        return left_root


def candidate_cluster_keys(row, evidence_map):
    """Return linkage keys for a candidate row.

    Strong unique-ish anchors are allowed to link globally. Weaker fields are
    only used as compound keys to avoid merging unrelated people with common
    names, shared postcodes, shared dates, generic usernames, or repeated
    administrative terms.
    """
    keys = []

    for evidence_type in PERSON_CLUSTER_STRONG_ANCHORS:
        for evidence_value in evidence_map.get(evidence_type, set()):
            lookup_pairs = email_lookup_pairs(evidence_type, evidence_value)
            if not lookup_pairs:
                lookup_pairs = ((evidence_type, evidence_value),)
            for key_type, key_value in lookup_pairs:
                if key_type in PERSON_CLUSTER_STRONG_ANCHORS and key_value:
                    keys.append(f"strong:{key_type}:{key_value}")

    anchor_type = row.get("anchor_type", "")
    anchor_value = row.get("anchor_value", "")
    if anchor_type in PERSON_CLUSTER_STRONG_ANCHORS and anchor_value:
        lookup_pairs = email_lookup_pairs(anchor_type, anchor_value)
        if not lookup_pairs:
            lookup_pairs = ((anchor_type, anchor_value),)
        for key_type, key_value in lookup_pairs:
            if key_type in PERSON_CLUSTER_STRONG_ANCHORS and key_value:
                keys.append(f"strong:{key_type}:{key_value}")

    for anchor_set in PERSON_CLUSTER_COMPOUND_ANCHOR_SETS:
        value_sets = [compound_anchor_values(evidence_map, evidence_type) for evidence_type in anchor_set]
        if not all(value_sets):
            continue
        combinations = [()]
        for values in value_sets:
            combinations = [existing + (value,) for existing in combinations for value in sorted(values)]
        for combination in combinations:
            label = "+".join(anchor_set)
            value_key = ":".join(combination)
            keys.append(f"compound:{label}:{value_key}")

    # No linkage key means this linked-evidence row remains a singleton cluster.
    if not keys:
        row_key = row.get("linked_evidence_key") or row.get("candidate_key", "")
        keys.append(f"singleton:{row_key}:{row.get('file_path', '')}:{row.get('row_number', '')}")

    return sorted(set(keys))


def compound_anchor_values(evidence_map, evidence_type):
    values = {value for value in evidence_map.get(evidence_type, set()) if value}
    if evidence_type in EMAIL_EVIDENCE_TYPES or evidence_type == "Email":
        aliased_values = set()
        for value in values:
            for key_type, key_value in email_lookup_pairs(evidence_type, value):
                if key_type == evidence_type and key_value:
                    aliased_values.add(key_value)
        values.update(aliased_values)
    if evidence_type == "Name":
        full_names = {value for value in values if len(value.split()) >= 2}
        if full_names:
            return full_names
    return values


def capped_join(values, limit=50):
    values = [value for value in sorted(set(values)) if value]
    if len(values) <= limit:
        return "|".join(values)
    return "|".join(values[:limit]) + f"|...(+{len(values) - limit} more)"


def strongest_risk(values):
    best = ""
    for value in values:
        if RISK_ORDER.get(value, 0) > RISK_ORDER.get(best, 0):
            best = value
    return best


def cluster_confidence(cluster):
    anchor_types = cluster["anchor_types"]
    evidence_types = cluster["evidence_types"]
    linked_evidence_count = cluster["linked_evidence_count"]

    if evidence_types & PERSON_CLUSTER_STRONG_ANCHORS:
        return "high"
    if any(set(anchor_set) <= evidence_types for anchor_set in PERSON_CLUSTER_COMPOUND_ANCHOR_SETS):
        return "medium" if linked_evidence_count == 1 else "high"
    if linked_evidence_count > 1:
        return "medium"
    return "low"


def identity_anchor_bases(evidence_types):
    if isinstance(evidence_types, str):
        evidence_types = set(split_pipe_values(evidence_types))
    else:
        evidence_types = set(evidence_types)

    bases = [
        f"strong:{evidence_type}"
        for evidence_type in sorted(
            evidence_types & PERSON_CLUSTER_STRONG_ANCHORS,
            key=lambda evidence_type: (ANCHOR_PRIORITY_BY_TYPE.get(evidence_type, 10_000), evidence_type),
        )
    ]
    bases.extend(
        "compound:" + "+".join(anchor_set)
        for anchor_set in PERSON_CLUSTER_COMPOUND_ANCHOR_SETS
        if set(anchor_set) <= evidence_types
    )
    return bases


def cluster_identity_anchor_basis(cluster):
    return "|".join(identity_anchor_bases(cluster.get("evidence_types", set())))


def cluster_meets_identity_anchor(cluster):
    evidence_types = cluster.get("evidence_types", "")

    return bool(identity_anchor_bases(evidence_types))


def build_person_clusters(linked_evidence_source, clusters_path, progress_every=1.0, total_rows=None, cluster_members_path=None):
    """Build global person clusters from linked-evidence rows.

    The scanner keeps linked-evidence generation local and cheap while files are
    being processed in threads. This post-processing pass merges rows that share
    strong identifiers or defensible compound keys.
    """
    source_is_path = isinstance(linked_evidence_source, (str, os.PathLike))
    if source_is_path and (
        not os.path.exists(linked_evidence_source) or os.path.getsize(linked_evidence_source) == 0
    ):
        with open(clusters_path, "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as f:
            csv.DictWriter(f, fieldnames=PERSON_CLUSTER_FIELDS).writeheader()
        return 0, {}
    if not source_is_path and not linked_evidence_source:
        with open(clusters_path, "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as f:
            csv.DictWriter(f, fieldnames=PERSON_CLUSTER_FIELDS).writeheader()
        return 0, {}

    union_find = UnionFind()
    key_to_index = {}
    key_counts = Counter()
    rows = []
    processed_rows = 0
    eligible_rows = 0
    excluded_rows = 0
    last_progress = time.time()
    printed_progress = False
    total_label = f"{total_rows:,}" if total_rows is not None else "?"

    source_context = (
        open(linked_evidence_source, "r", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE)
        if source_is_path
        else nullcontext(iter(linked_evidence_source))
    )
    with source_context as source:
        reader = csv.DictReader(source) if source_is_path else source
        for row in reader:
            processed_rows += 1
            evidence_map = parse_cluster_evidence_values(row.get("evidence_values", ""))
            cluster_exclusion_reason = row.get("cluster_exclusion_reason", "")
            if not cluster_exclusion_reason and row.get("cluster_eligible", "") != "yes":
                cluster_exclusion_reason = clustering_exclusion_reason(evidence_map)
            if row.get("cluster_eligible") == "no" or cluster_exclusion_reason:
                excluded_rows += 1
                now = time.time()
                if progress_every > 0 and now - last_progress >= progress_every:
                    print(
                        f"\rStage 5/7: clustering candidate {processed_rows:,} of {total_label} | "
                        f"eligible {eligible_rows:,} | excluded {excluded_rows:,} | "
                        f"merge keys {len(key_to_index):,}",
                        end="",
                        flush=True,
                    )
                    last_progress = now
                    printed_progress = True
                continue

            eligible_rows += 1
            keys = candidate_cluster_keys(row, evidence_map)
            row["_evidence_map"] = evidence_map
            row["_all_cluster_keys"] = keys
            row["_cluster_keys"] = keys
            rows.append(row)
            key_counts.update(keys)

            now = time.time()
            if progress_every > 0 and now - last_progress >= progress_every:
                print(
                    f"\rStage 5/7: clustering candidate {processed_rows:,} of {total_label} | "
                    f"eligible {eligible_rows:,} | excluded {excluded_rows:,} | "
                    f"merge keys {len(key_to_index):,}",
                    end="",
                    flush=True,
                )
                last_progress = now
                printed_progress = True

    for index, row in enumerate(rows):
        union_find.add()
        usable_keys = [key for key in row.get("_all_cluster_keys", []) if key_counts.get(key, 0) <= MAX_CLUSTER_KEY_FREQUENCY]
        suppressed_keys = [key for key in row.get("_all_cluster_keys", []) if key_counts.get(key, 0) > MAX_CLUSTER_KEY_FREQUENCY]
        row["_cluster_keys"] = usable_keys
        row["_suppressed_cluster_keys"] = suppressed_keys
        for key in usable_keys:
            previous = key_to_index.get(key)
            if previous is None:
                key_to_index[key] = index
            else:
                union_find.union(previous, index)

    print(
        f"\rStage 5/7: clustering candidate {processed_rows:,} of {total_label} | "
        f"eligible {eligible_rows:,} | excluded {excluded_rows:,} | merge keys {len(key_to_index):,}"
    )

    clusters = {}
    last_progress = time.time()
    printed_progress = False
    for index, row in enumerate(rows):
        root = union_find.find(index)
        cluster = clusters.setdefault(
            root,
            {
                "linked_evidence_count": 0,
                "row_ids": set(),
                "file_paths": set(),
                "file_names": set(),
                "anchor_types": set(),
                "anchor_values": set(),
                "cluster_merge_keys": set(),
                "evidence_types": set(),
                "evidence_values": set(),
                "risk_levels": [],
                "risk_reasons": set(),
                "source_rows": [],
                "linked_rows": [],
            },
        )

        cluster["linked_evidence_count"] += 1
        cluster["linked_rows"].append({field: row.get(field, "") for field in LINKED_EVIDENCE_FIELDS})
        if row.get("file_path"):
            cluster["file_paths"].add(row["file_path"])
        if row.get("file_name"):
            cluster["file_names"].add(row["file_name"])
        if row.get("row_number"):
            cluster["row_ids"].add(f"{row.get('file_path', '')}#row={row['row_number']}")
        if row.get("anchor_type"):
            cluster["anchor_types"].add(row["anchor_type"])
        if row.get("anchor_value"):
            cluster["anchor_values"].add(f"{row.get('anchor_type', '')}={row['anchor_value']}")
        cluster["cluster_merge_keys"].update(row.get("_cluster_keys", []))
        if row.get("_suppressed_cluster_keys"):
            cluster["risk_reasons"].add("ambiguous_high_frequency_anchor_suppressed")

        for evidence_type, values in row["_evidence_map"].items():
            cluster["evidence_types"].add(evidence_type)
            for value in values:
                cluster["evidence_values"].add(f"{evidence_type}={value}")

        if row.get("risk_level"):
            cluster["risk_levels"].append(row["risk_level"])
        for reason in split_pipe_values(row.get("risk_reasons", "")):
            cluster["risk_reasons"].add(reason)
        if row.get("source_row") and len(cluster["source_rows"]) < 10:
            cluster["source_rows"].append(row["source_row"])

        now = time.time()
        if progress_every > 0 and now - last_progress >= progress_every:
            print(
                f"\rStage 5/7: assembling candidate {index + 1:,} of {eligible_rows:,} | "
                f"provisional clusters {len(clusters):,}",
                end="",
                flush=True,
            )
            last_progress = now
            printed_progress = True

    print(
        f"\rStage 5/7: assembling candidate {len(rows):,} of {eligible_rows:,} | "
        f"provisional clusters {len(clusters):,}"
    )

    ordered_roots = sorted(
        clusters,
        key=lambda root: (
            -RISK_ORDER.get(strongest_risk(clusters[root]["risk_levels"]), 0),
            -clusters[root]["linked_evidence_count"],
            sorted(clusters[root]["anchor_values"])[0] if clusters[root]["anchor_values"] else "",
        ),
    )

    cluster_member_fields = ["person_cluster_id"] + LINKED_EVIDENCE_FIELDS
    member_handle = None
    member_writer = None
    if cluster_members_path:
        member_handle = open(cluster_members_path, "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE)
        member_writer = csv.DictWriter(member_handle, fieldnames=cluster_member_fields)
        member_writer.writeheader()

    with open(clusters_path, "w", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as f:
        writer = csv.DictWriter(f, fieldnames=PERSON_CLUSTER_FIELDS)
        writer.writeheader()
        total_clusters = len(ordered_roots)
        last_progress = time.time()
        printed_progress = False
        for number, root in enumerate(ordered_roots, start=1):
            cluster = clusters[root]
            if cluster["linked_evidence_count"] > MAX_CLUSTER_LINKED_ROWS:
                cluster["risk_reasons"].add(f"large_cluster_linked_rows>{MAX_CLUSTER_LINKED_ROWS}")
            if len(cluster["file_paths"]) > MAX_CLUSTER_FILE_COUNT:
                cluster["risk_reasons"].add(f"large_cluster_file_count>{MAX_CLUSTER_FILE_COUNT}")
            person_cluster_id = f"person_cluster_{number:08d}"
            if member_writer is not None:
                for linked_row in cluster["linked_rows"]:
                    member_row = {field: linked_row.get(field, "") for field in LINKED_EVIDENCE_FIELDS}
                    member_row["person_cluster_id"] = person_cluster_id
                    member_writer.writerow(member_row)
            writer.writerow(
                {
                    "person_cluster_id": person_cluster_id,
                    "cluster_confidence": cluster_confidence(cluster),
                    "risk_level": strongest_risk(cluster["risk_levels"]),
                    "linked_evidence_count": cluster["linked_evidence_count"],
                    "file_count": len(cluster["file_paths"]),
                    "row_count": len(cluster["row_ids"]),
                    "anchor_types": capped_join(cluster["anchor_types"]),
                    "anchor_values": capped_join(cluster["anchor_values"]),
                    "cluster_merge_keys": capped_join(cluster["cluster_merge_keys"], limit=100),
                    "identity_anchor_basis": cluster_identity_anchor_basis(cluster),
                    "evidence_types": capped_join(cluster["evidence_types"]),
                    "evidence_values": capped_join(cluster["evidence_values"], limit=100),
                    "risk_reasons": capped_join(cluster["risk_reasons"]),
                    "file_paths": capped_join(cluster["file_paths"], limit=25),
                    "file_names": capped_join(cluster["file_names"], limit=25),
                    "source_rows": " || ".join(cluster["source_rows"]),
                }
            )

            now = time.time()
            if progress_every > 0 and now - last_progress >= progress_every:
                print(
                    f"\rStage 5/7: writing cluster {number:,} of {total_clusters:,} | "
                    f"linked evidence rows {eligible_rows:,}",
                    end="",
                    flush=True,
                )
                last_progress = now
                printed_progress = True

    print(
        f"\rStage 5/7: writing cluster {total_clusters:,} of {total_clusters:,} | "
        f"linked evidence rows {eligible_rows:,}"
    )

    if member_handle is not None:
        member_handle.close()

    # Do not return the cluster-member map. It can be very large; Stage 3 is
    # deliberately driven from CSV outputs so Stage 2 data can be freed.
    return len(clusters), None


def load_cluster_members_from_linked_evidence(linked_evidence_path):
    if not os.path.exists(linked_evidence_path) or os.path.getsize(linked_evidence_path) == 0:
        return 0, {}

    union_find = UnionFind()
    key_to_index = {}
    rows = []

    with open(linked_evidence_path, "r", newline="", encoding="utf-8", buffering=OUTPUT_BUFFER_SIZE) as f:
        for row in csv.DictReader(f):
            evidence_map = parse_cluster_evidence_values(row.get("evidence_values", ""))
            cluster_exclusion_reason = row.get("cluster_exclusion_reason", "")
            if not cluster_exclusion_reason and row.get("cluster_eligible", "") != "yes":
                cluster_exclusion_reason = clustering_exclusion_reason(evidence_map)
            if row.get("cluster_eligible") == "no" or cluster_exclusion_reason:
                continue

            index = union_find.add()
            keys = candidate_cluster_keys(row, evidence_map)
            row["_evidence_map"] = evidence_map
            row["_cluster_keys"] = keys
            rows.append(row)

            for key in keys:
                previous = key_to_index.get(key)
                if previous is None:
                    key_to_index[key] = index
                else:
                    union_find.union(previous, index)

    clusters = {}
    for index, row in enumerate(rows):
        root = union_find.find(index)
        cluster = clusters.setdefault(
            root,
            {
                "linked_evidence_count": 0,
                "anchor_values": set(),
                "risk_levels": [],
                "linked_rows": [],
            },
        )
        cluster["linked_evidence_count"] += 1
        cluster["linked_rows"].append({field: row.get(field, "") for field in LINKED_EVIDENCE_FIELDS})
        if row.get("anchor_value"):
            cluster["anchor_values"].add(f"{row.get('anchor_type', '')}={row['anchor_value']}")
        if row.get("risk_level"):
            cluster["risk_levels"].append(row["risk_level"])

    ordered_roots = sorted(
        clusters,
        key=lambda root: (
            -RISK_ORDER.get(strongest_risk(clusters[root]["risk_levels"]), 0),
            -clusters[root]["linked_evidence_count"],
            sorted(clusters[root]["anchor_values"])[0] if clusters[root]["anchor_values"] else "",
        ),
    )

    cluster_members = {}
    for number, root in enumerate(ordered_roots, start=1):
        cluster_members[f"person_cluster_{number:08d}"] = clusters[root]["linked_rows"]
    return len(clusters), cluster_members


EMAIL_ANCHOR_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.IGNORECASE)


PERSON_TABLE_EXACT_PATTERN_NAME = "person_table_exact_match"
PERSON_TABLE_EXACT_MATCH_INDEX = {}
PERSON_TABLE_INFER_HEADER_INDEX = {}
PERSON_TABLE_REF_NAME_INDEX = {}
PERSON_TABLE_EXACT_EVIDENCE_TYPES = set()
PERSON_TABLE_EXACT_INDEX_KEY = None
PERSON_TABLE_EXACT_MIN_ALNUM_CHARS = 6
PERSON_TABLE_EXACT_VALUE_STOPWORDS = {
    "", "na", "n/a", "none", "null", "unknown", "not known", "missing",
    "true", "false", "yes", "no", "y", "n", "0", "1",
    "not applicable", "notspecified", "not specified", "prefer not to say",
}
PERSON_TABLE_EXACT_CONTEXTUAL_TYPES = {
    "Gender/Sex", "Religion", "Ethnicity", "Disability", "Citizenship Country", "Citizenship/Country", "Marital Status"
}
PERSON_TABLE_SUMMARY_STEMS = []
MAX_CLUSTER_KEY_FREQUENCY = 200
MAX_CLUSTER_LINKED_ROWS = 500
MAX_CLUSTER_FILE_COUNT = 100
SENSITIVE_TABLE_EMIT_TYPES = {
    "Gender/Sex", "Religion", "Ethnicity", "Disability", "Citizenship Country", "Citizenship/Country", "Marital Status"
}
SENSITIVE_TABLE_EMPTY_VALUES = {
    "", "na", "n/a", "none", "null", "unknown", "not known", "missing",
    "not applicable", "notspecified", "not specified", "prefer not to say"
}
GENDER_VALUE_RE = re.compile(r"^(?:m|f|male|female|non[-\s]?binary|other|intersex|trans(?:gender)?|prefer\s+not\s+to\s+say)$", re.IGNORECASE)
PERSON_TABLE_EXACT_TOKEN_RE = re.compile(
    r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b"
    r"|\b[A-Za-z0-9][A-Za-z0-9._%+@\-]{2,}\b"
    r"|\b\d(?:[\d\-\s]{2,}\d)\b",
    re.IGNORECASE,
)
