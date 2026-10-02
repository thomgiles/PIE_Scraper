# PII regex scanner

This folder contains the packaged regex scanner, rules, tests, documentation, and reporting utilities.

## Command-line flags

### Input and output

- `--root PATH`: input folder. Defaults to `tests/synthetic_data/inputs/breach_dump`.
- `--output-dir PATH`: output folder. Defaults to `tests/synthetic_data/outputs`.
- `--rules PATH`: rules root. When omitted, the regex scanner uses only the built-in email rule, plus the built-in minimal table-column defaults needed for conservative structured/header handling.
- `--person-tables CSV [CSV ...]`: optional person-list/reference CSVs.
- `--email-suffix DOMAIN[,DOMAIN...]`: splits email findings into institutional and personal email types. The flag can be repeated and supports `*` wildcards, for example `nottingham.*`.
- `--email-wildcard "A == B"`: treats equivalent email domains as the same person-matching key without rewriting the displayed evidence, for example `--email-wildcard "@nottingham == @exmail.nottingham"`.

### Scanning

- `--workers N`: Stage 4 scanning process workers. Default: `0`, which auto-selects logical CPU count minus one, with a minimum of one worker and no more workers than queued file targets. Pass a positive integer to force an exact worker count.
- `--file-preprocessing standalone|disabled|integrated`: source-file preprocessing mode. Default: `integrated`, which discovers, hashes, groups duplicate files, and writes `1.File_Preprocessing/file.index.json` before scanning. `standalone` builds/reuses the file index and exits. `disabled` skips this pass entirely.
- `--discovery-preprocessing standalone|disabled|integrated`: worker discovery/reference-data preprocessing mode. Default: `integrated`, which prepares worker-ready discovery artefacts before discovery/searching. `standalone` builds reusable discovery artefacts and exits. `disabled` leaves workers to load raw rules/person tables.
- `--index-dir PATH`: reusable index folder. If supplied and an index exists in the folder, it is trusted and reused; missing indexes are recreated by the relevant preprocessing mode. The folder contains `file.index.json`, `discovery.json`, `person-tables.index.json`, and future table-profile/schema indexes. Without `--index-dir`, indexes are written to their stage folders.
- `--hash-workers N`: Stage 1 content-hashing processes. Default: `0`, which uses up to twice the scan worker count, capped at 16 and never above the number of files being hashed. This only applies to files selected by `--hash-mode`.
- `--nlp [TRUE|FALSE]`: enables optional NLP-assisted header/context heuristics for profiling and structured/header-aware scanning. Default: `FALSE`.
- `--scan-images [TRUE|FALSE]`: enables image OCR. Default: `FALSE`.
- `--max-findings-per-file N`: maximum finding rows per file. Default: `0`, meaning unlimited.
- `--hash-mode duplicate-candidates|processed|all|none`: controls content hashing. Default: `duplicate-candidates`, which first groups files by byte size and only hashes same-size processable files so exact duplicates, including renamed copies, can be collapsed without pre-reading every unique file. `processed` hashes every processable file before Stage 1. With OCR disabled, `processed` does not hash image files. Use `all` when hashes are required for every discovered file. Use `none` to disable content hashing and duplicate-file collapse.
- `--file-hash sha256|md5`: content hash algorithm. Default: `sha256`; `md5` is retained for compatibility.
- `--duplicate-files scan|report|collapse`: handling for byte-identical files with the same selected content hash. Default: `collapse`, which scans the first copy and reuses content-derived evidence rows for duplicate paths while recording duplicate-file provenance in `file_summary.csv`. `scan` scans every copy. `report` scans the first copy and writes duplicate `file_summary.csv` rows only. The older `--duplicate-content` flag and `reuse` value are accepted as aliases.
- `--duplicate-evidence scan|report|collapse`: handling for semantically identical linked-evidence units after scanning. Default: `collapse`, which writes one `linked_evidence.csv` row per duplicate evidence group with provenance columns. `report` writes all linked rows with duplicate provenance. `scan` writes every linked row independently. Atomic evidence CSVs are always kept as the audit trail.
- `--large-file-cutoff-mb N`: split XML, JSONL, CSV, and TSV files into scan units only at or above this size in MB. Default: `100`. Use `0` to disable. Compatibility spellings `--large-file-cuttoff-mb` and `--large-file-threshold-mb` are also accepted.
- `--scan-unit-records N`: approximate records per large-file scan unit. Default: `1000`.
- `--include-hidden`: includes dot-prefixed files and folders.
- `--exclude PATH [PATH ...]`: excludes named files or folders. The flag can be repeated.
- `--priority discovery|alphabetical|size|type`: controls scan submission order. Default: `discovery`.
- `--progress-every SECONDS`: progress-reporting interval. Default: `1`.
- `--xml-scan fast|structured`: XML mode. `fast` is the v0.5 default and builds bounded XML evidence scopes from raw XML text; `structured` uses the structured XML record path and can be chunked for large files.

### Profiling

- `--profile standalone`: runs only the column/structured-data profiler. It rescans supported table and structured sources and writes non-disclosive profiling outputs.
- `--profile integrated`: runs profiling/schema planning as Stage 3 before Stage 4 discovery/searching, then uses safe actionable schema-plan decisions to route relevant regex rules or emit validated header-confirmed cell values. It also writes `3.Profiling/schema_plan.csv` so the routing decisions can be reviewed.
- `--profile create_rules`: reads an existing profile output folder and writes draft table-column JSON rules under `draft_table_column_rules/` for manual review.
- `--profile columns`: backward-compatible alias for `standalone`.

Standalone profiling uses the discovery/profile subset of runtime flags: `--root`, `--output-dir`, `--rules`, `--workers`, `--hash-mode`, `--file-hash`, `--exclude`, `--include-hidden`, `--priority`, `--progress-every`, `--xml-scan`, and `--nlp`. It normalizes scanning-only options such as email suffixes, email wildcard aliases, OCR, person tables, duplicate-file collapse, large-file scan units, and custom field-depth caps back to deterministic defaults. `create_rules` only reads existing profile outputs and ignores traversal controls. `integrated` runs as Stage 3 before discovery/searching and can be resumed with `--resume profiling`.

### Structured data

- `--structured-max-depth N`: maximum inspected nesting depth. Default: `12`.
- `--xml-max-fields N`: maximum retained labelled fields per XML evidence scope or structured record. Default: `200`.

### Person evidence

- `--write-person-evidence [TRUE|FALSE]`: writes detailed per-person evidence folders. Default: `FALSE`.

### Resume

The v0.5 pipeline uses explicit linear stage names:

- Stage 1 file preprocessing: no resume flag; run normally or use `--file-preprocessing standalone`.
- Stage 2 discovery preprocessing: `--resume discovery`.
- Stage 3 profiling/schema planning: `--resume profiling` (implies `--profile integrated` if no profile mode is supplied).
- Stage 4 regex scanning/discovery: `--resume scanning`.
- Stage 5 clustering: `--resume clustering`.
- Stage 6 reidentification: `--resume reidentification`.
- Stage 7 reporting: `--resume reporting`.

```bash
python3 PiiScraper/run_scanner.py --help
```

## Scanner

`run_scanner.py` launches the direct-streaming package under `src/pii_regex_scanner/`.

Run with one or more person lists:

```bash
python3 PiiScraper/run_scanner.py \
  --root PiiScraper/tests/synthetic_data/inputs/breach_dump \
  --output-dir PiiScraper/tests/synthetic_data/outputs/breach_dump \
  --person-tables PiiScraper/tests/synthetic_data/inputs/synthetic_slim_contacts.csv \
  --rules PiiScraper/rules \
  --email-suffix example.ac.uk \
  --workers 4
```

```powershell
python PiiScraper/run_scanner.py `
  --root PiiScraper/tests/synthetic_data/inputs/breach_dump `
  --output-dir PiiScraper/tests/synthetic_data/outputs/breach_dump `
  --person-tables PiiScraper/tests/synthetic_data/inputs/synthetic_slim_contacts.csv `
  --rules PiiScraper/rules `
  --email-suffix example.ac.uk `
  --scan-images FALSE `
  --workers 4
```

Package layout:

```text
src/pii_regex_scanner/
  cli.py           command-line entry point
  pipeline.py      shared scanner state plus component loader
  validation.py    validators, normalisation, email suffixes, name/address helpers
  rules.py         regex/table rules, identity anchors, and derived rule metadata
  extraction.py    file typing, table/structured/document extraction, target discovery
  scanning.py      atomic evidence scanning, XML scopes, scan chunks, per-file processing
  summaries.py     file/entity/regex summary builders
  clustering.py    linked-evidence clustering and cluster scoring
  people.py        person-table loading, person matching, risk/evidence outputs
  row_overlap.py   known/no-list row, person-anchor, and typed-value overlap reports
  runtime.py       direct CSV writer, resume modes, CLI parsing, and run orchestration
  engine.py        compatibility alias to pipeline
  __main__.py      python -m entry point
  __init__.py      package metadata
```

Run the package directly without installation:

```bash
PYTHONPATH=PiiScraper/src python3 -m pii_regex_scanner --help
```

Run the standard-library test suite:

```bash
cd PiiScraper
python3 -m unittest discover -s tests -p 'test_*.py'
```

Build the workflow documentation:

```bash
cd PiiScraper/documentation
python3 render_workflow_diagrams.py
quarto render PII_REGEX_WORKFLOW_WRITEUP.qmd --to docx
python3 build_workflow_reference.py --finalize
python3 build_workflow_reference.py
```

By default v0.5 only searches for email evidence using a built-in email rule.

Use `--rules PiiScraper/rules` for the standard full synthetic test run. That root contains grouped regex rules under `rules/regex_searching/` and table-column detection rules in `rules/table_column_rules/`.

Synthetic inputs are split into named datasets. `tests/synthetic_data/inputs/breach_dump` is the original fixture. `tests/synthetic_data/inputs/exposed_dump` is a larger fixture based on `breach_dump`, with two low-value files omitted and 68 additional exposed-data files added. Outputs are written to matching folders under `tests/synthetic_data/outputs/breach_dump` and `tests/synthetic_data/outputs/exposed_dump`.

Person-cluster identity merging is configured by `person_identity_anchors.json` inside the `--rules` root.

List-like linked-evidence rows are excluded from person clustering using `max_per_cluster` values embedded in the regex search rules. These limits are only applied to evidence types used by `rules/person_identity_anchors.json`.

`--progress-every` controls the heartbeat interval across the linear stages. Stage 1 reports file preprocessing, Stage 2 reports discovery/reference preprocessing, Stage 3 reports profiling/schema planning when enabled, Stage 4 reports discovery/regex scanning, Stage 5 reports evidence linking/clustering, Stage 6 reports reidentification, and Stage 7 writes run metadata and reports.

The v0.5 pipeline is linear: file preprocessing, discovery preprocessing, optional profiling/schema planning, discovery and regex searching, clustering, reidentification, then reporting. It writes CSV outputs directly and does not use a SQLite working store. Use `--resume discovery`, `--resume profiling`, `--resume scanning`, `--resume clustering`, `--resume reidentification`, or `--resume reporting` to start from the corresponding stage using existing upstream artefacts where possible. Known/no-list outputs must be rebuilt through `--resume reidentification` so the exclusion logic is recalculated consistently.

Use `--exclude cache backups "WP\PostCodes" staging.csv` to omit files or folders from traversal. Bare names and relative multi-part path suffixes match at any depth, so `WP\PostCodes` excludes that subtree wherever it appears below `--root`. Absolute paths match exactly; repeat `--exclude` to provide additional groups.

Use `--priority discovery`, `alphabetical`, `size`, or `type` to control scan submission order. With `--file-preprocessing integrated` or an existing `file.index.json` in `--index-dir`, Stage 4 knows the file denominator before scanning. With `--file-preprocessing disabled`, targets stream directly into Stage 4 and the exact denominator may only be known once scanning completes. `discovery` retains filesystem discovery order, `size` scans largest files first, and `type` groups files by extension. Parallel completion order can still differ from submission order.

The scanner has no RAM limit, RSS monitor, finding buffer, pending multiplier, or memory progress reporting. `--workers` is the main scan concurrency control, with `--large-file-cutoff-mb` and `--scan-unit-records` enabling parallel scan units for large XML, JSONL, CSV, and TSV files. Worker results are written directly to atomic evidence CSV files and linked-evidence CSV rows; Stage 5 reads `4.Regex_Scanning/linked_evidence.csv` to build clusters.

Stage 4 progress reports cumulative worker time spent hashing, extracting and applying regex rules. These figures are cumulative across parallel workers, so their sum can exceed wall-clock runtime. The final phase-time line is useful for identifying whether a live run is limited by source I/O, document extraction, or regex work.

`--profile standalone` and `integrated` use the same process-worker model as Stage 4 where possible. The profiler reports active worker/file progress and, for table-like sources, per-file progress similar to regex searching. In `integrated` mode, Stage 3 builds the schema plan before Stage 4 begins; only supported explicit/inferred headers become active scan routes. Headerless, value-only, and medium-confidence sensitive suggestions remain review-only.

Use `--email-suffix example.ac.uk` to split email matches into `Institutional Email` for addresses ending in that suffix and `Personal Email` for all other email addresses. Multiple suffixes can be comma-separated or supplied by repeating the flag, for example `--email-suffix example.ac.uk,nottingham.* --email-suffix "*.trusted.example"`. Literal suffixes match on domain boundaries, so `example.ac.uk` matches `mail.example.ac.uk` but not `badexample.ac.uk`; wildcard patterns such as `nottingham.*` match domains such as `nottingham.ac.uk` and `mail.nottingham.edu`.

Use `--email-wildcard "@nottingham == @exmail.nottingham"` when two institutional email domains should be treated as equivalent for every matching/search aspect. The rule is bidirectional and preserves suffixes: `a@nottingham.ac.uk` is considered equivalent to `a@exmail.nottingham.ac.uk`, and the reverse is also true. It affects person-table indexing, raw-evidence matching, linked-evidence matching, and cluster reidentification, but it does not rewrite the evidence value written to output CSVs. Repeat the flag or comma-separate rules to add more aliases, for example `--email-wildcard "@nottingham == @exmail.nottingham,@nottingham == @notttingham"`.

Each person-list table can be any CSV shape. Original input columns are carried through to the per-list outputs unchanged. The reader accepts common CSV encodings including UTF-8, UTF-8 with BOM, UTF-16-looking files, Windows-1252, and Latin-1. For matching, an exact `ID` column is treated as the person-list primary key and an `ID` anchor directly. Other column headers are resolved with `rules/table_column_rules/`, then interpreted by the loaded regex rules as labelled values. Email-looking values are always picked up as email anchors, so columns such as `UoN email`, `Other Email`, or `Other Emails` do not need to be renamed to `Institutional Email`. Split first/last-name columns can be combined into a full-name `Name` anchor when the table-column rules mark them with `name_part`. Duplicate source rows that resolve to the same internal person key are merged; repeated row numbers and differing original cell values are joined with ` | `.

The current scanner variants raise Python's CSV field-size limit to the largest value supported by the interpreter, preventing large individual fields from failing with `field larger than field limit`.

Before extraction, v0.5 sniffs file content so scrambled suffixes can still be routed to the right parser. It recognises signatures for PDF, ZIP-based Office files, legacy OLE Office files, RTF, HTML/XML, common image formats, delimited text, and plain text. `file_summary.csv` keeps the original `extension` and adds `detected_extension` to show the route used.

Excel extraction then tries the expected reader first and falls back through plausible spreadsheet encodings: mislabelled OOXML, HTML tables saved as `.xls`, delimited text, markup text, and plain text.

## Structured files in v0.5

Structured-record processing is enabled by default for JSON, JSONL, XML, YAML, and YML. V0.5 parses the hierarchy, infers person-bearing record boundaries, flattens bounded scalar fields into labelled record lines, and scans each line independently. Each inferred line becomes a potential linked-evidence unit, preventing all identifiers in a large structured export from being linked solely because they share a file.

Record inference uses person-like container names, list-item boundaries, identity-bearing keys and values, and supporting fields such as names, DOB, phone, address, postcode, gender, and nationality. XML attributes and repeated elements are preserved in the intermediate structure. Unique first-name and last-name values are combined into a synthesized `full name` field.

V0.5 uses parent-plus-child handling for person nodes that contain both direct identity fields and several repeated child collections. It emits the parent's own evidence without nested child-record fields, then emits qualifying email, address, and other child records separately. This preserves parent demographics while avoiding unsafe sibling flattening.

Controls:

```text
--structured-max-depth N              default 12
--xml-max-fields N                    default 200
```

Structural parse errors fall back automatically. Record inference remains heuristic, and depth/field limits can omit deeply nested evidence; see the workflow write-up for boundary rules and JSONL-specific behavior.

## Rules

The built-in default is a hard-coded email rule. External rules are loaded with `--rules`, usually from `PiiScraper/rules`.

Each `*.json` file under `rules/regex_searching/` is one regex search rule. Rules can be grouped in category folders such as `identity_documents`, `demographics`, or `financial`:

```json
{
  "evidence_type": "Email",
  "pattern_name": "contact_location_email",
  "confidence": "high",
  "regex": "\\b[A-Z0-9._%+\\-]+@[A-Z0-9.\\-]+\\.[A-Z]{2,}\\b",
  "flags": ["IGNORECASE"],
  "risk_tier": "tier_1_strong_identifier",
  "normalization": "lower",
  "is_identifiable": true,
  "max_per_cluster": 4
}
```

Required fields are `evidence_type`, `pattern_name`, and `regex`. `risk_tier` builds the evidence count columns, risk matrix flags, and tier sets directly from the loaded rules. `validator` is optional and names an internal Python validation function; it is not arbitrary code from JSON.

`max_per_cluster` is optional. It controls how many distinct values of that evidence type can appear in one linked-evidence row before the row is marked `cluster_eligible=no` and excluded from person clustering. It does not affect evidence reporting. The limit is only applied when the evidence type is part of `person_identity_anchors.json`. The `Email` rule can also define `max_per_cluster_by_evidence_type` so `Institutional Email` and `Personal Email` can have different limits after `--email-suffix` splitting.

Rule metadata drives normalization and risk scoring. Keep rule JSON terse: omit default/no-op values such as `normalization: none`, false booleans, and empty lists.

- `normalization`: one of `none`, `lower`, `compact_upper`, `address_compact`, `name_casefold`, or `country_name`.
- `is_identifiable`: whether this evidence type can identify a person for sensitive-plus-identifiable risk logic.
- `is_high_risk_standalone`: whether this evidence type is high risk on its own.
- Risk roles are normally derived from `evidence_type`, for example `DOB -> dob`, `Phone -> phone`, `Address -> address`, and `Payment Card -> payment_card`. Current rule files do not need `risk_roles`.

Linked-evidence anchor priority is configured in `rules/person_identity_anchors.json`, not in each regex rule.

`line_triggers` is optional. It is not a list of table columns. It is a list of lowercase terms that must appear in an extracted text line before the scanner runs that broad contextual regex on the line. Old rule files using `prefilter` still load, but `line_triggers` is the preferred name.

Address evidence is code-derived rather than a loose regex rule. It is assembled only from labelled table or structured-record fields containing a valid UK postcode and at least one searchable address component. V0.5 closes an address group at each postcode, allowing sequential home/current/term address groups on one source row to produce separate `Address` findings. Free-text address assembly is intentionally disabled because it produced too many false positives. Standalone postcodes are not reported as addresses.

Religion, disability, and citizenship/country evidence is restricted to recognised table columns and structured-record fields. These rules do not search ordinary free text. Citizenship/country values are validated and normalized where possible, so aliases such as `CHN` can become `China`, while broad region/admin values such as `EUROPE`, `home`, or `international` are rejected.

The generic technical `Date` search is intentionally not part of the default rules. Date-like values are reported only through contextual evidence such as DOB rules.

CAS evidence is accepted only from a labelled `CAS`, `CAS number`, `CAS no`, or `CAS id` field. The value must be exactly 14 uppercase alphanumeric characters and contain at least one letter and one digit. Standalone or hyphenated CAS-like text is not reported.

Table detection rules live separately in `rules/table_column_rules/`. Each JSON file under that folder is one column-header detection rule, grouped in category folders like the regex rules:

```json
{
  "canonical_header": "postcode",
  "pattern_name": "contact_location_postcode_column",
  "header_patterns": [
    "\\bpost\\s*code\\b",
    "\\bpostcode\\b",
    "\\bpostal\\s*code\\b"
  ]
}
```

When a table header matches a rule, the extractor replaces the original header with `canonical_header` before building row text. For example, `Post Code` and `postal_code` both become `postcode: <value>`, so downstream regex rules see a stable context label. Header word separators are detected per table/header rather than assumed globally: whitespace is always safe, while `_`, `-`, `~`, `#`, and `|` are only used as header word separators when splitting the label improves recognised header resolution. This prevents arbitrary values from teaching the scanner that punctuation is a separator.

For headerless tables, v0.5 samples up to 100 rows and treats schema inference as a first-class step. It infers a column only when at least three values are present and the sampled values agree on a validated type. It can infer common identifiers, email/phone/postcode, address columns adjacent to a postcode, and contextual person rows such as `gender + first name + last name + email`. Unknown/generic name and gender columns remain conservative: names/gender are inferred only when another column in the same headerless table provides person context such as an email or validated identifier. Date-shaped headerless columns are not inferred as DOB without explicit context.

Plain-text sources can also contain embedded headerless table blocks. The scanner detects repeated lines with the same delimiter and field count, chooses the separator per block, and then applies the same headerless inference. Supported embedded delimiters include comma, tab, semicolon, pipe, tilde, hash, underscore, and hyphen; underscore and hyphen require stronger table-shape evidence because they are common inside ordinary values. Surrounding prose remains plain text.

Tables that look transposed are rotated before labelled row text is produced. This applies to both scanning and profiling, so field-labelled exports such as `Field, person_1, person_2` can be interpreted as one evidence unit per person rather than one evidence unit per source row. Orientation is now assessed explicitly as `normal`, `transposed`, `headerless`, or `ambiguous`. Ambiguous orientation is kept review-only/raw-fallback rather than being forced into normal or transposed interpretation.

With `--nlp TRUE`, the scanner and profiler can use NLP-assisted header similarity for weak or unfamiliar structured labels. NLP is deliberately advisory: exact table-column rules, validators, and context guards still decide whether evidence is emitted. This is intended to improve header/index-key interpretation, not to permit broad free-text PII extraction.

The profiler also uses local vocabulary resources under `resources/vocabularies/` for demographic, country/nationality, marital-status, disability/support, NHS, HESA, and UCAS-style inference. These vocabularies are used to suggest candidate header rules and to identify review-only columns whose values look semantically meaningful but should not automatically become emitted evidence.

## Main outputs

Outputs are now grouped by workflow stage under `--output-dir`:

- `1.File_Preprocessing/`: source file index and duplicate-file metadata.
- `2.Discovery_Preprocessing/`: discovery/rule/person-table indexes.
- `3.Profiling/`: profile and schema-plan outputs.
- `4.Regex_Scanning/`: atomic evidence, linked evidence, file summaries, and regex summaries.
- `5.Clustering/`: inferred person clusters and cluster-member audit rows.
- `6.Reidentification/`: known-person and no-list/unknown-person outputs.
- `7.Reporting/`: run metadata, manifests, worker timing diagnostics, and cross-output reports.

Key files are:

- `4.Regex_Scanning/pii_regex_evidence/`: one CSV per evidence rule/pattern, plus `errors.csv`.
- `4.Regex_Scanning/file_summary.csv`: one row per scanned, duplicate-reported, or duplicate-collapsed file, including original `extension`, sniffed `detected_extension`, selected hash metadata such as `sha256`, duplicate-file metadata, `cluster_excluded_linked_evidence_count`, and `cluster_exclusion_reasons` to highlight files with list-like linked rows that were kept out of clustering.
- `4.Regex_Scanning/entity_summary.csv`: whole-scan summary by evidence type.
- `4.Regex_Scanning/regex_summary.csv`: whole-scan summary by evidence type and regex/pattern, including `unique_value_count`, `not_matched`, and per-person-table `matched_to_<person-table-stem>` counts when person tables are supplied.
- `4.Regex_Scanning/linked_evidence.csv`: one row per meaningful co-occurrence unit, such as a CSV row containing several findings. With default `--duplicate-evidence collapse`, semantically identical linked-evidence units are represented once with duplicate provenance columns. Rows with too many distinct identity values are marked `cluster_eligible=no` and kept out of person clustering.
- `5.Clustering/clusters.csv`: all inferred person clusters. The `cluster_merge_keys` column shows why linked-evidence rows were merged, such as a strong email/phone key or a compound `Name+DOB` key.
- `5.Clustering/cluster_members.csv`: cluster-to-linked-evidence membership audit rows.
- `6.Reidentification/<person-list-stem>_in_dataset.csv`: one row per matched person from each `--person-tables` CSV.
- `6.Reidentification/<person-list-stem>_risk_matrix.csv`: one row per supplied person-list row, with yes/no evidence category flags and overall risk score.
- `6.Reidentification/<person-list-stem>_pii_value_risk_matrix.csv`: one row per supplied person-list row, with contributing values for matched evidence categories where values can be shown safely.
- `6.Reidentification/<person-list-stem>_not_in_dataset.csv`: person-list rows that did not link to any person cluster, cluster-excluded linked-evidence row, or direct raw evidence row.
- `6.Reidentification/clusters_not_in_list.csv`: disclosive unmatched identity audit rows, including anchor values and merge keys for unmatched clusters; strong cluster-excluded linked-evidence identities can also appear without a `person_cluster_id`.
- `6.Reidentification/clusters_not_in_list_redacted.csv`: non-disclosive unmatched-person summaries.
- `6.Reidentification/clusters_not_in_list_risk_matrix.csv`: one row per unmatched/no-list person summary, with yes/no evidence category flags and overall risk score.
- `6.Reidentification/row_overlap_report/`: automatic known/no-list overlap audit, including person-anchor overlap, typed-value overlap, spreadsheet-style summary CSV, and a self-contained HTML report.
- `6.Reidentification/<person-list-stem>_evidence/` and `6.Reidentification/Clusters_not_in_list_evidence/`: optional per-identity evidence folders, written only with `--write-person-evidence TRUE`.
- `7.Reporting/run_info.txt`, `7.Reporting/run_manifest.json`, and `7.Reporting/metadata/process_timing.log`: v0.5 run metadata, machine-readable run manifest, and per-worker timing diagnostics.

Known-person outputs collate three evidence layers back to each matched person-list row. Stage 6 first matches inferred clusters from `5.Clustering/clusters.csv`, then matches cluster-excluded linked-evidence rows from `4.Regex_Scanning/linked_evidence.csv`, then streams direct atomic evidence from `4.Regex_Scanning/pii_regex_evidence/*.csv`. The main `<person-list-stem>_in_dataset.csv` output reports the combined result using `matched_cluster_count`, `unclustered_linked_evidence_count`, `linked_evidence_count`, `direct_raw_evidence_count`, and `matched_evidence_count`. If `--write-person-evidence TRUE` is supplied, the optional per-person evidence folder includes the cluster rows, linked-evidence rows, direct raw-evidence rows, and the raw atomic rows behind matched linked evidence.

When a supplied person table contains duplicate rows with the same internal person key, v0.5 merges those rows into one known-person record rather than creating `#2` suffix keys. Differing source values are pipe-joined and all anchors from the duplicate rows point to the merged person key.

The built-in row/person overlap report is written under `6.Reidentification/row_overlap_report/` after normal Stage 6, `--resume reidentification`, or `--resume reporting`. It produces `row_overlap_presentation.csv`, `row_overlap_report.html`, `row_overlap_membership_summary.csv`, `row_overlap_source_frequency.csv`, pairwise/matrix CSVs, `unverified_evidence_parent_dirs.csv`, and `row_overlap_manifest.json`. The `Persons` metric is based on the configured `person_identity_anchors.json`, so generic person-table IDs do not define person overlap unless they are deliberately included in that anchor config. The report is count-only by default and does not write raw PII values.

The scanner can also emit `Identity Document File` evidence for document metadata and filenames that strongly indicate passports, visas, BRPs, residence permits, national ID cards, driving licences, or birth certificates. This is a document-presence signal, not OCR extraction from the image/document contents. Filename/metadata-only evidence is deliberately conservative: generic names such as `passport.pdf` or `passport_photo.jpg` are not enough, and filenames containing an email address are rejected. The filename/metadata signal requires a document cue plus plausible owner-name context. If image OCR is enabled, OCR text is scanned normally and can link through actual names, document numbers, emails, or other anchors found inside the document.

## Profiling outputs

Profiling writes these files to `3.Profiling/`:

- `columns_all_profiles.csv`: one row per observed table/structured label, including labels already resolved by current rules.
- `columns_unknown_profiles.csv`: labels not resolved by the current rules, with non-disclosive metrics and a small capped sample preview for review.
- `columns_rule_candidates.csv`: grouped candidates that look suitable for reviewed table-column rule creation.
- `columns_review_candidates.csv`: grouped candidates that look meaningful but should remain manual-review candidates rather than automatic evidence rules.
- `value_type_candidates.csv`: unresolved columns whose value distributions strongly resemble known types even when the label is weak or generic.
- `rule_coverage.csv`: current table-column rule coverage, including likely stale or unobserved rules.
- `3.Profiling/schema_plan.csv`: per-file/per-table/per-column plan showing raw header, resolved header, suggested type, confidence, reason, scan action, linking scope, `orientation`, `orientation_confidence`, `orientation_reason`, `detected_separator`, `schema_signature`, and `schema_reused_from`. With `--profile integrated`, actionable rows drive Stage 4 routing. `route_suggested_rules` routes relevant regex rules; `route_suggested_rules_and_emit_cell_value` also permits validated header-confirmed cell emission. Review-only rows remain raw fallback/review diagnostics and do not emit sensitive evidence.
- `draft_table_column_rules/`: created by `--profile create_rules`; contains draft JSON rules plus `draft_rule_manifest.csv` for review.

The profiler is intentionally conservative. `columns_rule_candidates.csv` is not a ruleset; it is a review queue. Draft rules should be inspected before they are moved into `rules/table_column_rules/`.

## Comparing Two Output Folders

Use `reports/Compare_pii_regex_outputs.v0.1.py` to compare two scanner output folders:

```bash
python3 PiiScraper/reports/Compare_pii_regex_outputs.v0.1.py \
  PiiScraper/tests/synthetic_data/outputs/breach_dump \
  PiiScraper/tests/synthetic_data/outputs/exposed_dump \
  --person-table PiiScraper/tests/synthetic_data/inputs/synthetic_slim_contacts.csv
```

By default this writes `report.txt` and the known-person detail CSVs to:

```text
PiiScraper/tests/synthetic_data/outputs/breach_dump_vs_exposed_dump/
```

Use `--output-dir <folder>` to choose a different comparison folder. The report filename is always `report.txt`.

The report compares evidence terms, person-cluster identity terms, person-list presence, and no-list/unknown signature terms. Evidence terms are `evidence_type=normalized_value` pairs, so the same email address or identifier found in both datasets counts as conserved even if it came from a different file or row. For v0.5 scanner outputs, no-list comparison prefers `6.Reidentification/clusters_not_in_list.csv`; when only the sanitized summary exists, it resolves each row to `5.Clustering/clusters.csv` by `person_cluster_id` before comparing identity terms. The report still accepts legacy v3/v4 output names.

## Folder layout

- `documentation/`: workflow QMD, rendered Word documents, diagrams, and documentation build code.
- `reports/`: output comparison, lay-report generation code, and sample report artefacts.
- `rules/`: regex, table-column, and person-identity configuration.
- `src/pii_regex_scanner/`: packaged scanner implementation.
- `tests/`: unit and integration tests.
- `tests/synthetic_data/inputs/breach_dump/`: original synthetic breach-like test data.
- `tests/synthetic_data/inputs/exposed_dump/`: larger synthetic exposed-data fixture, approximately 20% more files than `breach_dump`.
- `tests/synthetic_data/inputs/synthetic_slim_contacts.csv`: synthetic known-person table.
- `tests/synthetic_data/outputs/`: generated scanner and comparison baselines.
