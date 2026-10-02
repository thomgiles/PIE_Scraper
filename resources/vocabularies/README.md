# Vocabulary resources for column inference

This folder contains seed vocabularies and source notes to improve structured
column inference, especially for:

- headerless or weak-header tables
- low-cardinality demographic/status columns
- education/public-sector exports
- UK-focused person attributes and support indicators

What is here:

- `sources_manifest.json`
  - authoritative source links and local resource mapping
- `ons_ethnic_groups_2021_england_wales.json`
  - ONS / GOV.UK ethnic group response options
- `ons_religion_response_options_england_wales_2021.json`
  - ONS religion response options
- `common_marital_status_terms.json`
  - curated marital-status terms and aliases
- `student_support_and_contextual_terms.json`
  - curated education/public-sector support-status terms
- `country_name_and_nationality_seed.json`
  - curated seed country/nationality aliases
- `nhs_demographic_code_sets_seed.json`
  - NHS-oriented demographic/status terms and common administrative labels
- `hesa_student_data_terms_seed.json`
  - HESA-oriented student-record headers and common response vocabularies
- `ucas_applicant_terms_seed.json`
  - UCAS/applicant support and widening-participation style terms
- `public_sector_demographic_variants.json`
  - extended public-sector ethnicity/religion/marital-status variants and code-style aliases
- `disability_and_adjustment_terms.json`
  - disability, impairment, adjustment, and support vocabulary for structured inference
- `build_country_names_from_babel.py`
  - generates a wider country-name list from local Babel data

Important distinction:

- `official_source`
  - copied or normalised from an official/public standard
- `curated_seed`
  - hand-curated starter terms for inference, intended to be reviewed and expanded

How the profiler uses these resources:

1. `ons_ethnic_groups_2021_england_wales.json` and
   `ons_religion_response_options_england_wales_2021.json` for low-cardinality
   value matching.
2. `common_marital_status_terms.json` for `Marital Status` /
   `MaritalStatus` inference.
3. `student_support_and_contextual_terms.json` for contextual/student
   support columns.
4. `country_name_and_nationality_seed.json` plus the generated country list
   from `build_country_names_from_babel.py` for nationality/citizenship hints.
5. The NHS/HESA/UCAS/public-sector/disability seed files for ambiguous
   columns where the header alone is weak but the value distribution is
   recognisable.

The vocabulary layer is deliberately advisory. It can raise a profile candidate
score, mark a column as review-only, or explain why an unresolved column looks
like a known public-sector category. It does not by itself cause the scanner to
emit PII evidence; evidence emission still requires current table-column rules,
regex rules, validators, and context guards.

NLP, when enabled with `--nlp TRUE`, is used after exact rule and vocabulary
signals to improve weak-header interpretation. The expected workflow is:

1. run `--profile standalone` or `--profile integrated`;
2. review `columns_rule_candidates.csv`, `columns_review_candidates.csv`,
   `value_type_candidates.csv`, and `schema_plan.csv`;
3. optionally run `--profile create_rules` to create draft table-column rules;
4. manually review those draft rules before promoting them into
   `rules/table_column_rules/`.
