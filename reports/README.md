# Reports

This folder contains scanner-output comparison and lay-report generation utilities.

- `Compare_pii_regex_outputs.v0.1.py` compares two completed scanner output folders and writes a text report plus comparison CSVs.
- `build_report.py` converts a comparison text report into a lay-facing Word document.
- `build_sample_report.sh` builds a local `reports/report.docx` from a locally supplied `reports/report.txt`.

Run commands from the repository root. The comparison utility accepts the v0.5 seven-stage output layout and legacy scanner output layouts.

Compare the synthetic output baselines:

```bash
python3 reports/Compare_pii_regex_outputs.v0.1.py \
  tests/synthetic_data/outputs/breach_dump \
  tests/synthetic_data/outputs/exposed_dump \
  --person-table tests/synthetic_data/inputs/synthetic_slim_contacts.csv
```

By default, the text report and detail CSVs are written beside the compared folders in `breach_dump_vs_exposed_dump/`. Use `--output-dir PATH` to choose another folder.

Build a Word report from the comparison text:

```bash
python3 reports/build_report.py \
  --report tests/synthetic_data/outputs/breach_dump_vs_exposed_dump/report.txt \
  --output-docx reports/report.docx \
  --overwrite
```

The Word builder requires `python-docx`, Matplotlib, and Pillow. `--left-display` and `--right-display` override the reader-facing dataset labels. Without `--output-docx`, the output is `<report_stem>_lay_summary.docx` beside the input report. `--overwrite` permits replacing an existing output document.

`reports/report.txt` and `reports/report.docx` are not bundled sample files. They are ignored by Git when generated locally. The shell wrapper requires the input text report to exist first; use `build_report.py` directly for other input and output paths. Generated comparison detail CSVs retain person-table data, so review reports before sharing them or committing them.
