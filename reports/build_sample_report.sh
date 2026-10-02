#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
python3 "$SCRIPT_DIR/build_report.py" \
  --report "$SCRIPT_DIR/report.txt" \
  --output-docx "$SCRIPT_DIR/report.docx" \
  --overwrite
