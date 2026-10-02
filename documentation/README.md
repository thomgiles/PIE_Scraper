# Workflow documentation

This folder contains the workflow source, generated Word documents, diagram assets, and build utilities.

```bash
python3 render_workflow_diagrams.py
quarto render PII_REGEX_WORKFLOW_WRITEUP.qmd --to docx
python3 build_workflow_reference.py --finalize
python3 build_workflow_reference.py
```

`PII_REGEX_WORKFLOW_WRITEUP.docx` is the rendered document. `PII_REGEX_WORKFLOW_REFERENCE.docx` is a minimal, style-only Quarto template: it retains Word styles and section settings but contains no workflow text, tables, or images.
