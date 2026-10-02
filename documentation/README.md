# Workflow documentation

This folder contains the workflow source, generated Word documents, diagram assets, and build utilities.

`PII_REGEX_WORKFLOW_WRITEUP.qmd` is the source for the v0.5 seven-stage workflow. Update that file before rebuilding the Word document. Run these commands from the repository root:

```bash
python3 documentation/render_workflow_diagrams.py
quarto render documentation/PII_REGEX_WORKFLOW_WRITEUP.qmd --to docx
python3 documentation/build_workflow_reference.py --finalize
python3 documentation/build_workflow_reference.py
```

`PII_REGEX_WORKFLOW_WRITEUP.docx` is the rendered document. `PII_REGEX_WORKFLOW_REFERENCE.docx` is a minimal, style-only Quarto template: it retains Word styles and section settings but contains no workflow text, tables, or images.

The build requires Quarto. Diagram regeneration also requires Pillow and the macOS Arial font paths configured in `render_workflow_diagrams.py`; adjust those paths to available fonts when building on another platform. Existing diagram PNGs can be reused for text-only updates.
