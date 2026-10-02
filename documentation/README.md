# PIE_Scraper documentation

This folder contains the v0.5 workflow guide and the files needed to build its Word version.

- [PIE_Scraper.qmd](PIE_Scraper.qmd): editable source for the seven-stage workflow.
- [PIE_Scraper.docx](PIE_Scraper.docx): rendered guide for readers.
- [templates/PIE_Scraper_styles.docx](templates/PIE_Scraper_styles.docx): Word style template used by Quarto. It retains styles and section settings but contains no workflow text, tables, or images.
- `diagrams/`: the 13 PNG diagrams used by the guide.
- `render_workflow_diagrams.py`: regenerates those diagrams.
- `build_workflow_reference.py`: finalises Word typography or rebuilds the style template.
- `pagebreak-headings.lua`: controls page breaks and diagram widths during rendering.

The guide and style template have separate roles: the guide contains the documentation, while the template preserves its Word formatting. Keep both for reproducible builds.

Update `PIE_Scraper.qmd` before rebuilding the Word guide. For text-only changes, run these commands from the repository root:

```bash
quarto render documentation/PIE_Scraper.qmd --to docx
python3 documentation/build_workflow_reference.py --finalize
```

Run `python3 documentation/render_workflow_diagrams.py` before rendering when diagram content changes. Run `python3 documentation/build_workflow_reference.py` after finalising the guide when rebuilding the style template, then render and finalise again to apply the updated styles.

The build requires Quarto. Diagram regeneration also requires Pillow and the macOS Arial font paths configured in `render_workflow_diagrams.py`; adjust those paths to available fonts when building on another platform. Existing diagram PNGs can be reused for text-only updates.
