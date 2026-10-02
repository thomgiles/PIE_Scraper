#!/usr/bin/env python3
"""Generate a broad English country/territory name list from local Babel data.

This is a helper for the vocabulary resources folder. It does not provide
nationality adjectives; use `country_name_and_nationality_seed.json` for those.

Output:
    country_names_babel_en.json
"""

from __future__ import annotations

import json
from pathlib import Path

from babel import Locale


OUTPUT = Path(__file__).with_name("country_names_babel_en.json")


def main() -> None:
    locale = Locale("en")
    entries = []
    for code, name in sorted(locale.territories.items()):
        if not (len(code) == 2 and code.isalpha() and code.upper() == code):
            continue
        entries.append({
            "code": code,
            "name": str(name),
        })

    payload = {
        "source_type": "generated_local",
        "generator": "Babel Locale('en').territories",
        "notes": [
            "Includes countries and territories known to Babel.",
            "Does not include nationality adjectives.",
            "Intended for supplementary matching alongside curated nationality aliases."
        ],
        "entries": entries,
    }

    OUTPUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
