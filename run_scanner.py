#!/usr/bin/env python3
"""Launcher for the direct-streaming PII scanner."""

import sys
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent / "src"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

print("PiiScraper startup: importing scanner modules", flush=True)
from pii_regex_scanner.pipeline import main
print("PiiScraper startup: scanner modules loaded", flush=True)


if __name__ == "__main__":
    main()
