"""Compatibility alias for the scanner implementation.

The implementation lives in :mod:`pii_regex_scanner.pipeline`.  This module is
kept so older tests/imports using ``pii_regex_scanner.engine`` still receive the
same live module object rather than a copied namespace with stale globals.
"""

import sys

from . import pipeline as _pipeline

sys.modules[__name__] = _pipeline
