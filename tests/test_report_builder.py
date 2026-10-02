import math
import unittest

from reports.build_report import fmt_pct, parse_conservation, parse_evidence_by_type, parse_pct


class ReportBuilderTests(unittest.TestCase):
    def test_parse_pct_accepts_unavailable_values(self):
        self.assertTrue(math.isnan(parse_pct("n/a")))
        self.assertTrue(math.isnan(parse_pct("N/A")))
        self.assertEqual(parse_pct("69.31%"), 69.31)

    def test_fmt_pct_preserves_unavailable_meaning(self):
        self.assertEqual(fmt_pct(math.nan), "n/a")
        self.assertEqual(fmt_pct(69.31), "69.31%")

    def test_evidence_by_type_accepts_zero_denominator(self):
        section = """
evidence_type  Left  Right  shared  Left conserved  Right conserved
CAS Number  0  7,523  0  n/a  0.00%
"""
        rows = parse_evidence_by_type(section, "Left", "Right")
        self.assertEqual(len(rows), 1)
        self.assertTrue(math.isnan(rows[0]["left_conserved_pct"]))
        self.assertEqual(rows[0]["right_conserved_pct"], 0.0)

    def test_conservation_accepts_all_zero_terms(self):
        section = """
Left unique terms: 0
Right unique terms: 0
Shared terms: 0
Left-only terms: 0
Right-only terms: 0
Left conserved in Right: n/a
Right conserved in Left: n/a
Jaccard overlap: n/a
"""
        metrics = parse_conservation(section, "Left", "Right")
        self.assertTrue(math.isnan(metrics.left_conserved_pct))
        self.assertTrue(math.isnan(metrics.right_conserved_pct))
        self.assertTrue(math.isnan(metrics.jaccard_pct))


if __name__ == "__main__":
    unittest.main()
