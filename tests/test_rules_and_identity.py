import json
import re
import tempfile
import unittest
from pathlib import Path

import test_support  # noqa: F401
from pii_regex_scanner import engine


class RuleAndIdentityTests(unittest.TestCase):
    def setUp(self):
        engine.set_email_suffix("example.ac.uk")
        engine.set_email_wildcards([])
        engine.load_identity_anchor_config(str(test_support.PROJECT_DIR / "rules"))
        engine.load_rules(str(test_support.PROJECT_DIR / "rules"))

    def test_email_split_and_aliases(self):
        self.assertEqual(engine.email_domain("A@Example.ac.uk"), "example.ac.uk")
        self.assertEqual(engine.email_evidence_type("a@example.ac.uk"), "Institutional Email")
        self.assertEqual(engine.email_evidence_type("a@gmail.com"), "Personal Email")
        self.assertEqual(set(engine.identity_anchor_aliases("Email")), {"Institutional Email", "Personal Email"})
        self.assertIn("Institutional Email", engine.PERSON_CLUSTER_STRONG_ANCHORS)

    def test_email_suffix_lists_and_wildcards(self):
        engine.set_email_suffix(["example.ac.uk,nottingham.*", "*.trusted.example"])
        self.assertEqual(engine.email_evidence_type("a@example.ac.uk"), "Institutional Email")
        self.assertEqual(engine.email_evidence_type("a@mail.example.ac.uk"), "Institutional Email")
        self.assertEqual(engine.email_evidence_type("a@nottingham.ac.uk"), "Institutional Email")
        self.assertEqual(engine.email_evidence_type("a@mail.nottingham.edu"), "Institutional Email")
        self.assertEqual(engine.email_evidence_type("a@mail.trusted.example"), "Institutional Email")
        self.assertEqual(engine.email_evidence_type("a@trusted.example"), "Personal Email")
        self.assertEqual(engine.email_evidence_type("a@evilnottingham.ac.uk"), "Personal Email")

    def test_email_wildcard_equivalence(self):
        engine.set_email_wildcards(["@nottingham == @exmail.nottingham"])
        self.assertEqual(
            set(engine.email_equivalent_values("a@nottingham.ac.uk")),
            {"a@nottingham.ac.uk", "a@exmail.nottingham.ac.uk"},
        )
        self.assertEqual(
            set(engine.email_equivalent_values("a@exmail.nottingham.ac.uk")),
            {"a@nottingham.ac.uk", "a@exmail.nottingham.ac.uk"},
        )

    def test_rule_helpers(self):
        self.assertEqual(engine.rule_slug("National Insurance Number"), "national_insurance_number")
        self.assertEqual(engine.regex_flags_from_names(["ignorecase"]), re.IGNORECASE)
        self.assertTrue(engine.parse_bool("yes"))
        self.assertFalse(engine.parse_bool("off"))
        with self.assertRaises(ValueError):
            engine.regex_flags_from_names(["unknown"])

    def test_load_single_rule_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "rule.json"
            path.write_text(json.dumps({
                "evidence_type": "Email",
                "pattern_name": "test_email",
                "regex": r"[A-Z]+@[A-Z]+\.[A-Z]+",
                "flags": ["IGNORECASE"],
            }), encoding="utf-8")
            loaded = engine.rule_objects_from_json_file(path)
            self.assertEqual(loaded[0]["pattern_name"], "test_email")
            compiled = engine.compile_rule_pattern(loaded[0])
            self.assertIsNotNone(compiled["regex"].search("a@b.com"))

    def test_load_rules_ignores_legacy_code_derived_regexes(self):
        with tempfile.TemporaryDirectory() as folder:
            regex_dir = Path(folder) / "regex_searching"
            regex_dir.mkdir()
            (regex_dir / "email.json").write_text(json.dumps({
                "evidence_type": "Email",
                "pattern_name": "email",
                "regex": r"[A-Z]+@[A-Z]+\.[A-Z]+",
                "flags": ["IGNORECASE"],
                "normalization": "lower",
                "risk_tier": "tier_1_strong_identifier",
            }), encoding="utf-8")
            (regex_dir / "legacy_name.json").write_text(json.dumps({
                "evidence_type": "Name",
                "pattern_name": "legacy_free_text_name",
                "regex": r"\b[A-Z][a-z]+ [A-Z][a-z]+\b",
                "normalization": "none",
                "risk_tier": "tier_3_supporting_evidence",
            }), encoding="utf-8")

            engine.load_rules(folder)

            self.assertEqual(engine.EVIDENCE_NORMALIZATION["Name"], "name_casefold")
            self.assertNotIn(
                "legacy_free_text_name",
                {pattern["pattern_name"] for pattern in engine.PATTERNS},
            )


if __name__ == "__main__":
    unittest.main()
