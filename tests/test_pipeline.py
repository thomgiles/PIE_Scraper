import csv
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import test_support
from pii_regex_scanner import pipeline as engine
from pii_regex_scanner.pipeline import load_table_column_rules, parse_args, resolve_table_header


class PipelineCliTests(unittest.TestCase):
    def test_parser_matches_direct_streaming_flags(self):
        args = parse_args([])
        self.assertFalse(hasattr(args, "rerun_from"))
        self.assertFalse(hasattr(args, "dedupe_identical"))
        self.assertFalse(hasattr(args, "export_discovery_csv"))
        self.assertFalse(hasattr(args, "person_table"))
        self.assertEqual(args.resume, "")
        self.assertEqual(args.xml_scan, "fast")
        self.assertEqual(args.large_file_cutoff_mb, 100.0)
        self.assertEqual(args.scan_unit_records, 1000)
        self.assertEqual(args.hash_workers, 0)
        self.assertFalse(args.nlp)
        self.assertEqual(args.hash_mode, "duplicate-candidates")
        self.assertEqual(args.file_hash, "sha256")
        self.assertEqual(args.duplicate_files, "collapse")
        self.assertEqual(args.duplicate_content, "collapse")
        self.assertEqual(args.duplicate_evidence, "collapse")
        self.assertEqual(
            parse_args(["--resume", "profiling"]).profile,
            "integrated",
        )
        self.assertEqual(
            parse_args(["--resume", "reidentification"]).resume,
            "reidentification",
        )

    def test_parser_accepts_nlp_true_style_values(self):
        args = parse_args(["--nlp", "true"])
        self.assertTrue(args.nlp)
        args = parse_args(["--nlp", "TR"])
        self.assertTrue(args.nlp)

    def test_parser_accepts_profile_modes_and_alias(self):
        self.assertEqual(parse_args(["--profile", "standalone"]).profile, "standalone")
        self.assertEqual(parse_args(["--profile", "integrated"]).profile, "integrated")
        self.assertEqual(parse_args(["--profile", "columns"]).profile, "standalone")

    def test_table_column_rules_cover_new_high_confidence_synonyms(self):
        load_table_column_rules(str(test_support.PROJECT_DIR / "rules"))
        expected = {
            "NotifyEmail": "email",
            "RegisteredEmail": "email",
            "EMAILID": "email",
            "CreditCard No": "payment card",
            "CreditCardLastFour": "payment card",
            "Candidate ID": "person id",
            "EMPLID": "person id",
            "TelephoneNo": "phone",
            "HomeTelephoneNo": "phone",
            "MobilePhoneNo": "phone",
            "EmergencyMobilePhone": "phone",
            "HomeAddress": "address",
            "CorrespondenceAddress": "address",
            "HomePostcode": "postcode",
            "IPAddress": "IP Address",
            "Middle Name": "middle name",
            "User Name": "username",
        }
        for label, canonical in expected.items():
            self.assertEqual(resolve_table_header(label), canonical, label)

    def test_context_guards_load_from_rule_metadata(self):
        rules = str(test_support.PROJECT_DIR / "rules")
        engine.load_rules(rules)
        engine.load_table_column_rules(rules)

        dob_metadata = engine.resolve_table_header_metadata("DOB")
        self.assertEqual(
            dob_metadata.get("context_guard", {}).get("required_tokens"),
            ("dob", "birth", "born"),
        )
        self.assertEqual(
            dob_metadata.get("context_guard", {}).get("required_phrases"),
            ("date of birth", "birth date"),
        )

        dob_pattern = next(
            pattern
            for pattern in engine.PATTERNS
            if pattern.get("pattern_name") == "demographics_dob_context"
        )
        self.assertEqual(
            dob_pattern.get("context_guard", {}).get("required_tokens"),
            ("dob", "birth", "born"),
        )

    def test_direct_streaming_outputs_and_resume_modes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            inputs = root / "inputs"
            outputs = root / "outputs"
            inputs.mkdir()
            (inputs / "evidence.csv").write_text(
                "full name,email,phone\nUnknown Person,unknown@example.org,07123456789\n",
                encoding="utf-8",
            )
            people = root / "people.csv"
            people.write_text("ID,email\nK1,known@example.org\n", encoding="utf-8")
            base = [
                sys.executable, str(test_support.PROJECT_DIR / "run_scanner.py"),
                "--root", str(inputs),
                "--output-dir", str(outputs),
                "--rules", str(test_support.PROJECT_DIR / "rules"),
                "--person-tables", str(people),
                "--workers", "1",
                "--progress-every", "0",
            ]

            fresh = subprocess.run(base, check=False, capture_output=True, text=True)
            self.assertEqual(fresh.returncode, 0, fresh.stderr + fresh.stdout)
            self.assertIn("Stage 4/7: discovery and regex scanning", fresh.stdout)
            self.assertIn("SQLite evidence store: not used", fresh.stdout)
            self.assertTrue((outputs / "4.Regex_Scanning" / "linked_evidence.csv").exists())
            self.assertTrue((outputs / "5.Clustering" / "clusters.csv").exists())
            self.assertTrue((outputs / "6.Reidentification" / "clusters_not_in_list_redacted.csv").exists())
            self.assertTrue((outputs / "7.Reporting" / "run_info.txt").exists())
            self.assertTrue((outputs / "7.Reporting" / "metadata" / "process_timing.log").exists())
            self.assertFalse((outputs / "pii_regex.sqlite").exists())

            with (outputs / "6.Reidentification" / "clusters_not_in_list_redacted.csv").open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)

            resume = subprocess.run(
                base + ["--resume", "clustering"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(resume.returncode, 0, resume.stderr + resume.stdout)
            self.assertIn("Resume mode: Stage 5 clustering", resume.stdout)
            self.assertIn("reclustering linked evidence", resume.stdout)

    def test_integrated_profile_mode_writes_discovery_and_profile_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            inputs = root / "inputs"
            outputs = root / "outputs"
            inputs.mkdir()
            (inputs / "mailbox.csv").write_text(
                "Mailbox,StatusFlag\nalice@example.org,active\nbob@example.org,inactive\n",
                encoding="utf-8",
            )
            cmd = [
                sys.executable, str(test_support.PROJECT_DIR / "run_scanner.py"),
                "--root", str(inputs),
                "--output-dir", str(outputs),
                "--rules", str(test_support.PROJECT_DIR / "rules"),
                "--profile", "integrated",
                "--workers", "1",
                "--hash-mode", "none",
                "--progress-every", "0",
            ]

            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn("Stage 3/7: profiling and schema planning", result.stdout)
            self.assertIn("Stage 4/7: discovery and regex scanning using Stage 3 schema plan", result.stdout)
            self.assertTrue((outputs / "4.Regex_Scanning" / "file_summary.csv").exists())
            self.assertTrue((outputs / "4.Regex_Scanning" / "regex_summary.csv").exists())
            self.assertTrue((outputs / "3.Profiling" / "columns_all_profiles.csv").exists())
            self.assertTrue((outputs / "3.Profiling" / "columns_unknown_profiles.csv").exists())
            self.assertTrue((outputs / "3.Profiling" / "columns_rule_candidates.csv").exists())
            self.assertTrue((outputs / "3.Profiling" / "rule_coverage.csv").exists())

            run_info = (outputs / "7.Reporting" / "run_info.txt").read_text(encoding="utf-8")
            self.assertIn("mode=direct_csv_streaming_with_integrated_profile_schema_plan", run_info)
            self.assertIn("profile=integrated", run_info)

    def test_duplicate_files_report_and_collapse_modes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            inputs = root / "inputs"
            report_outputs = root / "report_outputs"
            collapse_outputs = root / "collapse_outputs"
            inputs.mkdir()
            (inputs / "a.txt").write_text("duplicate@example.org\n", encoding="utf-8")
            (inputs / "b.txt").write_text("duplicate@example.org\n", encoding="utf-8")
            base = [
                sys.executable, str(test_support.PROJECT_DIR / "run_scanner.py"),
                "--root", str(inputs),
                "--rules", str(test_support.PROJECT_DIR / "rules"),
                "--workers", "1",
                "--progress-every", "0",
            ]

            report = subprocess.run(
                base + ["--output-dir", str(report_outputs), "--duplicate-files", "report"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(report.returncode, 0, report.stderr + report.stdout)
            with (report_outputs / "4.Regex_Scanning" / "file_summary.csv").open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 2)
            self.assertEqual(sorted(row["duplicate_content_action"] for row in rows), ["duplicate_reported", "scanned"])
            self.assertTrue(all(row["sha256"] for row in rows))
            with (report_outputs / "4.Regex_Scanning" / "pii_regex_evidence" / "email_contact_location_email.csv").open(newline="", encoding="utf-8") as handle:
                email_rows = list(csv.DictReader(handle))
            self.assertEqual(len(email_rows), 1)

            collapse = subprocess.run(
                base + ["--output-dir", str(collapse_outputs)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(collapse.returncode, 0, collapse.stderr + collapse.stdout)
            with (collapse_outputs / "4.Regex_Scanning" / "file_summary.csv").open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(sorted(row["duplicate_content_action"] for row in rows), ["duplicate_collapsed", "scanned"])
            with (collapse_outputs / "4.Regex_Scanning" / "pii_regex_evidence" / "email_contact_location_email.csv").open(newline="", encoding="utf-8") as handle:
                email_rows = list(csv.DictReader(handle))
            self.assertEqual(len(email_rows), 2)
            self.assertEqual({Path(row["file_path"]).name for row in email_rows}, {"a.txt", "b.txt"})

    def test_duplicate_candidate_hashing_skips_unique_size_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            unique = root / "unique.txt"
            duplicate_a = root / "a.txt"
            duplicate_b = root / "renamed.txt"
            unique.write_text("unique@example.org\nextra\n", encoding="utf-8")
            duplicate_a.write_text("same@example.org\n", encoding="utf-8")
            duplicate_b.write_text("same@example.org\n", encoding="utf-8")
            args = parse_args(["--root", str(root)])
            targets = [("file", str(unique)), ("file", str(duplicate_a)), ("file", str(duplicate_b))]
            metadata, digest_groups = engine.precompute_hash_metadata_for_targets(targets, args)
            self.assertEqual(metadata[str(unique)]["sha256"], "")
            self.assertTrue(metadata[str(duplicate_a)]["sha256"])
            self.assertTrue(metadata[str(duplicate_b)]["sha256"])
            self.assertEqual([len(paths) for paths in digest_groups.values()], [2])

    def test_duplicate_evidence_collapse_keeps_atomic_audit_rows(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            inputs = root / "inputs"
            outputs = root / "outputs"
            inputs.mkdir()
            (inputs / "a.csv").write_text(
                "email,phone,note\nsame@example.org,07123456789,first copy\n",
                encoding="utf-8",
            )
            (inputs / "b.csv").write_text(
                "email,phone,note\nsame@example.org,07123456789,second copy\n",
                encoding="utf-8",
            )
            cmd = [
                sys.executable, str(test_support.PROJECT_DIR / "run_scanner.py"),
                "--root", str(inputs),
                "--output-dir", str(outputs),
                "--rules", str(test_support.PROJECT_DIR / "rules"),
                "--workers", "1",
                "--progress-every", "0",
                "--duplicate-files", "scan",
                "--duplicate-evidence", "collapse",
            ]

            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            with (outputs / "4.Regex_Scanning" / "linked_evidence.csv").open(newline="", encoding="utf-8") as handle:
                linked_rows = list(csv.DictReader(handle))
            self.assertEqual(len(linked_rows), 1)
            self.assertEqual(linked_rows[0]["duplicate_evidence_action"], "duplicate_collapsed")
            self.assertEqual(linked_rows[0]["duplicate_evidence_count"], "2")
            self.assertIn("a.csv", linked_rows[0]["duplicate_evidence_paths"])
            self.assertIn("b.csv", linked_rows[0]["duplicate_evidence_paths"])
            with (outputs / "4.Regex_Scanning" / "pii_regex_evidence" / "email_contact_location_email.csv").open(newline="", encoding="utf-8") as handle:
                email_rows = list(csv.DictReader(handle))
            self.assertEqual(len(email_rows), 2)

    def test_resume_scanning_rebuilds_atomic_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            inputs = root / "inputs"
            outputs = root / "outputs"
            rules = root / "rules" / "regex_searching" / "base"
            inputs.mkdir()
            rules.mkdir(parents=True)
            (inputs / "a.txt").write_text("person@example.org ref ABC123\n", encoding="utf-8")
            (rules / "email.json").write_text(
                """
                {
                  "evidence_type": "Email",
                  "pattern_name": "email",
                  "confidence": "high",
                  "regex": "\\\\b[A-Z0-9._%+\\\\-]+@[A-Z0-9.\\\\-]+\\\\.[A-Z]{2,}\\\\b",
                  "flags": ["IGNORECASE"],
                  "risk_tier": "tier_1_strong_identifier",
                  "normalization": "lower",
                  "is_identifiable": true,
                  "max_per_cluster": 4
                }
                """,
                encoding="utf-8",
            )
            base = [
                sys.executable, str(test_support.PROJECT_DIR / "run_scanner.py"),
                "--root", str(inputs),
                "--output-dir", str(outputs),
                "--rules", str(root / "rules"),
                "--workers", "1",
                "--progress-every", "0",
            ]
            fresh = subprocess.run(base, check=False, capture_output=True, text=True)
            self.assertEqual(fresh.returncode, 0, fresh.stderr + fresh.stdout)

            (rules / "test_ref.json").write_text(
                """
                {
                  "evidence_type": "Test Ref",
                  "pattern_name": "test_ref_context",
                  "confidence": "high",
                  "regex": "\\\\bref\\\\s+(?P<value>ABC\\\\d{3})\\\\b",
                  "flags": ["IGNORECASE"],
                  "line_triggers": ["ref"],
                  "risk_tier": "tier_3_supporting_evidence",
                  "normalization": "compact_upper"
                }
                """,
                encoding="utf-8",
            )
            rerun = subprocess.run(
                base + ["--resume", "scanning"],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(rerun.returncode, 0, rerun.stderr + rerun.stdout)
            self.assertIn("Stage 4/7: discovery and regex scanning", rerun.stdout)
            self.assertTrue((outputs / "4.Regex_Scanning" / "pii_regex_evidence" / "test_ref_test_ref_context.csv").exists())


if __name__ == "__main__":
    unittest.main()
