import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import test_support


class ProfilingTests(unittest.TestCase):
    def test_column_profile_outputs_rank_and_group_candidates(self):
        fixture_root = test_support.PROJECT_DIR / "tests" / "synthetic_data" / "inputs" / "profile_fixture"
        with tempfile.TemporaryDirectory() as folder:
            output_dir = Path(folder) / "profile_out"
            cmd = [
                sys.executable,
                str(test_support.PROJECT_DIR / "run_scanner.py"),
                "--root", str(fixture_root),
                "--output-dir", str(output_dir),
                "--rules", str(test_support.PROJECT_DIR / "rules"),
                "--profile", "standalone",
                "--workers", "2",
                "--hash-mode", "none",
            ]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn("Profiling complete:", result.stdout)

            all_profiles_path = output_dir / "3.Profiling" / "columns_all_profiles.csv"
            candidates_path = output_dir / "3.Profiling" / "columns_rule_candidates.csv"
            profiles_path = output_dir / "3.Profiling" / "columns_unknown_profiles.csv"
            schema_plan_path = output_dir / "3.Profiling" / "schema_plan.csv"
            value_types_path = output_dir / "3.Profiling" / "value_type_candidates.csv"
            coverage_path = output_dir / "3.Profiling" / "rule_coverage.csv"

            self.assertTrue(all_profiles_path.exists())
            self.assertTrue(candidates_path.exists())
            self.assertTrue(profiles_path.exists())
            self.assertTrue(schema_plan_path.exists())
            self.assertTrue(value_types_path.exists())
            self.assertTrue(coverage_path.exists())

            with all_profiles_path.open(newline="", encoding="utf-8") as handle:
                all_profile_rows = list(csv.DictReader(handle))
            self.assertTrue(any(row["resolved_header"] for row in all_profile_rows))
            self.assertIn("sample_values_preview", all_profile_rows[0])

            with candidates_path.open(newline="", encoding="utf-8") as handle:
                candidate_rows = list(csv.DictReader(handle))
            self.assertTrue(candidate_rows)

            by_header = {row["suggested_header"]: row for row in candidate_rows}
            self.assertIn("email", by_header)
            self.assertIn("mailbox", by_header["email"]["source_labels"])
            self.assertNotIn("DOB", by_header)

            with value_types_path.open(newline="", encoding="utf-8") as handle:
                value_type_rows = list(csv.DictReader(handle))
            value_type_kinds = {(row["source_label"], row["candidate_kind"]) for row in value_type_rows}
            self.assertIn(("status_flag", "possible_enum_family"), value_type_kinds)
            self.assertIn(("external_ref", "possible_identifier_family"), value_type_kinds)

            with coverage_path.open(newline="", encoding="utf-8") as handle:
                coverage_rows = list(csv.DictReader(handle))
            self.assertTrue(coverage_rows)
            self.assertEqual(coverage_rows[0]["status"], "likely_stale_for_structured_data")
            stale_rows = [row for row in coverage_rows if row["status"] == "likely_stale_for_structured_data"]
            self.assertTrue(stale_rows)
            self.assertTrue(any(row["recommended_action"] == "review_or_remove_header_rule" for row in stale_rows))

            with schema_plan_path.open(newline="", encoding="utf-8") as handle:
                schema_rows = list(csv.DictReader(handle))
            self.assertTrue(schema_rows)
            self.assertIn("scan_action", schema_rows[0])
            self.assertIn("linking_scope", schema_rows[0])
            self.assertIn("orientation", schema_rows[0])
            self.assertIn("orientation_confidence", schema_rows[0])
            self.assertIn("orientation_reason", schema_rows[0])
            self.assertIn("detected_separator", schema_rows[0])
            self.assertIn("schema_signature", schema_rows[0])
            self.assertIn("schema_reused_from", schema_rows[0])

    def test_profile_mode_honours_exclude(self):
        fixture_root = test_support.PROJECT_DIR / "tests" / "synthetic_data" / "inputs" / "profile_fixture"
        with tempfile.TemporaryDirectory() as folder:
            output_dir = Path(folder) / "profile_out"
            cmd = [
                sys.executable,
                str(test_support.PROJECT_DIR / "run_scanner.py"),
                "--root", str(fixture_root),
                "--output-dir", str(output_dir),
                "--rules", str(test_support.PROJECT_DIR / "rules"),
                "--profile", "standalone",
                "--workers", "1",
                "--hash-mode", "none",
                "--exclude", "profile_records.xml",
            ]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn("Profile scan | 2 / 2 files complete", result.stdout)

            profiles_path = output_dir / "3.Profiling" / "columns_unknown_profiles.csv"
            self.assertTrue(profiles_path.exists())
            with profiles_path.open(newline="", encoding="utf-8") as handle:
                profile_rows = list(csv.DictReader(handle))

            xml_rows = [row for row in profile_rows if row["source_kind"] == "xml"]
            self.assertFalse(xml_rows)

    def test_integrated_profile_runs_stage1_and_writes_schema_plan(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "inputs"
            output_dir = Path(folder) / "outputs"
            root.mkdir()
            (root / "people.csv").write_text(
                "Email,DOB,NHS Number,Course Start Date\n"
                "jane@example.org,2000-01-02,9434765919,2020-09-01\n",
                encoding="utf-8",
            )

            cmd = [
                sys.executable,
                str(test_support.PROJECT_DIR / "run_scanner.py"),
                "--root", str(root),
                "--output-dir", str(output_dir),
                "--rules", str(test_support.PROJECT_DIR / "rules"),
                "--profile", "integrated",
                "--workers", "1",
                "--hash-mode", "none",
            ]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertIn("Stage 3/7: profiling and schema planning", result.stdout)
            self.assertIn("Stage 4/7: discovery and regex scanning using Stage 3 schema plan", result.stdout)

            schema_plan_path = output_dir / "3.Profiling" / "schema_plan.csv"
            findings_path = output_dir / "4.Regex_Scanning" / "pii_regex_evidence"
            self.assertTrue(schema_plan_path.exists())
            self.assertTrue(findings_path.exists())

            with schema_plan_path.open(newline="", encoding="utf-8") as handle:
                schema_rows = list(csv.DictReader(handle))
            by_header = {row["raw_header"]: row for row in schema_rows}
            self.assertEqual(by_header["Email"]["resolved_header"], "email")
            self.assertEqual(by_header["Email"]["scan_action"], "route_relevant_rules")
            self.assertEqual(by_header["NHS Number"]["scan_action"], "route_rules_and_emit_cell_value")
            self.assertEqual(by_header["Course Start Date"]["resolved_header"], "")

            finding_rows = []
            for csv_path in findings_path.glob("*.csv"):
                with csv_path.open(newline="", encoding="utf-8") as handle:
                    finding_rows.extend(csv.DictReader(handle))
            emitted = {row["evidence_type"] for row in finding_rows}
            self.assertIn("Email", emitted)
            self.assertIn("DOB", emitted)
            self.assertIn("NHS Number", emitted)

    def test_profile_create_rules_writes_review_stage_json(self):
        fixture_root = test_support.PROJECT_DIR / "tests" / "synthetic_data" / "inputs" / "profile_fixture"
        with tempfile.TemporaryDirectory() as folder:
            output_dir = Path(folder) / "profile_out"
            profile_cmd = [
                sys.executable,
                str(test_support.PROJECT_DIR / "run_scanner.py"),
                "--root", str(fixture_root),
                "--output-dir", str(output_dir),
                "--rules", str(test_support.PROJECT_DIR / "rules"),
                "--profile", "standalone",
                "--workers", "1",
                "--hash-mode", "none",
            ]
            profile_result = subprocess.run(profile_cmd, check=False, capture_output=True, text=True)
            self.assertEqual(profile_result.returncode, 0, profile_result.stderr + profile_result.stdout)

            create_cmd = [
                sys.executable,
                str(test_support.PROJECT_DIR / "run_scanner.py"),
                "--root", str(fixture_root),
                "--output-dir", str(output_dir),
                "--rules", str(test_support.PROJECT_DIR / "rules"),
                "--profile", "create_rules",
            ]
            create_result = subprocess.run(create_cmd, check=False, capture_output=True, text=True)
            self.assertEqual(create_result.returncode, 0, create_result.stderr + create_result.stdout)
            self.assertIn("Draft rule generation complete:", create_result.stdout)

            draft_dir = output_dir / "3.Profiling" / "draft_table_column_rules"
            manifest_path = draft_dir / "draft_rule_manifest.csv"
            self.assertTrue(draft_dir.exists())
            self.assertTrue(manifest_path.exists())

            draft_files = sorted(path for path in draft_dir.glob("*.json"))
            self.assertTrue(draft_files)

            with manifest_path.open(newline="", encoding="utf-8") as handle:
                manifest_rows = list(csv.DictReader(handle))
            self.assertTrue(manifest_rows)

            email_draft = draft_dir / "email.json"
            self.assertTrue(email_draft.exists())
            email_rule = json.loads(email_draft.read_text(encoding="utf-8"))
            self.assertEqual(email_rule["canonical_header"], "email")
            self.assertEqual(email_rule["pattern_name"], "profile_candidate_email_column")
            self.assertTrue(email_rule["review_required"])
            self.assertIn("mailbox", email_rule["profile_suggestion"]["source_labels"])

    def test_profile_semantic_review_blocks_value_shape_only_header_rules(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "inputs"
            output_dir = Path(folder) / "profile_out"
            root.mkdir()
            (root / "misleading_dates.csv").write_text(
                "Assessment Date,Course Start Date,Mailbox,IPAddress\n"
                "2020-01-01,2020-09-01,alice@example.org,192.168.1.10\n"
                "2020-01-02,2020-09-02,bob@example.org,192.168.1.11\n",
                encoding="utf-8",
            )
            (root / "headerless_dates.csv").write_text(
                "01/01/2020,alice@example.org\n"
                "02/01/2020,bob@example.org\n"
                "03/01/2020,charlie@example.org\n",
                encoding="utf-8",
            )
            (root / "ambiguous_codes.csv").write_text(
                "CAREER,CAMPUS,FLAG\n"
                "UG,U,Y\n"
                "PG,U,N\n"
                "PGT,U,Y\n"
                "PGR,U,N\n",
                encoding="utf-8",
            )
            (root / "bad_sensitive_candidates.csv").write_text(
                "Application Fee Status,Country,ApplicantHasWorkPlacement,CourseRequiresATAS,ADMIT_TERM\n"
                "Paid,GB,Y,N,2024\n"
                "Unpaid,GB,N,N,2025\n"
                "Paid,US,Y,Y,2026\n",
                encoding="utf-8",
            )
            (root / "transposed.csv").write_text(
                "Field,person_one,person_two\n"
                "Email,jane@example.org,john@example.org\n"
                "DOB,2000-01-02,1999-03-04\n"
                "NHS Number,9434765919,\n",
                encoding="utf-8",
            )

            cmd = [
                sys.executable,
                str(test_support.PROJECT_DIR / "run_scanner.py"),
                "--root", str(root),
                "--output-dir", str(output_dir),
                "--rules", str(test_support.PROJECT_DIR / "rules"),
                "--profile", "standalone",
                "--workers", "1",
                "--hash-mode", "none",
            ]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

            candidates_path = output_dir / "3.Profiling" / "columns_rule_candidates.csv"
            review_only_path = output_dir / "3.Profiling" / "columns_review_candidates.csv"
            profiles_path = output_dir / "3.Profiling" / "columns_unknown_profiles.csv"
            self.assertTrue(candidates_path.exists())
            self.assertTrue(review_only_path.exists())
            self.assertTrue(profiles_path.exists())

            with candidates_path.open(newline="", encoding="utf-8") as handle:
                candidate_rows = list(csv.DictReader(handle))
            candidate_headers = {row["suggested_header"] for row in candidate_rows}
            self.assertNotIn("DOB", candidate_headers)
            self.assertNotIn("citizenship country", candidate_headers)
            self.assertNotIn("disability", candidate_headers)

            with review_only_path.open(newline="", encoding="utf-8") as handle:
                review_rows = list(csv.DictReader(handle))
            self.assertFalse(any(row["suggested_header"] == "DOB" for row in review_rows))

            with profiles_path.open(newline="", encoding="utf-8") as handle:
                profile_rows = list(csv.DictReader(handle))
            self.assertFalse(any(row["suggested_header"] == "DOB" for row in profile_rows))
            self.assertFalse(any(row["source_label"] == "01/01/2020" for row in profile_rows))
            headerless_date_row = next(row for row in profile_rows if row["source_label"] == "column_1")
            self.assertIn("01/01/2020", headerless_date_row["sample_values_preview"])
            noisy_code_rows = [
                row for row in profile_rows
                if row["source_label"] in {"CAREER", "CAMPUS", "FLAG"}
            ]
            self.assertFalse(any(row["suggested_header"] in {"citizenship country", "ethnicity"} for row in noisy_code_rows))
            transposed_labels = {row["source_label"] for row in profile_rows}
            self.assertNotIn("person_one", transposed_labels)

            schema_path = output_dir / "3.Profiling" / "schema_plan.csv"
            with schema_path.open(newline="", encoding="utf-8") as handle:
                schema_rows = list(csv.DictReader(handle))
            transposed_schema_rows = [
                row for row in schema_rows
                if row["table_name"].endswith("transposed.csv")
            ]
            self.assertTrue(transposed_schema_rows)
            self.assertEqual({row["orientation"] for row in transposed_schema_rows}, {"transposed"})
            self.assertTrue(all(row["orientation_confidence"] for row in transposed_schema_rows))
            self.assertTrue(all(row["orientation_reason"] for row in transposed_schema_rows))

    def test_profile_nlp_recovers_known_pii_labels(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "inputs"
            output_dir = Path(folder) / "profile_out"
            root.mkdir()
            lines = [
                "NotifyEmail,RegisteredEmail,CreditCard No,Candidate ID,EMPLID,Reference No,Course Start Date,User Name,Middle Name"
            ]
            for index in range(30):
                lines.append(
                    ",".join([
                        f"notify.{index}@example.org",
                        f"registered.{index}@example.org",
                        "4111111111111111" if index % 3 == 0 else "4242424242424242",
                        f"C-{index:03d}",
                        f"{10000000 + index}",
                        f"REF-{100 + index}",
                        f"2020-09-{(index % 28) + 1:02d}",
                        f"user{index:02d}",
                        "Anne" if index % 2 == 0 else "Louise",
                    ])
                )
            (root / "known_terms.csv").write_text("\n".join(lines), encoding="utf-8")

            cmd = [
                sys.executable,
                str(test_support.PROJECT_DIR / "run_scanner.py"),
                "--root", str(root),
                "--output-dir", str(output_dir),
                "--rules", str(test_support.PROJECT_DIR / "rules"),
                "--profile", "standalone",
                "--workers", "1",
                "--hash-mode", "none",
                "--nlp", "true",
            ]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

            profiles_path = output_dir / "3.Profiling" / "columns_unknown_profiles.csv"
            candidates_path = output_dir / "3.Profiling" / "columns_rule_candidates.csv"
            review_only_path = output_dir / "3.Profiling" / "columns_review_candidates.csv"
            self.assertTrue(profiles_path.exists())
            self.assertTrue(candidates_path.exists())
            self.assertTrue(review_only_path.exists())

            with profiles_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            by_label = {row["source_label"]: row for row in rows}
            self.assertEqual(set(by_label), {"Reference No", "Course Start Date"})
            self.assertEqual(by_label["Reference No"]["processing_decision"], "review_only")
            self.assertEqual(by_label["Course Start Date"]["processing_decision"], "review_only")
            self.assertTrue(by_label["Reference No"]["sample_values_preview"])

            with candidates_path.open(newline="", encoding="utf-8") as handle:
                candidate_rows = list(csv.DictReader(handle))
            self.assertFalse(candidate_rows)

            with review_only_path.open(newline="", encoding="utf-8") as handle:
                review_rows = list(csv.DictReader(handle))
            review_headers = {row["suggested_header"] for row in review_rows}
            self.assertIn("DOB", review_headers)
            self.assertIn("person id", review_headers)

    def test_profile_nlp_uses_vocabularies_for_headerless_sensitive_columns(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "inputs"
            output_dir = Path(folder) / "profile_out"
            root.mkdir()
            (root / "headerless_sensitive.csv").write_text(
                "\n".join([
                    "Single,Christian,France,Dyslexia",
                    "Married,Muslim,Germany,Autism spectrum condition",
                    "Divorced,Hindu,Canada,Mental health condition",
                    "Widowed,Sikh,Spain,Physical impairment",
                    "Separated,Buddhist,Italy,Hearing impairment",
                ]),
                encoding="utf-8",
            )

            cmd = [
                sys.executable,
                str(test_support.PROJECT_DIR / "run_scanner.py"),
                "--root", str(root),
                "--output-dir", str(output_dir),
                "--rules", str(test_support.PROJECT_DIR / "rules"),
                "--profile", "standalone",
                "--workers", "1",
                "--hash-mode", "none",
                "--nlp", "true",
            ]
            result = subprocess.run(cmd, check=False, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)

            profiles_path = output_dir / "3.Profiling" / "columns_unknown_profiles.csv"
            with profiles_path.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            by_label = {row["source_label"]: row for row in rows}

            self.assertEqual(by_label["column_1"]["suggested_header"], "marital status")
            self.assertEqual(by_label["column_2"]["suggested_header"], "religion")
            self.assertEqual(by_label["column_3"]["suggested_header"], "citizenship country")
            self.assertEqual(by_label["column_4"]["suggested_header"], "disability")
            self.assertTrue(all(row["processing_decision"] == "review_only" for row in by_label.values()))
            self.assertTrue(all(row["suggestion_source"].startswith("vocabulary_") for row in by_label.values()))


if __name__ == "__main__":
    unittest.main()
