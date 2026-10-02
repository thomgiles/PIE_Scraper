import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import test_support  # noqa: F401
from pii_regex_scanner import engine


class ScanningAndClusteringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        engine.set_email_suffix("example.ac.uk")
        engine.load_identity_anchor_config(str(test_support.PROJECT_DIR / "rules"))
        engine.load_rules(str(test_support.PROJECT_DIR / "rules"))
        engine.load_table_column_rules(str(test_support.PROJECT_DIR / "rules"))

    def test_strong_singleton_candidate(self):
        candidate = engine.build_candidate(
            {"file_path": "x", "file_name": "x.txt", "extension": "txt", "size_bytes": 1, "md5": ""},
            1,
            "solo@example.ac.uk",
            [{"evidence_type": "Institutional Email", "normalized_value": "solo@example.ac.uk"}],
        )
        self.assertEqual(candidate["anchor_type"], "Institutional Email")
        self.assertEqual(candidate["cluster_eligible"], "yes")

    def test_multi_email_single_type_is_rejected(self):
        findings = [
            {"evidence_type": "Personal Email", "normalized_value": "a@gmail.com"},
            {"evidence_type": "Personal Email", "normalized_value": "b@gmail.com"},
        ]
        self.assertIsNone(engine.build_candidate(
            {"file_path": "x", "file_name": "x", "extension": "txt", "size_bytes": 1, "md5": ""},
            1,
            "a@gmail.com b@gmail.com",
            findings,
        ))

    def test_scan_text_and_file_risk(self):
        file_info = {"file_path": "x", "file_name": "x", "extension": "txt", "size_bytes": 10, "md5": ""}
        findings, candidates, count, entity_counts, candidate_count, _, _ = engine.scan_text(
            "solo@example.ac.uk\n", file_info, 0
        )
        self.assertEqual(count, 1)
        self.assertEqual(candidate_count, 1)
        self.assertEqual(findings[0]["evidence_type"], "Institutional Email")
        self.assertEqual(engine.file_risk_from_entity_counts(entity_counts), "medium")

    def test_line_iterator_matches_splitlines_without_allocating_a_list(self):
        for text in ("", "one", "one\n", "one\r\ntwo\rthree\n", "\n\n"):
            self.assertEqual(list(engine.iter_text_lines(text)), text.splitlines(keepends=True))

    def test_processed_hashing_skips_images_when_ocr_is_disabled(self):
        args = SimpleNamespace(hash_mode="processed", scan_images=False)
        self.assertFalse(engine.should_hash_file(args, ".png"))
        self.assertTrue(engine.should_hash_file(args, ".txt"))
        args.hash_mode = "duplicate-candidates"
        self.assertFalse(engine.should_hash_file(args, ".txt"))
        args.scan_images = True
        self.assertFalse(engine.should_hash_file(args, ".png"))
        args.hash_mode = "all"
        args.scan_images = False
        self.assertTrue(engine.should_hash_file(args, ".png"))

    def test_table_columns_route_rules_and_unresolved_columns_keep_raw_fallback(self):
        file_info = {"file_path": "x", "file_name": "x.csv", "extension": ".csv", "size_bytes": 1, "md5": ""}
        line = (
            "TABLE_ROW people.csv #1 | email: jane@example.org 07700 900123 | "
            "notes: server 192.168.1.5\n"
        )
        findings, *_ = engine.scan_text(line, file_info, 0)
        values = {(row["evidence_type"], row["matched_text"]) for row in findings}

        self.assertIn(("Personal Email", "jane@example.org"), values)
        self.assertIn(("IP Address", "192.168.1.5"), values)
        self.assertNotIn(("Phone", "07700 900123"), values)
        ip_finding = next(row for row in findings if row["evidence_type"] == "IP Address")
        self.assertEqual(ip_finding["start"], line.index("192.168.1.5"))

    def test_structured_labelled_records_route_rules_like_table_rows(self):
        file_info = {"file_path": "x", "file_name": "x.json", "extension": ".json", "size_bytes": 1, "md5": ""}
        line = (
            "JSON_RECORD $.people[0] | email: jane@example.org 07700 900123 | "
            "notes: server 192.168.1.5\n"
        )
        findings, *_ = engine.scan_text(line, file_info, 0)
        values = {(row["evidence_type"], row["matched_text"]) for row in findings}

        self.assertIn(("Personal Email", "jane@example.org"), values)
        self.assertIn(("IP Address", "192.168.1.5"), values)
        self.assertNotIn(("Phone", "07700 900123"), values)

    def test_sensitive_demographics_require_labelled_table_or_structured_fields(self):
        file_info = {"file_path": "x", "file_name": "x.txt", "extension": "txt", "size_bytes": 10, "md5": ""}
        plain_findings, *_ = engine.scan_text(
            "Christian dyslexia British\n",
            file_info,
            0,
        )
        self.assertFalse(
            {"Religion", "Disability", "Citizenship Country"}
            & {row["evidence_type"] for row in plain_findings}
        )

        labelled_findings, *_ = engine.scan_text(
            "TABLE_ROW people.csv #1 | religion: Christian | disability: dyslexia | nationality: British\n",
            file_info,
            0,
        )
        self.assertEqual(
            {"Religion", "Disability", "Citizenship Country"},
            {row["evidence_type"] for row in labelled_findings},
        )

    def test_generic_country_header_does_not_emit_citizenship_country(self):
        file_info = {"file_path": "x", "file_name": "x.txt", "extension": "txt", "size_bytes": 10, "md5": ""}
        generic_findings, *_ = engine.scan_text(
            "TABLE_ROW people.csv #1 | country: British\n",
            file_info,
            0,
        )
        self.assertNotIn("Citizenship Country", {row["evidence_type"] for row in generic_findings})

        specific_findings, *_ = engine.scan_text(
            "TABLE_ROW people.csv #1 | nationality: British\n",
            file_info,
            0,
        )
        self.assertIn("Citizenship Country", {row["evidence_type"] for row in specific_findings})

    def test_citizenship_country_rejects_fee_status_and_region_values(self):
        file_info = {"file_path": "x", "file_name": "x.txt", "extension": "txt", "size_bytes": 10, "md5": ""}
        findings, *_ = engine.scan_text(
            "TABLE_ROW people.csv #1 | nationality: UK - Home | domicile: ENGLAND | country of citizenship: United Kingdom\n",
            file_info,
            0,
        )
        citizenship_values = {
            row["matched_text"]
            for row in findings
            if row["evidence_type"] == "Citizenship Country"
        }
        self.assertEqual(citizenship_values, {"United Kingdom"})

    def test_student_support_headers_emit_header_confirmed_values(self):
        file_info = {"file_path": "x", "file_name": "x.txt", "extension": "txt", "size_bytes": 10, "md5": ""}
        findings, *_ = engine.scan_text(
            "TABLE_ROW support.csv #1 | care leaver: Yes | household income: 12500 | special support grant: Approved | "
            "maintenance grant: N | dependants adg indicator: No | number of sponsors: 0 | principal earner income: 0.0\n",
            file_info,
            0,
        )
        emitted = {(row["evidence_type"], row["matched_text"]) for row in findings}
        self.assertIn(("Care Leaver", "Yes"), emitted)
        self.assertIn(("Household Income", "12500"), emitted)
        self.assertIn(("Special Support Grant", "Approved"), emitted)
        self.assertNotIn(("Maintenance Grant", "N"), emitted)
        self.assertNotIn(("Dependants ADG Indicator", "No"), emitted)
        self.assertNotIn(("Number of Sponsors", "0"), emitted)
        self.assertNotIn(("Principal Earner Income", "0.0"), emitted)

    def test_marital_status_header_emits_valid_header_confirmed_values(self):
        file_info = {"file_path": "x", "file_name": "x.txt", "extension": "txt", "size_bytes": 10, "md5": ""}
        findings, *_ = engine.scan_text(
            "TABLE_ROW people.csv #1 | MaritalStatus: Married | relationship status: unknown\n",
            file_info,
            0,
        )
        emitted = {(row["evidence_type"], row["matched_text"]) for row in findings}
        self.assertIn(("Marital Status", "Married"), emitted)
        self.assertNotIn(("Marital Status", "unknown"), emitted)

    def test_sensitive_demographics_reject_low_quality_table_values(self):
        file_info = {"file_path": "x", "file_name": "x.txt", "extension": "txt", "size_bytes": 10, "md5": ""}
        findings, *_ = engine.scan_text(
            "TABLE_ROW people.csv #1 | religion: yes | disability: no | ethnicity: MSc Finance | nationality: jane@example.ac.uk\n",
            file_info,
            0,
        )
        self.assertFalse(
            {"Religion", "Disability", "Ethnicity", "Citizenship Country"}
            & {row["evidence_type"] for row in findings}
        )

        valid_findings, *_ = engine.scan_text(
            "TABLE_ROW people.csv #2 | religion: Christian | disability: dyslexia | ethnicity: White British | nationality: British\n",
            file_info,
            0,
        )
        self.assertEqual(
            {"Religion", "Disability", "Ethnicity", "Citizenship Country"},
            {row["evidence_type"] for row in valid_findings},
        )

        disability_location_findings, *_ = engine.scan_text(
            "TABLE_ROW people.csv #3 | disability: Nottingham | disability status: United Kingdom | accessibility needs: Dyslexia\n",
            file_info,
            0,
        )
        disability_values = {
            row["matched_text"]
            for row in disability_location_findings
            if row["evidence_type"] == "Disability"
        }
        self.assertEqual(disability_values, {"Dyslexia"})

    def test_nlp_enabled_scan_resolves_unmatched_structured_headers(self):
        file_info = {"file_path": "x", "file_name": "x.txt", "extension": "txt", "size_bytes": 10, "md5": ""}
        line = "TABLE_ROW people.csv #1 | born_when: 2000-01-02\n"
        try:
            engine.set_nlp_mode(False)
            findings, *_ = engine.scan_text(line, file_info, 0)
            self.assertNotIn("DOB", {row["evidence_type"] for row in findings})

            engine.set_nlp_mode(True)
            findings, *_ = engine.scan_text(line, file_info, 0)
            self.assertIn("DOB", {row["evidence_type"] for row in findings})

            course_findings, *_ = engine.scan_text(
                "TABLE_ROW course.csv #1 | course start date: 2020-01-02\n",
                file_info,
                0,
            )
            self.assertNotIn("DOB", {row["evidence_type"] for row in course_findings})
        finally:
            engine.set_nlp_mode(False)

    def test_header_confirmed_nhs_number_and_split_bank_account_emit(self):
        file_info = {"file_path": "x", "file_name": "x.txt", "extension": "txt", "size_bytes": 10, "md5": ""}
        findings, *_ = engine.scan_text(
            "TABLE_ROW finance.csv #1 | nhs_no: 9434765919 | sort code: 12-34-56 | account number: 12345678\n",
            file_info,
            0,
        )
        emitted = {(row["evidence_type"], row["normalized_value"]) for row in findings}
        self.assertIn(("NHS Number", "9434765919"), emitted)
        self.assertIn(("Bank Account", "12345612345678"), emitted)

    def test_metadata_headers_do_not_emit_identifier_evidence_and_saturn_id_does(self):
        file_info = {"file_path": "x", "file_name": "x.txt", "extension": "txt", "size_bytes": 10, "md5": ""}
        findings, *_ = engine.scan_text(
            (
                "TABLE_ROW people.csv #1 | CreditCard Type: VISA | CreditCard Country: GB | "
                "NHS Funded Income Assessed: Y | Email Type: HOME | Phone Type: HOME | "
                "DOCUMENT_NAME: jane@example.org_Passport_G3603766.pdf | "
                "BulkFileUploadGeneralRootElement.CAS.CourseDetails.CourseStartDate: 2025-09-22 | "
                "BulkFileUploadGeneralRootElement.CAS.ApplicantData.ApplicantPassportOrTravelDocumentNumber: G3603766 | "
                "Citizenship and Passport: GB | User Contact: 07700 900123 | Saturn ID: 4315421\n"
            ),
            file_info,
            0,
        )
        emitted = {(row["evidence_type"], row["matched_text"]) for row in findings}
        self.assertIn(("Saturn ID", "4315421"), emitted)
        self.assertIn(("Passport", "G3603766"), emitted)
        self.assertIn(("Phone", "07700 900123"), emitted)
        self.assertNotIn(("Identity Document File", "jane@example.org_Passport_G3603766.pdf"), emitted)
        self.assertNotIn(("Payment Card", "VISA"), emitted)
        self.assertNotIn(("Payment Card", "GB"), emitted)
        self.assertNotIn(("NHS Number", "Y"), emitted)
        self.assertNotIn(("Personal Email", "jane@example.org"), emitted)
        self.assertNotIn(("Email", "HOME"), emitted)
        self.assertNotIn(("Phone", "HOME"), emitted)
        self.assertNotIn(("Citizenship Country", "GB"), emitted)
        self.assertNotIn(("CAS Number", "2025-09-22"), emitted)

    def test_identity_document_file_signal_from_name_confirmed_file_name(self):
        file_info = {
            "file_path": "/tmp/Passport_of_Rui_SHEN.jpg",
            "file_name": "Passport_of_Rui_SHEN.jpg",
            "extension": "jpg",
            "size_bytes": 10,
            "md5": "",
        }
        findings = engine.file_signal_findings(file_info, ".jpg")
        emitted = {(row["evidence_type"], row["matched_text"]) for row in findings}
        self.assertIn(("Identity Document File", "Passport_of_Rui_SHEN.jpg"), emitted)

    def test_identity_document_file_signal_rejects_generic_file_name(self):
        file_info = {
            "file_path": "/tmp/passport_photo.jpg",
            "file_name": "passport_photo.jpg",
            "extension": "jpg",
            "size_bytes": 10,
            "md5": "",
        }
        findings = engine.file_signal_findings(file_info, ".jpg")
        emitted = {(row["evidence_type"], row["matched_text"]) for row in findings}
        self.assertNotIn(("Identity Document File", "passport_photo.jpg"), emitted)

    def test_nlp_context_guard_supports_semantic_header_aliases(self):
        try:
            engine.set_nlp_mode(True)
            self.assertTrue(engine.header_context_supports_guard(
                "faith group",
                {"required_tokens": ["religion"]},
            ))
        finally:
            engine.set_nlp_mode(False)

    def test_integrated_schema_plan_can_drive_safe_cell_emission(self):
        file_info = {"file_path": "x", "file_name": "x.csv", "extension": "csv", "size_bytes": 10, "md5": ""}
        line = "TABLE_ROW people.csv #1 | Belief Stream: Muslim | Course Religion Topic: Popular Religi\n"
        no_plan_findings, *_ = engine.scan_text(line, file_info, 0)
        self.assertNotIn(
            ("Religion", "Muslim"),
            {(row["evidence_type"], row["matched_text"]) for row in no_plan_findings},
        )

        schema_decisions = engine.actionable_schema_plan_decisions([
            {
                "raw_header": "Belief Stream",
                "suggested_type": "religion",
                "scan_action": "route_suggested_rules_and_emit_cell_value",
                "confidence": "high",
                "reason": "nlp_label_inference:religion_semantics_in_label",
            },
            {
                "raw_header": "Course Religion Topic",
                "suggested_type": "religion",
                "scan_action": "review_only_raw_fallback",
                "confidence": "medium",
                "reason": "review_only:label_semantics_do_not_support_suggestion",
            },
        ])
        findings, *_ = engine.scan_text(line, file_info, 0, schema_plan_decisions=schema_decisions)
        emitted = {(row["evidence_type"], row["matched_text"]) for row in findings}
        self.assertIn(("Religion", "Muslim"), emitted)
        self.assertNotIn(("Religion", "Popular Religi"), emitted)

    def test_national_insurance_rule_rejects_repeated_digit_dummy(self):
        file_info = {"file_path": "x", "file_name": "x.txt", "extension": "txt", "size_bytes": 10, "md5": ""}
        findings, *_ = engine.scan_text("AA999999A AB123456C\n", file_info, 0)
        ni_values = {
            row["normalized_value"]
            for row in findings
            if row["evidence_type"] == "National Insurance Number"
        }
        self.assertEqual(ni_values, {"AB123456C"})

    def test_union_find_and_anchor_basis(self):
        union = engine.UnionFind()
        left, right = union.add(), union.add()
        union.union(left, right)
        self.assertEqual(union.find(left), union.find(right))
        bases = engine.identity_anchor_bases({"Personal Email", "Phone"})
        self.assertIn("strong:Personal Email", bases)
        self.assertIn("compound:Personal Email+Phone", bases)

    def test_cluster_helpers(self):
        parsed = engine.parse_cluster_evidence_values("Name=Jane Smith|Phone=07123456789")
        self.assertEqual(parsed["Name"], {"Jane Smith"})
        self.assertEqual(engine.strongest_risk(["low", "high", "medium"]), "high")
        self.assertEqual(engine.capped_join({"b", "a"}), "a|b")

    def test_target_priority_and_exclusions(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "keep.txt").write_text("x")
            (root / "skip").mkdir()
            (root / "skip" / "x.txt").write_text("x")
            excluded_paths, excluded_names, excluded_suffixes = engine.excluded_path_config(str(root), [["skip"]])
            self.assertTrue(engine.is_excluded_path(
                root / "skip", root, excluded_paths, excluded_names, excluded_suffixes
            ))
            self.assertFalse(engine.is_excluded_path(
                root / "keep.txt", root, excluded_paths, excluded_names, excluded_suffixes
            ))
            self.assertTrue(engine.is_inside(root / "keep.txt", root))


if __name__ == "__main__":
    unittest.main()
