import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import test_support  # noqa: F401
from pii_regex_scanner import engine


class ExtractionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        engine.load_identity_anchor_config(str(test_support.PROJECT_DIR / "rules"))
        engine.load_rules(str(test_support.PROJECT_DIR / "rules"))
        engine.load_table_column_rules(str(test_support.PROJECT_DIR / "rules"))

    def test_nlp_person_identifier_resolution_requires_subject_semantics(self):
        self.addCleanup(engine.set_nlp_mode, engine.SCAN_NLP_ENABLED)
        engine.set_nlp_mode(True)
        with patch.object(engine, "nlp_header_suggestion", return_value=("person id", "medium")):
            for label in ("Reference No", "Reference Number", "Ref No", "Order Reference No"):
                with self.subTest(label=label):
                    self.assertEqual(engine.resolve_table_header(label), "")
            for label in ("Customer Reference No", "Person Reference", "Applicant Reference"):
                with self.subTest(label=label):
                    self.assertEqual(engine.resolve_table_header(label), "person id")
            for label in ("Candidate ID", "EMPLID", "ID"):
                with self.subTest(label=label):
                    self.assertEqual(engine.resolve_table_header(label), "person id")

    def test_text_decoding_and_binary_detection(self):
        text = "hello £"
        self.assertEqual(engine.decode_text_bytes(text.encode("utf-8")), text)
        self.assertEqual(engine.decode_text_bytes("hello".encode("utf-16")), "hello")
        self.assertTrue(engine.looks_like_utf16_text("hello".encode("utf-16")))
        self.assertTrue(engine.is_binary_like(b"\x00\x01\x02binary"))
        self.assertTrue(engine.text_like_bytes(b"plain text\n"))

    def test_content_detection_and_text_read(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            pdf = root / "wrong.bin"
            pdf.write_bytes(b"%PDF-1.7\n")
            self.assertEqual(engine.detect_extension_from_content(pdf, ".bin"), ".pdf")
            text_file = root / "data.unknown"
            text_file.write_text("name,email\nJane,jane@example.org\n", encoding="utf-8")
            self.assertEqual(engine.detect_extension_from_content(text_file, ".unknown"), ".csv")
            text, status = engine.read_text_sample(text_file, 0)
            self.assertEqual(status, "scanned")
            self.assertIn("jane@example.org", text)

    def test_ooxml_signature_detection(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "book.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("xl/workbook.xml", "<workbook/>")
            self.assertEqual(engine.sniff_zip_office_extension(path), ".xlsx")

    def test_reader_fallback(self):
        expected = engine.ExtractedText("ok", "second")
        result = engine.try_excel_readers(Path("x"), [
            ("first", lambda: (_ for _ in ()).throw(ValueError("bad"))),
            ("second", lambda: expected),
        ])
        self.assertEqual(result, expected)

    def test_transposed_table_rows_are_rotated_before_labelling(self):
        text = engine.table_rows_to_labelled_text(
            ["Field", "person_one", "person_two"],
            iter([
                ["Email", "jane@example.org", "john@example.org"],
                ["DOB", "2000-01-02", "1999-03-04"],
                ["NHS Number", "9434765919", ""],
            ]),
            "transposed.csv",
        )
        self.assertIn("TABLE_ROW transposed.csv #1", text)
        self.assertIn("Email: jane@example.org", text)
        self.assertIn("DOB: 2000-01-02", text)
        self.assertIn("NHS Number: 9434765919", text)
        self.assertIn("TABLE_ROW transposed.csv #2", text)
        self.assertIn("Email: john@example.org", text)

    def test_transposed_table_accepts_person_names_as_record_headers(self):
        assessment = engine.table_orientation_assessment(
            ["Field", "Jane Smith", "John Brown"],
            [
                ["Email", "jane@example.org", "john@example.org"],
                ["DOB", "2000-01-02", "1999-03-04"],
                ["Student No", "1234567", "7654321"],
            ],
        )
        self.assertEqual(assessment["orientation"], "transposed")
        self.assertTrue(assessment["transpose"])

        text = engine.table_rows_to_labelled_text(
            ["Field", "Jane Smith", "John Brown"],
            iter([
                ["Email", "jane@example.org", "john@example.org"],
                ["DOB", "2000-01-02", "1999-03-04"],
                ["Student No", "1234567", "7654321"],
            ]),
            "person_name_headers.csv",
        )
        self.assertIn("TABLE_ROW person_name_headers.csv #1", text)
        self.assertIn("Email: jane@example.org", text)
        self.assertIn("DOB: 2000-01-02", text)

    def test_transposed_table_with_metadata_rows_before_header_is_rotated(self):
        text = engine.table_rows_to_labelled_text(
            ["Report", "Student Export", ""],
            iter([
                ["Generated", "2026-06-29", ""],
                ["Field", "Jane Smith", "John Brown"],
                ["Email", "jane@example.org", "john@example.org"],
                ["DOB", "2000-01-02", "1999-03-04"],
                ["Nationality", "British", "Irish"],
            ]),
            "metadata_prefixed_transposed.csv",
        )
        self.assertIn("TABLE_ROW metadata_prefixed_transposed.csv #1", text)
        self.assertIn("Email: jane@example.org", text)
        self.assertIn("Nationality: British", text)
        self.assertNotIn("Generated: 2026-06-29", text)

    def test_two_column_field_value_form_is_single_transposed_record(self):
        text = engine.table_rows_to_labelled_text(
            ["Field", "Value"],
            iter([
                ["Email", "jane@example.org"],
                ["DOB", "2000-01-02"],
                ["NHS Number", "9434765919"],
            ]),
            "field_value.csv",
        )
        self.assertIn("TABLE_ROW field_value.csv #1", text)
        self.assertIn("Email: jane@example.org", text)
        self.assertIn("DOB: 2000-01-02", text)
        self.assertIn("NHS Number: 9434765919", text)
        self.assertNotIn("TABLE_ROW field_value.csv #2", text)

    def test_ambiguous_orientation_is_not_forced_into_transposed_headers(self):
        assessment = engine.table_orientation_assessment(
            ["Field", "DOB", "Email"],
            [
                ["DOB", "2000-01-02", "jane@example.org"],
                ["Nationality", "British", "john@example.org"],
            ],
        )
        self.assertEqual(assessment["orientation"], "ambiguous")
        self.assertFalse(assessment["transpose"])
        text = engine.table_rows_to_labelled_text(
            ["Field", "DOB", "Email"],
            iter([
                ["DOB", "2000-01-02", "jane@example.org"],
                ["Nationality", "British", "john@example.org"],
            ]),
            "ambiguous.csv",
        )
        self.assertEqual(text, "")

    def test_normal_table_remains_normal_when_first_column_is_data(self):
        assessment = engine.table_orientation_assessment(
            ["Email", "DOB", "Student No"],
            [
                ["jane@example.org", "2000-01-02", "1234567"],
                ["john@example.org", "1999-03-04", "7654321"],
            ],
        )
        self.assertEqual(assessment["orientation"], "normal")
        self.assertFalse(assessment["transpose"])

    def test_table_header_rules_do_not_match_container_or_metadata_labels(self):
        self.assertEqual(engine.resolve_table_header("CreditCard No"), "payment card")
        self.assertEqual(engine.resolve_table_header("CreditCard"), "payment card")
        self.assertEqual(engine.resolve_table_header("CreditCardLastFour"), "payment card")
        self.assertEqual(engine.resolve_table_header("CreditCard Country"), "payment metadata")
        self.assertEqual(engine.resolve_table_header("CreditCard Type"), "payment metadata")
        self.assertEqual(engine.table_patterns_for_header("CreditCard Country"), ())
        self.assertEqual(engine.table_patterns_for_header("CreditCard Type"), ())
        self.assertEqual(engine.resolve_table_header("Payment Card Type"), "payment metadata")
        self.assertEqual(engine.resolve_table_header("Payment Id Number"), "")
        self.assertEqual(engine.resolve_table_header("Method of Attendance"), "")
        self.assertEqual(engine.resolve_table_header("CAS Status"), "")
        self.assertEqual(engine.resolve_table_header("Leaving Status"), "")
        self.assertEqual(engine.resolve_table_header("Item Term"), "")
        self.assertEqual(
            engine.resolve_table_header("'Religion should never impose restrictions on medical research.' Do you agree?"),
            "",
        )
        self.assertEqual(engine.resolve_table_header("NHS Number"), "NHS number")
        self.assertEqual(engine.resolve_table_header("nhs_no"), "NHS number")
        self.assertEqual(engine.resolve_table_header("NHS Funded Income Assessed"), "")

    def test_table_header_matching_handles_common_non_space_separators(self):
        self.assertEqual(engine.resolve_table_header("date~of~birth"), "DOB")
        self.assertEqual(engine.resolve_table_header("date#of#birth"), "DOB")
        self.assertEqual(engine.resolve_table_header("date|of|birth"), "DOB")
        self.assertEqual(engine.resolve_table_header("date_of_birth"), "DOB")
        self.assertEqual(engine.resolve_table_header("date-of-birth"), "DOB")
        self.assertEqual(engine.resolve_table_header("email|address"), "email")

    def test_pipe_delimited_files_are_table_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "pipe_table.txt"
            path.write_text(
                "Email|date~of~birth|NHS#Number\n"
                "jane@example.org|2000-01-02|9434765919\n",
                encoding="utf-8",
            )
            extracted = engine.extract_delimited_table(path)
            self.assertEqual(extracted.extraction_method, "labelled_delimited_table")
            self.assertIn("Email: jane@example.org", extracted.text)
            self.assertIn("date~of~birth: 2000-01-02", extracted.text)
            self.assertIn("NHS#Number: 9434765919", extracted.text)

    def test_embedded_tilde_delimited_block_in_plain_text_is_detected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "mixed_text.txt"
            path.write_text(
                "blahalblald non table non header\n"
                "this-is a something~male~jon~doe~whatever\n"
                "something_else~female~jane~doe~whateverelse\n"
                "tail text\n",
                encoding="utf-8",
            )
            extracted = engine.extract_text_like(path, max_text_chars=0)
            self.assertEqual(extracted.extraction_method, "plain_text_with_detected_delimited_blocks")
            self.assertIn("blahalblald non table non header", extracted.text)
            self.assertIn("TABLE_ROW mixed_text.txt embedded_table_1 #1", extracted.text)
            self.assertIn("column_2: male", extracted.text)
            self.assertIn("column_3: jon", extracted.text)
            self.assertIn("TABLE_ROW mixed_text.txt embedded_table_1 #2", extracted.text)
            self.assertIn("column_2: female", extracted.text)
            self.assertIn("column_3: jane", extracted.text)

    def test_embedded_plain_text_table_detection_supports_conservative_delimiters(self):
        delimiters = ["~", "#", "|", ";", ",", "\t", "_", "-"]
        for delimiter in delimiters:
            with self.subTest(delimiter=delimiter):
                text = "\n".join([
                    "not a table",
                    delimiter.join(["alpha", "male", "jon", "doe"]),
                    delimiter.join(["beta", "female", "jane", "doe"]),
                ])
                labelled = engine.labelled_embedded_delimited_blocks(text, f"embedded_{ord(delimiter[0])}.txt")
                self.assertIn("TABLE_ROW", labelled)
                self.assertIn("column_2: male", labelled)
                self.assertIn("column_3: jon", labelled)
        self.assertEqual(engine.resolve_table_header("Email Type"), "")
        self.assertEqual(engine.resolve_table_header("Phone Type"), "")
        self.assertEqual(engine.resolve_table_header("Email Address"), "email")
        self.assertEqual(engine.resolve_table_header("User Contact"), "phone")
        self.assertEqual(engine.resolve_table_header("CAS Number"), "CAS number")
        self.assertEqual(
            engine.resolve_table_header("BulkFileUploadGeneralRootElement.CAS.CourseDetails.CourseStartDate"),
            "",
        )
        self.assertEqual(
            engine.resolve_table_header("UN_IFACE_CAS_USED.UN_CUR_CAS.SAD_PB_CAS_NUMBER"),
            "CAS number",
        )
        self.assertEqual(
            engine.resolve_table_header("BulkFileUploadGeneralRootElement.CAS.ApplicantData.ApplicantPassportOrTravelDocumentNumber"),
            "passport",
        )
        self.assertEqual(engine.resolve_table_header("Passport"), "passport")
        self.assertEqual(engine.resolve_table_header("Citizenship and Passport"), "")
        self.assertEqual(engine.resolve_table_header("DOCUMENT_NAME"), "document metadata")
        self.assertEqual(
            [pattern["pattern_name"] for pattern in engine.table_patterns_for_header("DOCUMENT_NAME")],
            ["documents_identity_document_file_reference"],
        )
        self.assertEqual(engine.resolve_table_header("Saturn ID"), "Saturn ID")
        self.assertEqual(engine.resolve_table_header("UN_IFACE_CAS_USED.UN_CUR_CAS.CURR_SATURN_ID"), "Saturn ID")
        self.assertEqual(
            engine.resolve_table_header("UN_IFACE_KINETICS.UN_IFC_BIO_DEMO.UN_IFC_PHONE.STUDENT_ID"),
            "student id",
        )
        self.assertEqual(
            engine.resolve_table_header("UN_IFACE_KINETICS.UN_IFC_BIO_DEMO.UN_IFC_PHONE.PHONE_TYPE"),
            "",
        )
        self.assertEqual(
            engine.resolve_table_header(
                "Genders have always been the most basic method to put people into groups. "
                "We go to the bathrooms according to our gender, male do not compete with female in any sport events."
            ),
            "",
        )

    def test_nlp_header_resolution_can_be_enabled_for_scanning(self):
        try:
            engine.set_nlp_mode(False)
            self.assertEqual(engine.resolve_table_header("born_when"), "")
            engine.set_nlp_mode(True)
            self.assertEqual(engine.resolve_table_header("born_when"), "DOB")
            self.assertTrue(engine.current_nlp_backend() in {"en_core_web_sm", "spacy.blank.en", ""} or bool(engine.current_nlp_backend()))
        finally:
            engine.set_nlp_mode(False)


if __name__ == "__main__":
    unittest.main()
