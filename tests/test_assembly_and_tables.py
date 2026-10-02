import unittest

import test_support  # noqa: F401
from pii_regex_scanner import engine


class AssemblyAndTableTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        engine.load_table_column_rules(str(test_support.PROJECT_DIR / "rules"))

    def test_name_assembly(self):
        line = "TABLE_ROW x #1 | first name: Jane | last name: Smith"
        names = engine.assembled_names_from_labelled_line(line)
        self.assertEqual([row["matched_text"] for row in names], ["Jane Smith"])
        self.assertEqual(engine.pair_name_parts(["Jane"], ["Smith", "Jones"]), ["Jane Smith", "Jane Jones"])

    def test_address_assembly(self):
        line = "TABLE_ROW x #1 | address1: 1 Test Road | city: Nottingham | postcode: NG7 2RD"
        addresses = engine.assembled_addresses_from_labelled_line(line)
        self.assertEqual([row["matched_text"] for row in addresses], ["1 Test Road, Nottingham, NG7 2RD"])
        self.assertTrue(engine.has_searchable_address_component(["1 Test Road"]))

    def test_table_header_resolution_and_labelling(self):
        self.assertEqual(engine.safe_cell(" a\n b "), "a b")
        self.assertEqual(engine.resolve_table_header("Date of Birth"), "DOB")
        self.assertEqual(engine.resolve_table_header("date_of_birth"), "DOB")
        text = engine.table_rows_to_labelled_text(
            ["Full Name", "Email"],
            [["Jane Smith", "jane@example.org"]],
            "people",
        )
        self.assertIn("full name: Jane Smith", text)
        self.assertIn("Email: jane@example.org", text)

    def test_headerless_table_infers_typed_columns_and_preserves_first_row(self):
        text = engine.table_rows_to_labelled_text(
            ["Jane Smith", "jane@example.org", "1 Test Road", "NG7 2RD"],
            [
                ["Alex Brown", "alex@example.org", "2 Test Road", "NG7 2RD"],
                ["Sam Jones", "sam@example.org", "3 Test Road", "NG7 2RD"],
                ["Robin Green", "robin@example.org", "4 Test Road", "NG7 2RD"],
            ],
            "headerless.csv",
        )
        self.assertIn("TABLE_ROW headerless.csv #1", text)
        self.assertIn("full name: Jane Smith", text)
        self.assertIn("email: jane@example.org", text)
        self.assertIn("address1: 1 Test Road", text)
        self.assertIn("postcode: NG7 2RD", text)

    def test_headerless_person_table_infers_names_and_gender_only_with_context(self):
        text = engine.table_rows_to_labelled_text(
            ["male", "Jon", "Doe", "jon@example.org"],
            [
                ["female", "Jane", "Doe", "jane@example.org"],
                ["male", "Alex", "Smith", "alex@example.org"],
            ],
            "people_headerless.csv",
        )
        self.assertIn("gender/sex: male", text)
        self.assertIn("first name: Jon", text)
        self.assertIn("last name: Doe", text)
        self.assertIn("email: jon@example.org", text)
        self.assertIn("full name: Jon Doe", text)

        weak_text = engine.table_rows_to_labelled_text(
            ["male", "Jon", "Doe"],
            [
                ["female", "Jane", "Doe"],
                ["male", "Alex", "Smith"],
            ],
            "weak_headerless.csv",
        )
        self.assertEqual(weak_text, "")

    def test_header_inference_rejects_small_or_untyped_samples(self):
        self.assertEqual(engine.infer_table_headers([["alpha", "beta"], ["gamma", "delta"]]), [])


if __name__ == "__main__":
    unittest.main()
