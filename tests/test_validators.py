import unittest
from datetime import date

import test_support  # noqa: F401
from pii_regex_scanner import engine


class ValidatorTests(unittest.TestCase):
    def test_numeric_validators(self):
        self.assertEqual(engine.digits_only("12-34 x"), "1234")
        self.assertTrue(engine.valid_luhn("4111 1111 1111 1111"))
        self.assertFalse(engine.valid_luhn("4111 1111 1111 1112"))
        self.assertFalse(engine.valid_luhn("1.81156E+12"))
        self.assertFalse(engine.valid_luhn("044 07562221625"))
        self.assertTrue(engine.valid_nhs_number("943 476 5919"))
        self.assertFalse(engine.valid_nhs_number("111 111 1111"))
        self.assertTrue(engine.valid_ucas_personal_id("123-456-7890"))
        self.assertTrue(engine.valid_bare_8_digit_id("58273941"))
        self.assertFalse(engine.valid_bare_8_digit_id("12345678"))

    def test_contextual_and_student_validators(self):
        today = date.today()
        self.assertTrue(engine.date_within_last_100_years(today.year - 20, 1, 1))
        self.assertFalse(engine.date_within_last_100_years(today.year - 101, 1, 1))
        self.assertTrue(engine.valid_contextual_date(f"{today.year - 20}-01-02"))
        self.assertFalse(engine.valid_contextual_date("2024-02-31"))
        self.assertTrue(engine.valid_cas_number("E08X43SL987T37"))
        self.assertFalse(engine.valid_cas_number("e08x43sl987t37"))
        self.assertTrue(engine.valid_husid_entry_year(f"{str(today.year)[-2:]}12345678901"))
        self.assertFalse(engine.valid_husid_entry_year("1.41156E+12"))
        self.assertFalse(engine.valid_saturn_id("4316257 | 4316882"))

    def test_contact_and_identity_validators(self):
        self.assertTrue(engine.valid_uk_postcode("NG7 2RD"))
        self.assertEqual(engine.canonical_uk_postcode("ng72rd"), "NG7 2RD")
        self.assertFalse(engine.valid_uk_postcode("NOT A CODE"))
        self.assertTrue(engine.valid_uk_phone_rough("+44 7700 900123"))
        self.assertFalse(engine.valid_uk_phone_rough("11111111111"))
        self.assertTrue(engine.valid_passport_like("123456789"))
        self.assertFalse(engine.valid_passport_like("PENDING"))
        self.assertTrue(engine.valid_orcid("0000-0002-1825-0097"))
        self.assertFalse(engine.valid_orcid("0000-0002-1825-0098"))
        self.assertTrue(engine.valid_china_national_id("11010519491231002X"))
        self.assertFalse(engine.valid_uk_driving_licence("INVALID"))
        self.assertTrue(engine.valid_uk_national_insurance_number("AB 12 34 56 C"))
        self.assertFalse(engine.valid_uk_national_insurance_number("AA999999A"))
        self.assertFalse(engine.valid_uk_national_insurance_number("BG123456A"))
        self.assertTrue(engine.valid_identity_document_file_reference("Passport_of_Rui_SHEN.pdf"))
        self.assertFalse(engine.valid_identity_document_file_reference("passport_photo.jpg"))
        self.assertFalse(engine.valid_identity_document_file_reference("jane@example.org_Passport_G3603766.pdf"))

    def test_sensitive_table_value_and_header_guards(self):
        self.assertFalse(engine.valid_citizenship_country_value("EUROPE"))
        self.assertTrue(engine.valid_citizenship_country_value("China"))
        self.assertEqual(engine.normalize_citizenship_country_value("CHN"), "China")
        self.assertEqual(engine.normalize_value("Citizenship Country", "CHN"), "China")
        self.assertFalse(engine.valid_religion_value("An Int"))
        self.assertTrue(engine.valid_religion_value("No religion"))
        self.assertTrue(engine.header_label_looks_like_free_text(
            "'Religion should never impose restrictions on medical research.' Do you agree?"
        ))
        self.assertFalse(engine.header_label_looks_like_free_text("Religion"))

    def test_name_and_address_normalisation(self):
        self.assertEqual(engine.clean_name_value(" Dr. Smith, Jane "), "Jane Smith")
        self.assertEqual(engine.normalize_name_value("Jane  O'Neil"), "jane o'neil")
        self.assertTrue(engine.valid_name_value("Jane Smith"))
        self.assertFalse(engine.valid_name_value("Jane"))
        self.assertEqual(engine.normalize_address_value("1 Test Rd, NG7 2RD"), "1TESTRDNG72RD")
        self.assertEqual(engine.normalize_email_suffix("@Example.ac.uk"), "example.ac.uk")
        self.assertEqual(
            engine.normalize_email_suffixes(["@Example.ac.uk, nottingham.*", "student.nottingham.ac.uk"]),
            ("example.ac.uk", "nottingham.*", "student.nottingham.ac.uk"),
        )


if __name__ == "__main__":
    unittest.main()
