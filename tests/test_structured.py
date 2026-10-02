import json
import tempfile
import unittest
from pathlib import Path

import test_support  # noqa: F401
from pii_regex_scanner import engine


class StructuredTests(unittest.TestCase):
    def test_scalar_and_path_helpers(self):
        self.assertTrue(engine.structured_is_scalar("x"))
        self.assertFalse(engine.structured_is_scalar({"x": 1}))
        self.assertEqual(engine.structured_humanise_token("first_name"), "first name")
        self.assertEqual(engine.structured_scalar_text(True), "true")
        self.assertIn("student", engine.structured_path_text(("students", 0)))

    def test_record_inference(self):
        data = {
            "students": [
                {"first_name": "Jane", "last_name": "Smith", "email": "jane@example.org"},
                {"first_name": "John", "last_name": "Jones", "email": "john@example.org"},
            ]
        }
        extracted = engine.structured_data_to_labelled_text(data, "json")
        self.assertIn("jane@example.org", extracted)
        self.assertIn("john@example.org", extracted)
        self.assertIn("full name", extracted.lower())

    def test_json_and_jsonl_extractors(self):
        with tempfile.TemporaryDirectory() as folder:
            json_path = Path(folder) / "one.json"
            json_path.write_text(json.dumps({"person": {"email": "one@example.org", "phone": "07123456789"}}))
            self.assertIn("one@example.org", engine.extract_json_structured(json_path).text)
            jsonl_path = Path(folder) / "many.jsonl"
            jsonl_path.write_text('{"email":"a@example.org","phone":"07123456789"}\n{"email":"b@example.org","phone":"07987654321"}\n')
            text = engine.extract_jsonl_structured(jsonl_path).text
            self.assertIn("a@example.org", text)
            self.assertIn("b@example.org", text)


if __name__ == "__main__":
    unittest.main()
