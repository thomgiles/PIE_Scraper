import csv
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import test_support
from pii_regex_scanner import parse_args


class CliIntegrationTests(unittest.TestCase):
    def test_parse_args_defaults_and_boolean(self):
        args = parse_args(["--scan-images", "TRUE", "--max-findings-per-file", "0"])
        self.assertTrue(args.scan_images)
        self.assertEqual(args.max_findings_per_file, 0)

    def test_package_launcher_end_to_end(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            inputs = root / "inputs"
            outputs = root / "outputs"
            inputs.mkdir()
            (inputs / "one.txt").write_text("unknown@example.org\n", encoding="utf-8")
            people = root / "people.csv"
            people.write_text("ID,email\nK1,known@example.org\n", encoding="utf-8")
            command = [
                sys.executable, "-m", "pii_regex_scanner",
                "--root", str(inputs),
                "--output-dir", str(outputs),
                "--rules", str(test_support.PROJECT_DIR / "rules"),
                "--person-tables", str(people),
                "--workers", "1",
            ]
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(test_support.SRC_DIR)
            completed = subprocess.run(
                command, check=False, capture_output=True, text=True,
                cwd=test_support.PROJECT_DIR, env=environment,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
            with (outputs / "6.Reidentification" / "clusters_not_in_list_redacted.csv").open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["identity_anchor_basis"], "strong:Email")


if __name__ == "__main__":
    unittest.main()
