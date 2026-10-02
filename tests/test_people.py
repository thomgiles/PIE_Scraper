import csv
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path

import test_support  # noqa: F401
from pii_regex_scanner import engine


class PeopleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        engine.set_email_suffix("example.ac.uk")
        engine.load_identity_anchor_config(str(test_support.PROJECT_DIR / "rules"))
        engine.load_rules(str(test_support.PROJECT_DIR / "rules"))
        engine.load_table_column_rules(str(test_support.PROJECT_DIR / "rules"))

    def test_load_person_table_and_anchors(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "engine.csv"
            path.write_text("ID,First Name,Last Name,Email\nK1,Jane,Smith,jane@example.ac.uk\n", encoding="utf-8")
            loaded, anchors, headers = engine.load_person_table(path)
            self.assertIn("K1", loaded)
            self.assertIn("Email", headers)
            self.assertIn("K1", anchors[("Institutional Email", "jane@example.ac.uk")])
            self.assertIn("K1", anchors[("Name", "jane smith")])

    def test_person_key_and_unique_suffix(self):
        row = {"ID": "K1", "Email": "jane@example.org"}
        self.assertEqual(engine.person_key_for_row(row, 1), "K1")
        self.assertEqual(engine.make_unique_person_key("K1", {"K1": {}}), "K1#2")

    def test_linked_people_matching(self):
        anchors = defaultdict(lambda: defaultdict(set))
        engine.add_person_anchor(anchors, "K1", "Institutional Email", "jane@example.ac.uk", "Email")
        matched, types, fields = engine.linked_people_for_record(
            {"anchor_type": "Institutional Email", "anchor_value": "jane@example.ac.uk"}, anchors
        )
        self.assertEqual(matched, {"K1"})
        self.assertEqual(types, {"Institutional Email"})
        self.assertEqual(fields, {"Email"})

    def test_exposure_risk(self):
        self.assertEqual(engine.exposure_risk({"Institutional Email", "DOB"}), "high")
        self.assertEqual(engine.exposure_risk_score(set()), (0, "none"))
        self.assertEqual(engine.split_person_cell_values("a | b; c"), ["a", "b", "c"])

    def test_unknown_outputs_include_unclustered_strong_email_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            person_table = root / "engine.csv"
            person_table.write_text("ID,Email\nK1,known@example.ac.uk\n", encoding="utf-8")

            clusters = root / "person_clusters.csv"
            with clusters.open("w", newline="", encoding="utf-8") as handle:
                csv.DictWriter(handle, fieldnames=engine.PERSON_CLUSTER_FIELDS).writeheader()

            linked = root / "linked.csv"
            linked_row = {field: "" for field in engine.LINKED_EVIDENCE_FIELDS}
            linked_row.update({
                "linked_evidence_key": "Institutional Email:unknown@example.ac.uk",
                "file_path": "unknown.txt",
                "file_name": "unknown.txt",
                "extension": "txt",
                "row_number": "1",
                "anchor_type": "Institutional Email",
                "anchor_value": "unknown@example.ac.uk",
                "evidence_types": "Institutional Email",
                "evidence_values": "Institutional Email=unknown@example.ac.uk",
                "risk_level": "medium",
                "cluster_eligible": "no",
                "cluster_exclusion_reason": "test exclusion",
            })
            with linked.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=engine.LINKED_EVIDENCE_FIELDS)
                writer.writeheader()
                writer.writerow(linked_row)

            evidence_dir = root / "evidence"
            evidence_dir.mkdir()
            finding = {field: "" for field in engine.FINDING_FIELDS}
            finding.update({
                "file_path": "unknown.txt",
                "file_name": "unknown.txt",
                "extension": "txt",
                "row_number": "1",
                "evidence_type": "Institutional Email",
                "matched_text": "unknown@example.ac.uk",
                "normalized_value": "unknown@example.ac.uk",
                "pattern_name": "contact_location_email",
                "evidence_tier": "tier_1_strong_identifier",
            })
            with (evidence_dir / "institutional_email__contact_location_email.csv").open(
                "w", newline="", encoding="utf-8"
            ) as handle:
                writer = csv.DictWriter(handle, fieldnames=engine.FINDING_FIELDS)
                writer.writeheader()
                writer.writerow(finding)

            output_names = [
                "known.csv", "known_risk.csv", "missing.csv", "unknown_clusters.csv",
                "unknown.csv", "unknown_risk.csv", "known_evidence", "unknown_evidence",
            ]
            outputs = [root / name for name in output_names]
            engine.build_known_person_outputs_from_clusters(
                person_table, clusters, linked, evidence_dir, *outputs, {}, 0, True, 0, 1, 1
            )

            with outputs[4].open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["identity_anchor_basis"], "strong:Institutional Email")
            self.assertEqual(rows[0]["evidence_types"], "Institutional Email")
            self.assertEqual(rows[0]["matched_evidence_count"], "1")

            evidence_files = list(outputs[7].glob("*.csv"))
            self.assertEqual(len(evidence_files), 1)
            with evidence_files[0].open(newline="", encoding="utf-8") as handle:
                evidence_rows = list(csv.DictReader(handle))
            self.assertTrue(any(
                row["source_scope"] == "unclustered"
                and row["anchor_type"] == "Institutional Email"
                and row["anchor_value"] == "unknown@example.ac.uk"
                for row in evidence_rows
            ))


if __name__ == "__main__":
    unittest.main()
