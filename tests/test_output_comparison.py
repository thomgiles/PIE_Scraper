import csv
import importlib.util
import tempfile
import unittest
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parents[1]
COMPARISON_PATH = PROJECT_DIR / "reports" / "Compare_pii_regex_outputs.v0.1.py"
SPEC = importlib.util.spec_from_file_location("pii_regex_output_comparison", COMPARISON_PATH)
comparison = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(comparison)


def write_csv(path, fieldnames, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


class UnknownPersonComparisonTests(unittest.TestCase):
    def make_output(self, folder, cluster_id, merge_key, summary_only=True):
        write_csv(
            folder / "person_clusters.csv",
            ["person_cluster_id", "cluster_merge_keys", "anchor_values", "evidence_values"],
            [
                {
                    "person_cluster_id": cluster_id,
                    "cluster_merge_keys": merge_key,
                    "anchor_values": "",
                    "evidence_values": "",
                }
            ],
        )
        write_csv(
            folder / "unknown_person_in_dataset.csv",
            ["unknown_person_key", "person_cluster_id", "identity_anchor_basis"],
            [
                {
                    "unknown_person_key": cluster_id,
                    "person_cluster_id": cluster_id,
                    "identity_anchor_basis": "strong:Email",
                }
            ],
        )
        if not summary_only:
            write_csv(
                folder / "unknown_person_in_dataset_clusters.csv",
                ["unknown_person_key", "person_cluster_id", "cluster_merge_keys"],
                [
                    {
                        "unknown_person_key": cluster_id,
                        "person_cluster_id": cluster_id,
                        "cluster_merge_keys": merge_key,
                    }
                ],
            )

    def test_non_disclosive_summary_resolves_through_person_clusters(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            left = root / "left"
            right = root / "right"
            left.mkdir()
            right.mkdir()
            merge_key = "strong:Email:unknown@example.com"
            self.make_output(left, "person_cluster_00000001", merge_key)
            self.make_output(right, "person_cluster_00000999", merge_key)

            left_clusters = comparison.load_clusters(left, progress_every=0)
            right_clusters = comparison.load_clusters(right, progress_every=0)
            left_unknown = comparison.load_unknown_people(left, left_clusters, progress_every=0)
            right_unknown = comparison.load_unknown_people(right, right_clusters, progress_every=0)

            self.assertEqual(left_unknown["source_file"], "unknown_person_in_dataset.csv")
            self.assertEqual(left_unknown["resolved_from_clusters"], 1)
            self.assertEqual(left_unknown["rows_without_keys"], 0)
            self.assertEqual(comparison.matched_unknown_count(left_unknown, right_unknown), 1)
            self.assertEqual(comparison.matched_unknown_count(right_unknown, left_unknown), 1)

    def test_cluster_audit_is_preferred_when_available(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            self.make_output(
                output,
                "person_cluster_00000001",
                "strong:Email:unknown@example.com",
                summary_only=False,
            )
            clusters = comparison.load_clusters(output, progress_every=0)
            unknown = comparison.load_unknown_people(output, clusters, progress_every=0)

            self.assertEqual(unknown["source_file"], "unknown_person_in_dataset_clusters.csv")
            self.assertEqual(unknown["resolved_from_clusters"], 0)
            self.assertEqual(unknown["rows_without_keys"], 0)


if __name__ == "__main__":
    unittest.main()
