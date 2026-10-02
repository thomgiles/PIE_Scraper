import unittest

import test_support  # noqa: F401
from pii_regex_scanner import engine


class ClassBehaviorTests(unittest.TestCase):
    def test_extracted_text_dataclass(self):
        extracted = engine.ExtractedText("hello", "plain_text")
        self.assertEqual(extracted.text, "hello")
        self.assertEqual(extracted.extraction_method, "plain_text")

    def test_union_find(self):
        union = engine.UnionFind()
        indexes = [union.add() for _ in range(3)]
        union.union(indexes[0], indexes[1])
        self.assertEqual(union.find(indexes[0]), union.find(indexes[1]))
        self.assertNotEqual(union.find(indexes[0]), union.find(indexes[2]))

if __name__ == "__main__":
    unittest.main()
