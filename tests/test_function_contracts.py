import inspect
import ast
import unittest
from pathlib import Path

import test_support  # noqa: F401
from pii_regex_scanner import engine, pipeline


class FunctionContractTests(unittest.TestCase):
    def test_core_and_pipeline_functions_have_signatures(self):
        for module in (engine, pipeline):
            for name, function in inspect.getmembers(module, inspect.isfunction):
                if function.__module__ != module.__name__:
                    continue
                with self.subTest(module=module.__name__, function=name):
                    self.assertIsInstance(inspect.signature(function), inspect.Signature)

    def test_src_component_modules_contain_real_implementations(self):
        src_dir = Path(engine.__file__).resolve().parent
        component_names = {
            "validation.py",
            "rules.py",
            "extraction.py",
            "scanning.py",
            "summaries.py",
            "clustering.py",
            "people.py",
            "runtime.py",
        }
        present = {path.name for path in src_dir.glob("*.py")}
        self.assertTrue(component_names <= present)

        for name in component_names:
            with self.subTest(component=name):
                path = src_dir / name
                tree = ast.parse(path.read_text(encoding="utf-8"))
                implementation_nodes = [
                    node for node in tree.body
                    if isinstance(node, (ast.FunctionDef, ast.ClassDef))
                ]
                self.assertGreaterEqual(len(implementation_nodes), 3)


if __name__ == "__main__":
    unittest.main()
