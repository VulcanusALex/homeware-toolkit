"""Minimal validation for the HACS custom component manifest."""

from __future__ import annotations

import json
import unittest
from pathlib import Path


class HacsManifestTest(unittest.TestCase):
    def test_manifest_is_valid_json(self):
        manifest = Path(__file__).resolve().parent.parent / (
            "custom_components/homeware_toolkit/manifest.json")
        data = json.loads(manifest.read_text())
        self.assertEqual(data["domain"], "homeware_toolkit")
        self.assertTrue(data["config_flow"])
        self.assertIn("requirements", data)


if __name__ == "__main__":
    unittest.main()
