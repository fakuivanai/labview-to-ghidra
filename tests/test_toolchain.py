"""Portable installation selection and exact language-version capture."""

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from labview_vi_to_ghidra.toolchain import ghidra_backend


class BackendTests(unittest.TestCase):
    def test_normal_installation_uses_its_own_launcher_and_definitions(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            home = directory / "ghidra"
            launcher = home / "support/analyzeHeadless"
            launcher.parent.mkdir(parents=True)
            launcher.write_text("synthetic launcher")
            properties = home / "Ghidra/application.properties"
            properties.parent.mkdir(parents=True)
            properties.write_text("application.version=12.1.3\n")
            definitions = home / "Ghidra/Processors/x86/data/languages/x86.ldefs"
            definitions.parent.mkdir(parents=True)
            definitions.write_text('<language version="4.8"/>')
            output = directory / "out"
            output.mkdir()
            with patch.dict(os.environ, GHIDRA_HOME=str(home)):
                command, environment, versions = ghidra_backend(None, output)
            self.assertEqual(command, [str(launcher)])
            self.assertIn("application.version=12.1.3", versions)
            self.assertIn('language version="4.8"', versions)
            self.assertIn("ActiveProcessorCount=1", environment["_JAVA_OPTIONS"])
            self.assertIn(str(output / ".ghidra-tmp"), environment["JAVA_TOOL_OPTIONS"])

    def test_missing_headless_launcher_reports_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "headless launcher not found"):
                ghidra_backend(directory, directory)


if __name__ == "__main__":
    unittest.main()
