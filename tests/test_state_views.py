"""Small dispatcher selection and saved Ghidra installation regressions."""
from pathlib import Path
import os
import tempfile
import unittest
from unittest import mock

from labview_vi_to_ghidra.vi_state_views import select_states
from labview_vi_to_ghidra.toolchain import ghidra_backend, resolve_ghidra_installation


class StateSelectionTests(unittest.TestCase):
    def test_sample_is_valid_for_small_dispatcher_tables(self):
        for count in (1, 2, 3, 5, 11, 21):
            with self.subTest(count=count):
                selected = select_states(count)
                self.assertTrue(selected)
                self.assertTrue(all(0 <= index < count for index in selected))
                self.assertIn(0, selected)
                self.assertIn(count - 1, selected)
        self.assertEqual(select_states(3), [0, 1, 2])

    def test_all_and_explicit_indices(self):
        self.assertEqual(select_states(3, "all"), [0, 1, 2])
        self.assertEqual(select_states(3, "2,0"), [2, 0])
        for count, selection in ((0, "sample"), (3, "3"), (3, "-1"), (3, "")):
            with self.subTest(count=count, selection=selection), self.assertRaises(ValueError):
                select_states(count, selection)


class SavedBackendTests(unittest.TestCase):
    def test_relative_flag_and_environment_survive_working_directory_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            home = directory / "ghidra"
            (home / "support").mkdir(parents=True)
            launcher = home / "support/analyzeHeadless"
            launcher.write_text("test launcher")
            (home / "Ghidra/Processors/x86/data/languages").mkdir(parents=True)
            (home / "Ghidra/application.properties").write_text("application.version=test-version\n")
            (home / "Ghidra/Processors/x86/data/languages/x86.ldefs").write_text("test-language\n")
            output = directory / "output"
            output.mkdir()
            other = directory / "other"
            other.mkdir()
            before = Path.cwd()
            try:
                for explicit in ("ghidra", None):
                    with self.subTest(explicit=explicit), mock.patch.dict(os.environ, {"GHIDRA_HOME": "ghidra"}):
                        os.chdir(directory)
                        saved = resolve_ghidra_installation(explicit)
                        self.assertEqual(saved, str(home))
                        os.chdir(other)
                        command, env, version = ghidra_backend(saved, output)
                        self.assertEqual(command, [str(launcher)])
                        self.assertIn("test-version", version)
                        self.assertIn("test-language", version)
            finally:
                os.chdir(before)

    def test_path_default_is_saved_and_prepare_only_can_skip_missing_backend(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("shutil.which", return_value="/opt/ghidra/support/analyzeHeadless"):
            self.assertEqual(resolve_ghidra_installation(), "/opt/ghidra")
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("shutil.which", return_value=None):
            self.assertIsNone(resolve_ghidra_installation(required=False))
            with self.assertRaises(ValueError):
                resolve_ghidra_installation()
        self.assertEqual(resolve_ghidra_installation("flatpak"), "flatpak")


if __name__ == "__main__":
    unittest.main()
