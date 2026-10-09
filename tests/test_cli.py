"""Public input and output refusal checks for the installed entry point."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class InputTests(unittest.TestCase):
    def run_converter(self, source, output, runtime, runtime_map, cache):
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "labview_vi_to_ghidra",
                str(source),
                "--output",
                str(output),
                "--runtime",
                str(runtime),
                "--runtime-map",
                str(runtime_map),
                "--prepare-only",
            ],
            env=dict(os.environ, XDG_CACHE_HOME=str(cache)),
            capture_output=True,
            text=True,
        )

    def test_non_vi_rejected_without_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / "input.bin"
            source.write_bytes(b"MZ not a VI")
            output = directory / "output"
            result = self.run_converter(
                source, output, directory / "runtime", directory / "map", directory
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Input must be an extracted RSRC VI", result.stderr)
            self.assertFalse(output.exists())

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / "example.vi"
            source.write_bytes(b"RSRC example")
            output = directory / "output"
            output.mkdir()
            sentinel = output / "keep.txt"
            sentinel.write_text("keep")
            result = self.run_converter(
                source, output, directory / "runtime", directory / "map", directory
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Output is not empty", result.stderr)
            self.assertEqual(sentinel.read_text(), "keep")
            self.assertEqual(list(output.iterdir()), [sentinel])

    def test_wrong_runtime_build_rejected_before_decoding(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            source = directory / "example.vi"
            source.write_bytes(b"RSRC example")
            runtime = directory / "runtime.dll"
            runtime.write_bytes(b"Unsupported runtime")
            output = directory / "output"
            result = self.run_converter(
                source, output, runtime, directory / "map", directory
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Unsupported runtime build", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
