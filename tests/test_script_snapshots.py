"""Byte-preserving Java staging and self-contained source snapshot replay."""

import hashlib
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch

from labview_vi_to_ghidra.toolchain import (
    GHIDRA_SCRIPT_DIRECTORY,
    snapshot_ghidra_scripts,
    snapshot_hashes,
)
from labview_vi_to_ghidra.vi_state_views import snapshot_state_view_sources
from labview_vi_to_ghidra.vi_to_ghidra import snapshot_converter_sources


def load_standalone(script):
    """Load a retained runner using only its adjacent modules for local imports."""
    with patch.dict(sys.modules):
        for name in (
            "toolchain",
            "make_ghidra_bundle",
            "vi_dispatch",
            "vi_metadata",
            "vi_facts",
        ):
            sys.modules.pop(name, None)
        with patch.object(sys, "path", [str(script.parent), *sys.path]):
            return runpy.run_path(str(script), run_name="retained_runner")


class ScriptStagingTests(unittest.TestCase):
    def test_original_bytes_and_comments_survive_class_renaming(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "Example.java"
            original = (
                b"// public class Example is mentioned in this comment\r\n"
                b"public\tclass\tExample extends GhidraScript {\r\n"
                b"    // retained non-ASCII bytes: \xc3\xa9\r\n}\r\n"
            )
            source.write_bytes(original)
            destination = directory / "snapshot/ghidra"
            names = snapshot_ghidra_scripts(destination, [source])
            renamed = "Example_" + hashlib.sha256(original).hexdigest()[:12]
            self.assertEqual(names, {"Example": renamed + ".java"})
            self.assertEqual((destination / "Example.java").read_bytes(), original)
            self.assertEqual(
                (destination / names["Example"]).read_bytes(),
                original.replace(
                    b"\tExample extends", b"\t" + renamed.encode() + b" extends", 1
                ),
            )
            second = directory / "second"
            self.assertEqual(snapshot_ghidra_scripts(second, [source]), names)
            self.assertEqual(
                (second / names["Example"]).read_bytes(),
                (destination / names["Example"]).read_bytes(),
            )

    def test_malformed_declarations_are_rejected_before_staging(self):
        invalid = [
            b"class Example {}",
            b"public class Other {}",
            b"public class Example {}\npublic class Other {}",
            b"public class Example {}\npublic class Example {}",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "Example.java"
            for index, data in enumerate(invalid):
                with self.subTest(data=data):
                    source.write_bytes(data)
                    destination = directory / str(index)
                    with self.assertRaisesRegex(
                        ValueError, "exactly one matching public class"
                    ):
                        snapshot_ghidra_scripts(destination, [source])
                    self.assertFalse(destination.exists())

    def test_duplicate_class_names_are_rejected_before_staging(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            paths = [
                directory / "first/Example.java",
                directory / "second/Example.java",
            ]
            for source in paths:
                source.parent.mkdir()
                source.write_bytes(b"public class Example {}\n")
            destination = directory / "snapshot"
            with self.assertRaisesRegex(ValueError, "Duplicate Ghidra script class"):
                snapshot_ghidra_scripts(destination, paths)
            self.assertFalse(destination.exists())

    def test_recursive_hashes_include_original_and_renamed_java(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "Example.java"
            source.write_bytes(b"public class Example {}\n")
            snapshot = directory / "snapshot"
            snapshot_ghidra_scripts(snapshot / "ghidra", [source])
            (snapshot / "runner.py").write_bytes(b"# retained runner\n")
            hashes = snapshot_hashes(snapshot)
            self.assertEqual(len(hashes), 3)
            for path in snapshot.rglob("*"):
                if path.is_file():
                    self.assertEqual(
                        hashes[str(path)], hashlib.sha256(path.read_bytes()).hexdigest()
                    )


class SnapshotReplayTests(unittest.TestCase):
    def assert_original_scripts(self, snapshot, names):
        for original in names:
            filename = original if original.endswith(".java") else original + ".java"
            self.assertEqual(
                (snapshot / "ghidra" / filename).read_bytes(),
                (GHIDRA_SCRIPT_DIRECTORY / filename).read_bytes(),
            )

    def test_converter_snapshot_replays_from_its_retained_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            snapshot = directory / "reproduce"
            names = snapshot_converter_sources(snapshot)
            self.assertEqual(len(names), 5)
            self.assert_original_scripts(snapshot, names)
            retained = load_standalone(snapshot / "vi_to_ghidra.py")
            self.assertEqual(retained["GHIDRA_SCRIPT_DIRECTORY"], snapshot / "ghidra")
            replay = directory / "replayed"
            self.assertEqual(retained["snapshot_converter_sources"](replay), names)
            self.assert_original_scripts(replay, names)
            hashes = retained["snapshot_hashes"](replay)
            self.assertIn(str(replay / "ghidra/ImportLabVIEW13.java"), hashes)
            self.assertIn(
                str(replay / "ghidra" / names["ImportLabVIEW13.java"]), hashes
            )

    def test_state_snapshot_replays_with_optional_facts_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for include_facts in (False, True):
                with self.subTest(include_facts=include_facts):
                    snapshot = directory / (
                        "with-facts" if include_facts else "without-facts"
                    )
                    names = snapshot_state_view_sources(snapshot, include_facts)
                    self.assertEqual("ImportVIFacts" in names, include_facts)
                    self.assert_original_scripts(snapshot, names)
                    retained = load_standalone(snapshot / "vi_state_views.py")
                    self.assertEqual(
                        retained["GHIDRA_SCRIPT_DIRECTORY"], snapshot / "ghidra"
                    )
                    replay = directory / (
                        "replayed-with-facts"
                        if include_facts
                        else "replayed-without-facts"
                    )
                    self.assertEqual(
                        retained["snapshot_state_view_sources"](replay, include_facts),
                        names,
                    )
                    self.assert_original_scripts(replay, names)
                    hashes = retained["snapshot_hashes"](replay)
                    self.assertIn(str(replay / "ghidra/DecompileVIState.java"), hashes)
                    self.assertIn(
                        str(replay / "ghidra" / names["DecompileVIState"]), hashes
                    )


if __name__ == "__main__":
    unittest.main()
