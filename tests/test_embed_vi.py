"""Original-VI archive selection using independently generated input bytes."""

from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from labview_vi_to_ghidra import make_ghidra_bundle as bundle
from labview_vi_to_ghidra import vi_to_ghidra as converter


XML = """<RSRC>
<LVSR><Section><Version Major="13" Minor="0" Bugfix="0"/></Section></LVSR>
<VICD><Section><General CodeID="i386" Version="0x13008000"/>
<Code File="native.bin" InitProcOffset="40"/><Patches/></Section></VICD>
</RSRC>"""


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decoded_files(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    xml = directory / "example.xml"
    xml.write_text(XML)
    panel = directory / "example_FPH.xml"
    panel.write_text('<Panel><Control name="Example"/></Panel>')
    code = directory / "native.bin"
    code.write_bytes(bytes(range(64)))
    code.with_suffix(".entrypoints.json").write_text("[]")
    return xml, panel, code


class EmbedVITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.source = self.directory / "example.vi"
        self.vi_bytes = b"RSRC independently generated original VI archive fixture"
        self.source.write_bytes(self.vi_bytes)
        self.runtime = self.directory / "runtime.dll"
        self.runtime.write_bytes(b"independently generated runtime fixture")
        self.runtime_map = self.directory / "runtime-map.json"
        self.runtime_map.write_text("{}")
        self.runtime_info = dict(
            modules=[],
            runtime=str(self.runtime),
            sha256=digest(self.runtime.read_bytes()),
            image_base=0x30000000,
        )
        self.xml, self.panel, self.code = decoded_files(self.directory / "decoded")

    def build_plan(self, output_name, **options):
        with (
            patch.object(bundle, "validate_runtime", return_value=self.runtime_info),
            redirect_stdout(io.StringIO()),
        ):
            return bundle.build(
                self.source.name,
                xml_path=self.xml,
                vi_path=self.source,
                output_dir=self.directory / output_name,
                runtime=self.runtime,
                runtime_map=self.runtime_map,
                **options,
            )

    def test_default_excludes_vi_but_preserves_xml_and_source_hash(self):
        plan = self.build_plan("default")
        self.assertFalse(plan["original_vi_embedded"])
        self.assertEqual(plan["original_vi_sha256"], digest(self.vi_bytes))
        self.assertEqual(
            [resource["label"] for resource in plan["resources"]],
            ["VI_Metadata_XML", "FrontPanel_XML"],
        )
        self.assertEqual(
            [resource["address"] for resource in plan["resources"]],
            [0x50000000, 0x50100000],
        )
        for resource, path in zip(plan["resources"], [self.xml, self.panel]):
            data = path.read_bytes()
            self.assertEqual(resource["path"], str(path))
            self.assertEqual(resource["size"], len(data))
            self.assertEqual(resource["sha256"], digest(data))
            self.assertNotIn(self.vi_bytes, data)

    def test_explicit_embedding_restores_full_resource_order_and_bytes(self):
        default = self.build_plan("default")
        plan = self.build_plan("embedded", embed_vi=True)
        self.assertTrue(plan["original_vi_embedded"])
        self.assertEqual(plan["original_vi_sha256"], default["original_vi_sha256"])
        self.assertEqual(
            [resource["label"] for resource in plan["resources"]],
            ["Original_VI", "VI_Metadata_XML", "FrontPanel_XML"],
        )
        self.assertEqual(
            [resource["address"] for resource in plan["resources"]],
            [0x50000000, 0x50100000, 0x50200000],
        )
        original = plan["resources"][0]
        self.assertEqual(Path(original["path"]).read_bytes(), self.vi_bytes)
        self.assertEqual(original["size"], len(self.vi_bytes))
        self.assertEqual(original["sha256"], digest(self.vi_bytes))
        for key in [
            "source_sha256",
            "patched_sha256",
            "changes",
            "entries",
            "unresolved",
        ]:
            self.assertEqual(plan[key], default[key])
        for resource, previous in zip(plan["resources"][1:], default["resources"]):
            self.assertEqual(
                {key: value for key, value in resource.items() if key != "address"},
                {key: value for key, value in previous.items() if key != "address"},
            )

    def test_prepare_only_cli_reports_default_and_explicit_embedding(self):
        # The decoder and runtime verifier are replaced with generated fixtures;
        # the CLI and relocation/resource planner run normally in both modes.
        def decode(command, *, cwd, **kwargs):
            self.assertEqual(command[1:3], ["-m", "pylabview.readRSRC"])
            decoded_files(cwd)
            return SimpleNamespace(returncode=0)

        for embed_vi in [False, True]:
            with self.subTest(embed_vi=embed_vi):
                output = self.directory / (
                    "cli-embedded" if embed_vi else "cli-default"
                )
                arguments = [
                    "vi-to-ghidra",
                    str(self.source),
                    "--output",
                    str(output),
                    "--runtime",
                    str(self.runtime),
                    "--runtime-map",
                    str(self.runtime_map),
                    "--prepare-only",
                ]
                if embed_vi:
                    arguments.append("--embed-vi")
                lock = Mock()
                metadata = dict(records=[], fields=[], dcos=[], limitations=[])
                facts = dict(
                    layout=dict(status="synthetic", reasons=[]), limitations=[]
                )
                with (
                    patch.object(sys, "argv", arguments),
                    patch.object(
                        converter, "validate_runtime", return_value=self.runtime_info
                    ),
                    patch.object(
                        bundle, "validate_runtime", return_value=self.runtime_info
                    ),
                    patch.object(converter, "acquire_job", return_value=(lock, {})),
                    patch.object(
                        converter.subprocess, "run", side_effect=decode
                    ) as process,
                    patch.object(converter, "restore_entry"),
                    patch.object(converter, "recognize"),
                    patch.object(converter, "recognize_dispatchers", return_value=[]),
                    patch.object(
                        converter, "resolve_ghidra_installation", return_value=None
                    ),
                    patch.object(converter, "extract", return_value=metadata),
                    patch.object(converter, "extract_facts", return_value=facts),
                    redirect_stdout(io.StringIO()),
                ):
                    converter.main()
                result = json.loads((output / "result.json").read_text())
                plan = json.loads((output / "plan.json").read_text())
                self.assertEqual(result["mode"], "prepare-only")
                self.assertIs(result["original_vi_embedded"], embed_vi)
                self.assertIs(plan["original_vi_embedded"], embed_vi)
                self.assertEqual(result["source_sha256"], digest(self.vi_bytes))
                self.assertEqual(plan["original_vi_sha256"], result["source_sha256"])
                labels = [resource["label"] for resource in plan["resources"]]
                self.assertEqual("Original_VI" in labels, embed_vi)
                self.assertIn("VI_Metadata_XML", labels)
                self.assertIn("FrontPanel_XML", labels)
                self.assertFalse((output / "FAILED.json").exists())
                self.assertFalse((output / "project").exists())
                process.assert_called_once()
                lock.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
