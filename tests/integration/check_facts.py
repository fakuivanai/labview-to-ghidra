#!/usr/bin/env python3
"""Check opaque native extents and signed/wide enums through a Ghidra round trip."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
from labview_vi_to_ghidra.vi_facts import extract
from labview_vi_to_ghidra.toolchain import (
    GHIDRA_SCRIPT_DIRECTORY,
    acquire_job,
    ghidra_backend,
    snapshot_ghidra_scripts,
)


def fixtures(output):
    root = ET.Element("RSRC")
    version = ET.SubElement(
        ET.SubElement(ET.SubElement(root, "LVSR"), "Section"), "Version"
    )
    version.attrib.update(Major="13", Minor="0", Bugfix="0")
    general = ET.SubElement(
        ET.SubElement(ET.SubElement(root, "VICD"), "Section"), "General"
    )
    general.attrib.update(CodeID="i386", Version="0x13008000")
    section = ET.SubElement(ET.SubElement(root, "VCTP"), "Section")
    ET.SubElement(
        section, "TypeDesc", Type="MeasureData", Flavor="TimeStamp", Label="Timestamp"
    )
    ET.SubElement(section, "TypeDesc", Type="NumFloatExt", Label="Extended")
    ET.SubElement(section, "TypeDesc", Type="NumUInt8", Label="Flag")
    ET.SubElement(section, "TypeDesc", Type="NumInt16", Label="Signed choice")
    ET.SubElement(section, "TypeDesc", Type="NumUInt32", Label="Wide choice")
    top = ET.SubElement(section, "TopLevel")
    for index in range(5):
        ET.SubElement(top, "TypeDesc", Index=str(100 + index), FlatTypeID=str(index))
    tm = ET.SubElement(ET.SubElement(root, "TM80"), "Section", IndexShift="100")
    for index in range(3):
        ET.SubElement(tm, "Client", Index=str(index))
    ET.SubElement(
        ET.SubElement(ET.SubElement(root, "DTHP"), "Section"),
        "TypeDescSlice",
        IndexShift="100",
    )
    fill = ET.SubElement(
        ET.SubElement(ET.SubElement(root, "DFDS"), "Section"), "DataFill", TypeID="100"
    )
    fill.append(ET.Comment("Table of Front Panel DCOs"))
    block = ET.SubElement(fill, "RepeatedBlock")
    for index, offset, size in [(0, 0, 16), (1, 16, 10), (2, 26, 1)]:
        row = ET.SubElement(block, "Cluster")
        for key, value in {
            "dcoIndex": index,
            "flagTMI": index,
            "flagDSO": offset,
            "defaultDataOffset": offset,
            "transferDataOffset": offset,
            "dsSz": size,
        }.items():
            row.append(ET.Comment(key))
            ET.SubElement(row, "I32").text = str(value)
    xml = output / "example.xml"
    ET.ElementTree(root).write(xml)
    panel = ET.Element("Panel")
    for uid, type_id, labels, values in [
        ("7", 4, ["Minus ten", "Zero", "Wide"], ["F6", "00", "0100"]),
        ("9", 5, ["Large", "Maximum"], ["00010000", "FFFFFFFF"]),
    ]:
        control = ET.SubElement(panel, "Control", {"class": "fPDCO", "uid": uid})
        ddo = ET.SubElement(control, "ddo")
        ET.SubElement(ddo, "typeDesc").text = f"TypeID({type_id})"
        sparse = ET.SubElement(ddo, "ringSparseValues")
        for value in values:
            ET.SubElement(sparse, "Value").text = value
        parts = ET.SubElement(ddo, "partsList")
        entry = ET.SubElement(parts, "SL__arrayElement", {"class": "multiLabel"})
        ET.SubElement(entry, "buf").text = f"({len(labels)})" + "".join(
            '"' + label + '"' for label in labels
        )
    panel_path = output / "panel.xml"
    ET.ElementTree(panel).write(panel_path)
    return xml, panel_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", help="Ghidra installation directory or flatpak")
    parser.add_argument(
        "--output", type=Path, required=True, help="new or empty output directory"
    )
    args = parser.parse_args()
    output = args.output.expanduser().resolve()
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        parser.error("Output must be new or empty")
    lock, limits = acquire_job()
    output.mkdir(parents=True, exist_ok=True)
    xml, panel = fixtures(output)
    code = b"\xc3" + b"\x90" * 63
    native = output / "native-code.bin"
    native.write_bytes(code)
    digest = hashlib.sha256(code).hexdigest()
    plan = {
        "base": 0x10000000,
        "code_size": len(code),
        "code_path": str(native),
        "patched_sha256": digest,
        "changes": [],
        "dispatchers": [],
    }
    (output / "plan.json").write_text(json.dumps(plan, indent=2))
    facts = extract(xml, panel, output, plan)
    if facts["layout"]["status"] != "anchored_profile":
        raise RuntimeError("Synthetic layout was not anchored")
    if [ring["status"] for ring in facts["rings"]] != ["recorded", "recorded"]:
        raise RuntimeError("Synthetic rings were not decoded")
    if [[entry["value"] for entry in ring["entries"]] for ring in facts["rings"]] != [
        [-10, 0, 256],
        [65536, 4294967295],
    ]:
        raise RuntimeError("Synthetic ring values changed")
    scripts = output / "scripts"
    names = snapshot_ghidra_scripts(
        scripts, [GHIDRA_SCRIPT_DIRECTORY / "ImportVIFacts.java"]
    )
    name = names["ImportVIFacts"]
    head, environment, version = ghidra_backend(args.ghidra, output)
    (output / "ghidra-version.txt").write_text(version)
    projects = output / "projects"
    projects.mkdir()
    flags = ["-max-cpu", "1", "-noanalysis", "-scriptPath", str(scripts)]
    commands = []

    def run(stage, command):
        commands.append({"stage": stage, "argv": command})
        with (output / (stage + ".log")).open("w") as log:
            result = subprocess.run(
                command, env=environment, stdout=log, stderr=subprocess.STDOUT
            )
        text = (output / (stage + ".log")).read_text(errors="replace")
        if result.returncode or "VI_FACTS_OK" not in text:
            raise RuntimeError(stage + " failed; see " + str(output / (stage + ".log")))

    try:
        run(
            "apply",
            head
            + [
                str(projects),
                "Facts",
                "-import",
                str(native),
                "-loader",
                "BinaryLoader",
                "-loader-baseAddr",
                hex(plan["base"]),
                "-processor",
                "x86:LE:32:default",
                "-cspec",
                "windows",
            ]
            + flags
            + ["-postScript", name, str(output / "facts.json")],
        )
        run(
            "export",
            head
            + [str(projects), "Facts", "-process", native.name]
            + flags
            + ["-postScript", name, str(output / "facts.json"), "export"],
        )
        run(
            "roundtrip",
            head
            + [str(projects), "FactsRoundTrip", "-import", str(output / "analysis.gzf")]
            + flags
            + ["-postScript", name, str(output / "facts.json"), "roundtrip"],
        )
        audits = [
            json.loads((output / ("facts-audit-" + mode + ".json")).read_text())
            for mode in ["apply", "export", "roundtrip"]
        ]
        for key in audits[0]:
            if key != "mode" and any(
                audit[key] != audits[0][key] for audit in audits[1:]
            ):
                raise RuntimeError("Round-trip audit mismatch: " + key)
        result = {
            "status": "passed",
            "opaque_native_extents": [16, 10],
            "signed_and_wide_enum_values": [[-10, 0, 256], [65536, 4294967295]],
            "roundtrip_audit": audits[-1],
            "resource_limits": limits,
        }
        (output / "result.json").write_text(json.dumps(result, indent=2))
        print(json.dumps(result, indent=2))
    except Exception as error:
        (output / "FAILED.json").write_text(json.dumps({"error": str(error)}, indent=2))
        raise
    finally:
        (output / "commands.json").write_text(json.dumps(commands, indent=2))
        lock.close()


if __name__ == "__main__":
    main()
