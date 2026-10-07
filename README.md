# LabVIEW VI to Ghidra

Create a Ghidra project from one compiled LabVIEW VI. The tool decodes the VI,
restores supported relocations and callbacks, imports saved metadata, and
verifies the project after saving and exporting it as a portable GZF file.
Analysis is static. The input VI and LabVIEW runtime are read as files.

## Supported profile

- LabVIEW **13.0.0**, compiled **32-bit x86** code.
- VICD code version **0x13008000**.
- LabVIEW runtime **13.0.0.4046**, `lvrt.dll` SHA-256
  `2dcb88ecdec6bac366530cb28fc760060a13def9da72ffb7ed2d35985101e74e`.
- Python 3.10 or later on Linux; tested with Python 3.12.
- Ghidra 12.1.3 and 12.1.4 are the tested versions. Generated projects record
  the Ghidra version and processor-language definitions. Opening a project
  with an older processor-language version may require regeneration.

The input must be an individual RSRC VI with a supported compiled code section.
Other profiles are rejected. Obtain the supported runtime separately; this
repository contains no runtime binaries or example application files.

## Install

Install Ghidra and configure its Java runtime according to its own instructions.
Then install this package in a Python virtual environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

The decoder dependency is pinned to
[pylabview commit 5f20e23](https://github.com/mefistotelis/pylabview/tree/5f20e23de6a386021eb955c825cc43d221f09ff1).
Installation needs Git and access to that repository. Capstone, pefile and Pillow
versions are pinned in `pyproject.toml`.

## Convert a VI

First derive a callback map from the supported runtime. This inspects the DLL
without loading it:

```sh
vi-runtime-map --runtime /path/to/lvrt.dll --output /path/to/runtime-map.json
```

Then generate a project in a new or empty output directory:

```sh
vi-to-ghidra /path/to/example.vi \
  --runtime /path/to/lvrt.dll \
  --runtime-map /path/to/runtime-map.json \
  --ghidra /path/to/ghidra \
  --output /path/to/analysis
```

`GHIDRA_HOME` or `analyzeHeadless` on `PATH` can supply the Ghidra installation.
The existing Flatpak installation is an alternative with `--ghidra flatpak`.
`python -m labview_vi_to_ghidra` runs the same converter.

Open `project/VIAnalysis.gpr` together with its `.rep` directory, or import
`analysis.gzf` into another Ghidra project. Keep the whole output directory if
using the companion state-view command or reproducing the analysis.

`--prepare-only` decodes the VI and writes validated plans without starting
Ghidra. An unresolved relocation stops conversion by default.
`--allow-unresolved` explicitly permits a project with unresolved references
marked in its report and bookmarks. It does not resolve them.

A successful conversion writes `result.json`. A failed stage exits nonzero and
writes `FAILED.json` and stage logs. Existing nonempty outputs are refused.
Linux analysis runs at low priority on one available CPU core. Concurrent
converter/state-view jobs are refused while another job is running.

## Preserved information

The Ghidra project contains relocated native code, recognized callback names,
verified runtime targets and decompiler output where available. It also embeds
the original VI, decoded VI XML and available front-panel XML in read-only,
non-executable blocks at clearly marked artificial addresses.

Saved type descriptors, defaults, labels, control UIDs, connector numbers and
SubVI link slots are searchable metadata. Supported native data-space fields
are available in the Data Type Manager under `/LabVIEW/VI_metadata` and
`/LabVIEW/Recorded_facts`. Computed packed layouts require agreement with every
available independent DCO offset anchor. Handles and unknown internals remain
opaque.

Plans, relocation records, exact commands, source snapshots, SHA-256 manifests
and stage audits accompany the project. Reopening and GZF reimport verify
native bytes, original resource archives and their permissions, imported
metadata, types, annotations and supported dispatcher state tables.

Saved defaults are recorded values, not current runtime memory. Saved SubVI
slots identify recorded links, not proven runtime instances. The importer does
not invent native callback prototypes or initialize a runtime data space.

## Large state-machine VIs

The supported return-dispatch emitter receives original state-index labels,
table data, computed-branch recovery and an instruction-based RunProc body.
The decompiler can time out on the complete function. Export smaller views:

```sh
vi-state-views /path/to/analysis/plan.json --states 12,13 --ghidra /path/to/ghidra
```

Omit `--states` for a small sample, or use `--states all` for every entry.
Each view has assembly output and, when decompilation succeeds, a paired C file.
These are analysis fragments, not separate native functions. Unknown runtime prototypes can hide arguments
in the C output; consult the assembly. Use `LV_state_NNNN` labels for original
state indices because displayed switch-case numbers can differ.

## Tests

The public tests generate their XML and native-byte fixtures. They need no
external application or original VI collection:

```sh
python -m unittest discover -s tests -v
```

A separate Ghidra check verifies original-resource preservation through GZF
export/reimport and requires corrupted, missing or incorrectly protected
archives to be rejected:

```sh
python tests/check_resource_archives.py \
  --ghidra /path/to/ghidra --output /path/to/new-test-output
```

A second synthetic Ghidra check verifies opaque timestamp/extended-float
extents and signed/wider ring values after saving and GZF reimport:

```sh
python tests/check_facts.py \
  --ghidra /path/to/ghidra --output /path/to/new-facts-output
```

A three-state fixture verifies default fragment selection and checks that
exporting state views preserves the saved program:

```sh
python tests/check_state_views.py \
  --ghidra /path/to/ghidra --output /path/to/new-state-output
```

The checks and their coverage are recorded in [VALIDATION.md](VALIDATION.md).

## Remaining boundaries

Supported timestamps occupy 16 opaque native bytes; extended floats occupy 10.
Their internal representation remains opaque. Compact signed/wider ring values
follow the pinned decoder's big-endian heap convention. Unsigned 64-bit values
above Java's signed-long range remain decoded facts without enum import.

Some unsupported type encodings and missing offset anchors leave an anchored
layout unavailable. Explicit metadata and the original VI remain preserved.
Some control writes have no unique verified native call frame. Some relocated
calls can remain undisassembled. Complete large-function decompilation, native
ABI recovery and dynamic instance bindings remain separate analysis tasks.

This package imports individual VIs. It does not reconstruct project-wide
execution or recursively import other VIs. Compiled files cannot supply source
or diagrams removed before distribution.

## License and provenance

This repository's code is MIT licensed. It uses
[pylabview](https://github.com/mefistotelis/pylabview), also MIT licensed, for
RSRC decoding. Decoder conventions adapted here have source permalinks beside
the code; the upstream license is in `licenses/pylabview-MIT.txt`.
Ghidra and the LabVIEW runtime are separate dependencies with their own licenses.
