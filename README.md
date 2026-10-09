# LabVIEW to Ghidra

Convert a compiled LabVIEW VI into a Ghidra project for static analysis. The
converter restores supported relocations and callbacks, imports saved metadata,
and checks the project after saving and exporting it as a portable GZF file.
It reads the VI and runtime as files without executing them.

## Supported profile

- LabVIEW 13.0.0, 32-bit x86, VICD code version `0x13008000`.
- Runtime 13.0.0.4046, with `lvrt.dll` SHA-256
  `2dcb88ecdec6bac366530cb28fc760060a13def9da72ffb7ed2d35985101e74e`.
- Linux with Python 3.10 or later. CI tests Python 3.10 through 3.14.
- Ghidra 12.1.3 and 12.1.4. Projects record the Ghidra version and processor
  definitions; an older installation may require regenerating the project.

The input must be an individual RSRC VI with a supported compiled code section.
Other profiles are rejected. Supply the runtime separately. Whole projects and
recursive SubVI imports are outside the current scope.

## Install and convert

Install Ghidra and Java using the
[Ghidra 12.1.4 installation instructions](https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/README.md#install).
Then install the converter:

```sh
git clone https://github.com/fakuivanai/labview-to-ghidra.git
cd labview-to-ghidra
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
```

Installation needs Git and access to the pinned
[pylabview dependency](https://github.com/mefistotelis/pylabview/tree/5f20e23de6a386021eb955c825cc43d221f09ff1).
Other dependency versions are in `pyproject.toml`.

Derive a callback map from the runtime, then convert into a new or empty output
directory:

```sh
vi-runtime-map --runtime /path/to/lvrt.dll --output /path/to/runtime-map.json
vi-to-ghidra /path/to/example.vi \
  --runtime /path/to/lvrt.dll \
  --runtime-map /path/to/runtime-map.json \
  --ghidra /path/to/ghidra \
  --output /path/to/analysis
```

`GHIDRA_HOME` or `analyzeHeadless` on `PATH` can supply the Ghidra installation.
The Flatpak app `org.ghidra_sre.Ghidra` works with `--ghidra flatpak`.
`python -m labview_vi_to_ghidra` runs the same converter.

Open `project/VIAnalysis.gpr` with its `.rep` directory, or import `analysis.gzf`
into another Ghidra project. Retain the whole output directory for state views
and reproduction. It includes plans, source snapshots, commands, hashes and
stage audits. A successful conversion writes `result.json`; a failed stage
exits nonzero and writes `FAILED.json` and logs. Analysis runs at low priority
on one CPU core and refuses concurrent converter or state-view jobs.

- `--embed-vi` adds an exact copy of the input VI to the project. The default
  omits it. Both modes record the input hash and the embedding choice.
- `--prepare-only` validates and writes plans without starting Ghidra.
- `--allow-unresolved` permits unresolved relocations, marked in reports and
  bookmarks. Otherwise they stop conversion.

## What the project preserves

Ghidra receives relocated native code, recognized callbacks, verified symbolic
runtime references and available decompiler output. Read-only, non-executable blocks at
artificial addresses hold decoded VI XML and available front-panel XML. Labels,
defaults, control UIDs, connector numbers and saved SubVI link slots remain
searchable metadata.

Supported native data-space fields appear under `/LabVIEW/VI_metadata` and
`/LabVIEW/Recorded_facts` in the Data Type Manager. Layouts must agree with every
available saved offset anchor. The supported initialization record can supply
anchors for VIs without DCO records. Handles and unknown internals remain
opaque. Saving and GZF reimport check native bytes, resource blocks, permissions,
metadata, types, annotations and supported dispatcher tables.

The analysis cannot reconstruct a complete VI. With `--embed-vi`, the
`Original_VI` block holds the unchanged input bytes, including undecoded resources.
Exporting that block recovers the original file; analysis edits do not update it.
It is useful when moving a GZF without the separate VI or revisiting the file
with a future decoder. It does not improve decompilation by itself.

Saved defaults are recorded values, and saved SubVI links do not identify live
instances. Timestamps occupy 16 opaque native bytes and extended floats occupy
10. Unsigned 64-bit ring values above Java's signed-long range remain facts
without enum import. Unsupported types or missing anchors can prevent layout
recovery while explicit metadata remains available. Some calls and control
writes lack verified native bindings. Source and diagrams removed before
distribution cannot be recovered from the compiled file.

## State views

Complete decompilation of large state machines can time out. Export smaller
views from a converted project:

```sh
vi-state-views /path/to/analysis/plan.json --states 12,13 --ghidra /path/to/ghidra
```

Omit `--states` for a small sample or use `--states all`. Each fragment includes
assembly and, when decompilation succeeds, C output. These fragments are parts
of the original function. Unknown runtime prototypes can hide arguments in C;
consult the assembly. `LV_state_NNNN` labels retain original state indices,
which can differ from the decompiler's displayed switch-case numbers.

## Development

Python sources and packaged Ghidra scripts are in `src/labview_vi_to_ghidra/`.
Unit tests generate their own XML and native-byte fixtures. Install the package
before running them, so tests use the installed code. The development extra
includes the pinned formatter:

```sh
python -m pip install ".[dev]"
python -m ruff format --check src tests tools
python -m unittest discover -s tests -v
python -m pip install build
python -m build
python tools/check_distribution.py
```

Run `python -m ruff format src tests tools` to apply formatting.

The distribution check compares packaged scripts and license notices with the
source tree. Ghidra checks cover resource blocks, recorded facts and state
views. Each run needs a separate, empty output directory:

```sh
python tests/integration/check_resource_archives.py --ghidra /path/to/ghidra --output /path/to/archive-check
python tests/integration/check_facts.py --ghidra /path/to/ghidra --output /path/to/facts-check
python tests/integration/check_state_views.py --ghidra /path/to/ghidra --output /path/to/state-check
```

Keep changes within the documented profile. Add generated regression fixtures
for decoding, relocation and layout changes. New layout rules need independent
saved offset anchors or equivalent format evidence. Cite pinned sources beside
adapted code, preserve license notices, and run the relevant Ghidra check when
changing imports or state views. Record the tested Ghidra version. The CLI is
the documented interface; Python modules and JSON schemas are experimental.

## License and security

This code is MIT licensed. Adapted decoder conventions cite their sources;
the pylabview license is in `licenses/pylabview-MIT.txt`. Ghidra and the LabVIEW
runtime have separate licenses. Report vulnerabilities through the private
form in [SECURITY.md](SECURITY.md).
