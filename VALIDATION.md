# Validation

The checked profile is LabVIEW 13.0.0 / i386 / VICD 0x13008000 with runtime
13.0.0.4046. These checks use static file analysis. They do not run VIs or
validate runtime behavior.

## Public fixtures

The package has 54 synthetic Python tests. They cover dispatcher recognition,
metadata extraction, native layout anchors, timestamp/extended-float extents,
signed/wider ring values, malformed input, saved backend paths and state
selection for small tables, strict initialization-record identification, and
optional original-VI embedding. Corrupted, duplicate and non-primary
initialization records are rejected. Archive-selection and prepare-only CLI
fixtures exercise both embedding modes and preserve the input hash in each.
All 54 passed against an installed wheel with Python 3.12 on Linux.

The synthetic resource-archive Ghidra check preserved three embedded archives
through save and GZF reimport. Seven kinds of damaged, missing or incorrectly
protected archive were rejected both in the saved project and after reimport.
It also checked legacy plans whose resource sizes must be read from input files.
New plans retain sizes and hashes for audits after those input files are removed.

The synthetic facts Ghidra check preserved opaque 16-byte timestamp and 10-byte
extended-float fields. It preserved signed ring values -10, 0 and 256, and
unsigned values 65536 and 4294967295. Saved and reimported types, facts and native
code hashes agreed.

The synthetic three-state dispatcher check verified default state selection.
All three fragments decompiled. Native bytes, resource archives, metadata,
function signatures and dispatcher cases remained unchanged, including after
an independent reopening of the saved project.

## Additional local coverage

A collection of 984 VIs from the supported profile was used
for metadata/layout regression checks. All 984 have an anchored native layout.
All 10,116 available DCO offset anchors agree with their inferred fields.
The 925 previously supported layouts are unchanged. Timestamp and extended-float
support added 58 layouts and 1,017 matching anchors. All 30 ring records decode.

One VI has no front-panel DCO records. Its saved initialization record
provides three independent offset/type-map pairs, with matching table types
and counts. A fallback supports that exact form at primary TM80 slot 1 and
requires a unique saved record. It activates once in this collection. All 983
previously supported layouts retain their rows and DCO anchors.

A separate format audit checked 2,488 saved initialization-record offset pairs
across the collection and found no mismatches. Other same-length arrays are
present, so length alone is never used to identify the initialization record.
These counts describe layout coverage, not 984 complete Ghidra conversions.

Three additional VIs completed fresh end-to-end conversions with no unresolved
relocation records. They cover timestamps with Ghidra 12.1.4, extended floats
with Ghidra 12.1.3, and signed ring values with Ghidra 12.1.3. Each conversion
verified native code, embedded original files, metadata and supported facts
after saving and GZF reimport. Those runs included the original VI archive.
Both a normal Ghidra installation and the Flatpak backend were exercised.

The no-DCO VI also completed a fresh conversion with the Flatpak backend.
Its three saved initialization-record anchors support an 804-byte native
layout. Native code, both embedded resources, metadata and the six recorded
native fields passed saving and GZF reimport checks.

The installed wheel then converted that VI in both current modes. The default
project preserved its one XML archive; `--embed-vi` preserved XML plus the exact
original VI. Both projects passed native-code, metadata, facts and resource
audits after saving and GZF reimport. Native code, function signatures, layout
types and recorded bindings agreed across modes. Provenance hashes that include
the separate output paths remain distinct.

## Package review

The wheel and source distribution contain matching Python and Java source, all
six importer scripts, and both MIT license notices. The source distribution
includes the synthetic tests and contributor documentation.

## Local release-readiness review

The [Trail of Bits open-sourcing workflow](https://github.com/trailofbits/skills/blob/82fe8226252622fa807643bdca1710901198553a/plugins/open-sourcing/skills/open-sourcing/SKILL.md)
was applied on 2026-10-07 with the generic organization profile. A clean clone
installed using the README in a fresh Python 3.12.14 virtual environment.
All 54 tests, help commands for all three CLI tools, and `pip check` passed.
Gitleaks 8.30.1 scanned the complete Git history with `--all` and the working
tree, reporting zero findings in both. License text and package metadata agree.

Before a public release, choose and configure a private security-reporting
route, add CI covering the declared Python versions, and select lint and type
checks. Dependency-update automation, hosted documentation, release tags and
publishing settings also remain unset. This review did not publish a repository
or package. Python 3.10 and other declared versions beyond 3.12 have not yet
been tested.

## Limits of the evidence

The checks cover the documented version and emitter patterns. The runtime
fingerprint and VI version checks reject other profiles. Large function
pseudocode can time out; bounded state views preserve their original index and
assembly. Unknown native prototypes, unsupported types and uncertain runtime
bindings remain explicit limitations.
