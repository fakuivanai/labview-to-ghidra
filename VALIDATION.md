# Validation

The checked profile is LabVIEW 13.0.0 / i386 / VICD 0x13008000 with runtime
13.0.0.4046. These checks use static file analysis. They do not run VIs or
validate runtime behavior.

## Public fixtures

The package has 40 synthetic Python tests. They cover dispatcher recognition,
metadata extraction, native layout anchors, timestamp/extended-float extents,
signed/wider ring values, malformed input, saved backend paths and state
selection for small tables. All 40 passed against an installed wheel with
Python 3.12 on Linux.

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

A non-redistributed collection of 984 VIs from the supported profile was used
for metadata/layout regression checks. Of these, 983 have an anchored native
layout. All 10,116 available DCO offset anchors agree with their inferred fields.
The 925 previously supported layouts are unchanged. Timestamp and extended-float
support added 58 layouts and 1,017 matching anchors. All 30 ring records decode.

The remaining VI has no independent offset anchor. Its metadata remains
available, but the tool withholds an inferred layout. These counts describe
layout coverage, not 984 complete Ghidra conversions. The collection is not part
of the repository or required by the public tests.

Three additional VIs completed fresh end-to-end conversions with no unresolved
relocation records. They cover timestamps with Ghidra 12.1.4, extended floats
with Ghidra 12.1.3, and signed ring values with Ghidra 12.1.3. Each conversion
verified native code, embedded original files, metadata and supported facts
after saving and GZF reimport. Both a normal Ghidra installation and the Flatpak
backend were exercised. These private input files are not distributed.

## Limits of the evidence

The checks cover the documented version and emitter patterns. The runtime
fingerprint and VI version checks reject other profiles. Large function
pseudocode can time out; bounded state views preserve their original index and
assembly. Unknown native prototypes, unsupported types and uncertain runtime
bindings remain explicit limitations.
