# Contributing

Keep changes scoped to the documented LabVIEW and runtime profile. Add a
synthetic regression fixture for changes to decoding, relocations or native
layout recognition. New layout rules need independent saved offset anchors
or equivalent format evidence. Cite pinned source links beside adapted code.

Install the package using the README, then run:

```sh
python -m unittest discover -s tests -v
```

Generate small XML and byte fixtures in the tests. Ghidra integration checks
are separate commands documented in the README. Run the relevant check when
changing import, resource preservation, facts or state-view behavior, and
record the tested Ghidra version. Tests do not establish runtime behavior.

The CLI is the documented interface. Python modules and JSON schemas remain
experimental. Describe compatibility limits and validation evidence with
changes to these interfaces. Preserve dependency license notices.
