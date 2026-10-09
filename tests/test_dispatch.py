"""Synthetic native-byte fixtures for the documented LV13 return dispatcher."""

import struct
import unittest
from labview_vi_to_ghidra.vi_dispatch import (
    PREFIX,
    SUFFIX,
    EPILOGUE,
    scan,
    recognize_dispatchers,
)


def make_code():
    base, dispatch = 0x10000000, 80
    table = dispatch + len(PREFIX) + 4 + len(SUFFIX)
    targets = [45, 50, 45]
    code = bytearray(table + 4 * len(targets) + len(EPILOGUE))
    code[40] = 0xE9
    struct.pack_into("<i", code, 41, dispatch - 45)
    code[dispatch : dispatch + len(PREFIX)] = PREFIX
    struct.pack_into("<I", code, dispatch + 23, base + table)
    code[dispatch + 27 : table] = SUFFIX
    for index, target in enumerate(targets):
        struct.pack_into("<i", code, table + 4 * index, target - (table + 4 * index))
    code[table + 4 * len(targets) :] = EPILOGUE
    plan = {
        "base": base,
        "entries": [{"offset": 40, "name": "RunProc"}],
        "changes": [
            {
                "offset": dispatch + 23,
                "kind": "code_base",
                "new": base + table,
                "record": 0,
            }
        ],
    }
    return bytes(code), plan


class DispatcherTests(unittest.TestCase):
    def test_original_indices_and_aliases_are_preserved(self):
        code, plan = make_code()
        result = recognize_dispatchers(code, plan)[0]
        self.assertEqual(result["targets"], [45, 50, 45])
        self.assertEqual(result["end"] - result["table"], 12)

    def test_missing_or_wrong_relocation_is_rejected(self):
        code, plan = make_code()
        for changes in [[], [dict(plan["changes"][0], new=0)]]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                recognize_dispatchers(code, dict(plan, changes=changes))

    def test_destination_inside_table_is_rejected(self):
        code, _ = make_code()
        result = scan(code)
        changed = bytearray(code)
        struct.pack_into("<i", changed, result["table"], 0)
        with self.assertRaises(ValueError):
            scan(changed, require=True)

    def test_truncated_epilogue_is_rejected(self):
        code, _ = make_code()
        with self.assertRaises(ValueError):
            scan(code[:-2], require=True)

    def test_wrong_dispatcher_opcode_is_rejected(self):
        code, _ = make_code()
        changed = bytearray(code)
        changed[scan(code)["branch"]] = 0x90
        with self.assertRaises(ValueError):
            scan(changed, require=True)

    def test_unrelated_bytes_are_not_recognized(self):
        self.assertIsNone(scan(bytes(100)))
        self.assertEqual(
            recognize_dispatchers(bytes(100), {"entries": [], "changes": []}), []
        )


if __name__ == "__main__":
    unittest.main()
