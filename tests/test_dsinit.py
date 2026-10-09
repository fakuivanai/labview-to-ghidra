"""Synthetic regressions for the no-DCO DSINIT54 anchor fallback."""

import copy
import tempfile
import unittest
from pathlib import Path
import xml.etree.ElementTree as E
from labview_vi_to_ghidra.vi_facts import extract


def fixture():
    root = E.Element("RSRC")
    section = E.SubElement(E.SubElement(root, "LVSR"), "Section")
    E.SubElement(section, "Version", Major="13", Minor="0", Bugfix="0")
    section = E.SubElement(E.SubElement(root, "VICD"), "Section")
    E.SubElement(section, "General", CodeID="i386", Version="0x13008000")
    section = E.SubElement(E.SubElement(root, "VCTP"), "Section")
    for kind in ["NumUInt8", "NumInt32", "NumUInt16", "NumUInt32", "Ptr"]:
        E.SubElement(section, "TypeDesc", Type=kind)

    def aggregate(kind, children, **attrs):
        td = E.SubElement(section, "TypeDesc", Type=kind, **attrs)
        for child in children:
            E.SubElement(td, "TypeDesc", TypeID=str(child))
        return td

    aggregate("RepeatedBlock", [0], NumRepeats="16")
    aggregate("RepeatedBlock", [1], NumRepeats="54")
    aggregate("Cluster", [4, 4, 4, 1, 1, 3, 3, 1, 4, 1, 4, 3])
    aggregate("Cluster", [0, 0, 2, 3])
    aggregate("RepeatedBlock", [8], NumRepeats="2")
    aggregate("RepeatedBlock", [1], NumRepeats="2")
    E.SubElement(section, "TypeDesc", Type="Void")
    top = E.SubElement(section, "TopLevel")
    for index, flat in enumerate([5, 6, 7, 9, 10, 10, 11], 2):
        E.SubElement(top, "TypeDesc", Index=str(index), FlatTypeID=str(flat))
    section = E.SubElement(E.SubElement(root, "TM80"), "Section", IndexShift="2")
    for _ in range(7):
        E.SubElement(section, "Client")
    section = E.SubElement(E.SubElement(root, "DFDS"), "Section")
    repeated = E.SubElement(
        E.SubElement(section, "DataFill", TypeID="3"), "RepeatedBlock"
    )
    values = [0] * 54
    values[0:6] = [2, 280, 3, 1, 304, 5]
    values[8] = -1
    values[12:15] = [1, 232, 2]
    values[51:54] = [3, 4, 5]
    for value in values:
        E.SubElement(repeated, "I32").text = str(value)
    return root


class DSInitTests(unittest.TestCase):
    def facts(self, root):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "example.xml"
            E.ElementTree(root).write(path, encoding="utf-8")
            return extract(path, None, Path(tmp) / "output")

    def test_three_independent_offset_tmi_pairs_allow_layout(self):
        facts = self.facts(fixture())
        self.assertEqual(facts["layout"]["status"], "anchored_profile")
        self.assertEqual(facts["layout"]["extent"], 312)
        self.assertEqual(
            [a["offset"] for a in facts["layout"]["anchors"]], [280, 304, 232]
        )
        self.assertTrue(
            all(a["kind"] == "DSINIT_offset_tmi" for a in facts["layout"]["anchors"])
        )
        self.assertTrue(
            all(a["source_tm80_slot"] == 1 for a in facts["layout"]["anchors"])
        )
        self.assertEqual(facts["controls"], [])
        self.assertEqual(len(facts["offset_facts"]), 6)

    def test_offset_corruption_withholds_layout(self):
        for index in [1, 4, 13]:
            root = fixture()
            leaf = root.findall("DFDS/Section/DataFill/RepeatedBlock/I32")[index]
            leaf.text = str(int(leaf.text) + 4)
            with self.subTest(index=index):
                facts = self.facts(root)
                self.assertEqual(facts["layout"]["status"], "unresolved")
                self.assertIn(
                    "DSINIT offset anchor mismatch", facts["layout"]["reasons"][0]
                )
                self.assertEqual(facts["layout"]["rows"], [])
                self.assertEqual(facts["offset_facts"], [])

    def test_table_count_corruption_is_rejected(self):
        root = fixture()
        root.findall("DFDS/Section/DataFill/RepeatedBlock/I32")[0].text = "3"
        facts = self.facts(root)
        self.assertEqual(facts["layout"]["status"], "unresolved")
        self.assertIn("table type/count mismatch", facts["layout"]["reasons"][0])

    def test_unrelated_54_word_array_is_not_an_anchor(self):
        root = fixture()
        for leaf in root.findall("DFDS/Section/DataFill/RepeatedBlock/I32"):
            leaf.text = "0"
        facts = self.facts(root)
        self.assertEqual(facts["layout"]["status"], "unresolved")
        self.assertEqual(
            facts["layout"]["reasons"], ["No independent saved offset anchors"]
        )

    def test_truncated_saved_record_is_rejected(self):
        root = fixture()
        repeated = root.find("DFDS/Section/DataFill/RepeatedBlock")
        repeated.remove(repeated[-1])
        self.assertEqual(self.facts(root)["layout"]["status"], "unresolved")

    def test_missing_anchor_is_rejected(self):
        root = fixture()
        root.findall("DFDS/Section/DataFill/RepeatedBlock/I32")[12].text = "0"
        facts = self.facts(root)
        self.assertEqual(facts["layout"]["status"], "unresolved")
        self.assertIn("Incomplete DSINIT", facts["layout"]["reasons"][0])

    def test_duplicate_primary_saved_fills_are_ambiguous(self):
        root = fixture()
        fill = copy.deepcopy(root.find("DFDS/Section/DataFill"))
        root.find("DFDS/Section").append(fill)
        facts = self.facts(root)
        self.assertEqual(facts["layout"]["status"], "unresolved")
        self.assertIn(
            "Ambiguous primary DSINIT saved fill", facts["layout"]["reasons"][0]
        )

    def test_matching_nonprimary_record_cannot_substitute(self):
        root = fixture()
        E.SubElement(
            root.find("VCTP/Section/TopLevel"), "TypeDesc", Index="9", FlatTypeID="6"
        )
        E.SubElement(root.find("TM80/Section"), "Client")
        fill = root.find("DFDS/Section/DataFill")
        fill.set("TypeID", "9")
        facts = self.facts(root)
        self.assertEqual(facts["layout"]["status"], "unresolved")
        self.assertEqual(
            facts["layout"]["reasons"], ["No independent saved offset anchors"]
        )

    def test_tmi_flag_bits_use_documented_low24_index(self):
        root = fixture()
        leaves = root.findall("DFDS/Section/DataFill/RepeatedBlock/I32")
        for index in [2, 5, 14]:
            leaves[index].text = str(int(leaves[index].text) | 0x01000000)
        self.assertEqual(self.facts(root)["layout"]["status"], "anchored_profile")

    def test_dco_record_prevents_fallback(self):
        root = fixture()
        fill = E.SubElement(root.find("DFDS/Section"), "DataFill", TypeID="99")
        fill.append(E.Comment("Table of Front Panel DCOs"))
        cluster = E.SubElement(E.SubElement(fill, "RepeatedBlock"), "Cluster")
        for key, value in {"dcoIndex": 0, "flagTMI": 0, "flagDSO": -1}.items():
            cluster.append(E.Comment(key))
            E.SubElement(cluster, "I32").text = str(value)
        self.assertEqual(self.facts(root)["layout"]["status"], "unresolved")

    def test_record_suffix_does_not_get_assigned_semantics(self):
        root = fixture()
        leaves = root.findall("DFDS/Section/DataFill/RepeatedBlock/I32")
        for leaf in leaves[51:54]:
            leaf.text = "12345"
        facts = self.facts(root)
        self.assertEqual(facts["layout"]["status"], "anchored_profile")
        self.assertTrue(all(a["offset_field"] < 51 for a in facts["layout"]["anchors"]))


if __name__ == "__main__":
    unittest.main()
