"""Synthetic metadata fixtures; no application files or runtime execution."""
import tempfile
import unittest
from pathlib import Path
import xml.etree.ElementTree as E

from labview_vi_to_ghidra.vi_facts import Layout, extract, ring_labels, rings, sparse_integer


def native_root(kind, extent, flavor=None, anchors=True, profile=True):
    root = E.Element('RSRC')
    section = E.SubElement(E.SubElement(root, 'LVSR'), 'Section')
    E.SubElement(section, 'Version', Major='13' if profile else '14', Minor='0', Bugfix='0')
    section = E.SubElement(E.SubElement(root, 'VICD'), 'Section')
    E.SubElement(section, 'General', CodeID='i386', Version='0x13008000')
    section = E.SubElement(E.SubElement(root, 'VCTP'), 'Section')
    value = E.SubElement(section, 'TypeDesc', Type=kind, Label='Value')
    if flavor:
        value.set('Flavor', flavor)
    E.SubElement(section, 'TypeDesc', Type='NumInt32', Label='Following field')
    top = E.SubElement(section, 'TopLevel')
    for index in range(2):
        E.SubElement(top, 'TypeDesc', Index=str(index), FlatTypeID=str(index))
    section = E.SubElement(E.SubElement(root, 'TM80'), 'Section', IndexShift='0')
    for _ in range(2):
        E.SubElement(section, 'Client')
    section = E.SubElement(E.SubElement(root, 'DFDS'), 'Section')
    if anchors:
        fill = E.SubElement(section, 'DataFill', TypeID='999')
        fill.append(E.Comment('Table of Front Panel DCOs'))
        cluster = E.SubElement(E.SubElement(fill, 'RepeatedBlock'), 'Cluster')
        for key, value in {'dcoIndex': 0, 'flagTMI': 1, 'flagDSO': extent}.items():
            cluster.append(E.Comment(key))
            E.SubElement(cluster, 'NumInt32').text = str(value)
    return root


def sparse_root(kind):
    root = E.Element('RSRC')
    section = E.SubElement(E.SubElement(root, 'VCTP'), 'Section')
    E.SubElement(section, 'TypeDesc', Type=kind)
    top = E.SubElement(section, 'TopLevel')
    E.SubElement(top, 'TypeDesc', Index='100', FlatTypeID='0')
    section = E.SubElement(E.SubElement(root, 'DTHP'), 'Section')
    E.SubElement(section, 'TypeDescSlice', IndexShift='100')
    return root


def sparse_panel(values, labels, copies=1, value_type='TypeID(1)'):
    panel = E.Element('Panel')
    control = E.SubElement(panel, 'Control', {'class': 'fPDCO', 'uid': '5'})
    ddo = E.SubElement(control, 'ddo')
    E.SubElement(ddo, 'typeDesc').text = value_type
    sparse = E.SubElement(ddo, 'ringSparseValues')
    for value in values:
        E.SubElement(sparse, 'SL__arrayElement').text = value
    parts = E.SubElement(ddo, 'partsList')
    for _ in range(copies):
        item = E.SubElement(parts, 'SL__arrayElement', {'class': 'multiLabel'})
        E.SubElement(item, 'buf').text = labels
    return panel


class LayoutTests(unittest.TestCase):
    def extract_root(self, root):
        with tempfile.TemporaryDirectory() as directory:
            xml = Path(directory) / 'example.xml'
            E.ElementTree(root).write(xml, encoding='utf-8')
            return extract(xml, None, Path(directory) / 'output')

    def test_timestamp_is_opaque_and_anchor_checked(self):
        facts = self.extract_root(native_root('MeasureData', 16, 'TimeStamp'))
        self.assertEqual(facts['layout']['status'], 'anchored_profile')
        self.assertEqual(facts['layout']['extent'], 20)
        timestamp = next(t for t in facts['layout']['types'] if t['kind'] == 'MeasureData')
        self.assertEqual(timestamp['size'], 16)
        self.assertEqual(timestamp['representation'], 'opaque')
        self.assertNotIn('scalar', timestamp)
        self.assertIn('internal fields', timestamp['note'])

    def test_extended_float_native_extent_differs_from_saved_storage(self):
        for kind in ['NumFloatExt', 'UnitFloatExt']:
            with self.subTest(kind=kind):
                facts = self.extract_root(native_root(kind, 10))
                self.assertEqual(facts['layout']['status'], 'anchored_profile')
                self.assertEqual(facts['layout']['extent'], 14)
                value = next(t for t in facts['layout']['types'] if t['kind'] == kind)
                self.assertEqual(value['size'], 10)
                self.assertEqual(value['representation'], 'opaque')
                self.assertNotIn('scalar', value)
                self.assertIn('DFDS storage is 16 bytes', value['note'])

    def test_extended_float_anchor_mismatch_withholds_layout(self):
        for extent in [12, 16]:
            with self.subTest(extent=extent):
                facts = self.extract_root(native_root('NumFloatExt', extent))
                self.assertEqual(facts['layout']['status'], 'unresolved')
                self.assertEqual(facts['layout']['rows'], [])
                self.assertEqual(facts['layout']['types'], [])
                self.assertIn('DCO flag anchor mismatch', facts['layout']['reasons'][0])
                self.assertEqual(facts['offset_facts'], [])

    def test_timestamp_anchor_mismatch_withholds_layout(self):
        facts = self.extract_root(native_root('MeasureData', 8, 'TimeStamp'))
        self.assertEqual(facts['layout']['status'], 'unresolved')
        self.assertIn('DCO flag anchor mismatch', facts['layout']['reasons'][0])

    def test_layout_without_anchor_is_unresolved(self):
        facts = self.extract_root(native_root('MeasureData', 16, 'TimeStamp', anchors=False))
        self.assertEqual(facts['layout']['status'], 'unresolved')
        self.assertEqual(facts['layout']['reasons'], ['No independent DCO offset anchors'])

    def test_unknown_measure_flavor_retains_specific_reason(self):
        facts = self.extract_root(native_root('MeasureData', 16, 'DigitalWaveform'))
        self.assertEqual(facts['layout']['status'], 'unresolved')
        self.assertIn('DigitalWaveform', facts['layout']['reasons'][0])
        self.assertIn('native extent not established', facts['layout']['reasons'][0])

    def test_profile_limit_is_explicit(self):
        facts = self.extract_root(native_root('NumFloatExt', 10, profile=False))
        self.assertEqual(facts['layout']['status'], 'unresolved')
        self.assertIn('Outside validated', facts['layout']['reasons'][0])


class SparseIntegerTests(unittest.TestCase):
    def test_signed_compact_and_big_endian_values(self):
        for raw, kind, expected in [
            ('f6', 'NumInt16', -10),
            ('ff80', 'NumInt32', -128),
            ('80', 'NumInt64', -128),
            ('0080', 'NumInt16', 128),
            ('0102', 'NumInt32', 258),
            ('7fffffffffffffff', 'NumInt64', (1 << 63) - 1),
            ('8000000000000000', 'NumInt64', -(1 << 63)),
        ]:
            with self.subTest(raw=raw, kind=kind):
                value, width, signed = sparse_integer(raw, kind)
                self.assertEqual(value, expected)
                self.assertEqual(width, int(kind.removeprefix('NumInt')) // 8)
                self.assertTrue(signed)

    def test_unsigned_heap_sign_extension(self):
        for raw, kind, expected in [
            ('ff', 'NumUInt8', 255),
            ('ff', 'NumUInt16', 65535),
            ('f6', 'UnitUInt16', 65526),
            ('0080', 'NumUInt32', 128),
            ('8000', 'NumUInt32', 0xffff8000),
            ('ff', 'NumUInt64', (1 << 64) - 1),
        ]:
            with self.subTest(raw=raw, kind=kind):
                value, _, signed = sparse_integer(raw, kind)
                self.assertEqual(value, expected)
                self.assertFalse(signed)

    def test_invalid_payloads_are_rejected(self):
        for raw in ['', '0', 'zz', '000000']:
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    sparse_integer(raw, 'NumInt16')

    def test_unsupported_value_type_is_rejected(self):
        for kind in ['NumFloat64', 'UnitInt16', 'UnitUInt64', 'Unknown']:
            with self.subTest(kind=kind):
                with self.assertRaises(ValueError):
                    sparse_integer('00', kind)


class RingTests(unittest.TestCase):
    def ring(self, kind, values, labels, **options):
        root = sparse_root(kind)
        with tempfile.TemporaryDirectory() as directory:
            panel = Path(directory) / 'panel.xml'
            E.ElementTree(sparse_panel(values, labels, **options)).write(panel, encoding='utf-8')
            return rings(root, panel, Layout(root))[0]

    def test_signed_ring_preserves_exact_type_and_values(self):
        ring = self.ring('NumInt16', ['f6', '0102'], '(2)"Negative""Positive"')
        self.assertEqual(ring['status'], 'recorded')
        self.assertEqual(ring['size'], 2)
        self.assertTrue(ring['signed'])
        self.assertEqual([e['value'] for e in ring['entries']], [-10, 258])
        self.assertEqual(ring['raw_values'], ['f6', '0102'])
        self.assertIn('no native DCO', ring['binding'])

    def test_unsigned64_import_bound_retains_exact_value(self):
        ring = self.ring('NumUInt64', ['ff'], '(1)"Maximum"')
        self.assertEqual(ring['status'], 'unresolved')
        self.assertEqual(ring['entries'][0]['value'], (1 << 64) - 1)
        self.assertIn('Ghidra enum range', ring['reason'])
        self.assertFalse(ring['signed'])

    def test_unsigned64_within_verified_bound_is_recorded(self):
        ring = self.ring('NumUInt64', ['7fffffffffffffff'], '(1)"Maximum"')
        self.assertEqual(ring['status'], 'recorded')
        self.assertEqual(ring['entries'][0]['value'], (1 << 63) - 1)

    def test_decoder_quote_control_and_literal_backslash_escaping(self):
        encoded = '(2)"A &#x22;quote&#x22;""C:\\data&#x01;"'
        self.assertEqual(ring_labels(encoded), ['A "quote"', 'C:\\data\x01'])
        ring = self.ring('NumUInt8', ['00', '01'], encoded)
        self.assertEqual(ring['status'], 'recorded')
        self.assertEqual([e['label'] for e in ring['entries']], ['A "quote"', 'C:\\data\x01'])

    def test_backslash_is_literal_and_unknown_entities_are_not_reinterpreted(self):
        self.assertEqual(ring_labels('(1)"A\\n&#xFF;&amp;"'), ['A\\n&#xFF;&amp;'])

    def test_ambiguous_label_lists_remain_unresolved(self):
        ring = self.ring('NumUInt8', ['00'], '(1)"First"', copies=2)
        self.assertEqual(ring['status'], 'unresolved')
        self.assertEqual(ring['reason'], 'Ambiguous label list')
        self.assertEqual(len(ring['raw_labels']), 2)

    def test_bad_counts_and_malformed_lists_remain_unresolved(self):
        for encoded in ['(2)"One"', '(1)"One"trailing', '(1)"bad "quote""', '(0)']:
            with self.subTest(encoded=encoded):
                ring = self.ring('NumUInt8', ['00'], encoded)
                self.assertEqual(ring['status'], 'unresolved')
                self.assertEqual(ring['raw_labels'], [encoded])

    def test_missing_type_mapping_remains_unresolved(self):
        ring = self.ring('NumUInt8', ['00'], '(1)"First"', value_type='TypeID(0)')
        self.assertEqual(ring['status'], 'unresolved')
        self.assertEqual(ring['reason'], 'No value type mapping')

    def test_malformed_value_retains_original_payload(self):
        ring = self.ring('NumInt16', ['not hex'], '(1)"First"')
        self.assertEqual(ring['status'], 'unresolved')
        self.assertEqual(ring['raw_values'], ['not hex'])


if __name__ == '__main__':
    unittest.main()
