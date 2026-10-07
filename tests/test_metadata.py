"""Synthetic metadata fixtures; no input VI or application files are required."""
import contextlib
import io
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from labview_vi_to_ghidra.vi_metadata import extract


def make_xml(duplicate=False, overlap=False):
    root = ET.Element('RSRC')
    section = ET.SubElement(ET.SubElement(root, 'VCTP'), 'Section')
    ET.SubElement(section, 'TypeDesc', Type='Boolean')
    ET.SubElement(section, 'TypeDesc', Type='String')
    top = ET.SubElement(section, 'TopLevel')
    ET.SubElement(top, 'TypeDesc', Index='100', FlatTypeID='0')
    ET.SubElement(top, 'TypeDesc', Index='101', FlatTypeID='1')
    ET.SubElement(ET.SubElement(root, 'DTHP'), 'Section')
    ET.SubElement(root.find('DTHP/Section'), 'TypeDescSlice', IndexShift='100')
    section = ET.SubElement(ET.SubElement(root, 'DFDS'), 'Section')
    for table in range(2 if duplicate else 1):
        fill = ET.SubElement(section, 'DataFill', TypeID=str(table))
        fill.append(ET.Comment('Table of Front Panel DCOs'))
        block = ET.SubElement(fill, 'RepeatedBlock')
        for index, connector, size, default, transfer in [(0, 11, 1, 24, 25), (1, 14, 4, 25 if overlap else 32, 36)]:
            row = ET.SubElement(block, 'Cluster')
            values = {'dcoIndex': index, 'conNum': connector, 'dsSz': size, 'flagDSO': 16 + index,
                      'defaultDataOffset': default, 'transferDataOffset': transfer,
                      'extraDataOffset': -1, 'execDataPtrOffset': -1, 'subTypeDSO': -1}
            for key, value in values.items():
                row.append(ET.Comment(key))
                ET.SubElement(row, 'I32').text = str(value)
    return ET.ElementTree(root)


def make_panel():
    root = ET.Element('Panel')
    connections = ET.SubElement(ET.SubElement(root, 'conPane'), 'cons')
    for connector, uid, typ, label in [(11, '7', 1, 'Enabled'), (14, '9', 2, 'Text')]:
        item = ET.SubElement(connections, 'SL__arrayElement', index=str(connector))
        ET.SubElement(item, 'ConnectionDCO', uid=uid)
        control = ET.SubElement(root, 'Control', {'class': 'fPDCO', 'uid': uid})
        ET.SubElement(control, 'typeDesc').text = f'TypeID({typ})'
        parts = ET.SubElement(ET.SubElement(control, 'ddo'), 'partsList')
        element = ET.SubElement(parts, 'SL__arrayElement', {'class': 'label'})
        ET.SubElement(ET.SubElement(element, 'textRec'), 'text').text = label
    return ET.ElementTree(root)


class MetadataTests(unittest.TestCase):
    def decode(self, panel=True, duplicate=False, overlap=False):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            directory = Path(directory)
            xml = directory / 'example.xml'
            make_xml(duplicate, overlap).write(xml)
            panel_path = directory / 'panel.xml'
            if panel:
                make_panel().write(panel_path)
            return extract(xml, panel_path if panel else None, directory / 'out', 'example.vi')

    def test_sparse_connector_indices_are_preserved(self):
        metadata = self.decode()
        self.assertEqual([d['control']['connector'] for d in metadata['dcos']], [11, 14])
        self.assertEqual(metadata['fields'][0]['name'], 'DCO0_Enabled_defaultDataOffset')

    def test_scalar_requires_size_agreement_and_string_stays_opaque(self):
        fields = self.decode()['fields']
        self.assertEqual([(f['offset'], f['size'], f['type']) for f in fields],
                         [(24, 1, 'Boolean'), (25, 1, 'Boolean'), (32, 4, None), (36, 4, None)])

    def test_missing_panel_does_not_invent_control_bindings(self):
        metadata = self.decode(panel=False)
        self.assertTrue(all(d['control'] is None for d in metadata['dcos']))
        self.assertTrue(all(f['type'] is None for f in metadata['fields']))
        self.assertTrue(all('_unnamed_' in f['name'] for f in metadata['fields']))

    def test_duplicate_tables_keep_records_and_deduplicate_fields(self):
        metadata = self.decode(duplicate=True)
        self.assertEqual(len(metadata['dcos']), 4)
        self.assertEqual(len(metadata['fields']), 4)
        self.assertEqual(sum(r['kind'] == 'DCO' for r in metadata['records']), 4)

    def test_overlapping_native_fields_are_rejected(self):
        with self.assertRaises(AssertionError):
            self.decode(overlap=True)


if __name__ == '__main__':
    unittest.main()
