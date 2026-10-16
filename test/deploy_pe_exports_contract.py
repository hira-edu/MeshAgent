"""Exercise export address validation without loading fixture DLLs."""
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deploy


def image(pe32=False):
    data = bytearray(0x600)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    optional_size = 224 if pe32 else 240
    struct.pack_into('<HH', data, 0x84, 0x14c if pe32 else 0xaa64, 1)
    struct.pack_into('<H', data, 0x94, optional_size)
    struct.pack_into('<H', data, 0x98, 0x10b if pe32 else 0x20b)
    struct.pack_into('<II', data, 0x98 + (96 if pe32 else 112), 0x1000, 0x100)
    struct.pack_into('<IIII', data, 0x98 + optional_size + 8, 0x400, 0x1000, 0x400, 0x200)
    struct.pack_into('<IIIII', data, 0x214, 1, 1, 0x1040, 0x1060, 0x1050)
    struct.pack_into('<I', data, 0x240, 0x1200)
    struct.pack_into('<I', data, 0x260, 0x1080)
    name = b'ServiceHost_ServiceMain\0'
    data[0x280:0x280 + len(name)] = name
    return data


class ExportContracts(unittest.TestCase):
    def read(self, data):
        with tempfile.TemporaryDirectory() as directory:
            dll = Path(directory) / 'fixture.dll'
            dll.write_bytes(data)
            exports = deploy.read_pe_export_names(dll)
            # Force the production cross-architecture path, even on ARM64 hosts.
            with mock.patch.object(deploy, 'read_pe_machine', side_effect=lambda path:
                                   0x8664 if str(path) == sys.executable else 0xaa64):
                self.assertEqual(deploy.has_service_host_export(dll), b'ServiceHost_ServiceMain' in exports)
            return exports

    def test_valid_pe32_and_pe64(self):
        for pe32 in (False, True):
            self.assertIn(b'ServiceHost_ServiceMain', self.read(image(pe32)))

    def test_null_and_forwarded_exports_are_not_local_entrypoints(self):
        for address in (0, 0x1080):
            data = image()
            struct.pack_into('<I', data, 0x240, address)
            self.assertNotIn(b'ServiceHost_ServiceMain', self.read(data))

    def test_bad_ordinal_and_unbacked_address(self):
        for offset, fmt, value in ((0x250, '<H', 1), (0x240, '<I', 0x2000),
                                   (0x214, '<I', 0), (0x21c, '<I', 0x13ff),
                                   (0x224, '<I', 0x13ff), (0x220, '<I', 0x13ff)):
            data = image()
            struct.pack_into(fmt, data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                self.read(data)

    def test_name_must_end_inside_section_not_in_overlay(self):
        data = image()
        struct.pack_into('<I', data, 0x260, 0x13fe)
        data[0x5fe:] = b'bad-export\0'
        with self.assertRaises(ValueError):
            self.read(data)


if __name__ == '__main__':
    unittest.main()
