#!/usr/bin/env python3
import hashlib
import importlib.util
import struct
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("stage", ROOT / "tools/stage_runtime_components.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def executable(machine: int, dll: bool = False) -> bytes:
    pe = 0x80
    optional_size = 0xF0 if machine == MODULE.IMAGE_FILE_MACHINE_AMD64 else 0xE0
    magic = 0x20B if machine == MODULE.IMAGE_FILE_MACHINE_AMD64 else 0x10B
    data = bytearray(0x1200)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, pe)
    data[pe:pe + 4] = b"PE\0\0"
    characteristics = MODULE.IMAGE_FILE_EXECUTABLE_IMAGE | (MODULE.IMAGE_FILE_DLL if dll else 0)
    struct.pack_into("<HHIIIHH", data, pe + 4, machine, 1, 0, 0, 0, optional_size, characteristics)
    optional = pe + 24
    struct.pack_into("<H", data, optional, magic)
    struct.pack_into("<I", data, optional + 32, 0x1000)
    struct.pack_into("<I", data, optional + 36, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 16, 0x1200)
    directories = 108 if magic == 0x20B else 92
    struct.pack_into("<I", data, optional + directories, 16)
    section = optional + optional_size
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x1000, 0x1000, 0x1000, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    return bytes(data)


class RuntimeControllerPackaging(unittest.TestCase):
    def test_stages_two_controller_executables_and_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            x86 = root / "x86.exe"
            x64 = root / "x64.exe"
            x86.write_bytes(executable(MODULE.IMAGE_FILE_MACHINE_I386))
            x64.write_bytes(executable(MODULE.IMAGE_FILE_MACHINE_AMD64))
            output = root / "out"
            metadata = MODULE.stage_components(root, x86, x64, output)
            self.assertEqual((output / "runtime-controller-x86.exe").read_bytes(), x86.read_bytes())
            self.assertEqual((output / "runtime-controller-x64.exe").read_bytes(), x64.read_bytes())
            self.assertEqual(metadata["components"][0]["sha256"], hashlib.sha256(x86.read_bytes()).hexdigest())
            catalog = (output / "catalog.bin").read_bytes()
            self.assertEqual(struct.unpack_from("<IIII", catalog),
                (MODULE.CATALOG_MAGIC, MODULE.CATALOG_VERSION, MODULE.CATALOG_HEADER_SIZE, 2))
            rc = (output / "RuntimeComponents.generated.rc").read_text()
            self.assertIn("IDR_RUNTIME_CONTROLLER_X86", rc)
            self.assertIn("IDR_RUNTIME_CONTROLLER_X64", rc)

    def test_rejects_dll_or_wrong_architecture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.exe"
            path.write_bytes(executable(MODULE.IMAGE_FILE_MACHINE_I386, dll=True))
            with self.assertRaisesRegex(MODULE.ComponentImageError, "application"):
                MODULE.inspect_pe(path)
            path.write_bytes(executable(MODULE.IMAGE_FILE_MACHINE_AMD64))
            x64 = Path(directory) / "x64.exe"
            x64.write_bytes(executable(MODULE.IMAGE_FILE_MACHINE_AMD64))
            with self.assertRaisesRegex(MODULE.ComponentImageError, "does not match"):
                MODULE.stage_components(Path(directory), path, x64)

    def test_rejects_missing_or_non_executable_entry_point(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image.exe"
            data = bytearray(executable(MODULE.IMAGE_FILE_MACHINE_I386))
            optional = 0x80 + 24
            struct.pack_into("<I", data, optional + 16, 0)
            path.write_bytes(data)
            with self.assertRaisesRegex(MODULE.ComponentImageError, "image layout"):
                MODULE.inspect_pe(path)
            data = bytearray(executable(MODULE.IMAGE_FILE_MACHINE_I386))
            section = optional + 0xE0
            struct.pack_into("<I", data, section + 36, 0x40000040)
            path.write_bytes(data)
            with self.assertRaisesRegex(MODULE.ComponentImageError, "entry point"):
                MODULE.inspect_pe(path)

    def test_builds_isolated_library_then_architecture_controllers(self):
        namespace = {"m": "http://schemas.microsoft.com/developer/msbuild/2003"}
        root = ET.parse(ROOT / "meshservice/MeshAgent.MSBuild.targets").getroot()
        target = root.find("m:Target[@Name='BuildRuntimeComponentsForServiceBundle']", namespace)
        assert target is not None
        builds = target.findall("m:MSBuild", namespace)
        projects = [item.attrib["Projects"] for item in builds]
        self.assertEqual(projects, ["$(RuntimeLibraryBuildProject)", "$(RuntimeLibraryBuildProject)",
                                    "$(RuntimeControllerBuildProject)", "$(RuntimeControllerBuildProject)"])
        self.assertTrue(all(item.attrib.get("BuildInParallel") == "false" for item in builds))

        properties = [item.attrib["Properties"] for item in builds]
        self.assertEqual(properties, ["$(RuntimeLibraryWin32Properties)", "$(RuntimeLibraryX64Properties)",
                                      "$(RuntimeControllerX64Properties)", "$(RuntimeControllerWin32Properties)"])

        property_text = {
            child.tag.rsplit("}", 1)[-1]: child.text or ""
            for group in root.findall("m:PropertyGroup", namespace)
            for child in group
        }
        expected_paths = {
            "RuntimeLibraryWin32Properties": ("\\library\\x86\\", "\\obj\\library\\x86\\"),
            "RuntimeLibraryX64Properties": ("\\library\\x64\\", "\\obj\\library\\x64\\"),
            "RuntimeControllerWin32Properties": ("\\loader\\x86\\", "\\obj\\loader\\x86\\"),
            "RuntimeControllerX64Properties": ("\\loader\\x64\\", "\\obj\\loader\\x64\\"),
        }
        out_dirs = set()
        int_dirs = set()
        for name, (out_suffix, int_suffix) in expected_paths.items():
            values = dict(part.split("=", 1) for part in property_text[name].split(";") if "=" in part)
            self.assertEqual(values["SolutionDir"], "$(RuntimeComponentBuildSourceRoot)\\")
            self.assertEqual(values["OutDir"], "$(RuntimeComponentBuildOutputRoot)" + out_suffix)
            self.assertEqual(values["IntDir"], "$(RuntimeComponentBuildRoot)" + int_suffix)
            out_dirs.add(values["OutDir"])
            int_dirs.add(values["IntDir"])
        self.assertEqual(len(out_dirs), 4)
        self.assertEqual(len(int_dirs), 4)

        source_copies = target.findall("m:Copy", namespace)[:2]
        self.assertEqual([copy.attrib["SourceFiles"] for copy in source_copies],
                         ["@(_RuntimeLibrarySource)", "@(_RuntimeControllerSource)"])
        self.assertTrue(all("$(RuntimeComponentBuildSourceRoot)" in copy.attrib["DestinationFiles"]
                            for copy in source_copies))

        dependency_copies = target.findall("m:Copy", namespace)[2:]
        self.assertEqual(dependency_copies[0].attrib["SourceFiles"],
                         r"$(RuntimeComponentBuildOutputRoot)\library\x86\Runtime32.dll;$(RuntimeComponentBuildOutputRoot)\library\x64\Runtime64.dll")
        self.assertEqual(dependency_copies[0].attrib["DestinationFiles"],
                         r"$(RuntimeComponentBuildSourceRoot)\x86\Release\Runtime32.dll;$(RuntimeComponentBuildSourceRoot)\x64\Release\Runtime64.dll")
        self.assertEqual(dependency_copies[1].attrib["SourceFiles"],
                         r"$(RuntimeComponentBuildOutputRoot)\loader\x64\RuntimeLoader.exe")
        self.assertEqual(dependency_copies[1].attrib["DestinationFiles"],
                         r"$(RuntimeComponentBuildSourceRoot)\x64\Release\RuntimeLoader.exe")

        build_actions = []
        for child in target:
            kind = child.tag.rsplit("}", 1)[-1]
            if kind == "MSBuild":
                build_actions.append(child.attrib["Properties"])
            elif kind == "Copy" and child not in source_copies:
                build_actions.append(child.attrib["SourceFiles"])
            elif kind == "Exec" and "stage_runtime_components.py" in child.attrib["Command"]:
                build_actions.append("stage")
        self.assertEqual(build_actions, [
            "$(RuntimeLibraryWin32Properties)",
            "$(RuntimeLibraryX64Properties)",
            r"$(RuntimeComponentBuildOutputRoot)\library\x86\Runtime32.dll;$(RuntimeComponentBuildOutputRoot)\library\x64\Runtime64.dll",
            "$(RuntimeControllerX64Properties)",
            r"$(RuntimeComponentBuildOutputRoot)\loader\x64\RuntimeLoader.exe",
            "$(RuntimeControllerWin32Properties)",
            "stage",
        ])

        command = target.find("m:Exec", namespace).attrib["Command"]
        self.assertIn(r'--x86 "$(RuntimeComponentBuildOutputRoot)\loader\x86\RuntimeLoader.exe"', command)
        self.assertIn(r'--x64 "$(RuntimeComponentBuildOutputRoot)\loader\x64\RuntimeLoader.exe"', command)
        self.assertNotIn(r"$(RuntimeComponentSourceRoot)\x86\Release", command)
        self.assertNotIn(r"$(RuntimeComponentSourceRoot)\x64\Release", command)
        serialized_target = ET.tostring(target, encoding="unicode")
        self.assertNotIn(r"$(RuntimeComponentSourceRoot)\x86\Release", serialized_target)
        self.assertNotIn(r"$(RuntimeComponentSourceRoot)\x64\Release", serialized_target)
        self.assertNotIn("RuntimeInitiallyInactive", ET.tostring(root, encoding="unicode"))


if __name__ == "__main__":
    unittest.main()
