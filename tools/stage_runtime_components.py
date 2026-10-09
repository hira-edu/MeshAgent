#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import struct
import sys
from pathlib import Path


IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_FILE_DLL = 0x2000
CONTRACT_HEADER = (
    Path(__file__).resolve().parents[1]
    / "meshservice"
    / "runtime_component_resources.h"
)


def _read_contract() -> dict:
    source = CONTRACT_HEADER.read_text(encoding="utf-8")

    def integer(name: str) -> int:
        match = re.search(
            rf"^#define\s+{re.escape(name)}\s+(0x[0-9A-Fa-f]+|[0-9]+)u?$",
            source,
            re.MULTILINE,
        )
        if match is None:
            raise RuntimeError(f"missing integer contract definition: {name}")
        return int(match.group(1), 0)

    return {
        "catalog_magic": integer("MESH_RUNTIME_CATALOG_MAGIC"),
        "catalog_version": integer("MESH_RUNTIME_CATALOG_VERSION"),
        "catalog_header_size": integer("MESH_RUNTIME_CATALOG_HEADER_SIZE"),
        "catalog_entry_size": integer("MESH_RUNTIME_CATALOG_ENTRY_SIZE"),
        "catalog_entry_count": integer("MESH_RUNTIME_CATALOG_ENTRY_COUNT"),
        "role_x86": integer("MESH_RUNTIME_COMPONENT_ROLE_CONTROLLER_X86"),
        "role_x64": integer("MESH_RUNTIME_COMPONENT_ROLE_CONTROLLER_X64"),
        "maximum_image_size": integer("MESH_RUNTIME_COMPONENT_MAX_SIZE"),
    }


CONTRACT = _read_contract()
CATALOG_MAGIC = CONTRACT["catalog_magic"]
CATALOG_VERSION = CONTRACT["catalog_version"]
CATALOG_HEADER_SIZE = CONTRACT["catalog_header_size"]
CATALOG_ENTRY_SIZE = CONTRACT["catalog_entry_size"]
CATALOG_ENTRY_COUNT = CONTRACT["catalog_entry_count"]
MAX_COMPONENT_IMAGE_SIZE = CONTRACT["maximum_image_size"]

if CATALOG_HEADER_SIZE != struct.calcsize("<IIII"):
    raise RuntimeError("runtime component catalog header layout does not match the contract")
if CATALOG_ENTRY_SIZE != struct.calcsize("<IIQ32s"):
    raise RuntimeError("runtime component catalog entry layout does not match the contract")
if CATALOG_ENTRY_COUNT != 2:
    raise RuntimeError("runtime component staging currently requires exactly two roles")


class ComponentImageError(ValueError):
    pass


def _unpack(fmt: str, data: bytes, offset: int):
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise ComponentImageError("truncated PE structure")
    return struct.unpack_from(fmt, data, offset)


def inspect_pe(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) < 4096 or len(data) > MAX_COMPONENT_IMAGE_SIZE:
        raise ComponentImageError(f"component image size {len(data)} is outside the supported range")
    if data[:2] != b"MZ":
        raise ComponentImageError("missing DOS header")
    (pe_offset,) = _unpack("<I", data, 0x3C)
    if pe_offset < 0x40 or pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ComponentImageError("missing or invalid PE signature")

    machine, section_count, _, _, _, optional_size, characteristics = _unpack(
        "<HHIIIHH", data, pe_offset + 4
    )
    if section_count == 0 or section_count > 96:
        raise ComponentImageError("invalid PE section count")
    if (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0 or (characteristics & IMAGE_FILE_DLL) != 0:
        raise ComponentImageError("component image is not marked as an executable application")

    optional_offset = pe_offset + 24
    if optional_size < 2 or optional_offset + optional_size > len(data):
        raise ComponentImageError("invalid PE optional header")
    (optional_magic,) = _unpack("<H", data, optional_offset)
    if machine == IMAGE_FILE_MACHINE_I386 and optional_magic == 0x10B:
        data_directory_offset = optional_offset + 96
        number_of_directories_offset = optional_offset + 92
    elif machine == IMAGE_FILE_MACHINE_AMD64 and optional_magic == 0x20B:
        data_directory_offset = optional_offset + 112
        number_of_directories_offset = optional_offset + 108
    else:
        raise ComponentImageError("PE machine and optional-header magic do not match")
    if data_directory_offset + 8 > optional_offset + optional_size:
        raise ComponentImageError("PE export directory is absent")
    (number_of_directories,) = _unpack("<I", data, number_of_directories_offset)
    (section_alignment,) = _unpack("<I", data, optional_offset + 32)
    (file_alignment,) = _unpack("<I", data, optional_offset + 36)
    (size_of_image,) = _unpack("<I", data, optional_offset + 56)
    (size_of_headers,) = _unpack("<I", data, optional_offset + 60)
    (entry_point,) = _unpack("<I", data, optional_offset + 16)
    available_directories = (optional_offset + optional_size - data_directory_offset) // 8
    section_alignment_is_power_of_two = (
        section_alignment != 0 and (section_alignment & (section_alignment - 1)) == 0
    )
    file_alignment_is_power_of_two = (
        file_alignment != 0 and (file_alignment & (file_alignment - 1)) == 0
    )
    valid_alignment = (
        section_alignment_is_power_of_two
        and file_alignment_is_power_of_two
        and section_alignment >= file_alignment
        and (
            (section_alignment < 0x1000 and file_alignment == section_alignment)
            or (section_alignment >= 0x1000 and 0x200 <= file_alignment <= 0x10000)
        )
    )
    if (
        number_of_directories > available_directories
        or not valid_alignment
        or entry_point == 0
        or size_of_image == 0
        or size_of_image % section_alignment != 0
        or size_of_headers == 0
        or size_of_headers % file_alignment != 0
        or size_of_headers > size_of_image
        or size_of_headers > len(data)
    ):
        raise ComponentImageError("invalid PE image layout")

    section_offset = optional_offset + optional_size
    if section_offset + section_count * 40 > size_of_headers:
        raise ComponentImageError("PE section table is outside the headers")
    sections = []
    entry_point_valid = False
    for index in range(section_count):
        current = section_offset + index * 40
        if current + 40 > len(data):
            raise ComponentImageError("truncated PE section table")
        virtual_size, virtual_address, raw_size, raw_offset = _unpack("<IIII", data, current + 8)
        (section_characteristics,) = _unpack("<I", data, current + 36)
        if virtual_address % section_alignment != 0:
            raise ComponentImageError("PE section virtual address is misaligned")
        if raw_size and (raw_offset % file_alignment != 0 or raw_size % file_alignment != 0):
            raise ComponentImageError("PE section raw data is misaligned")
        if section_alignment < 0x1000 and raw_offset != virtual_address:
            raise ComponentImageError("low-alignment PE section offsets do not match")
        if virtual_size or raw_size:
            span = max(virtual_size, raw_size)
            if virtual_address < size_of_headers:
                raise ComponentImageError("PE section overlaps the headers")
            for prior_virtual_address, prior_virtual_size, _, prior_raw_size, _ in sections:
                prior_span = max(prior_virtual_size, prior_raw_size)
                if prior_span and (
                    virtual_address < prior_virtual_address + prior_span
                    and prior_virtual_address < virtual_address + span
                ):
                    raise ComponentImageError("PE virtual sections overlap")
        if raw_size:
            if raw_offset < size_of_headers:
                raise ComponentImageError("PE section raw data overlaps the headers")
            for _, _, prior_raw_offset, prior_raw_size, _ in sections:
                if prior_raw_size and (
                    raw_offset < prior_raw_offset + prior_raw_size
                    and prior_raw_offset < raw_offset + raw_size
                ):
                    raise ComponentImageError("PE raw sections overlap")
        if raw_size and (raw_offset >= len(data) or raw_offset + raw_size > len(data)):
            raise ComponentImageError("PE section data is outside the file")
        span = max(virtual_size, raw_size)
        if span and (
            virtual_address >= size_of_image
            or virtual_address + span > size_of_image
            or virtual_address + span > 0xFFFFFFFF
        ):
            raise ComponentImageError("PE section exceeds SizeOfImage")
        if (
            virtual_address <= entry_point < virtual_address + raw_size
            and section_characteristics & 0x20000000
        ):
            entry_point_valid = True
        sections.append(
            (virtual_address, virtual_size, raw_offset, raw_size, section_characteristics)
        )
    if not entry_point_valid:
        raise ComponentImageError("PE entry point is not executable file-backed code")

    return {
        "machine": machine,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "data": data,
    }

def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(data)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _resource_script(destination: Path) -> bytes:
    def quoted(path: Path) -> str:
        return str(path.resolve()).replace("\\", "\\\\").replace('"', '\\"')

    return (
        '#pragma code_page(65001)\n'
        '#include "runtime_component_resources.h"\n\n'
        f'IDR_RUNTIME_CONTROLLER_X86 RCDATA "{quoted(destination / "runtime-controller-x86.exe")}"\n'
        f'IDR_RUNTIME_CONTROLLER_X64 RCDATA "{quoted(destination / "runtime-controller-x64.exe")}"\n'
        f'IDR_RUNTIME_COMPONENT_CATALOG RCDATA "{quoted(destination / "catalog.bin")}"\n'
    ).encode("utf-8")


def stage_components(
    repo_root: Path,
    x86_path: Path,
    x64_path: Path,
    destination: Path | None = None,
) -> dict:
    inputs = [
        ("runtime-controller-x86", CONTRACT["role_x86"], IMAGE_FILE_MACHINE_I386, x86_path),
        ("runtime-controller-x64", CONTRACT["role_x64"], IMAGE_FILE_MACHINE_AMD64, x64_path),
    ]
    records = []
    for name, role, expected_machine, source in inputs:
        if not source.is_file():
            raise FileNotFoundError(f"missing {name} component image: {source}")
        record = inspect_pe(source)
        if record["machine"] != expected_machine:
            raise ComponentImageError(
                f"{name} machine 0x{record['machine']:04X} does not match 0x{expected_machine:04X}"
            )
        record.update({"name": name, "role": role, "source": str(source.resolve())})
        records.append(record)

    if destination is None:
        destination = repo_root / "meshservice" / "embedded" / "runtime-components"
    destination = destination.resolve()
    for record in records:
        _atomic_write(destination / f"{record['name']}.exe", record["data"])

    catalog = struct.pack(
        "<IIII", CATALOG_MAGIC, CATALOG_VERSION, CATALOG_HEADER_SIZE, len(records)
    )
    for record in records:
        catalog += struct.pack(
            "<IIQ32s",
            record["role"],
            record["machine"],
            record["size"],
            bytes.fromhex(record["sha256"]),
        )
    _atomic_write(destination / "catalog.bin", catalog)

    metadata = {
        "version": CATALOG_VERSION,
        "catalogSize": len(catalog),
        "components": [
            {key: value for key, value in record.items() if key != "data"}
            for record in records
        ],
    }
    _atomic_write(
        destination / "catalog.json",
        (json.dumps(metadata, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    _atomic_write(destination / "RuntimeComponents.generated.rc", _resource_script(destination))
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate and stage embedded runtime components.")
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--x86", required=True)
    parser.add_argument("--x64", required=True)
    parser.add_argument("--destination")
    args = parser.parse_args()
    try:
        metadata = stage_components(
            Path(args.repo_root).resolve(),
            Path(args.x86).resolve(),
            Path(args.x64).resolve(),
            Path(args.destination).resolve() if args.destination else None,
        )
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    for record in metadata["components"]:
        print(
            f"[OK] {record['name']} machine=0x{record['machine']:04X} "
            f"size={record['size']} sha256={record['sha256']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
