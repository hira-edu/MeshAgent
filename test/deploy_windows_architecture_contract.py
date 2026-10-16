#!/usr/bin/env python3
"""Contract checks for fail-closed Windows PE architecture detection."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import deploy


def write_pe(path: Path, machine: int) -> None:
    image = bytearray(0x100)
    image[0:2] = b"MZ"
    image[0x3C:0x40] = (0x80).to_bytes(4, "little")
    image[0x80:0x84] = b"PE\0\0"
    image[0x84:0x86] = machine.to_bytes(2, "little")
    path.write_bytes(image)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="meshagent-pe-machine-") as temp_dir:
        root = Path(temp_dir)
        x64 = root / "x64.exe"
        arm64 = root / "arm64.exe"
        invalid = root / "invalid.exe"
        write_pe(x64, 0x8664)
        write_pe(arm64, 0xAA64)
        invalid.write_bytes(b"not a pe")

        assert deploy.read_pe_machine(x64) == 0x8664
        assert deploy.read_pe_machine(arm64) == 0xAA64
        try:
            deploy.read_pe_machine(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("invalid PE input was not rejected")

    print("deploy Windows architecture contract passed")


if __name__ == "__main__":
    main()
