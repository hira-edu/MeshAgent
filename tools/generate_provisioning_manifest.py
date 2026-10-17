#!/usr/bin/env python3
"""Generate the Windows MeshAgent provisioning sidecar from branding JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


FIELDS = (
    ("MeshName", "provisioning", "meshName"),
    ("MeshType", "provisioning", "meshType"),
    ("MeshID", "provisioning", "meshId"),
    ("ServerID", "provisioning", "serverId"),
    ("MeshServer", "provisioning", "serverUrl"),
    ("meshServiceName", "branding", "serviceName"),
    ("displayName", "branding", "displayName"),
    ("companyName", "branding", "companyName"),
    ("description", "branding", "description"),
    ("fileName", "branding", "binaryName"),
)


def build_manifest(config: dict, allow_placeholders: bool = False) -> str:
    lines: list[str] = []
    for output_key, section_name, input_key in FIELDS:
        section = config.get(section_name)
        value = section.get(input_key) if isinstance(section, dict) else None
        text = "" if value is None else str(value).strip()
        if not text:
            raise ValueError(f"{section_name}.{input_key} must be populated")
        if "\n" in text or "\r" in text:
            raise ValueError(f"{section_name}.{input_key} must be a single line")
        if not allow_placeholders and "REPLACE_WITH_" in text.upper():
            raise ValueError(f"{section_name}.{input_key} still contains a deployment placeholder")
        lines.append(f"{output_key}={text}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--allow-placeholders", action="store_true")
    args = parser.parse_args()

    config_path = Path(args.config).resolve()
    output_path = Path(args.output).resolve()
    try:
        config = json.loads(config_path.read_text(encoding="utf-8-sig"))
        manifest = build_manifest(config, allow_placeholders=args.allow_placeholders)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(manifest, encoding="utf-8", newline="\n")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    print(f"[OK] Provisioning manifest generated: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
