#!/usr/bin/env python3
import argparse
import re
import sys
from pathlib import Path


def extract_define(text: str, name: str) -> str | None:
    pattern = re.compile(rf'#define\s+{re.escape(name)}\s+"([^"]*)"')
    match = pattern.search(text)
    return match.group(1) if match else None


def update_rc(commit_header: Path, rc_path: Path) -> bool:
    commit_text = commit_header.read_text(encoding="utf-8", errors="replace")
    commit_hash = extract_define(commit_text, "SOURCE_COMMIT_HASH")
    commit_date = extract_define(commit_text, "SOURCE_COMMIT_DATE")
    if not commit_hash or not commit_date:
        raise ValueError(f"Missing commit metadata in {commit_header}")

    original = rc_path.read_text(encoding="utf-8", errors="replace")
    lines = original.splitlines()
    updated_lines = []
    changed = False

    for line in lines:
        parts = line.split('"')
        if len(parts) >= 4:
            if parts[1] == "ProductVersion":
                new_value = "Commit: " + commit_date
                if parts[3] != new_value:
                    parts[3] = new_value
                    changed = True
                line = '"'.join(parts)
            elif parts[1] == "FileVersion":
                if parts[3] != commit_date:
                    parts[3] = commit_date
                    changed = True
                line = '"'.join(parts)
        updated_lines.append(line)

    if changed:
        rc_path.write_text("\n".join(updated_lines) + "\n", encoding="utf-8", newline="\n")
    return changed


def main() -> int:
    parser = argparse.ArgumentParser(description="Update MeshService.rc with commit metadata.")
    parser.add_argument("commit_header")
    parser.add_argument("resource_file")
    args = parser.parse_args()

    commit_header = Path(args.commit_header).resolve()
    resource_file = Path(args.resource_file).resolve()
    try:
        changed = update_rc(commit_header, resource_file)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    if changed:
        print(f"[OK] Updated {resource_file.name}")
    else:
        print(f"[OK] {resource_file.name} already current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
