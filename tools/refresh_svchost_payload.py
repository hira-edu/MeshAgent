#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


def repo_root_from(path_value: str | None) -> Path:
    if path_value:
        return Path(path_value).resolve()
    return Path(__file__).resolve().parents[1]


def choose_config_path(repo_root: Path, explicit: str | None) -> Path:
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    branding_env = os.environ.get("BRANDING_CONFIG_PATH")
    if not explicit and branding_env:
        candidates.append(Path(branding_env))
    candidates.extend([repo_root / "branding_config.local.json", repo_root / "branding_config.json"])
    for candidate in candidates:
        resolved = candidate if candidate.is_absolute() else (repo_root / candidate)
        if resolved.exists():
            return resolved.resolve()
    raise FileNotFoundError(f"Branding configuration not found under {repo_root}")


def load_service_dll_name(config_path: Path) -> str:
    with config_path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)
    branding = config.get("branding", {}) or {}
    stealth = config.get("stealth", {}) or {}
    name = branding.get("serviceDllName") or stealth.get("serviceDllName") or "meshsvc.dll"
    return str(name).strip() or "meshsvc.dll"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def refresh_payload(repo_root: Path, dll_path: Path, config_path: Path) -> None:
    if not dll_path.exists():
        raise FileNotFoundError(
            f"Missing payload DLL '{dll_path}'. Build StealthLab_DLL|x64 before StealthLab|x64."
        )

    installer_dll_name = load_service_dll_name(config_path)
    generated_dir = repo_root / "meshcore" / "embedded" / "generated"
    header_path = generated_dir / "svchost_payload.h"
    metadata_path = generated_dir / "svchost_payload.json"
    embedded_dir = repo_root / "meshservice" / "embedded"
    embedded_dll_path = embedded_dir / "svchost_payload.dll"
    installer_dir = repo_root / "meshservice" / "installer" / "payload"
    installer_dll_path = installer_dir / installer_dll_name

    for directory in [generated_dir, embedded_dir, installer_dir]:
        directory.mkdir(parents=True, exist_ok=True)

    for existing in installer_dir.glob("*.dll"):
        if existing.name.lower() != installer_dll_name.lower():
            existing.unlink()

    shutil.copy2(dll_path, embedded_dll_path)
    shutil.copy2(dll_path, installer_dll_path)

    if header_path.exists():
        header_path.unlink()

    payload = {
        "input": str(dll_path.resolve()),
        "sha256": file_sha256(dll_path),
        "size": dll_path.stat().st_size,
        "embeddedDll": str(embedded_dll_path.resolve()),
        "installerDll": str(installer_dll_path.resolve()),
        "generatedUtc": datetime.now(timezone.utc).isoformat(),
    }
    metadata_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"[OK] Synced payload from {dll_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh the embedded svchost payload from the built DLL.")
    parser.add_argument("--repo-root", dest="repo_root")
    parser.add_argument("--dll", dest="dll_path")
    parser.add_argument("--config", dest="config_path")
    args = parser.parse_args()

    repo_root = repo_root_from(args.repo_root)
    dll_path = (
        Path(args.dll_path).resolve()
        if args.dll_path
        else (repo_root / "meshservice" / "x64" / "StealthLab_DLL" / "MeshService-2022.dll")
    )
    try:
        config_path = choose_config_path(repo_root, args.config_path)
        refresh_payload(repo_root, dll_path, config_path)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
