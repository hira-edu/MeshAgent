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
    runtime = config.get("runtime", {}) or {}
    name = branding.get("serviceDllName") or runtime.get("serviceDllName") or "meshsvc.dll"
    return str(name).strip() or "meshsvc.dll"


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def refresh_service_bundle(
    repo_root: Path,
    dll_path: Path,
    config_path: Path,
    architecture: str = "x64",
) -> None:
    if architecture not in {"x64", "arm64"}:
        raise ValueError(f"Unsupported Windows service-bundle architecture: {architecture}")
    if not dll_path.exists():
        raise FileNotFoundError(
            f"Missing service-bundle DLL '{dll_path}'. Build MeshServiceBundle|{architecture} "
            f"before MeshServiceRuntime|{architecture}."
        )

    installer_dll_name = load_service_dll_name(config_path)
    generated_dir = repo_root / "meshcore" / "embedded" / "generated"
    header_path = generated_dir / "service_bundle.h"
    metadata_path = generated_dir / f"service_bundle.{architecture}.json"
    embedded_dir = repo_root / "meshservice" / "embedded"
    embedded_dll_path = embedded_dir / architecture / "service_bundle.dll"
    installer_dir = repo_root / "meshservice" / "installer" / "components"
    installer_dll_path = installer_dir / installer_dll_name

    for directory in [generated_dir, embedded_dll_path.parent, installer_dir]:
        directory.mkdir(parents=True, exist_ok=True)

    shutil.copy2(dll_path, embedded_dll_path)

    # Preserve the established x64 compatibility paths used by the existing
    # installer and deployment flow. ARM64 has its own isolated embedded copy.
    if architecture == "x64":
        compatibility_dll_path = embedded_dir / "service_bundle.dll"
        for existing in installer_dir.glob("*.dll"):
            if existing.name.lower() != installer_dll_name.lower():
                existing.unlink()
        shutil.copy2(dll_path, compatibility_dll_path)
        shutil.copy2(dll_path, installer_dll_path)
    else:
        compatibility_dll_path = None
        installer_dll_path = None

    if header_path.exists():
        header_path.unlink()

    metadata = {
        "input": str(dll_path.resolve()),
        "architecture": architecture,
        "sha256": file_sha256(dll_path),
        "size": dll_path.stat().st_size,
        "embeddedDll": str(embedded_dll_path.resolve()),
        "compatibilityEmbeddedDll": (
            str(compatibility_dll_path.resolve()) if compatibility_dll_path else None
        ),
        "installerDll": str(installer_dll_path.resolve()) if installer_dll_path else None,
        "generatedUtc": datetime.now(timezone.utc).isoformat(),
    }
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8", newline="\n")
    if architecture == "x64":
        compatibility_metadata_path = generated_dir / "service_bundle.json"
        compatibility_metadata_path.write_text(
            json.dumps(metadata, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
    print(f"[OK] Synced service bundle from {dll_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh the embedded service bundle from the built DLL.")
    parser.add_argument("--repo-root", dest="repo_root")
    parser.add_argument("--dll", dest="dll_path")
    parser.add_argument("--config", dest="config_path")
    parser.add_argument("--architecture", choices=("x64", "arm64"), default="x64")
    args = parser.parse_args()

    repo_root = repo_root_from(args.repo_root)
    dll_path = (
        Path(args.dll_path).resolve()
        if args.dll_path
        else (
            repo_root
            / "meshservice"
            / ("ARM64" if args.architecture == "arm64" else "x64")
            / "MeshServiceBundle"
            / "MeshService-2022.dll"
        )
    )
    try:
        config_path = choose_config_path(repo_root, args.config_path)
        refresh_service_bundle(repo_root, dll_path, config_path, args.architecture)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
