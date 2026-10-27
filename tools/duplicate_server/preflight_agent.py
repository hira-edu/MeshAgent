#!/usr/bin/env python3
"""Refuse a duplicate-server test-agent build that could point at production.

    python tools/duplicate_server/preflight_agent.py --branding <branding.json> --msh <dup.msh>

Fails (exit 1) when:
  - --branding or --msh is missing, so MeshAgent.Build.proj would pick its implicit default
    (branding_config.local.json, WinDiagnosticHost.msh; docs/CONFIGURATION.md "Provisioning manifest
    selection");
  - either file is the repository's own branding_config.local.json, WinDiagnosticHost.msh or
    MeshAgent.msh, or lives inside the repository;
  - either file names a production host, IP, ServerID or MeshID from the denylist (C:\\mc-dup\\denylist.json);
  - the .msh has no 96-hex ServerID, or its MeshServer is not a loopback, private-network or
    *.localhost / *.test host.
On success it prints the msbuild command to run on the VM build host.
"""
import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from dup_common import DENYLIST_PATH, WORKTREE_ROOT, DupError  # noqa: E402
from dup_config import load_denylist, msh_identifiers, parse_msh, scan_text  # noqa: E402

PROPERTY_RE = r"<{name} Condition=\"'\$\({name}\)'==''(?: and Exists\('\$\(RepoRoot\)([^']+)'\))?\">\$\(RepoRoot\)([^<]+)</{name}>"
LOCAL_SUFFIXES = (".localhost", ".test")


def implicit_defaults(repo, name):
    """The files MeshAgent.Build.proj picks for a property left empty, in its own order."""
    proj = (repo / "MeshAgent.Build.proj").read_text(encoding="utf-8")
    rules = re.findall(PROPERTY_RE.format(name=name), proj)
    if not rules:
        raise DupError(f"MeshAgent.Build.proj no longer defines a default for {name}; update this preflight")
    for exists_file, value in rules:
        if exists_file and exists_file != value:
            raise DupError(f"Unexpected {name} rule in MeshAgent.Build.proj: Exists({exists_file}) -> {value}")
    return [value for _, value in rules]


def implicit_choice(repo, name):
    for candidate in implicit_defaults(repo, name):
        if (repo / candidate).exists():
            return repo / candidate
    return repo / implicit_defaults(repo, name)[-1]


def host_is_local(host):
    host = host.strip("[]").lower()
    try:
        address = ipaddress.ip_address(host)
        return address.is_loopback or address.is_private or address.is_link_local
    except ValueError:
        return host == "localhost" or host.endswith(LOCAL_SUFFIXES)


def check(branding, msh, repo, denylist_path):
    errors = []
    repo = repo.resolve()
    for flag, path, prop in (("--branding", branding, "MeshAgentBrandingConfig"),
                             ("--msh", msh, "MeshAgentProvisioningManifest")):
        if path is None:
            errors.append(f"{flag} is required: without /p:{prop} the build would use {implicit_choice(repo, prop)}")
    if errors:
        return errors
    branding, msh = branding.resolve(), msh.resolve()
    for label, path, prop in (("branding config", branding, "MeshAgentBrandingConfig"),
                              ("manifest", msh, "MeshAgentProvisioningManifest")):
        defaults = {(repo / d).resolve() for d in implicit_defaults(repo, prop)}
        if path in defaults:
            errors.append(f"{label} {path} is one of the build's implicit production defaults; refusing to open it")
        elif path.is_relative_to(repo):
            errors.append(f"{label} {path} is inside the repository; keep duplicate-only files outside it")
        elif not path.is_file():
            errors.append(f"{label} {path} does not exist")
    if errors:
        return errors

    tokens = load_denylist(denylist_path)
    branding_text = branding.read_text(encoding="utf-8")
    msh_bytes = msh.read_bytes()
    for label, text in (("branding config", branding_text), ("manifest", msh_bytes.decode("utf-8", errors="replace"))):
        hits = scan_text(text, tokens)
        if hits:
            errors.append(f"{label} names production identifiers: " + ", ".join(h[:16] + ("..." if len(h) > 16 else "") for h in hits))

    values = parse_msh(msh_bytes)
    ids, hosts = msh_identifiers(values)
    if not re.fullmatch(r"[0-9a-f]{96}", ids.get("ServerID", "")):
        errors.append("manifest ServerID is missing or not a 96-hex SHA-384 key hash")
    if not hosts:
        errors.append("manifest MeshServer has no wss:// host")
    for host in hosts:
        if not host_is_local(host):
            errors.append(f"manifest MeshServer host {host} is not loopback, private or *.localhost/*.test")

    try:
        config = json.loads(branding_text)
    except json.JSONDecodeError as error:
        errors.append(f"branding config is not JSON: {error}")
        return errors
    for section, key in (("network", "primaryEndpoint"), ("provisioning", "serverUrl")):
        value = str((config.get(section) or {}).get(key) or "")
        match = re.match(r"wss?://([^/:]+|\[[^\]]+\])", value)
        if match and "REPLACE_WITH" not in value and not host_is_local(match.group(1)):
            errors.append(f"branding {section}.{key} host {match.group(1)} is not loopback, private or *.localhost/*.test")
    server_id = str((config.get("provisioning") or {}).get("serverId") or "").lower()
    if server_id and "replace_with" not in server_id and server_id != ids.get("ServerID"):
        errors.append("branding provisioning.serverId differs from the manifest ServerID")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--branding", type=Path)
    parser.add_argument("--msh", type=Path)
    parser.add_argument("--repo", type=Path, default=WORKTREE_ROOT, help="MeshAgent checkout that will build the agent")
    parser.add_argument("--denylist", type=Path, default=DENYLIST_PATH)
    args = parser.parse_args(argv)
    try:
        errors = check(args.branding, args.msh, args.repo, args.denylist)
    except DupError as error:
        errors = [str(error)]
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[OK] branding config and manifest are duplicate-only.")
    print("Build on the VM build host with both properties explicit:")
    print(f'  msbuild .\\MeshAgent.Build.proj /m /nologo /verbosity:minimal '
          f'"/p:MeshAgentBrandingConfig={args.branding.resolve()}" '
          f'"/p:MeshAgentProvisioningManifest={args.msh.resolve()}"')
    return 0


if __name__ == "__main__":
    sys.exit(main())
