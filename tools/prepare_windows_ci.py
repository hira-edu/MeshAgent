"""Materialize CI inputs without allowing validation fixtures into a release."""
import argparse
import json
import os
from pathlib import Path
from urllib.parse import urlsplit


def prepare_inputs(root, environment, require_deployment=False):
    branding_text = environment.get("BRANDING_CONFIG_JSON", "").strip()
    manifest_text = environment.get("PROVISIONING_MSH", "").strip()
    deployment_ready = bool(branding_text and manifest_text)
    if require_deployment and not deployment_ready:
        raise ValueError("Release, deployment and runtime validation require BRANDING_CONFIG_JSON and PROVISIONING_MSH")
    config = json.loads(branding_text) if branding_text else json.loads(
        (root / "branding_config.json").read_text(encoding="utf-8")
    )
    branding = config.get("branding", {})
    for key in ("serviceName", "displayName"):
        if not isinstance(branding.get(key), str) or not branding[key].strip() or any(c in branding[key] for c in "\r\n"):
            raise ValueError(f"branding.{key} must be a nonempty single-line string")
    if deployment_ready and "REPLACE_WITH" in json.dumps(config).upper():
        raise ValueError("Deployment branding still contains template placeholders")
    if manifest_text:
        fields = {}
        for line in manifest_text.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            key, separator, value = line.partition("=")
            key = key.strip().lower()
            if not separator or key in fields:
                raise ValueError("Provisioning manifest contains an invalid or duplicate field")
            fields[key] = value.strip()
        for key in ("meshid", "serverid", "meshserver"):
            if not fields.get(key) or "REPLACE_WITH" in fields[key].upper():
                raise ValueError(f"Provisioning manifest requires a configured {key}")
        endpoint = urlsplit(fields["meshserver"])
        if endpoint.scheme not in ("ws", "wss") or not endpoint.hostname:
            raise ValueError("Provisioning MeshServer must be a ws/wss URL")
        for key, expected in (("meshservicename", branding["serviceName"]), ("displayname", branding["displayName"])):
            if fields.get(key, expected) != expected:
                raise ValueError(f"Provisioning {key} differs from branding")
    else:
        manifest_text = (
            "MeshID=0x" + "00" * 48 + "\nServerID=" + "00" * 48 +
            "\nMeshServer=wss://validation.invalid/agent.ashx\nMeshType=2\n" +
            f"meshServiceName={branding['serviceName']}\ndisplayName={branding['displayName']}\n"
        )
    # Validate all inputs before writing either file. Never echo provisioning.
    (root / "branding_config.local.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    (root / "MeshAgent.msh").write_text(manifest_text + "\n", encoding="utf-8")
    return deployment_ready


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--require-deployment", action="store_true")
    args = parser.parse_args()
    required = args.require_deployment or os.environ.get("REQUIRE_DEPLOYMENT_CONFIG", "").lower() == "true"
    ready = prepare_inputs(args.repo_root, os.environ, required)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            output.write(f"deployment_ready={str(ready).lower()}\n")
    print("Prepared deployment inputs" if ready else "Prepared build-only validation inputs; publication is disabled")


if __name__ == "__main__":
    main()
