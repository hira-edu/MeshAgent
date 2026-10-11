#!/usr/bin/env python3
"""Exercise the native-runtime relay boundary without simulating target policy."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
CC = os.environ.get("CC", "clang" if os.name == "nt" else "cc")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="mesh-runtime-relay-") as directory:
        binary = Path(directory) / "relay"
        subprocess.run(
            [
                CC,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-fsanitize=address,undefined",
                "-I" + str(ROOT / "meshservice"),
                str(ROOT / "meshservice/runtime_controller.c"),
                str(ROOT / "test/native_runtime_controller_cases.c"),
                "-o",
                str(binary),
            ],
            check=True,
        )
        runtime_env = os.environ.copy()
        if os.name == "nt":
            compiler = shutil.which(CC)
            if compiler:
                runtimes = list(
                    Path(compiler).parent.parent.glob(
                        "lib/clang/*/lib/windows/clang_rt.asan_dynamic-*.dll"
                    )
                )
                if runtimes:
                    runtime_env["PATH"] = (
                        str(runtimes[0].parent)
                        + os.pathsep
                        + runtime_env.get("PATH", "")
                    )
        subprocess.run([str(binary)], check=True, timeout=20, env=runtime_env)

    binding = (ROOT / "meshcore/runtime_control_binding.c").read_text(encoding="utf-8")
    assert '"getStatus"' not in binding, "operations belong in the portable relay parser"
    assert "MeshRuntimeRelay_Operation" in binding
    assert "CallNamedPipeW" not in binding
    assert "CreateProcessW" in binding, "process launch must use CreateProcessW"
    assert "CREATE_SUSPENDED" in binding, "process launch must create suspended thread before job assignment"
    assert "ResumeThread" in binding, "primary thread must be resumed after job assignment"
    assert "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE" in binding, "Job Object must enforce kill-on-close limit"
    assert "TerminateJobObject" in binding, "unload must terminate via Job Object"
    assert "--controller" not in binding, "binary must launch directly without --controller daemon flag"
    assert "MESH_RUNTIME_PIPE_TIMEOUT_MS" not in binding, "controller pipe timeout must be removed"
    assert "FILE_FLAG_OVERLAPPED" not in binding, "named pipe overlapped I/O must be removed"
    assert "CancelIoEx" not in binding
    assert "GetOverlappedResult" not in binding
    assert "MeshRuntimeBinding_Supervisor" not in binding
    assert "SCRIPT_ENGINE_NO_MESH_AGENT_ACCESS" in binding, "binding must check script container security flags"
    execute = binding[binding.index("duk_ret_t MeshRuntimeBinding_Execute"):]
    assert "MeshRuntimeComponents_InstallControllers" not in execute, \
        "command processing must not hash or rewrite controller images on the event loop"
    assert "g_MeshRuntimeInstallError" in execute, "load must fail closed on a startup install error"
    assert "endpoint->launchError = jobError;" in execute, "load must fail closed without a kill-on-close job"
    assert "ERROR_PROCESS_ABORTED" in execute, "status must distinguish a crashed controller from never-started"
    assert "MeshRuntimeBinding_Shutdown" in binding
    for forbidden in ("expectedGeneration", "controllerEpoch", "MeshRuntimeTarget", "policy"):
        assert forbidden not in binding, f"MeshAgent must not own {forbidden}"
    print("PASS native runtime boundary: direct process lifecycle via job object; no controller pipe or policy")


if __name__ == "__main__":
    main()
