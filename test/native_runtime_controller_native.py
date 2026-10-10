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
    assert "FILE_FLAG_OVERLAPPED" in binding and "CreateProcessW" in binding
    assert "CancelIoEx" in binding and "GetOverlappedResult" in binding
    assert "MeshRuntimeBinding_Remaining" in binding
    execute = binding[binding.index("duk_ret_t MeshRuntimeBinding_Execute"):]
    assert execute.index("ReleaseSRWLockExclusive(&g_MeshRuntimeBindingLock)") < execute.index(
        "AcquireSRWLockExclusive(&g_MeshRuntimeTransactionLock)"
    ), "pipe I/O must not hold the supervision/shutdown lock"
    assert "CreateThread" in binding and "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE" in binding
    assert "MeshRuntimeBinding_Shutdown" in binding
    for forbidden in ("expectedGeneration", "controllerEpoch", "MeshRuntimeTarget", "policy"):
        assert forbidden not in binding, f"MeshAgent must not own {forbidden}"
    assert "MESH_RUNTIME_PIPE_TIMEOUT_MS" in binding
    assert "#define MESH_RUNTIME_PIPE_TIMEOUT_MS 1000u" in binding
    assert "one absolute connect/write/read deadline" in binding
    assert "outside a wall-clock claim" in binding
    print("PASS native runtime boundary: install/supervise/fixed relay only; no policy or target state")


if __name__ == "__main__":
    main()
