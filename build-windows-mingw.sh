#!/bin/bash
# MeshAgent Windows Build Script using MinGW-w64
# Builds Windows service and console agents for x86 and x64

set -e

MESH_VER=194
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== MeshAgent Windows Build with MinGW-w64 ==="
echo "Version: $MESH_VER"
echo ""

LOG_ROOT="build/mingw"
LOG_FILE="$LOG_ROOT/build-mingw.log"
mkdir -p "$LOG_ROOT"
: > "$LOG_FILE"

log_info() {
    echo "[INFO] $1" | tee -a "$LOG_FILE"
}

log_warn() {
    echo "[WARN] $1" | tee -a "$LOG_FILE" >&2
}

log_error() {
    echo "[ERROR] $1" | tee -a "$LOG_FILE" >&2
}

# Generate provisioning data if Python is available
if command -v python &> /dev/null; then
    log_info "Generating provisioning data with Python..."
    python ./tools/generate_branding_assets.py --repo-root .
else
        log_warn "Python not found. Building without custom provisioning."
        log_warn "Install Python 3 to enable branding."
fi
echo ""

SERVICE_NAME=""
DISPLAY_NAME=""
MESH_ID=""
SERVER_ID=""

CONFIG_FILE="branding_config.local.json"
if [ ! -f "$CONFIG_FILE" ]; then
    CONFIG_FILE="branding_config.json"
fi

if [ -f "$CONFIG_FILE" ]; then
    log_info "Reading branding metadata from $CONFIG_FILE"
    readarray -t BRANDING_VALUES < <(python - "$CONFIG_FILE" <<'PY' 2>/dev/null
import json
import sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    cfg = json.load(fh)
branding = cfg.get("branding", {})
prov = cfg.get("provisioning", {})
print(branding.get("serviceName", ""))
print(branding.get("displayName", ""))
print(prov.get("meshId", ""))
print(prov.get("serverId", ""))
PY
)
    SERVICE_NAME="${BRANDING_VALUES[0]}"
    DISPLAY_NAME="${BRANDING_VALUES[1]}"
    MESH_ID="${BRANDING_VALUES[2]}"
    SERVER_ID="${BRANDING_VALUES[3]}"
else
    log_warn "Branding configuration not found; binaries will be built with placeholder metadata."
fi

validate_binary() {
    local binary="$1"
    local arch="$2"

    if [ ! -f "$binary" ]; then
        log_warn "Validation skipped: $binary not found"
        return
    }

    if command -v strings >/dev/null 2>&1; then
        if [ -n "$SERVICE_NAME" ]; then
            if strings "$binary" | grep -Fq "$SERVICE_NAME"; then
                log_info "[$arch] Found service name '$SERVICE_NAME' in $(basename "$binary")"
            else
                log_warn "[$arch] Service name '$SERVICE_NAME' not located in $(basename "$binary")"
            fi
        fi
        if [ -n "$DISPLAY_NAME" ]; then
            if strings "$binary" | grep -Fq "$DISPLAY_NAME"; then
                log_info "[$arch] Found display name '$DISPLAY_NAME' in $(basename "$binary")"
            else
                log_warn "[$arch] Display name '$DISPLAY_NAME' not located in $(basename "$binary")"
            fi
        fi
        if [ -n "$MESH_ID" ]; then
            if strings "$binary" | grep -Fq "$MESH_ID"; then
                log_info "[$arch] Mesh ID embedded in $(basename "$binary")"
            else
                log_warn "[$arch] Mesh ID missing from $(basename "$binary")"
            fi
        fi
        if [ -n "$SERVER_ID" ]; then
            if strings "$binary" | grep -Fq "$SERVER_ID"; then
                log_info "[$arch] Server ID embedded in $(basename "$binary")"
            else
                log_warn "[$arch] Server ID missing from $(basename "$binary")"
            fi
        fi
    else
        log_warn "strings command not available; skipping textual validation"
    }

    if command -v osslsigncode >/dev/null 2>&1; then
        if osslsigncode verify -in "$binary" >/dev/null 2>&1; then
            log_info "[$arch] osslsigncode verify succeeded for $(basename "$binary")"
        else
            log_warn "[$arch] osslsigncode verify failed for $(basename "$binary") (expected when unsigned)"
        fi
    else
        log_info "osslsigncode not installed; skipping Authenticode verification for $(basename "$binary")"
    fi
}

# Common source files (from makefile)
SOURCES="microstack/ILibAsyncServerSocket.c microstack/ILibAsyncSocket.c microstack/ILibAsyncUDPSocket.c"
SOURCES="$SOURCES microstack/ILibParsers.c microstack/ILibMulticastSocket.c"
SOURCES="$SOURCES microstack/ILibRemoteLogging.c microstack/ILibWebClient.c microstack/ILibWebServer.c"
SOURCES="$SOURCES microstack/ILibCrypto.c microstack/ILibSimpleDataStore.c microstack/ILibProcessPipe.c"
SOURCES="$SOURCES microstack/ILibIPAddressMonitor.c"
SOURCES="$SOURCES microscript/duktape.c microscript/duk_module_duktape.c"
SOURCES="$SOURCES microscript/ILibDuktape_DuplexStream.c microscript/ILibDuktape_Helpers.c"
SOURCES="$SOURCES microscript/ILibDuktape_net.c microscript/ILibDuktape_ReadableStream.c"
SOURCES="$SOURCES microscript/ILibDuktape_WritableStream.c microscript/ILibDuktapeModSearch.c"
SOURCES="$SOURCES microscript/ILibDuktape_SimpleDataStore.c microscript/ILibDuktape_GenericMarshal.c"
SOURCES="$SOURCES microscript/ILibDuktape_fs.c microscript/ILibDuktape_SHA256.c"
SOURCES="$SOURCES microscript/ILibduktape_EventEmitter.c microscript/ILibDuktape_EncryptionStream.c"
SOURCES="$SOURCES microscript/ILibDuktape_Polyfills.c microscript/ILibDuktape_Dgram.c"
SOURCES="$SOURCES microscript/ILibDuktape_ScriptContainer.c microscript/ILibDuktape_MemoryStream.c"
SOURCES="$SOURCES microscript/ILibDuktape_NetworkMonitor.c microscript/ILibDuktape_ChildProcess.c"
SOURCES="$SOURCES microscript/ILibDuktape_HttpStream.c microscript/ILibDuktape_Debugger.c"
SOURCES="$SOURCES microscript/ILibDuktape_CompressedStream.c"
SOURCES="$SOURCES meshcore/zlib/adler32.c meshcore/zlib/deflate.c meshcore/zlib/inffast.c"
SOURCES="$SOURCES meshcore/zlib/inflate.c meshcore/zlib/inftrees.c meshcore/zlib/trees.c meshcore/zlib/zutil.c"
SOURCES="$SOURCES microstack/ILibWebRTC.c microstack/ILibWrapperWebRTC.c microscript/ILibDuktape_WebRTC.c"
SOURCES="$SOURCES meshcore/agentcore.c meshcore/meshinfo.c"

# Windows-specific KVM sources
WIN_KVM_SOURCES="meshcore/KVM/Windows/kvm.c meshcore/KVM/Windows/input.c"

# Include directories
INCLUDES="-I. -Iopenssl/include -Imicrostack -Imicroscript -Imeshcore -Imeshconsole -Imeshservice"

# Include branding header if it exists
if [ -f "meshcore/generated/meshagent_branding.h" ]; then
    INCLUDES="$INCLUDES -include meshcore/generated/meshagent_branding.h"
    log_info "Including branding header: meshcore/generated/meshagent_branding.h"
fi

# Common compiler flags
COMMON_CFLAGS="-std=gnu99 -Wall -D_POSIX -DMICROSTACK_PROXY -DMICROSTACK_TLS_DETECT"
COMMON_CFLAGS="$COMMON_CFLAGS -fno-strict-aliasing $INCLUDES"
COMMON_CFLAGS="$COMMON_CFLAGS -DDUK_USE_DEBUGGER_SUPPORT -DDUK_USE_INTERRUPT_COUNTER"
COMMON_CFLAGS="$COMMON_CFLAGS -DDUK_USE_DEBUGGER_INSPECT -DDUK_USE_DEBUGGER_PAUSE_UNCAUGHT"

# Common linker flags for Windows
COMMON_LDFLAGS="-lws2_32 -liphlpapi -lwinhttp -ladvapi32 -lshell32 -lole32 -loleaut32"
COMMON_LDFLAGS="$COMMON_LDFLAGS -luser32 -lgdi32 -lcrypt32 -lwtsapi32 -lkernel32 -luserenv"
COMMON_LDFLAGS="$COMMON_LDFLAGS -static-libgcc -static-libstdc++"

# Function to build agent
build_agent() {
    local ARCH=$1
    local ARCHID=$2
    local CC=$3
    local TARGET=$4
    local MAIN_SOURCE=$5

    log_info "Building $TARGET (ARCHID=$ARCHID, $ARCH)..."
    
    $CC $COMMON_CFLAGS -DMESH_AGENTID=$ARCHID -D_LINKVM -O2 \
        $MAIN_SOURCE $SOURCES $WIN_KVM_SOURCES \
        -o $TARGET \
        $COMMON_LDFLAGS \
        -lm -lpthread
    
    if [ -f "$TARGET" ]; then
        local size
        size=$(ls -lh "$TARGET" | awk '{print $5}')
        log_info "Built: $TARGET ($size)"
        file "$TARGET" | tee -a "$LOG_FILE"
        validate_binary "$TARGET" "$ARCH"
    else
        log_error "Failed to build $TARGET"
        return 1
    fi
}

# Build 64-bit Windows Service Agent (ARCHID=4)
build_agent "x86-64" "4" "x86_64-w64-mingw32-gcc" "MeshService64.exe" "meshservice/ServiceMain.c"

echo ""

# Build 32-bit Windows Service Agent (ARCHID=3)  
build_agent "x86" "3" "i686-w64-mingw32-gcc" "MeshService.exe" "meshservice/ServiceMain.c"

echo ""

# Build 64-bit Windows Console Agent (ARCHID=2)
build_agent "x86-64" "2" "x86_64-w64-mingw32-gcc" "MeshConsole64.exe" "meshconsole/main.c"

echo ""

# Build 32-bit Windows Console Agent (ARCHID=1)
build_agent "x86" "1" "i686-w64-mingw32-gcc" "MeshConsole.exe" "meshconsole/main.c"

echo ""
echo "=== Build Summary ==="
ls -lh MeshService*.exe MeshConsole*.exe 2>/dev/null || log_warn "Some builds may have failed"

if [ -n "$SERVICE_NAME" ] || [ -n "$MESH_ID" ] || [ -n "$SERVER_ID" ]; then
    log_info "Validation details captured in $LOG_FILE"
else
    log_warn "Branding configuration not detected; provisioning checks skipped"
fi

echo ""
echo "Note: These binaries are built with MinGW and may need testing."
echo "Official builds use Visual Studio on Windows."
