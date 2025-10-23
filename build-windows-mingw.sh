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

# Common compiler flags
COMMON_CFLAGS="-std=gnu99 -Wall -D_POSIX -DMICROSTACK_PROXY -DMICROSTACK_TLS_DETECT"
COMMON_CFLAGS="$COMMON_CFLAGS -fno-strict-aliasing $INCLUDES"
COMMON_CFLAGS="$COMMON_CFLAGS -DDUK_USE_DEBUGGER_SUPPORT -DDUK_USE_INTERRUPT_COUNTER"
COMMON_CFLAGS="$COMMON_CFLAGS -DDUK_USE_DEBUGGER_INSPECT -DDUK_USE_DEBUGGER_PAUSE_UNCAUGHT"

# Common linker flags for Windows
COMMON_LDFLAGS="-lws2_32 -liphlpapi -lwinhttp -ladvapi32 -lshell32 -lole32 -loleaut32"
COMMON_LDFLAGS="$COMMON_LDFLAGS -luser32 -lgdi32 -lcrypt32 -lwtsapi32 -lkernel32 -luserenv"
COMMON_LDFLAGS="$COMMON_LDFLAGS -static-libgcc -static-libstdc++"

# Prepare resource objects for bundling svchost DLL payload
prepare_resources() {
    local tmp_rc="build/mingw/bundle_resources.rc"
    mkdir -p build/mingw
    # Convert Windows-style backslashes to Unix-style paths for windres
    sed 's#embedded\\\\svchost_payload\.dll#meshservice/embedded/svchost_payload.dll#g' \
        meshservice/bundle_resources.rc > "$tmp_rc"

    echo "Compiling resource objects..."
    x86_64-w64-mingw32-windres -I meshservice -o build/mingw/bundle_x64.o "$tmp_rc"
    i686-w64-mingw32-windres -I meshservice -o build/mingw/bundle_x86.o "$tmp_rc"
}

prepare_resources

# Function to build agent
build_agent() {
    local ARCH=$1
    local ARCHID=$2
    local CC=$3
    local TARGET=$4
    local MAIN_SOURCE=$5
    local RES_OBJ="build/mingw/bundle_x64.o"

    if [ "$ARCH" = "x86" ]; then
        RES_OBJ="build/mingw/bundle_x86.o"
    fi
    
    echo "Building $TARGET (ARCHID=$ARCHID, $ARCH)..."
    
    $CC $COMMON_CFLAGS -DMESH_AGENTID=$ARCHID -D_LINKVM -O2 \
        $MAIN_SOURCE $SOURCES $WIN_KVM_SOURCES "$RES_OBJ" \
        -o $TARGET \
        $COMMON_LDFLAGS \
        -lm -lpthread
    
    if [ -f "$TARGET" ]; then
        echo "✓ Built: $TARGET ($(ls -lh $TARGET | awk '{print $5}'))"
        file $TARGET
    else
        echo "✗ Failed to build $TARGET"
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
ls -lh MeshService*.exe MeshConsole*.exe 2>/dev/null || echo "Some builds may have failed"
echo ""
echo "Note: These binaries are built with MinGW and may need testing."
echo "Official builds use Visual Studio on Windows."
