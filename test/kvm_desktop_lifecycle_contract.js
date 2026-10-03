const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) {
            throw new Error(`Unexpected argument: ${token}`);
        }
        const key = token.substring(2);
        const value = argv[i + 1];
        if (value == null || value.startsWith('--')) {
            args[key] = true;
        } else {
            args[key] = value;
            i += 1;
        }
    }
    return args;
}

function ensureDir(dirPath) {
    fs.mkdirSync(dirPath, { recursive: true });
}

function writeJson(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
}

function writeText(filePath, value) {
    ensureDir(path.dirname(filePath));
    fs.writeFileSync(filePath, value, 'utf8');
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message);
    }
}

function countOccurrences(source, needle) {
    let count = 0;
    let offset = 0;
    for (;;) {
        const index = source.indexOf(needle, offset);
        if (index < 0) { return count; }
        count += 1;
        offset = index + needle.length;
    }
}

function extractFunction(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `${signature} not found`);
    const bodyStart = source.indexOf('{', start);
    assert(bodyStart >= 0, `${signature} body start not found`);
    let depth = 0;
    for (let i = bodyStart; i < source.length; ++i) {
        const ch = source[i];
        if (ch === '{') {
            depth += 1;
        } else if (ch === '}') {
            depth -= 1;
            if (depth === 0) {
                return source.slice(start, i + 1);
            }
        }
    }
    throw new Error(`${signature} body end not found`);
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const kvmPath = path.resolve('meshcore', 'KVM', 'Windows', 'kvm.c');
    const tileHeaderPath = path.resolve('meshcore', 'KVM', 'Windows', 'tile.h');
    const tileSourcePath = path.resolve('meshcore', 'KVM', 'Windows', 'tile.cpp');
    const serviceMainPath = path.resolve('meshservice', 'ServiceMain.c');
    const kvmSource = fs.readFileSync(kvmPath, 'utf8');
    const tileHeaderSource = fs.readFileSync(tileHeaderPath, 'utf8');
    const tileSource = fs.readFileSync(tileSourcePath, 'utf8');
    const serviceMainSource = fs.readFileSync(serviceMainPath, 'utf8');
    const kvmBindBody = extractFunction(kvmSource, 'static BOOL kvm_bind_current_process_to_interactive_window_station(DWORD* errorOut)');
    const serviceBindBody = extractFunction(serviceMainSource, 'static BOOL MeshService_BindCurrentProcessToInteractiveWindowStation(DWORD* errorOut)');
    const checkDesktopSwitchBody = extractFunction(kvmSource, 'void CheckDesktopSwitch(int checkres, ILibKVM_WriteHandler writeHandler, void *reserved)');
    const bindBody = extractFunction(kvmSource, 'static void kvm_bind_thread_to_input_desktop(KvmThreadDesktopState* state, KvmDesktopBindResult* result)');
    const readThreadDesktopNameBody = extractFunction(kvmSource, 'static int kvm_read_thread_desktop_name(char* name, DWORD nameLen)');
    const inputBindBody = extractFunction(kvmSource, 'static void kvm_server_bind_input_thread_desktop(void)');
    const traceBindBody = extractFunction(kvmSource, 'static void kvm_trace_desktop_bind(KvmThreadDesktopState* state, const KvmDesktopBindResult* result)');
    const inputDataBody = extractFunction(kvmSource, 'int kvm_server_inputdata(char* block, int blocklen, ILibKVM_WriteHandler writeHandler, void *reserved)');
    const setResolutionBody = extractFunction(kvmSource, 'void kvm_server_SetResolution(ILibKVM_WriteHandler writeHandler, void *reserved)');
    const ensureTileGeometryBody = extractFunction(kvmSource, 'static void kvm_server_ensure_tile_geometry()');
    const primeStartupGeometryBody = extractFunction(kvmSource, 'static void kvm_server_prime_startup_geometry_if_needed()');
    const initializeGdiplusBody = extractFunction(tileSource, 'short initialize_gdiplus()');
    const winlogonReopenIndex = bindBody.indexOf('HDESK secureDesktop = OpenDesktopW(L"Winlogon"');
    const unchangedDesktopIndex = bindBody.indexOf('_stricmp(result->previousName, targetName) == 0');
    const setThreadDesktopIndex = bindBody.indexOf('SetThreadDesktop(desktop)');
    const captureReadyAssignments = (kvmSource.match(/\bgKvmDesktopCaptureReady\s*=[^=]/g) || []).length;
    const setResolutionEnsureIndex = setResolutionBody.indexOf('kvm_server_ensure_tile_geometry();');
    const setResolutionPrimeIndex = setResolutionBody.indexOf('kvm_server_prime_startup_geometry_if_needed();');
    const setResolutionInvalidGeometryIndex = setResolutionBody.indexOf('if (SCREEN_WIDTH <= 0 || SCREEN_HEIGHT <= 0)');
    const setResolutionTileCountIndex = setResolutionBody.indexOf('newTileWidthCount = newScaledWidth / TILE_WIDTH;');

    const checks = {
        kvmTileDefaultsAreSharedConstants:
            tileHeaderSource.includes('#define KVM_TILE_DEFAULT_WIDTH 32') &&
            tileHeaderSource.includes('#define KVM_TILE_DEFAULT_HEIGHT 32') &&
            kvmSource.includes('int TILE_WIDTH = KVM_TILE_DEFAULT_WIDTH;') &&
            kvmSource.includes('int TILE_HEIGHT = KVM_TILE_DEFAULT_HEIGHT;') &&
            initializeGdiplusBody.includes('TILE_WIDTH = KVM_TILE_DEFAULT_WIDTH;') &&
            initializeGdiplusBody.includes('TILE_HEIGHT = KVM_TILE_DEFAULT_HEIGHT;'),
        kvmSetResolutionRestoresTileGeometryBeforeArithmetic:
            ensureTileGeometryBody.includes('if (TILE_WIDTH <= 0) { TILE_WIDTH = KVM_TILE_DEFAULT_WIDTH;') &&
            ensureTileGeometryBody.includes('if (TILE_HEIGHT <= 0) { TILE_HEIGHT = KVM_TILE_DEFAULT_HEIGHT;') &&
            setResolutionEnsureIndex >= 0 &&
            setResolutionTileCountIndex >= 0 &&
            setResolutionEnsureIndex < setResolutionTileCountIndex,
        kvmSetResolutionPrimesAndValidatesScreenGeometryBeforeTileAllocation:
            primeStartupGeometryBody.includes('VSCREEN_WIDTH = GetSystemMetrics(SM_CXVIRTUALSCREEN);') &&
            primeStartupGeometryBody.includes('SCREEN_WIDTH = GetSystemMetrics(SM_CXSCREEN);') &&
            setResolutionPrimeIndex >= 0 &&
            setResolutionInvalidGeometryIndex >= 0 &&
            setResolutionTileCountIndex >= 0 &&
            setResolutionPrimeIndex < setResolutionInvalidGeometryIndex &&
            setResolutionInvalidGeometryIndex < setResolutionTileCountIndex,
        kvmBindChecksCurrentWindowStationBeforeOpen:
            kvmBindBody.indexOf('GetProcessWindowStation()') >= 0 &&
            kvmBindBody.indexOf('GetProcessWindowStation()') < kvmBindBody.indexOf('OpenWindowStationW(L"WinSta0"'),
        kvmBindSkipsAlreadyInteractiveWindowStation:
            kvmBindBody.includes('GetUserObjectInformationW(currentWindowStation, UOI_NAME') &&
            kvmBindBody.includes('_wcsicmp(currentName, L"WinSta0") == 0') &&
            kvmBindBody.includes('return TRUE;'),
        kvmBindClosesOpenedWindowStationOnlyOnFailure:
            countOccurrences(kvmBindBody, 'CloseWindowStation(windowStation)') === 1 &&
            kvmBindBody.includes('if (!ok) { CloseWindowStation(windowStation); }'),
        kvmDesktopBindIsOnlyKvmStationBindCaller:
            countOccurrences(kvmSource, 'kvm_bind_current_process_to_interactive_window_station(&windowStationError)') === 1 &&
            bindBody.includes('kvm_bind_current_process_to_interactive_window_station(&windowStationError)'),
        // The capture thread runs CheckDesktopSwitch; the input path only moves its own thread.
        kvmCheckDesktopSwitchStillCoversKnownCallSurface:
            countOccurrences(kvmSource, 'CheckDesktopSwitch(') === 5 &&
            kvmSource.includes('CheckDesktopSwitch(0, writeHandler, reserved);') &&
            kvmSource.includes('CheckDesktopSwitch(1, writeHandler, reserved);') &&
            !inputDataBody.includes('CheckDesktopSwitch(') &&
            inputDataBody.includes('kvm_server_bind_input_thread_desktop();'),
        // SetThreadDesktop moves only the calling thread, so capture readiness is decided by the
        // capture thread alone; the input thread's binding never marks capture ready or unready.
        kvmCaptureReadinessOwnedByCaptureThread:
            captureReadyAssignments === 2 &&
            kvmSource.includes('int gKvmDesktopCaptureReady = 1;') &&
            checkDesktopSwitchBody.includes('kvm_bind_thread_to_input_desktop(&gKvmCaptureDesktopState, &bind);') &&
            checkDesktopSwitchBody.includes('gKvmDesktopCaptureReady = bind.accessible;') &&
            inputBindBody.includes('kvm_bind_thread_to_input_desktop(&gKvmInputDesktopState, &bind);') &&
            !inputBindBody.includes('gKvmDesktopCaptureReady') &&
            !bindBody.includes('gKvmDesktopCaptureReady'),
        kvmDoesNotCloseBorrowedThreadDesktopHandle:
            !kvmSource.includes('CloseDesktop(desktop2)') &&
            !kvmSource.includes('CloseDesktop(threadDesktop)') &&
            readThreadDesktopNameBody.includes('HDESK threadDesktop = GetThreadDesktop(GetCurrentThreadId());'),
        // Each role closes only the handle it opened and attached, once its thread has moved on.
        kvmReleasesOnlyDesktopHandlesItAttached:
            bindBody.includes('state->ownedDesktop = desktop;') &&
            bindBody.includes('state->ownedDesktop != desktop && CloseDesktop(state->ownedDesktop) == 0') &&
            bindBody.indexOf('SetThreadDesktop(desktop) == 0') < bindBody.indexOf('state->ownedDesktop = desktop;'),
        kvmReadsCurrentAndTargetDesktopNames:
            readThreadDesktopNameBody.includes('GetUserObjectInformationA(threadDesktop, UOI_NAME, name') &&
            bindBody.includes('kvm_read_thread_desktop_name(result->previousName') &&
            bindBody.includes('GetUserObjectInformationA(desktop, UOI_NAME, targetName') &&
            bindBody.indexOf('SetThreadDesktop(desktop) == 0') < bindBody.indexOf('kvm_read_thread_desktop_name(result->currentName'),
        kvmUnchangedDesktopPollClosesOnlyNewTargetHandle:
            unchangedDesktopIndex >= 0 &&
            unchangedDesktopIndex < setThreadDesktopIndex &&
            bindBody.includes('CloseDesktop(UnchangedDesktop)'),
        kvmReopensSecureDesktopBeforeThreadAssignment:
            winlogonReopenIndex >= 0 &&
            setThreadDesktopIndex >= 0 &&
            winlogonReopenIndex < setThreadDesktopIndex,
        // Failures keep the API name in the trace ("OpenInputDesktop failed", "SetThreadDesktop
        // failed") for the runtime probes, and are traced on change rather than on every poll.
        kvmTracesDesktopBindFailuresOnChange:
            bindBody.includes('kvm_desktop_bind_note_failure(result, "OpenInputDesktop", GetLastError());') &&
            bindBody.includes('kvm_desktop_bind_note_failure(result, "SetThreadDesktop", GetLastError());') &&
            traceBindBody.includes('"KVM desktop[%s]: %s failed error=%lu; thread desktop=\'%s\' accessible=%d"') &&
            traceBindBody.indexOf('result->failedStage == state->lastFailedStage') < traceBindBody.indexOf('%s failed error=%lu'),
        serviceBindChecksCurrentWindowStationBeforeOpen:
            serviceBindBody.indexOf('GetProcessWindowStation()') >= 0 &&
            serviceBindBody.indexOf('GetProcessWindowStation()') < serviceBindBody.indexOf('OpenWindowStationW(L"WinSta0"'),
        serviceBindSkipsAlreadyInteractiveWindowStation:
            serviceBindBody.includes('GetUserObjectInformationW(currentWindowStation, UOI_NAME') &&
            serviceBindBody.includes('_wcsicmp(currentName, L"WinSta0") == 0') &&
            serviceBindBody.includes('return TRUE;'),
        serviceBindClosesOpenedWindowStationOnlyOnFailure:
            countOccurrences(serviceBindBody, 'CloseWindowStation(windowStation)') === 1 &&
            serviceBindBody.includes('if (!ok) { CloseWindowStation(windowStation); }'),
        serviceBindKnownProbeSurfaceIsUnchanged:
            countOccurrences(serviceMainSource, 'MeshService_BindCurrentProcessToInteractiveWindowStation(&') === 3
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `desktop lifecycle contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        files: {
            kvmPath,
            tileHeaderPath,
            tileSourcePath,
            serviceMainPath
        },
        regressionSurface: {
            kvm: [
                'kvm_server_bind_input_thread_desktop input path',
                'CheckDesktopSwitch startup pre-GDI path',
                'CheckDesktopSwitch startup resolution recovery path',
                'CheckDesktopSwitch steady capture loop',
                'CheckDesktopSwitch capture failure recovery path'
            ],
            service: [
                'kvm elevated input probe window-station bind',
                'kvm block-input holder window-station bind',
                'kvm block-input probe window-station bind'
            ]
        },
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'kvm_desktop_lifecycle_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

try {
    main();
} catch (error) {
    console.error(error && error.stack ? error.stack : String(error));
    process.exit(1);
}
