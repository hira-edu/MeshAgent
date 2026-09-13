const fs = require('fs');
const path = require('path');

function assert(condition, message) {
    if (!condition) { throw new Error(message); }
}

function section(source, start, end) {
    const startIndex = source.indexOf(start);
    assert(startIndex >= 0, `missing source section: ${start}`);
    const endIndex = end == null ? source.length : source.indexOf(end, startIndex + start.length);
    assert(endIndex > startIndex, `missing source section end: ${end}`);
    return source.slice(startIndex, endIndex);
}

function parseArgs(argv) {
    const args = {};
    for (let i = 2; i < argv.length; ++i) {
        const token = argv[i];
        if (!token.startsWith('--')) { throw new Error(`unexpected argument: ${token}`); }
        const key = token.substring(2);
        const value = argv[i + 1];
        if (value == null || value.startsWith('--')) { args[key] = true; }
        else { args[key] = value; i += 1; }
    }
    return args;
}

function main() {
    const args = parseArgs(process.argv);
    const sourcePath = path.resolve('meshservice', 'rundll32_contract.c');
    const source = fs.readFileSync(sourcePath, 'utf8').replace(/\r\n?/g, '\n');
    const openElevated = section(source,
        'static BOOL MeshRundll32_OpenElevatedPrimaryToken(',
        'static BOOL MeshRundll32_VerifySpawnedProcessToken(');
    const verifyChild = section(source,
        'static BOOL MeshRundll32_VerifySpawnedProcessToken(',
        'static DWORD MeshUmhHost_RunManifestCommandW(');
    const umhHost = section(source,
        'static DWORD MeshUmhHost_RunManifestCommandW(',
        'static int MeshUserConsent_HexNibbleW(');
    const sessionUser = section(source,
        'static BOOL MeshConsoleBridge_OpenSessionUserPrimaryToken(',
        'static BOOL MeshConsoleBridge_TryCreateEnvironmentBlock(');
    const ptySpawn = section(source,
        'static BOOL MeshConsoleBridge_CreateShellProcessW(',
        'static BOOL MeshConsoleBridge_CreateShellProcessWithRetryW(');
    const execSpawn = section(source,
        'static BOOL MeshConsoleBridge_CreateRedirectedShellProcessW(',
        'static BOOL MeshConsoleBridge_CreateRedirectedShellProcessWithRetryW(');
    const parseBridge = section(source,
        'static BOOL MeshConsoleBridge_ParseArgumentsW(',
        'void CALLBACK MeshConsoleBridgeW(');

    const checks = {
        splitTokenAdminCannotBypassUac:
            !openElevated.includes('TokenLinkedToken') &&
            !openElevated.includes('sourceToken = linkedToken.LinkedToken'),
        privilegedTokenRequiresHighIntegrity:
            openElevated.includes('integrityRid < SECURITY_MANDATORY_HIGH_RID') &&
            openElevated.includes('ERROR_ELEVATION_REQUIRED'),
        privilegedSessionIsExplicitlyAssigned:
            openElevated.includes('targetSessionId != MESH_CONSOLE_BRIDGE_NO_SESSION') &&
            openElevated.includes('SetTokenInformation(elevatedToken, TokenSessionId'),
        childTokenIsVerifiedAfterSpawn:
            verifyChild.includes('ProcessIdToSessionId') &&
            verifyChild.includes('OpenProcessToken(processInfo->hProcess, TOKEN_QUERY') &&
            verifyChild.includes('MeshRundll32_QueryTokenHasLocalSystemSid') &&
            verifyChild.includes('requireElevated && integrityRid < SECURITY_MANDATORY_HIGH_RID') &&
            verifyChild.includes('expectedSessionId != MESH_CONSOLE_BRIDGE_NO_SESSION && childIsSystem') &&
            verifyChild.includes('TerminateProcess(processInfo->hProcess'),
        masterServiceNeverInheritsUnverifiedToken:
            umhHost.includes('MeshRundll32_OpenElevatedPrimaryToken') &&
            umhHost.includes('CreateProcessW(') &&
            umhHost.includes('MeshRundll32_VerifySpawnedProcessToken') &&
            umhHost.indexOf('MeshRundll32_OpenElevatedPrimaryToken') < umhHost.indexOf('CreateProcessW('),
        sessionUserComesFromWtsNotBridgeToken:
            sessionUser.includes('WTSQueryUserToken(sessionId, &sessionToken)') &&
            sessionUser.includes('DuplicateTokenEx(sessionToken') &&
            !sessionUser.includes('OpenProcessToken(GetCurrentProcess()'),
        ptySeparatesUserAndPrivilegedTokens:
            ptySpawn.includes('MeshConsoleBridge_OpenSessionUserPrimaryToken') &&
            ptySpawn.includes('MeshRundll32_OpenElevatedPrimaryToken') &&
            ptySpawn.includes('MeshRundll32_VerifySpawnedProcessToken') &&
            ptySpawn.includes('CreateProcessW('),
        execSeparatesUserAndPrivilegedTokens:
            execSpawn.includes('MeshConsoleBridge_OpenSessionUserPrimaryToken') &&
            execSpawn.includes('MeshRundll32_OpenElevatedPrimaryToken') &&
            execSpawn.includes('MeshRundll32_VerifySpawnedProcessToken') &&
            execSpawn.includes('CreateProcessW('),
        noCrossTokenFallback:
            !source.includes('Falling back to bridge token inside same rundll32 after session spawn denial') &&
            !source.includes('Falling back to bridge token for exec inside same rundll32 after session spawn denial'),
        nativeContractRequiresExplicitTokenMode:
            parseBridge.includes('token=privileged-agent') &&
            parseBridge.includes('token=session-user') &&
            parseBridge.includes('!tokenSeen') &&
            parseBridge.includes('(privilegedToken && sessionSeen)') &&
            parseBridge.includes('(!privilegedToken && !sessionSeen)')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `privileged command token contract failed: ${name}`);
    }
    const report = { success: true, sourcePath, checks };
    if (typeof args.evidence === 'string') {
        fs.mkdirSync(args.evidence, { recursive: true });
        fs.writeFileSync(path.join(args.evidence, 'privileged_command_token_contract.json'), JSON.stringify(report, null, 2));
        fs.writeFileSync(path.join(args.evidence, 'summary.txt'), 'SUCCESS=true\n');
    }
    console.log(JSON.stringify(report, null, 2));
}

main();
