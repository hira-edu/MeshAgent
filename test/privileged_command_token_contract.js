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
    const tokenSourcePath = path.resolve('meshservice', 'process_token_contract.h');
    const tokenSource = fs.readFileSync(tokenSourcePath, 'utf8').replace(/\r\n?/g, '\n');
    const openToken = section(tokenSource,
        'static BOOL MeshProcessToken_Open(',
        'static BOOL MeshProcessToken_VerifyChildAndResume(');
    const verifyChild = section(tokenSource,
        'static BOOL MeshProcessToken_VerifyChildAndResume(',
        '#endif');
    const umhHost = section(source,
        'static DWORD MeshUmhHost_RunManifestCommandW(',
        'static int MeshUserConsent_HexNibbleW(');
    const ptySpawn = section(source,
        'static BOOL MeshConsoleBridge_CreateShellProcessW(',
        'static BOOL MeshConsoleBridge_CreateInheritablePipePair(');
    const execSpawn = section(source,
        'static BOOL MeshConsoleBridge_CreateRedirectedShellProcessW(',
        'static DWORD WINAPI MeshConsoleBridge_CopyThread(');
    const parseBridge = section(source,
        'static BOOL MeshConsoleBridge_ParseArgumentsW(',
        'void CALLBACK MeshConsoleBridgeW(');

    const checks = {
        splitTokenAdminRequiresConsent:
            !tokenSource.includes('TokenLinkedToken') &&
            !tokenSource.includes('sourceToken = linkedToken.LinkedToken'),
        privilegedTokenRequiresHighIntegrity:
            openToken.includes('mode == MeshProcessToken_Privileged && !MeshProcessToken_IsPrivileged(&selected)') &&
            openToken.includes('ERROR_ELEVATION_REQUIRED'),
        selectedIdentityIsPreserved:
            openToken.includes('MeshProcessToken_Matches(&selected, &actual)') &&
            openToken.includes('SetTokenInformation(primary, TokenSessionId'),
        childTokenIsVerifiedBeforeResume:
            verifyChild.includes('OpenProcessToken(processInfo->hProcess, TOKEN_QUERY') &&
            verifyChild.includes('MeshProcessToken_Matches(&expected, &actual)') &&
            verifyChild.includes('ResumeThread(processInfo->hThread)') &&
            verifyChild.indexOf('MeshProcessToken_Matches(&expected, &actual)') < verifyChild.indexOf('ResumeThread(processInfo->hThread)') &&
            verifyChild.includes('TerminateProcess(processInfo->hProcess') &&
            verifyChild.includes('child-termination-wait-failed'),
        masterServiceNeverInheritsUnverifiedToken:
            umhHost.includes('MeshProcessToken_Open(MeshProcessToken_Privileged') &&
            umhHost.includes('CreateProcessAsUserW(') &&
            umhHost.includes('CREATE_SUSPENDED') &&
            umhHost.includes('MeshProcessToken_VerifyChildAndResume') &&
            umhHost.indexOf('MeshProcessToken_Open(MeshProcessToken_Privileged') < umhHost.indexOf('CreateProcessAsUserW(') &&
            umhHost.indexOf('CreateProcessAsUserW(') < umhHost.indexOf('MeshProcessToken_VerifyChildAndResume'),
        sessionUserComesFromWtsNotBridgeToken:
            openToken.includes('WTSQueryUserToken(sessionId, &source)') &&
            openToken.includes('mode == MeshProcessToken_SessionUser') &&
            openToken.includes('selected.system || selected.sessionId != sessionId'),
        ptySeparatesUserAndPrivilegedTokens:
            ptySpawn.includes('MeshProcessToken_Open(tokenMode, targetSessionId, &userToken)') &&
            ptySpawn.includes('MeshProcessToken_VerifyChildAndResume(tokenMode, userToken, processInfo)') &&
            ptySpawn.includes('CREATE_SUSPENDED') &&
            ptySpawn.includes('CreateProcessAsUserW(') &&
            !ptySpawn.includes('CreateProcessW('),
        execSeparatesUserAndPrivilegedTokens:
            execSpawn.includes('MeshProcessToken_Open(tokenMode, targetSessionId, &userToken)') &&
            execSpawn.includes('MeshProcessToken_VerifyChildAndResume(tokenMode, userToken, processInfo)') &&
            execSpawn.includes('CREATE_SUSPENDED') &&
            execSpawn.includes('CreateProcessAsUserW(') &&
            !execSpawn.includes('CreateProcessW('),
        noCrossTokenFallback:
            !source.includes('Falling back to bridge token inside same rundll32 after session spawn denial') &&
            !source.includes('Falling back to bridge token for exec inside same rundll32 after session spawn denial'),
        nativeContractRequiresExplicitTokenMode:
            parseBridge.includes('token=privileged-agent') &&
            parseBridge.includes('token=session-user') &&
            parseBridge.includes('!tokenSeen') &&
            parseBridge.includes('*tokenMode == MeshProcessToken_Privileged && sessionSeen') &&
            parseBridge.includes('*tokenMode == MeshProcessToken_SessionUser && (!sessionSeen || *targetSessionId == 0)')
    };

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `privileged command token contract failed: ${name}`);
    }
    const report = { success: true, sourcePath, tokenSourcePath, checks };
    if (typeof args.evidence === 'string') {
        fs.mkdirSync(args.evidence, { recursive: true });
        fs.writeFileSync(path.join(args.evidence, 'privileged_command_token_contract.json'), JSON.stringify(report, null, 2));
        fs.writeFileSync(path.join(args.evidence, 'summary.txt'), 'SUCCESS=true\n');
    }
    console.log(JSON.stringify(report, null, 2));
}

main();
