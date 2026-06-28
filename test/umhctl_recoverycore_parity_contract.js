const fs = require('fs');
const path = require('path');
const { loadRecoveryCoreVm } = require('./lib/recoverycore_vm');

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

function readText(filePath) {
    return fs.readFileSync(filePath, 'utf8');
}

function hasAll(source, tokens) {
    return tokens.every((token) => source.includes(token));
}

function extractFunction(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `missing function signature: ${signature}`);
    const open = source.indexOf('{', start);
    assert(open >= 0, `missing function body: ${signature}`);
    let depth = 0;
    for (let i = open; i < source.length; ++i) {
        if (source[i] === '{') {
            depth += 1;
        } else if (source[i] === '}') {
            depth -= 1;
            if (depth === 0) {
                return source.substring(start, i + 1);
            }
        }
    }
    throw new Error(`unterminated function body: ${signature}`);
}

function main() {
    const args = parseArgs(process.argv);
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const recoveryCorePath = path.resolve('modules', 'RecoveryCore.js');
    const umhctlPath = path.resolve('modules', 'umhctl.js');
    const operatorContractPath = path.resolve('test', 'lib', 'umh_operator_contract.js');
    const recoveryCore = readText(recoveryCorePath);
    const umhctl = readText(umhctlPath);
    const operatorContract = readText(operatorContractPath);
    const { sandbox } = loadRecoveryCoreVm();

    const sharedTokens = [
        "var umhctlAllowedInstallMethodKeys = { standard: 1, setwindowshookex: 1, manualmap: 1, reflective: 1 };",
        'function umhctlMasterServiceCommandSucceeded(exitCode, outputText)',
        'function umhctlMasterServiceCommandFailureDetail(outputText)',
        "sendConsoleText('umhctl: resolved binary missing at ' + msExePath + ', native uninstall unavailable; removing service registration only.', sessionid);",
        "sendConsoleText('umhctl: native uninstall cleanup was not proven; reporting uninstall incomplete.', sessionid);",
        'var nativeUninstallOk = umhctlMasterServiceCommandSucceeded(code, out);',
        "sendConsoleText('umhctl: native uninstall failed; clean uninstall is not proven (' + umhctlMasterServiceCommandFailureDetail(out) + ').', sessionid);",
        "completeUninstall(finalCleanSuccess);"
    ];

    const checks = {
        recoveryCoreHasSharedTokens: hasAll(recoveryCore, sharedTokens),
        umhctlHasSharedTokens: hasAll(umhctl, sharedTokens),
        recoveryCoreDoesNotReportForcedRemovalAsClean: !recoveryCore.includes("sendConsoleText('umhctl: resolved binary missing at ' + msExePath + ', removing service registration via fallback.', sessionid);") &&
            !recoveryCore.includes('completeUninstall(true);\n        });\n    };'),
        umhctlDoesNotReportForcedRemovalAsClean: !umhctl.includes("sendConsoleText('umhctl: resolved binary missing at ' + msExePath + ', removing service registration via fallback.', sessionid);") &&
            !umhctl.includes('completeUninstall(true);\n        });\n    };'),
        operatorContractAdvertisesSetWindowsHookExInstallMethod: operatorContract.includes('standard|setwindowshookex|manualmap|reflective') &&
            operatorContract.includes("methodKey: 'setwindowshookex'"),
        recoveryCoreRejectsSuccessFalseJson: sandbox.umhctlMasterServiceCommandSucceeded(0, '{"success":false,"message":"native failed"}') === false,
        recoveryCoreRejectsNonZeroExit: sandbox.umhctlMasterServiceCommandSucceeded(2, '{"success":true}') === false,
        recoveryCoreAcceptsZeroExitWithoutFailureJson: sandbox.umhctlMasterServiceCommandSucceeded(0, '{"success":true}') === true,
        recoveryCoreFailureDetailUsesJsonMessage: sandbox.umhctlMasterServiceCommandFailureDetail('{"success":false,"message":"native failed"}') === 'native failed'
    };

    for (const [label, source] of [['RecoveryCore', recoveryCore], ['umhctl', umhctl]]) {
        const preferredBody = extractFunction(source, 'function umhctlGetPreferredManagedMasterServicePaths');
        const managedPathBody = extractFunction(source, 'function umhctlIsManagedMasterServicePath');
        const resolveBody = extractFunction(source, 'function umhctlResolveMasterServicePaths');
        const agentDirBody = extractFunction(source, 'function umhctlGetAgentDirectory');
        const handleCommandBody = extractFunction(source, 'function umhctlHandleCommand');
        checks[`${label}UsesKnownFolderUmhRoot`] =
            preferredBody.includes('umhctlProgramDataRoot()') &&
            preferredBody.includes("programData + '\\\\UserModeHook\\\\MasterService.exe'");
        checks[`${label}DoesNotUseProgramDataEnvForUmhRoot`] =
            !preferredBody.includes("umhctlGetEnvValue('ProgramData')") &&
            !managedPathBody.includes("umhctlGetEnvValue('ProgramData')") &&
            !preferredBody.includes("process.env['MESH_SERVICE_NAME']");
        checks[`${label}DoesNotStageMasterServiceBesideAgent`] =
            !preferredBody.includes("agentDir + '/MasterService.exe'") &&
            !resolveBody.includes("agentDir + '/MasterService.exe'") &&
            !resolveBody.includes(": 'MasterService.exe'");
        checks[`${label}DoesNotSelectArbitraryServiceImagePath`] =
            !resolveBody.includes('var fallbacks') &&
            !resolveBody.includes('pushFallback') &&
            !resolveBody.includes('fallbackSeen') &&
            resolveBody.includes('umhctlIsManagedMasterServicePath(imagePath, agentDir)') &&
            !resolveBody.includes('selected = (typeof agentDir');
        checks[`${label}PreservesManagedCleanupRoots`] =
            managedPathBody.includes("pushRoot(programData + '\\\\UserModeHook');") &&
            managedPathBody.includes('pushRoot(umhctlGetActiveAgentInstallRoot());') &&
            managedPathBody.includes('pushRoot(agentDir);');
        checks[`${label}FailsClosedWhenMasterServicePathUnavailable`] =
            resolveBody.includes('MasterService binary path unavailable') &&
            agentDirBody.includes("if (process.platform == 'win32') { return null; }") &&
            handleCommandBody.includes('msPaths.error != null');
    }

    for (const [name, passed] of Object.entries(checks)) {
        assert(passed, `UMH parity contract failed: ${name}`);
    }

    const report = {
        generatedUtc: new Date().toISOString(),
        recoveryCorePath,
        umhctlPath,
        operatorContractPath,
        checks
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'umhctl_recoverycore_parity_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `RECOVERYCORE_PATH=${recoveryCorePath}`,
            `UMHCTL_PATH=${umhctlPath}`,
            `OPERATOR_CONTRACT_PATH=${operatorContractPath}`,
            'SUCCESS=true',
            `CHECKS=${Object.entries(checks).map(([name, passed]) => `${name}:${passed}`).join(',')}`
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
