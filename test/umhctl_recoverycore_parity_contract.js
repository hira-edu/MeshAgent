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
