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

function readRepoFile(repoRoot, relativePath) {
    return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function normalizeWindowsPath(value) {
    return String(value || '').trim().replace(/\//g, '\\').replace(/\\+$/g, '');
}

function windowsLeaf(value) {
    const normalized = normalizeWindowsPath(value);
    const parts = normalized.split('\\').filter(Boolean);
    return parts.length > 0 ? parts[parts.length - 1] : '';
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
    const repoRoot = path.resolve(__dirname, '..');
    const evidenceDir = args.evidence ? path.resolve(args.evidence) : null;
    const brandingPath = path.join(repoRoot, 'branding_config.local.json');
    const branding = JSON.parse(fs.readFileSync(brandingPath, 'utf8'));
    const installRoot = normalizeWindowsPath(branding.branding && branding.branding.installRoot);
    const logsDir = normalizeWindowsPath(branding.branding && branding.branding.logPath);
    const serviceDllName = String((branding.branding && branding.branding.serviceDllName) || '').trim();
    const runtimeDirLeaf = windowsLeaf(installRoot);

    assert(installRoot.length > 0, 'active branding must define branding.installRoot');
    assert(logsDir.length > 0, 'active branding must define branding.logPath');
    assert(serviceDllName.length > 0, 'active branding must define branding.serviceDllName');
    assert(runtimeDirLeaf.length > 0, 'active install root must have a leaf directory');
    assert(logsDir.toLowerCase() === `${installRoot}\\logs`.toLowerCase(), 'active log path must be installRoot\\logs');

    const generatedBranding = readRepoFile(repoRoot, 'meshcore/generated/meshagent_branding.h');
    const generatedInstallRoot = installRoot.replace(/\\/g, '/');
    const generatedLogsDir = logsDir.replace(/\\/g, '/');
    assert(generatedBranding.includes(`#define MESH_AGENT_INSTALL_ROOT TEXT("${generatedInstallRoot}")`), 'generated branding install root does not match active branding JSON');
    assert(generatedBranding.includes(`#define MESH_AGENT_LOG_DIRECTORY TEXT("${generatedLogsDir}")`), 'generated branding log directory does not match active branding JSON');
    assert(generatedBranding.includes(`#define MESH_AGENT_SVCHOST_DLL TEXT("${serviceDllName}")`), 'generated branding service DLL does not match active branding JSON');

    const stealthDefaults = readRepoFile(repoRoot, 'meshservice/stealth_defaults.h');
    assert(stealthDefaults.includes('STEALTH_INSTALL_ROOT_DACL_SDDL       L"D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;IU)"'), 'install-root DACL must give Interactive Users a non-inheritable direct root ACE');
    assert(!stealthDefaults.includes('(A;OI;0x1200a9;;;IU)'), 'install-root Interactive Users ACE must not inherit to child files');

    const stealthFirewall = readRepoFile(repoRoot, 'meshservice/stealth_firewall.c');
    const createDirBody = extractFunction(stealthFirewall, 'static BOOL Stealth_CreateDirectoryWithProtectedDacl');
    assert(!createDirBody.includes('Fallback: standard CreateDirectory'), 'secure directory creation must not fall back to default DACL creation');
    assert(!createDirBody.includes('CreateDirectoryW(path, NULL)'), 'secure directory creation must not create the directory without the protected DACL');
    assert(createDirBody.includes('SetNamedSecurityInfoW'), 'secure directory creation must harden existing directories');
    assert(createDirBody.includes('SetLastError(setResult);') && createDirBody.includes('return FALSE;'), 'secure directory creation must fail when DACL hardening fails');

    const agentCore = readRepoFile(repoRoot, 'meshcore/agentcore.c');
    const activeLogsBody = extractFunction(agentCore, 'static BOOL MeshAgent_GetActiveStealthLogsDirW');
    assert(activeLogsBody.includes('Stealth_GetInstallPaths(&paths)'), 'native log paths must resolve through Stealth_GetInstallPaths');
    const nativeLogBody = extractFunction(agentCore, 'static void MeshAgent_LogNativeInstallerEvent');
    assert(nativeLogBody.includes('MeshAgent_GetActiveStealthLogsDirW'), 'native install log must use active branded logs directory');
    assert(!nativeLogBody.includes('CSIDL_COMMON_APPDATA'), 'native install log must not synthesize a ProgramData fallback path');
    const preProtectionBody = extractFunction(agentCore, 'static BOOL MeshAgent_BuildDefaultPreProtectionCapturePathW');
    assert(preProtectionBody.includes('MeshAgent_GetActiveStealthLogsDirW'), 'default pre-protection capture path must use active branded logs directory');
    assert(preProtectionBody.includes('L"%s\\\\preprotection"'), 'default pre-protection capture path must be under logs\\preprotection');
    assert(!preProtectionBody.includes('STEALTH_FALLBACK_SERVICE_NAME'), 'default pre-protection capture path must not use the generic service fallback name');
    const snapshotBody = extractFunction(agentCore, 'static void MeshAgent_CopyEvidenceSnapshot');
    assert(!snapshotBody.includes('C:\\\\ProgramData\\\\%s'), 'evidence snapshot must not invent a legacy ProgramData fallback');

    const serviceMain = readRepoFile(repoRoot, 'meshservice/ServiceMain.c');
    const runtimeNameBody = extractFunction(serviceMain, 'static BOOL MeshService_GetUserRuntimeDirectoryNameW');
    assert(runtimeNameBody.includes('Stealth_GetInstallPaths(&paths)') && runtimeNameBody.includes('paths.installDir'), 'GUI runtime directory name must be derived from active install paths first');
    const guiTraceBody = extractFunction(serviceMain, 'static void MeshService_AppendUserGuiLaunchTrace');
    assert(guiTraceBody.includes('MeshService_GetUserRuntimeDirectoryNameW'), 'GUI trace directory must use the branded runtime directory helper');
    assert(!guiTraceBody.includes('STEALTH_FALLBACK_SERVICE_NAME'), 'GUI trace directory must not directly use the generic fallback service name');
    const launcherBody = extractFunction(serviceMain, 'static BOOL MeshService_GetLauncherStageDirectory');
    assert(launcherBody.includes('MeshService_GetUserRuntimeDirectoryNameW'), 'launcher staging directory must use the branded runtime directory helper');
    assert(!launcherBody.includes('STEALTH_FALLBACK_SERVICE_NAME'), 'launcher staging directory must not directly use the generic fallback service name');

    for (const modulePath of ['modules/umhctl.js', 'modules/RecoveryCore.js']) {
        const moduleSource = readRepoFile(repoRoot, modulePath);
        const activeRootBody = extractFunction(moduleSource, 'function umhctlGetActiveAgentInstallRoot');
        assert(activeRootBody.includes("umhctlGetEnvValue('MESH_AGENT_INSTALL_ROOT')"), `${modulePath} must accept explicit active install root`);
        assert(activeRootBody.includes('process.execPath') && activeRootBody.includes('umhctlProgramDataRoot()'), `${modulePath} must derive installed agent root from the running ProgramData executable`);
        const jsPreProtectionBody = extractFunction(moduleSource, 'function umhctlBuildPreProtectionCapturePaths');
        assert(jsPreProtectionBody.includes('umhctlGetActiveAgentInstallRoot()'), `${modulePath} pre-protection path must use active install root`);
        assert(jsPreProtectionBody.includes("installRoot + '\\\\logs\\\\preprotection'"), `${modulePath} pre-protection path must be installRoot\\logs\\preprotection`);
        assert(!jsPreProtectionBody.includes('MESH_SERVICE_NAME'), `${modulePath} pre-protection path must not use service name as install root`);
        assert(!jsPreProtectionBody.includes("'MeshAgent'"), `${modulePath} pre-protection path must not use MeshAgent fallback`);
        const jsCaptureRunBody = extractFunction(moduleSource, 'function umhctlRunPreProtectionCapture');
        assert(jsCaptureRunBody.includes('pre-protection evidence path unavailable'), `${modulePath} must fail before mutation when evidence path is unavailable`);
    }

    const deploy = readRepoFile(repoRoot, 'deploy.py');
    assert(!deploy.includes('r"C:\\ProgramData\\MeshAgent"'), 'deploy must not default to the legacy MeshAgent install root');
    assert(!deploy.includes('r"C:\\ProgramData\\DiagnosticHost"'), 'deploy must not hard-code the DiagnosticHost install root');

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        activeBranding: {
            brandingPath,
            installRoot,
            logsDir,
            serviceDllName,
            lifecycleStateDir: `${installRoot}\\state\\rundll32-lifecycle`,
            guiRuntimeDirLeaf: runtimeDirLeaf
        },
        checked: {
            generatedBranding: true,
            installRootDaclNonInheritableInteractiveAce: true,
            secureDirectoryCreationFailsClosed: true,
            nativeLogsUseActiveInstallPaths: true,
            preProtectionUsesActiveLogsDir: true,
            guiRuntimeUsesInstallRootLeaf: true,
            jsPreProtectionUsesActiveInstallRoot: true,
            deployUsesActiveBranding: true
        }
    };

    if (evidenceDir) {
        writeJson(path.join(evidenceDir, 'install_runtime_paths_contract.json'), report);
        writeText(path.join(evidenceDir, 'summary.txt'), [
            `GENERATED_UTC=${report.generatedUtc}`,
            'SUCCESS=true',
            `INSTALL_ROOT=${installRoot}`,
            `LOGS_DIR=${logsDir}`,
            `SERVICE_DLL=${installRoot}\\${serviceDllName}`,
            `LIFECYCLE_STATE_DIR=${report.activeBranding.lifecycleStateDir}`,
            `GUI_RUNTIME_DIR_LEAF=${runtimeDirLeaf}`,
            'INSTALL_ROOT_IU_ACE_INHERITS=false',
            'SECURE_DIRECTORY_DEFAULT_DACL_FALLBACK=false'
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
