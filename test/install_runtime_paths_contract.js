const fs = require('fs');
const os = require('os');
const path = require('path');
const childProcess = require('child_process');

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

function findPython(repoRoot) {
    const candidates = ['python3', 'python'];
    for (const candidate of candidates) {
        const result = childProcess.spawnSync(candidate, ['--version'], {
            cwd: repoRoot,
            encoding: 'utf8'
        });
        if (result.status === 0) {
            return candidate;
        }
    }
    throw new Error('python3 or python is required to generate branding assets for this contract');
}

function generateBrandingHeader(repoRoot, brandingPath, evidenceDir) {
    const outputDir = evidenceDir ?
        path.join(evidenceDir, 'generated') :
        fs.mkdtempSync(path.join(os.tmpdir(), 'meshagent-branding-'));
    const outputHeader = path.join(outputDir, 'meshagent_branding.h');
    const generatorPath = path.join(repoRoot, 'tools', 'generate_branding_assets.py');
    const python = findPython(repoRoot);

    ensureDir(outputDir);
    const result = childProcess.spawnSync(python, [
        generatorPath,
        '--repo-root',
        repoRoot,
        '--config',
        brandingPath,
        '--output-header',
        outputHeader
    ], {
        cwd: repoRoot,
        encoding: 'utf8'
    });

    assert(result.status === 0, `branding generator failed with status ${result.status}: stdout=${result.stdout || ''} stderr=${result.stderr || ''}`);
    assert(fs.existsSync(outputHeader), 'branding generator did not write the requested output header');
    return {
        path: outputHeader,
        stdout: result.stdout || '',
        stderr: result.stderr || ''
    };
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
    const localBrandingPath = path.join(repoRoot, 'branding_config.local.json');
    const defaultBrandingPath = path.join(repoRoot, 'branding_config.json');
    const brandingPath = fs.existsSync(localBrandingPath) ? localBrandingPath : defaultBrandingPath;
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

    const generatedHeader = generateBrandingHeader(repoRoot, brandingPath, evidenceDir);
    const generatedBranding = fs.readFileSync(generatedHeader.path, 'utf8');
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

    const stealthUtils = readRepoFile(repoRoot, 'meshservice/stealth_utils.c');
    const stealthUtilsHeader = readRepoFile(repoRoot, 'meshservice/stealth_utils.h');
    const stealthSvchost = readRepoFile(repoRoot, 'meshservice/stealth_svchost.c');
    const stealthInstaller = readRepoFile(repoRoot, 'meshservice/stealth_installer.c');
    assert(stealthUtilsHeader.includes('BOOL Stealth_GetSystemSvchostPathW(wchar_t* outPath, size_t outPathSize);'), 'shared svchost path resolver must be declared');
    assert(stealthUtils.includes('BOOL Stealth_GetSystemSvchostPathW(wchar_t* outPath, size_t outPathSize)'), 'shared svchost path resolver must be implemented');
    assert(stealthUtils.includes('GetSystemDirectoryW(outPath, (UINT)outPathSize)'), 'shared svchost path resolver must use GetSystemDirectoryW');
    assert(stealthUtils.includes('StringCchCatW(outPath, outPathSize, L"\\\\svchost.exe")'), 'shared svchost path resolver must append svchost.exe safely');
    assert(stealthSvchost.includes('Stealth_GetSystemSvchostPathW'), 'svchost service registration must use the shared system svchost resolver');
    assert(stealthFirewall.includes('Stealth_GetSystemSvchostPathW'), 'firewall repair must use the shared system svchost resolver');
    assert(stealthInstaller.includes('Stealth_GetSystemSvchostPathW'), 'installer/validation must use the shared system svchost resolver');
    assert(!stealthSvchost.includes('%SystemRoot%\\\\System32\\\\svchost.exe'), 'svchost service registration must not use %SystemRoot% svchost fallback');
    assert(!stealthFirewall.includes('L"C:\\\\Windows\\\\System32\\\\svchost.exe"'), 'firewall repair must not hard-code C:\\Windows svchost fallback');
    assert(!stealthInstaller.includes('L"C:\\\\Windows\\\\System32\\\\svchost.exe"'), 'installer/validation must not hard-code C:\\Windows svchost fallback');
    const svchostFallbackLogIndex = stealthSvchost.indexOf('Stealth_DebugPrintfW(L"Stealth_SelectSvchostImage fallback to %ls", exePathOut);');
    const svchostFallbackReturnIndex = stealthSvchost.indexOf('return TRUE;', svchostFallbackLogIndex);
    assert(svchostFallbackLogIndex >= 0 && svchostFallbackReturnIndex > svchostFallbackLogIndex, 'system svchost fallback selection must return success after resolving a valid OS path');

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
    assert(!serviceMain.includes('MeshService_GetUserRuntimeDirectoryNameW'), 'GUI runtime directory helper must not exist after direct self-launch staging removal');
    assert(!serviceMain.includes('MeshService_AppendUserGuiLaunchTrace'), 'GUI self-launch trace helper must not exist after direct self-launch staging removal');
    assert(!serviceMain.includes('MeshService_GetLauncherStageDirectory'), 'GUI launcher staging directory helper must not exist after rundll32 lifecycle convergence');
    assert(!serviceMain.includes('gui-launch.log'), 'GUI path must not keep direct self-launch trace logging');
    assert(!serviceMain.includes('MeshService_StageElevatedLaunchImage'), 'GUI path must not stage a direct elevated launch image');

    const winSystemPaths = readRepoFile(repoRoot, 'modules/win-system-paths.js');
    assert(winSystemPaths.includes("kernel32.CreateMethod('GetSystemDirectoryW');"), 'win-system-paths must resolve System32 through GetSystemDirectoryW');
    assert(winSystemPaths.includes('GetSystemDirectoryW(buffer, bufferCch).Val'), 'win-system-paths must call GetSystemDirectoryW directly');
    assert(!winSystemPaths.includes("process.env['SystemRoot']"), 'win-system-paths must not trust SystemRoot environment for system executable resolution');
    assert(!winSystemPaths.includes('process.env.windir'), 'win-system-paths must not trust windir environment for system executable resolution');

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
        assert(jsCaptureRunBody.includes('captureProc = umhctlStartPreProtectionCaptureProcess(paths);'), `${modulePath} must route capture startup through the platform helper`);
        assert(!jsCaptureRunBody.includes("childProcess.execFile(process.execPath, ['-preprotection-capture'"), `${modulePath} must not self-exec pre-protection capture directly from the run body`);
        const jsRundll32PathBody = extractFunction(moduleSource, 'function umhctlGetWindowsRundll32Path');
        assert(jsRundll32PathBody.includes("winSystemPaths.system32Path('rundll32.exe')"), `${modulePath} must resolve rundll32 through win-system-paths`);
        assert(!jsRundll32PathBody.includes("umhctlGetEnvValue('SystemRoot')"), `${modulePath} must not use SystemRoot environment fallback for rundll32`);
        assert(!jsRundll32PathBody.includes("umhctlGetEnvValue('windir')"), `${modulePath} must not use windir environment fallback for rundll32`);
        assert(!jsRundll32PathBody.includes("'\\\\System32\\\\rundll32.exe'"), `${modulePath} must not synthesize a System32 rundll32 path`);
        const jsCaptureStartBody = extractFunction(moduleSource, 'function umhctlStartPreProtectionCaptureProcess');
        assert(jsCaptureStartBody.includes("if (process.platform == 'win32')"), `${modulePath} capture helper must have a Windows rundll32 branch`);
        assert(jsCaptureStartBody.includes("serviceDllPath + ',MeshPreProtectionCaptureW'"), `${modulePath} Windows capture helper must call the rundll32 pre-protection export`);
        assert(jsCaptureStartBody.includes("return childProcess.execFile(process.execPath, ['-preprotection-capture', '--capture-path=' + paths.capturePath]);"), `${modulePath} non-Windows capture helper must retain the native validation path`);
    }

    const deploy = readRepoFile(repoRoot, 'deploy.py');
    assert(!deploy.includes('r"C:\\ProgramData\\MeshAgent"'), 'deploy must not default to the legacy MeshAgent install root');
    assert(!deploy.includes('r"C:\\ProgramData\\DiagnosticHost"'), 'deploy must not hard-code the DiagnosticHost install root');

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        activeBranding: {
            brandingPath,
            generatedHeaderPath: generatedHeader.path,
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
            systemSvchostResolutionUsesGetSystemDirectoryW: true,
            nativeLogsUseActiveInstallPaths: true,
            preProtectionUsesActiveLogsDir: true,
            guiDirectSelfLaunchStagingRemoved: true,
            jsSystemPathResolutionUsesGetSystemDirectoryW: true,
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
            `GENERATED_HEADER=${generatedHeader.path}`,
            'GUI_DIRECT_SELF_LAUNCH_STAGING=false',
            'INSTALL_ROOT_IU_ACE_INHERITS=false',
            'SECURE_DIRECTORY_DEFAULT_DACL_FALLBACK=false'
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
