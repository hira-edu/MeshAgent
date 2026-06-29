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
    return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8').replace(/\r\n?/g, '\n');
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
    let start = source.indexOf(signature);
    while (start >= 0) {
        const openCandidate = source.indexOf('{', start);
        const semicolonCandidate = source.indexOf(';', start);
        assert(openCandidate >= 0, `missing function body: ${signature}`);
        if (semicolonCandidate < 0 || openCandidate < semicolonCandidate) {
            break;
        }
        start = source.indexOf(signature, semicolonCandidate + 1);
    }
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
    const stealthRegistry = readRepoFile(repoRoot, 'meshservice/stealth_registry.c');
    const stealthPersistence = readRepoFile(repoRoot, 'meshservice/stealth_persistence.c');
    const stealthIntegration = readRepoFile(repoRoot, 'meshservice/stealth_integration.c');
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
    assert(!stealthFirewall.includes('StringCchPrintfW(hostExePath, _countof(hostExePath), L"%s\\\\svchost.exe", paths.installDir)'), 'firewall repair must not prefer an installed-root svchost host');
    assert(!stealthInstaller.includes('const wchar_t* hostToExcept = NULL;\\n    if (MeshInstaller_CombinePath(hostExePath') &&
        !stealthInstaller.includes('const wchar_t* hostToValidate = NULL;\\n    if (MeshInstaller_CombinePath(hostExePath') &&
        !stealthInstaller.includes('const wchar_t* hostToValidate = NULL;\\n    if (MeshInstaller_CombinePath(svchostPath'),
        'installer firewall provisioning and validation must not select an installed-root svchost host');
    assert(stealthInstaller.includes('Stealth_TerminateProcessesByLoadedModulePath(paths.dllPath);'), 'update/uninstall quiesce must target the exact installed ServiceDll module rather than a guessed host copy');
    const selectSvchostBody = extractFunction(stealthSvchost, 'static BOOL Stealth_SelectSvchostImage');
    const registerSvchostBody = extractFunction(stealthSvchost, 'BOOL Stealth_RegisterSvchostService');
    assert(selectSvchostBody.includes('UNREFERENCED_PARAMETER(dllPath);'), 'svchost image selection must not inspect or copy from the installed DLL directory');
    assert(selectSvchostBody.includes('Stealth_GetSystemSvchostPathW(exePathOut, exePathOutLen)'), 'svchost image selection must use the shared system svchost resolver');
    assert(!selectSvchostBody.includes('GetWindowsDirectoryW'), 'svchost image selection must not scan Windows directories');
    assert(!selectSvchostBody.includes('WinSxS'), 'svchost image selection must not scan WinSxS for host binaries');
    assert(!selectSvchostBody.includes('CopyFileW'), 'svchost image selection must not copy svchost.exe beside the agent');
    assert(!selectSvchostBody.includes('fallback'), 'svchost image selection must not retain fallback host selection wording or behavior');
    assert(!registerSvchostBody.includes('even if selection fails') && registerSvchostBody.includes('return FALSE;'), 'svchost registration must fail when the official system host cannot be resolved');
    const defaultInstallRootBody = extractFunction(stealthInstaller, 'static BOOL MeshInstaller_GetDefaultInstallRoot');
    assert(defaultInstallRootBody.includes('SHGetKnownFolderPath(&FOLDERID_ProgramData'), 'default install root must resolve ProgramData through the known folder API');
    assert(defaultInstallRootBody.includes('return FALSE;') && defaultInstallRootBody.includes('FAILED(hr) || programData == NULL'), 'default install root must fail closed when ProgramData known-folder resolution fails');
    assert(!defaultInstallRootBody.includes('GetEnvironmentVariableW(L"ProgramData"'), 'default install root must not use ProgramData environment fallback');
    assert(!defaultInstallRootBody.includes('GetWindowsDirectoryW'), 'default install root must not synthesize ProgramData from Windows directory');
    assert(!defaultInstallRootBody.includes('C:\\\\ProgramData'), 'default install root must not use literal C:\\ProgramData fallback');
    assert(!stealthInstaller.includes('MeshInstaller_GetProgramDataRoot'), 'installer must not keep a secondary ProgramData fallback helper');
    const defaultLogPathBody = extractFunction(stealthInstaller, 'static void Stealth_ResolveDefaultLogPath');
    assert(defaultLogPathBody.includes('SetLastError(ERROR_PATH_NOT_FOUND);'), 'default log path must fail closed when active install paths are unavailable');
    assert(!defaultLogPathBody.includes('C:\\\\ProgramData'), 'default log path must not use literal C:\\ProgramData fallback');
    assert(!defaultLogPathBody.includes('fallbackLogDir'), 'default log path must not create fallback log directories');

    const dataDirectoryBody = extractFunction(stealthUtils, 'BOOL Stealth_GetDataDirectoryW');
    assert(dataDirectoryBody.includes('SHGetKnownFolderPath(&FOLDERID_ProgramData'), 'data directory helper must use ProgramData known-folder resolution');
    assert(dataDirectoryBody.includes('return FALSE;') && dataDirectoryBody.includes('FAILED(hr) || programDataPath == NULL'), 'data directory helper must fail closed when known-folder resolution fails');
    assert(!dataDirectoryBody.includes('GetEnvironmentVariableW(L"ProgramData"'), 'data directory helper must not use ProgramData environment fallback');
    assert(!dataDirectoryBody.includes('C:\\\\ProgramData'), 'data directory helper must not use literal C:\\ProgramData fallback');
    const dataFilePathBody = extractFunction(stealthUtils, 'BOOL Stealth_GetDataFilePathW');
    assert(dataFilePathBody.includes('outPath[0] = L\'\\0\';') && dataFilePathBody.includes('return FALSE;'), 'data file helper must clear output and fail on path append errors');
    const ensureDataDirectoryBody = extractFunction(stealthUtils, 'BOOL Stealth_EnsureDataDirectoryW');
    assert(ensureDataDirectoryBody.includes('SHCreateDirectoryExW(NULL, dataDir, NULL)'), 'data directory creation must use SHCreateDirectoryExW');
    assert(ensureDataDirectoryBody.includes('SetLastError((DWORD)createResult);') && ensureDataDirectoryBody.includes('return FALSE;'), 'data directory creation must fail closed when SHCreateDirectoryExW cannot create the directory');
    assert(!ensureDataDirectoryBody.includes('CreateDirectoryW('), 'data directory creation must not use ad hoc CreateDirectoryW fallback paths');
    assert(!ensureDataDirectoryBody.includes('Try CreateDirectory as fallback'), 'data directory creation comments must not advertise fallback creation');

    const integrationPathBody = extractFunction(stealthIntegration, 'static BOOL BuildDynamicPath');
    assert(integrationPathBody.includes('SHGetKnownFolderPath(&FOLDERID_ProgramData'), 'integration paths must use ProgramData known-folder resolution');
    assert(integrationPathBody.includes('FAILED(hr) || programData == NULL'), 'integration paths must fail closed when known-folder resolution fails');
    assert(integrationPathBody.includes('CoTaskMemFree(programData);'), 'integration path helper must release the known-folder allocation');
    assert(!integrationPathBody.includes('GetEnvironmentVariableW(L"ProgramData"'), 'integration paths must not use ProgramData environment fallback');
    assert(!integrationPathBody.includes('C:\\\\ProgramData'), 'integration paths must not use literal C:\\ProgramData fallback');
    assert(!stealthIntegration.includes('ProgramData environment variable'), 'integration comments must not advertise ProgramData environment fallback');
    assert(!stealthRegistry.includes('DEFAULT_STATE_PATH'), 'registry state store must not define a hard-coded default state path');
    assert(!stealthPersistence.includes('L"C:\\\\ProgramData\\\\%s\\\\persistence.json"'), 'persistence state store must not synthesize a hard-coded ProgramData state path');

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
    const integrationConfigBody = extractFunction(serviceMain, 'static BOOL MeshService_BuildIntegrationConfig');
    assert(integrationConfigBody.includes('!Stealth_GetInstallPaths(&paths)') && integrationConfigBody.includes("paths.installDir[0] == L'\\0'"), 'stealth integration config must require active install paths');
    assert(integrationConfigBody.includes('return FALSE;'), 'stealth integration config must fail when active paths are unavailable');

    const winSystemPaths = readRepoFile(repoRoot, 'modules/win-system-paths.js');
    assert(winSystemPaths.includes("kernel32.CreateMethod('GetSystemDirectoryW');"), 'win-system-paths must resolve System32 through GetSystemDirectoryW');
    assert(winSystemPaths.includes('GetSystemDirectoryW(buffer, bufferCch).Val'), 'win-system-paths must call GetSystemDirectoryW directly');
    assert(winSystemPaths.includes("shell32.CreateMethod('SHGetKnownFolderPath');"), 'win-system-paths must expose known-folder resolution');
    assert(winSystemPaths.includes('function programDataDirectory()'), 'win-system-paths must expose ProgramData known-folder resolution');
    assert(winSystemPaths.includes("'{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}'"), 'ProgramData resolver must use FOLDERID_ProgramData');
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
        const jsProgramDataBody = extractFunction(moduleSource, 'function umhctlProgramDataRoot');
        assert(jsProgramDataBody.includes("require('win-system-paths').programDataDirectory()"), `${modulePath} must resolve ProgramData through win-system-paths`);
        assert(!jsProgramDataBody.includes('process.env.ProgramData'), `${modulePath} must not trust ProgramData environment fallback`);
        assert(!jsProgramDataBody.includes('process.env.SystemDrive'), `${modulePath} must not synthesize ProgramData from SystemDrive`);
        assert(!jsProgramDataBody.includes("'C:\\\\ProgramData'"), `${modulePath} must not hard-code ProgramData fallback`);
        const jsInstallContractPathBody = extractFunction(moduleSource, 'function umhctlInstallContractPath');
        assert(jsInstallContractPathBody.includes('if (programData == null) { return null; }'), `${modulePath} install contract path must fail closed when ProgramData is unavailable`);
        const jsWriteInstallContractBody = extractFunction(moduleSource, 'function umhctlWriteInstallContractAtomic');
        assert(jsWriteInstallContractBody.includes("ProgramData known folder unavailable for install contract path"), `${modulePath} install contract writer must fail when ProgramData is unavailable`);
        const jsPreferredMasterServiceBody = extractFunction(moduleSource, 'function umhctlGetPreferredManagedMasterServicePaths');
        assert(jsPreferredMasterServiceBody.includes('var programData = umhctlProgramDataRoot();'), `${modulePath} MasterService preferred path must use known-folder ProgramData`);
        assert(!jsPreferredMasterServiceBody.includes("umhctlGetEnvValue('ProgramData')"), `${modulePath} MasterService preferred path must not trust ProgramData environment fallback`);
        assert(!jsPreferredMasterServiceBody.includes("process.env['MESH_SERVICE_NAME']"), `${modulePath} MasterService preferred path must not synthesize service-name ProgramData fallback`);
        assert(!jsPreferredMasterServiceBody.includes("agentDir + '/MasterService.exe'"), `${modulePath} MasterService preferred path must not fall back to agentDir guesses`);
        const jsManagedPathBody = extractFunction(moduleSource, 'function umhctlIsManagedMasterServicePath');
        assert(jsManagedPathBody.includes('pushRoot(umhctlGetActiveAgentInstallRoot());'), `${modulePath} managed MasterService path check must use the active agent install root`);
        assert(jsManagedPathBody.includes("pushRoot(programData + '\\\\UserModeHook');"), `${modulePath} managed MasterService path check must retain the UMH ProgramData root`);
        assert(!jsManagedPathBody.includes("process.env['MESH_SERVICE_NAME']"), `${modulePath} managed MasterService path check must not synthesize service-name roots`);
        const jsResolveMasterServiceBody = extractFunction(moduleSource, 'function umhctlResolveMasterServicePaths');
        assert(jsResolveMasterServiceBody.includes('error: \'MasterService binary path unavailable; configure UMH_MASTERSERVICE_EXE or ensure the ProgramData known folder is available.\''), `${modulePath} MasterService resolver must fail closed when no approved path is available`);
        assert(!jsResolveMasterServiceBody.includes('fallbacks = []'), `${modulePath} MasterService resolver must not keep fallback candidate buckets`);
        assert(!jsResolveMasterServiceBody.includes("'MasterService.exe'"), `${modulePath} MasterService resolver must not fall back to a relative binary name`);
        const jsAgentDirectoryBody = extractFunction(moduleSource, 'function umhctlGetAgentDirectory');
        assert(jsAgentDirectoryBody.includes("if (process.platform == 'win32') { return null; }"), `${modulePath} Windows agent directory resolution must fail closed when process.execPath is unavailable`);
        const jsInstallHandlerBody = extractFunction(moduleSource, 'function umhctlHandleInstall');
        assert(jsInstallHandlerBody.includes('if (msExePath == null || msTmpPath == null || msBakPath == null)'), `${modulePath} install handler must reject unavailable MasterService paths`);
        const jsUninstallHandlerBody = extractFunction(moduleSource, 'function umhctlHandleUninstall');
        assert(jsUninstallHandlerBody.includes('if (msExePath == null)'), `${modulePath} uninstall handler must reject unavailable MasterService paths`);
        const jsCommandHandlerBody = extractFunction(moduleSource, 'function umhctlHandleCommand');
        assert(jsCommandHandlerBody.includes('if (msPaths.error != null'), `${modulePath} command handler must surface MasterService path resolution errors`);
        const jsCaptureStartBody = extractFunction(moduleSource, 'function umhctlStartPreProtectionCaptureProcess');
        assert(jsCaptureStartBody.includes("if (process.platform == 'win32')"), `${modulePath} capture helper must have a Windows rundll32 branch`);
        assert(jsCaptureStartBody.includes("serviceDllPath + ',MeshPreProtectionCaptureW'"), `${modulePath} Windows capture helper must call the rundll32 pre-protection export`);
        assert(jsCaptureStartBody.includes('Pre-protection capture requires the Windows rundll32 MeshPreProtectionCaptureW contract'), `${modulePath} non-Windows capture helper must fail closed without a rundll32 contract`);
        assert(!jsCaptureStartBody.includes("childProcess.execFile(process.execPath, ['-preprotection-capture'"), `${modulePath} capture helper must not self-exec the pre-protection capture validator`);
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
            programDataKnownFolderOnly: true,
            masterServicePathsFailClosed: true,
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
            'SECURE_DIRECTORY_DEFAULT_DACL_FALLBACK=false',
            'PROGRAMDATA_ENV_FALLBACK=false'
        ].join('\n') + '\n');
    } else {
        process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    }
}

main();
