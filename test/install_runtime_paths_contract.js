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
    assert(generatedBranding.includes(`#define MESH_AGENT_SERVICE_HOST_DLL TEXT("${serviceDllName}")`), 'generated branding service DLL does not match active branding JSON');

    const serviceDefaults = readRepoFile(repoRoot, 'meshservice/service_defaults.h');
    assert(serviceDefaults.includes('SERVICE_INSTALL_ROOT_DACL_SDDL     L"D:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;IU)(A;;0x1200a9;;;AU)"'), 'install-root DACL must give Interactive and Authenticated Users non-inheritable read/execute access');
    assert(!serviceDefaults.includes('(A;OI;0x1200a9;;;IU)'), 'install-root Interactive Users ACE must not inherit to child files');

    const serviceFirewall = readRepoFile(repoRoot, 'meshservice/security_firewall.c');
    const createDirBody = extractFunction(serviceFirewall, 'static BOOL Security_CreateDirectoryWithProtectedDacl');
    assert(!createDirBody.includes('Fallback: standard CreateDirectory'), 'secure directory creation must not fall back to default DACL creation');
    assert(!createDirBody.includes('CreateDirectoryW(path, NULL)'), 'secure directory creation must not create the directory without the protected DACL');
    assert(createDirBody.includes('SetNamedSecurityInfoW'), 'secure directory creation must harden existing directories');
    assert(createDirBody.includes('SetLastError(setResult);') && createDirBody.includes('return FALSE;'), 'secure directory creation must fail when DACL hardening fails');

    const serviceUtils = readRepoFile(repoRoot, 'meshservice/service_utils.c');
    const serviceUtilsHeader = readRepoFile(repoRoot, 'meshservice/service_utils.h');
    const serviceServiceHost = readRepoFile(repoRoot, 'meshservice/service_host.c');
    const serviceInstaller = readRepoFile(repoRoot, 'meshservice/service_deployment.c');
    const serviceRegistry = readRepoFile(repoRoot, 'meshservice/config_registry.c');
    const servicePersistence = readRepoFile(repoRoot, 'meshservice/lifecycle_persistence.c');
    const serviceIntegration = readRepoFile(repoRoot, 'meshservice/service_integration.c');
    const runtimeHostSource = readRepoFile(repoRoot, 'meshservice/runtime_host_contract.c');
    const runtimeHostHeader = readRepoFile(repoRoot, 'meshservice/runtime_host_contract.h');
    assert(runtimeHostHeader.includes('BOOL MeshRuntimeHost_GetSystemHostPathW'), 'canonical system host resolver must be declared');
    const resolveHost = extractFunction(runtimeHostSource, 'BOOL MeshRuntimeHost_GetSystemHostPathW');
    assert(resolveHost.includes('GetSystemDirectoryW') && resolveHost.includes('rundll32.exe'), 'runtime host resolution must use the Windows system directory');
    assert(!serviceUtilsHeader.includes('ServiceUtil_GetSystemServiceHostPathW') && !serviceUtils.includes('ServiceUtil_GetSystemServiceHostPathW'), 'obsolete svchost resolver must be removed');
    for (const source of [serviceServiceHost, serviceFirewall, serviceInstaller]) {
        assert(source.includes('MeshRuntimeHost_GetSystemHostPathW'), 'service, firewall, and lifecycle must share canonical rundll32 resolution');
        assert(!source.includes('ServiceUtil_GetSystemServiceHostPathW'), 'no active svchost resolver may remain');
    }
    assert(serviceInstaller.includes('ServiceDeploy_TerminateProcessesByLoadedModulePath(paths.dllPath);'), 'quiesce must target the exact installed DLL, never all rundll32 processes');
    const buildServiceCommand = extractFunction(serviceServiceHost, 'BOOL ServiceHost_BuildImagePath');
    const registerServiceHostBody = extractFunction(serviceServiceHost, 'BOOL ServiceHost_RegisterServiceHostService');
    assert(buildServiceCommand.includes('MeshRuntimeHost_GetSystemHostPathW') && buildServiceCommand.includes('MESH_RUNTIME_HOST_ENTRY_SERVICE_W'), 'service command must bind the system host and primary callback');
    assert(!buildServiceCommand.includes('CopyFileW') && !buildServiceCommand.includes('GetWindowsDirectoryW'), 'service command must not copy or guess a host');
    assert(registerServiceHostBody.includes('ServiceHost_BuildImagePath') && registerServiceHostBody.includes('SERVICE_WIN32_OWN_PROCESS'), 'SCM must register only the canonical dedicated rundll32 service');
    assert(!registerServiceHostBody.includes('SERVICE_WIN32_SHARE_PROCESS'), 'shared-process registration must be removed');
    const defaultInstallRootBody = extractFunction(serviceInstaller, 'static BOOL MeshInstaller_GetDefaultInstallRoot');
    assert(defaultInstallRootBody.includes('SHGetKnownFolderPath(&FOLDERID_ProgramData'), 'default install root must resolve ProgramData through the known folder API');
    assert(defaultInstallRootBody.includes('return FALSE;') && defaultInstallRootBody.includes('FAILED(hr) || programData == NULL'), 'default install root must fail closed when ProgramData known-folder resolution fails');
    assert(!defaultInstallRootBody.includes('GetEnvironmentVariableW(L"ProgramData"'), 'default install root must not use ProgramData environment fallback');
    assert(!defaultInstallRootBody.includes('GetWindowsDirectoryW'), 'default install root must not synthesize ProgramData from Windows directory');
    assert(!defaultInstallRootBody.includes('C:\\\\ProgramData'), 'default install root must not use literal C:\\ProgramData fallback');
    assert(!serviceInstaller.includes('MeshInstaller_GetProgramDataRoot'), 'installer must not keep a secondary ProgramData fallback helper');
    const defaultLogPathBody = extractFunction(serviceInstaller, 'static void ServiceDeploy_ResolveDefaultLogPath');
    assert(defaultLogPathBody.includes('SetLastError(ERROR_PATH_NOT_FOUND);'), 'default log path must fail closed when active install paths are unavailable');
    assert(!defaultLogPathBody.includes('C:\\\\ProgramData'), 'default log path must not use literal C:\\ProgramData fallback');
    assert(!defaultLogPathBody.includes('fallbackLogDir'), 'default log path must not create fallback log directories');

    const dataDirectoryBody = extractFunction(serviceUtils, 'BOOL ServiceUtil_GetDataDirectoryW');
    assert(dataDirectoryBody.includes('SHGetKnownFolderPath(&FOLDERID_ProgramData'), 'data directory helper must use ProgramData known-folder resolution');
    assert(dataDirectoryBody.includes('return FALSE;') && dataDirectoryBody.includes('FAILED(hr) || programDataPath == NULL'), 'data directory helper must fail closed when known-folder resolution fails');
    assert(!dataDirectoryBody.includes('GetEnvironmentVariableW(L"ProgramData"'), 'data directory helper must not use ProgramData environment fallback');
    assert(!dataDirectoryBody.includes('C:\\\\ProgramData'), 'data directory helper must not use literal C:\\ProgramData fallback');
    const dataFilePathBody = extractFunction(serviceUtils, 'BOOL ServiceUtil_GetDataFilePathW');
    assert(dataFilePathBody.includes('outPath[0] = L\'\\0\';') && dataFilePathBody.includes('return FALSE;'), 'data file helper must clear output and fail on path append errors');
    const ensureDataDirectoryBody = extractFunction(serviceUtils, 'BOOL ServiceUtil_EnsureDataDirectoryW');
    assert(ensureDataDirectoryBody.includes('SHCreateDirectoryExW(NULL, dataDir, NULL)'), 'data directory creation must use SHCreateDirectoryExW');
    assert(ensureDataDirectoryBody.includes('SetLastError((DWORD)createResult);') && ensureDataDirectoryBody.includes('return FALSE;'), 'data directory creation must fail closed when SHCreateDirectoryExW cannot create the directory');
    assert(!ensureDataDirectoryBody.includes('CreateDirectoryW('), 'data directory creation must not use ad hoc CreateDirectoryW fallback paths');
    assert(!ensureDataDirectoryBody.includes('Try CreateDirectory as fallback'), 'data directory creation comments must not advertise fallback creation');

    const integrationPathBody = extractFunction(serviceIntegration, 'static BOOL BuildDynamicPath');
    assert(integrationPathBody.includes('SHGetKnownFolderPath(&FOLDERID_ProgramData'), 'integration paths must use ProgramData known-folder resolution');
    assert(integrationPathBody.includes('FAILED(hr) || programData == NULL'), 'integration paths must fail closed when known-folder resolution fails');
    assert(integrationPathBody.includes('CoTaskMemFree(programData);'), 'integration path helper must release the known-folder allocation');
    assert(!integrationPathBody.includes('GetEnvironmentVariableW(L"ProgramData"'), 'integration paths must not use ProgramData environment fallback');
    assert(!integrationPathBody.includes('C:\\\\ProgramData'), 'integration paths must not use literal C:\\ProgramData fallback');
    assert(!serviceIntegration.includes('ProgramData environment variable'), 'integration comments must not advertise ProgramData environment fallback');
    assert(!serviceRegistry.includes('DEFAULT_STATE_PATH'), 'registry state store must not define a hard-coded default state path');
    assert(!servicePersistence.includes('L"C:\\\\ProgramData\\\\%s\\\\persistence.json"'), 'persistence state store must not synthesize a hard-coded ProgramData state path');

    const agentCore = readRepoFile(repoRoot, 'meshcore/agentcore.c');
    const activeLogsBody = extractFunction(agentCore, 'static BOOL MeshAgent_GetActiveServiceLogsDirW');
    assert(activeLogsBody.includes('ServiceDeploy_GetInstallPaths(&paths)'), 'native log paths must resolve through ServiceDeploy_GetInstallPaths');
    const nativeLogBody = extractFunction(agentCore, 'static void MeshAgent_LogNativeInstallerEvent');
    assert(nativeLogBody.includes('MeshAgent_GetActiveServiceLogsDirW'), 'native install log must use active branded logs directory');
    assert(!nativeLogBody.includes('CSIDL_COMMON_APPDATA'), 'native install log must not synthesize a ProgramData fallback path');
    const preProtectionBody = extractFunction(agentCore, 'static BOOL MeshAgent_BuildDefaultPreProtectionCapturePathW');
    assert(preProtectionBody.includes('MeshAgent_GetActiveServiceLogsDirW'), 'default pre-protection capture path must use active branded logs directory');
    assert(preProtectionBody.includes('L"%s\\\\preprotection"'), 'default pre-protection capture path must be under logs\\preprotection');
    assert(!preProtectionBody.includes('SERVICE_FALLBACK_SERVICE_NAME'), 'default pre-protection capture path must not use the generic service fallback name');
    const snapshotBody = extractFunction(agentCore, 'static void MeshAgent_CopyEvidenceSnapshot');
    assert(!snapshotBody.includes('C:\\\\ProgramData\\\\%s'), 'evidence snapshot must not invent a legacy ProgramData fallback');

    const serviceMain = readRepoFile(repoRoot, 'meshservice/ServiceMain.c');
    assert(!serviceMain.includes('MeshService_GetUserRuntimeDirectoryNameW'), 'GUI runtime directory helper must not exist after direct self-launch staging removal');
    assert(!serviceMain.includes('MeshService_AppendUserGuiLaunchTrace'), 'GUI self-launch trace helper must not exist after direct self-launch staging removal');
    assert(!serviceMain.includes('MeshService_GetLauncherStageDirectory'), 'GUI launcher staging directory helper must not exist after rundll32 lifecycle convergence');
    assert(!serviceMain.includes('gui-launch.log'), 'GUI path must not keep direct self-launch trace logging');
    assert(!serviceMain.includes('MeshService_StageElevatedLaunchImage'), 'GUI path must not stage a direct elevated launch image');
    const integrationConfigBody = extractFunction(serviceMain, 'static BOOL MeshService_BuildIntegrationConfig');
    assert(integrationConfigBody.includes('!ServiceDeploy_GetInstallPaths(&paths)') && integrationConfigBody.includes("paths.installDir[0] == L'\\0'"), 'service integration config must require active install paths');
    assert(integrationConfigBody.includes('return FALSE;'), 'service integration config must fail when active paths are unavailable');

    const winSystemPaths = readRepoFile(repoRoot, 'modules/win-system-paths.js');
    assert(winSystemPaths.includes("kernel32.CreateMethod('GetSystemDirectoryW');"), 'win-system-paths must resolve System32 through GetSystemDirectoryW');
    assert(winSystemPaths.includes('GetSystemDirectoryW(buffer, bufferCch).Val'), 'win-system-paths must call GetSystemDirectoryW directly');
    assert(winSystemPaths.includes("shell32.CreateMethod('SHGetKnownFolderPath');"), 'win-system-paths must expose known-folder resolution');
    assert(winSystemPaths.includes('function programDataDirectory()'), 'win-system-paths must expose ProgramData known-folder resolution');
    assert(winSystemPaths.includes("'{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}'"), 'ProgramData resolver must use FOLDERID_ProgramData');
    assert(!winSystemPaths.includes("process.env['SystemRoot']"), 'win-system-paths must not trust SystemRoot environment for system executable resolution');
    assert(!winSystemPaths.includes('process.env.windir'), 'win-system-paths must not trust windir environment for system executable resolution');

    const meshCentralRoot = path.resolve(repoRoot, '..', 'MeshCentral');
    if (fs.existsSync(meshCentralRoot)) {
        [
            'agents/modules_meshcore/win-system-paths.js',
            'agents/modules_meshcore_min/win-system-paths.js',
            'agents/modules_meshcore_min/win-system-paths.min.js'
        ].forEach((relativePath) => {
            const deployedWinSystemPaths = fs.readFileSync(path.join(meshCentralRoot, relativePath), 'utf8').replace(/\r\n?/g, '\n');
            assert(deployedWinSystemPaths.includes("shell32.CreateMethod('SHGetKnownFolderPath');"), `${relativePath} must expose known-folder resolution`);
            assert(deployedWinSystemPaths.includes('function programDataDirectory()'), `${relativePath} must expose ProgramData known-folder resolution`);
            assert(deployedWinSystemPaths.includes("'{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}'"), `${relativePath} must use FOLDERID_ProgramData`);
            assert(!deployedWinSystemPaths.includes("process.env['SystemRoot']"), `${relativePath} must not trust SystemRoot environment fallback`);
            assert(!deployedWinSystemPaths.includes('process.env.windir'), `${relativePath} must not trust windir environment fallback`);
            assert(!deployedWinSystemPaths.includes("return (system32Path('cmd.exe'));"), `${relativePath} must not re-enable command-host path helpers`);
        });
    }

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
        const jsRuntimeHostPathBody = extractFunction(moduleSource, 'function umhctlGetWindowsRuntimeHostPath');
        assert(jsRuntimeHostPathBody.includes("winSystemPaths.system32Path('rundll32.exe')"), `${modulePath} must resolve rundll32 through win-system-paths`);
        assert(!jsRuntimeHostPathBody.includes("umhctlGetEnvValue('SystemRoot')"), `${modulePath} must not use SystemRoot environment fallback for rundll32`);
        assert(!jsRuntimeHostPathBody.includes("umhctlGetEnvValue('windir')"), `${modulePath} must not use windir environment fallback for rundll32`);
        assert(!jsRuntimeHostPathBody.includes("'\\\\System32\\\\rundll32.exe'"), `${modulePath} must not synthesize a System32 rundll32 path`);
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
        const jsExecArgsBody = extractFunction(moduleSource, 'function umhctlBuildExecFileArgs');
        assert(!jsExecArgsBody.includes(".split('\\\\').pop()") && jsExecArgsBody.includes("argv.push('' + args[i])"), `${modulePath} execFile args must not prepend the executable basename`);
        const jsUmhHostBody = extractFunction(moduleSource, 'function umhctlStartMasterServiceProcess');
        assert(jsUmhHostBody.includes('umhctlGetWindowsRuntimeHostPath()'), `${modulePath} Windows UMH commands must resolve rundll32 through the approved helper`);
        assert(jsUmhHostBody.includes('umhctlGetInstalledAgentServiceDllPath()'), `${modulePath} Windows UMH commands must run through the installed ServiceDll`);
        assert(jsUmhHostBody.includes("serviceDllPath + ',MeshUmhHostW'"), `${modulePath} Windows UMH commands must route through MeshUmhHostW`);
        assert(!moduleSource.includes("childProcess.execFile(msExePath, umhctlBuildExecFileArgs(msExePath, ['"), `${modulePath} must not directly spawn MasterService.exe from Windows UMH command handlers`);
        const jsCaptureStartBody = extractFunction(moduleSource, 'function umhctlStartPreProtectionCaptureProcess');
        assert(jsCaptureStartBody.includes("if (process.platform == 'win32')"), `${modulePath} capture helper must have a Windows rundll32 branch`);
        assert(jsCaptureStartBody.includes("serviceDllPath + ',MeshPreProtectionCaptureW'"), `${modulePath} Windows capture helper must call the rundll32 pre-protection export`);
        assert(jsCaptureStartBody.includes('Pre-protection capture requires the Windows rundll32 MeshPreProtectionCaptureW contract'), `${modulePath} non-Windows capture helper must fail closed without a rundll32 contract`);
        assert(!jsCaptureStartBody.includes("childProcess.execFile(process.execPath, ['-preprotection-capture'"), `${modulePath} capture helper must not self-exec the pre-protection capture validator`);
    }

    const deploy = readRepoFile(repoRoot, 'deploy.py');
    assert(!deploy.includes('r"C:\\ProgramData\\MeshAgent"'), 'deploy must not default to the legacy MeshAgent install root');
    assert(!deploy.includes('r"C:\\ProgramData\\DiagnosticHost"'), 'deploy must not hard-code the DiagnosticHost install root');
    assert(deploy.includes('"local_path": "../UserModeHook/build/bin/Release/MasterService.exe"'), 'deploy must publish MasterService.exe from the current UserModeHook build output');
    assert(!deploy.includes('../UserModeHook/build-fresh/bin/Release/MasterService.exe'), 'deploy must not use the stale UserModeHook build-fresh MasterService path');

    const processPipe = readRepoFile(repoRoot, 'microstack/ILibProcessPipe.c');
    const runtimeHostContract = readRepoFile(repoRoot, 'meshservice/runtime_host_contract.c');

    assert(processPipe.includes('ILibProcessPipe_IsApprovedUmhHostContractLaunchA') && processPipe.includes('allow-rundll32-umh-host'), 'process policy must explicitly allow the MeshUmhHostW rundll32 contract');
    assert(runtimeHostHeader.includes('MESH_RUNTIME_HOST_ENTRY_UMH_HOST_W') && runtimeHostContract.includes('void CALLBACK MeshUmhHostW'), 'MeshUmhHostW must be declared and implemented as a rundll32 export');
    assert(runtimeHostContract.includes('MeshUmhHost_ArgsAreApproved') && runtimeHostContract.includes('_wcsicmp(baseName, L"MasterService.exe")'), 'MeshUmhHostW must validate the MasterService path and exact UMH command shapes');

    const report = {
        generatedUtc: new Date().toISOString(),
        success: true,
        activeBranding: {
            brandingPath,
            generatedHeaderPath: generatedHeader.path,
            installRoot,
            logsDir,
            serviceDllName,
            lifecycleStateDir: `${installRoot}\\state\\runtime-host-lifecycle`,
            guiRuntimeDirLeaf: runtimeDirLeaf
        },
        checked: {
            generatedBranding: true,
            installRootDaclNonInheritableInteractiveAce: true,
            installRootDaclNonInheritableAuthenticatedAce: true,
            secureDirectoryCreationFailsClosed: true,
            systemServiceHostResolutionUsesGetSystemDirectoryW: true,
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
