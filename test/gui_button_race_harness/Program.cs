using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;

const int IDC_INSTALLBUTTON = 1002;
const int IDC_UNINSTALLBUTTON = 1004;
const int IDC_CONNECTBUTTON = 1009;
const int IDC_DETAILSBUTTON = 1031;
const int IDOK_ID = 1;
const int IDCANCEL_ID = 2;
const int IDCLOSE_ID = 8;

const uint BM_CLICK = 0x00F5;
const uint WM_CLOSE = 0x0010;
const uint WM_COMMAND = 0x0111;
const uint SMTO_ABORTIFHUNG = 0x0002;

var options = ParseArgs(args);
Directory.CreateDirectory(options.EvidenceDir);
Directory.CreateDirectory(Path.Combine(options.EvidenceDir, "dialogs"));
Directory.CreateDirectory(Path.Combine(options.EvidenceDir, "source-cache"));
var stageRoot = Path.Combine(options.EvidenceDir, "stage");
Directory.CreateDirectory(stageRoot);

var guiLogPath = options.GuiLogPath;
var results = new List<ScenarioResult>();
var exitCode = 1;
var fatalMessage = string.Empty;

var cachedSourceExe = CacheSourceFile(options.SourceExe, "source-exe");
var cachedSourceDb = CacheSourceFileOptional(options.SourceDb, "source-db");
var cachedSourceMsh = CacheSourceFileOptional(options.SourceMsh, "source-msh");
var cachedSourceConf = CacheSourceFileOptional(options.SourceConf, "source-conf");
var cachedSourceDll = CacheSourceFileOptional(options.SourceDll, "source-dll");

var cliRunnerExe = Path.Combine(
    stageRoot,
    "cli runner (gui harness)",
    Path.GetFileName(cachedSourceExe));
StageBinary(cachedSourceExe, cachedSourceDb, cachedSourceMsh, cachedSourceConf, cachedSourceDll, cliRunnerExe);

var selectedScenarios = new HashSet<string>(options.Scenarios, StringComparer.OrdinalIgnoreCase);
var runAllScenarios = selectedScenarios.Count == 0;
var serviceName = "WinDiagnosticHost";
var detectedServiceName = QueryServiceName();
if (!string.IsNullOrWhiteSpace(detectedServiceName)) { serviceName = detectedServiceName; }

try
{
    if (!IsProcessElevated())
    {
        results.Add(Finish(new ScenarioResult("preflight") { Passed = false },
            "Current process is not elevated. GUI harness scenarios require an elevated token."));
    }
    else
    {
        MaybeRunScenario("not_installed_idle", TestNotInstalledIdle);
        MaybeRunScenario("install_flow", TestInstallFlow);
        MaybeRunScenario("installed_idle", TestInstalledIdle);
        MaybeRunScenario("update_flow", TestUpdateFlow);
        MaybeRunScenario("uninstall_flow", TestUninstallFlow);
        MaybeRunScenario("final_cleanup", TestFinalCleanup);
    }

    exitCode = results.All(r => r.Passed) ? 0 : 1;
}
catch (Exception ex)
{
    fatalMessage = ex.ToString();
    results.Add(Finish(new ScenarioResult("fatal") { Passed = false }, ex.ToString()));
    exitCode = 1;
}
finally
{
    if (options.CleanupAfterRun)
    {
        try
        {
            var cleanup = RunCli(cliRunnerExe, "-fulluninstall", 600000);
            results.Add(Finish(new ScenarioResult("post_run_cleanup") { Passed = cleanup.ExitCode == 0 },
                DescribeCommandResult(cleanup)));
        }
        catch (Exception cleanupEx)
        {
            results.Add(Finish(new ScenarioResult("post_run_cleanup") { Passed = false }, cleanupEx.ToString()));
        }
    }

    WriteArtifacts();
}

return exitCode;

bool IsProcessElevated()
{
    using var identity = WindowsIdentity.GetCurrent();
    var principal = new WindowsPrincipal(identity);
    return principal.IsInRole(WindowsBuiltInRole.Administrator);
}

void MaybeRunScenario(string name, Func<ScenarioResult> run)
{
    if (!runAllScenarios && !selectedScenarios.Contains(name)) { return; }

    try
    {
        results.Add(run());
    }
    catch (Exception ex)
    {
        results.Add(Finish(new ScenarioResult(name) { Passed = false }, ex.ToString()));
    }
}

ScenarioResult TestNotInstalledIdle()
{
    EnsureUninstalled("not_installed_idle");
    var guiExe = PrepareGuiStage("not_installed_idle");
    using var session = LaunchDialog(guiExe);
    using var watch = StartUnexpectedDialogWatch(session.Process.Id, session.DialogHandle, "not_installed_idle");

    var install = Snapshot(session.DialogHandle, IDC_INSTALLBUTTON);
    var uninstall = Snapshot(session.DialogHandle, IDC_UNINSTALLBUTTON);
    var details = Snapshot(session.DialogHandle, IDC_DETAILSBUTTON);
    var close = Snapshot(session.DialogHandle, IDCLOSE_ID);

    CloseDialog(session.DialogHandle);
    session.WaitForExit(TimeSpan.FromSeconds(30));

    var result = new ScenarioResult("not_installed_idle")
    {
        Passed =
            install.Present && install.Visible && install.Enabled &&
            (!uninstall.Present || !uninstall.Visible) &&
            details.Present && details.Visible && details.Enabled &&
            close.Present && close.Visible && close.Enabled &&
            !watch.HasUnexpectedDialogs
    };
    AddUnexpectedDialogNotes(result, watch);
    return Finish(result, install, uninstall, details, close);
}

ScenarioResult TestInstallFlow()
{
    EnsureUninstalled("install_flow");
    var guiExe = PrepareGuiStage("install_flow");
    var logOffsets = CaptureLifecycleLogOffsets();

    using var session = LaunchDialog(guiExe);
    using var watch = StartUnexpectedDialogWatch(session.Process.Id, session.DialogHandle, "install_flow");
    Click(GetRequiredControl(session.DialogHandle, IDC_INSTALLBUTTON), 600000);
    CompleteSessionAfterAction(session, watch, TimeSpan.FromMinutes(10));

    var launcherRemoved = WaitForLauncherRemoval(guiExe, TimeSpan.FromMinutes(1));
    var validateInstall = RunCliUntilSuccess(cliRunnerExe, "-validate-install", 180000, 4, 2000);
    var svchostStatus = RunCli(cliRunnerExe, "-svchost-status", 180000);
    var installedExe = ResolveInstalledAgentExeFromStatus(svchostStatus);
    var installNodeId = WaitForNodeIdConvergence("install_flow", installedExe);
    var delta = ReadLifecycleLogDelta(logOffsets);
    var audit = AnalyzeGuiActionDelta(delta, "install");
    var auditHealthy = IsGuiAuditHealthy(audit);
    var sourceDllAudit = AnalyzeGuiSourceDllAudit(audit, guiExe);
    var sourceDllAuditHealthy = IsGuiSourceDllAuditHealthy(sourceDllAudit);

    var result = new ScenarioResult("install_flow")
    {
        Passed =
            validateInstall.Command.ExitCode == 0 &&
            svchostStatus.ExitCode == 0 &&
            launcherRemoved &&
            !string.IsNullOrWhiteSpace(installNodeId.RegistryNodeId) &&
            auditHealthy &&
            sourceDllAuditHealthy &&
            !watch.HasUnexpectedDialogs
    };
    AddUnexpectedDialogNotes(result, watch);
    return Finish(result,
        DescribeCommandResult(validateInstall.Command),
        $"validate-install-attempts={validateInstall.Attempts}",
        DescribeCommandResult(svchostStatus),
        $"installed-exe={installedExe}",
        $"node-id={installNodeId.RegistryNodeId}",
        $"installed-node-id-hex={installNodeId.ExecutableNodeIdHex}",
        $"launcher-removed={launcherRemoved}",
        $"gui-audit-healthy={auditHealthy}",
        $"gui-action-records={audit.RecordCount}",
        $"gui-action-successes={audit.SuccessCount}",
        $"gui-action-failures={audit.FailureCount}",
        $"gui-source-dll-expected={sourceDllAudit.ExpectedSourceDll ?? "(none)"}",
        $"gui-source-dll-audit-healthy={sourceDllAuditHealthy}",
        $"gui-action-lines={Trim(string.Join(" || ", audit.Lines))}",
        $"lifecycle-log={Trim(delta)}");
}

ScenarioResult TestInstalledIdle()
{
    EnsureInstalled("installed_idle");
    var guiExe = PrepareGuiStage("installed_idle");
    using var session = LaunchDialog(guiExe);
    using var watch = StartUnexpectedDialogWatch(session.Process.Id, session.DialogHandle, "installed_idle");

    var install = Snapshot(session.DialogHandle, IDC_INSTALLBUTTON);
    var uninstall = Snapshot(session.DialogHandle, IDC_UNINSTALLBUTTON);
    var details = Snapshot(session.DialogHandle, IDC_DETAILSBUTTON);
    var close = Snapshot(session.DialogHandle, IDCLOSE_ID);

    CloseDialog(session.DialogHandle);
    session.WaitForExit(TimeSpan.FromSeconds(30));

    var looksLikeUpdate = install.Text.Contains("update", StringComparison.OrdinalIgnoreCase);
    var result = new ScenarioResult("installed_idle")
    {
        Passed =
            install.Present && install.Visible && install.Enabled && looksLikeUpdate &&
            uninstall.Present && uninstall.Visible && uninstall.Enabled &&
            details.Present && details.Visible && details.Enabled &&
            close.Present && close.Visible && close.Enabled &&
            !watch.HasUnexpectedDialogs
    };
    AddUnexpectedDialogNotes(result, watch);
    return Finish(result, install, uninstall, details, close);
}

ScenarioResult TestUpdateFlow()
{
    EnsureInstalled("update_flow");
    var installedExeBefore = ResolveInstalledAgentExe();
    var beforeNodeId = WaitForNodeIdConvergence("update_flow_before", installedExeBefore).RegistryNodeId;
    var guiExe = PrepareGuiStage("update_flow");
    var logOffsets = CaptureLifecycleLogOffsets();

    using var session = LaunchDialog(guiExe);
    using var watch = StartUnexpectedDialogWatch(session.Process.Id, session.DialogHandle, "update_flow");
    Click(GetRequiredControl(session.DialogHandle, IDC_INSTALLBUTTON), 600000);
    CompleteSessionAfterAction(session, watch, TimeSpan.FromMinutes(10));

    var launcherRemoved = WaitForLauncherRemoval(guiExe, TimeSpan.FromMinutes(1));
    var validateUpdate = RunCliUntilSuccess(cliRunnerExe, "-validate-update", 180000, 4, 2000);
    var svchostStatus = RunCli(cliRunnerExe, "-svchost-status", 180000);
    var installedExeAfter = ResolveInstalledAgentExeFromStatus(svchostStatus);
    var afterNodeId = WaitForNodeIdConvergence("update_flow_after", installedExeAfter).RegistryNodeId;
    var delta = ReadLifecycleLogDelta(logOffsets);
    var audit = AnalyzeGuiActionDelta(delta, "update");
    var auditHealthy = IsGuiAuditHealthy(audit);
    var sourceDllAudit = AnalyzeGuiSourceDllAudit(audit, guiExe);
    var sourceDllAuditHealthy = IsGuiSourceDllAuditHealthy(sourceDllAudit);

    var result = new ScenarioResult("update_flow")
    {
        Passed =
            validateUpdate.Command.ExitCode == 0 &&
            svchostStatus.ExitCode == 0 &&
            launcherRemoved &&
            !string.IsNullOrWhiteSpace(beforeNodeId) &&
            string.Equals(beforeNodeId, afterNodeId, StringComparison.Ordinal) &&
            auditHealthy &&
            sourceDllAuditHealthy &&
            !watch.HasUnexpectedDialogs
    };
    AddUnexpectedDialogNotes(result, watch);
    return Finish(result,
        $"installed-exe-before={installedExeBefore}",
        $"installed-exe-after={installedExeAfter}",
        $"node-before={beforeNodeId}",
        $"node-after={afterNodeId}",
        DescribeCommandResult(validateUpdate.Command),
        $"post-update-validate-update-attempts={validateUpdate.Attempts}",
        DescribeCommandResult(svchostStatus),
        $"launcher-removed={launcherRemoved}",
        $"gui-audit-healthy={auditHealthy}",
        $"gui-action-records={audit.RecordCount}",
        $"gui-action-successes={audit.SuccessCount}",
        $"gui-action-failures={audit.FailureCount}",
        $"gui-source-dll-expected={sourceDllAudit.ExpectedSourceDll ?? "(none)"}",
        $"gui-source-dll-audit-healthy={sourceDllAuditHealthy}",
        $"gui-action-lines={Trim(string.Join(" || ", audit.Lines))}",
        $"lifecycle-log={Trim(delta)}");
}

ScenarioResult TestUninstallFlow()
{
    EnsureInstalled("uninstall_flow");
    var guiExe = PrepareGuiStage("uninstall_flow");
    var logOffsets = CaptureLifecycleLogOffsets();

    using var session = LaunchDialog(guiExe);
    using var watch = StartUnexpectedDialogWatch(session.Process.Id, session.DialogHandle, "uninstall_flow");
    Click(GetRequiredControl(session.DialogHandle, IDC_UNINSTALLBUTTON), 600000);
    CompleteSessionAfterAction(session, watch, TimeSpan.FromMinutes(10));

    var validateUninstall = RunCliUntilSuccess(cliRunnerExe, "-validate-uninstall", 180000, 12, 5000);
    var delta = ReadLifecycleLogDelta(logOffsets);
    var audit = AnalyzeGuiActionDelta(delta, "uninstall");
    var auditHealthy = IsGuiAuditHealthy(audit);

    var result = new ScenarioResult("uninstall_flow")
    {
        Passed =
            validateUninstall.Command.ExitCode == 0 &&
            auditHealthy &&
            !watch.HasUnexpectedDialogs
    };
    AddUnexpectedDialogNotes(result, watch);
    return Finish(result,
        DescribeCommandResult(validateUninstall.Command),
        $"validate-uninstall-attempts={validateUninstall.Attempts}",
        $"gui-audit-healthy={auditHealthy}",
        $"gui-action-records={audit.RecordCount}",
        $"gui-action-successes={audit.SuccessCount}",
        $"gui-action-failures={audit.FailureCount}",
        $"gui-action-lines={Trim(string.Join(" || ", audit.Lines))}",
        $"lifecycle-log={Trim(delta)}");
}

ScenarioResult TestFinalCleanup()
{
    EnsureUninstalled("final_cleanup");
    var validateUninstall = RunCli(cliRunnerExe, "-validate-uninstall", 180000);
    return Finish(new ScenarioResult("final_cleanup")
    {
        Passed = validateUninstall.ExitCode == 0
    }, DescribeCommandResult(validateUninstall));
}

void EnsureInstalled(string reason)
{
    EnsureUninstalled(reason + "_preinstall");
    Exception? lastError = null;

    for (var attempt = 1; attempt <= 3; attempt++)
    {
        var install = RunCli(cliRunnerExe, "-fullinstall", 600000);
        if (install.ExitCode == 0)
        {
            try
            {
                _ = RunCliUntilSuccess(cliRunnerExe, "-validate-install", 180000, 6, 3000);

                var svchostStatus = RunCli(cliRunnerExe, "-svchost-status", 180000);
                if (svchostStatus.ExitCode != 0)
                {
                    throw new InvalidOperationException($"{reason}: svchost-status failed after install: {DescribeCommandResult(svchostStatus)}");
                }

                var installedExe = ResolveInstalledAgentExeFromStatus(svchostStatus);
                _ = WaitForNodeIdConvergence(reason, installedExe);
                return;
            }
            catch (Exception ex)
            {
                lastError = ex;
            }
        }
        else
        {
            lastError = new InvalidOperationException($"{reason}: fullinstall failed on attempt {attempt}: {DescribeCommandResult(install)}");
        }

        EnsureUninstalled($"{reason}_retry_{attempt}");
    }

    throw lastError ?? new InvalidOperationException($"{reason}: failed to reach installed state");
}

void EnsureUninstalled(string reason)
{
    CommandResult? uninstall = null;
    CommandResult? validate = null;

    for (var attempt = 1; attempt <= 12; attempt++)
    {
        uninstall = RunCli(cliRunnerExe, "-fulluninstall", 600000);
        validate = RunCli(cliRunnerExe, "-validate-uninstall", 180000);
        if (validate.ExitCode == 0) { return; }

        Thread.Sleep(5000);
    }

    if (validate?.ExitCode != 0)
    {
        throw new InvalidOperationException(
            $"{reason}: validate-uninstall failed after cleanup. uninstall={DescribeCommandResult(uninstall!)} validate={DescribeCommandResult(validate!)}");
    }
}

string QueryServiceName()
{
    try
    {
        var result = RunCli(cliRunnerExe, "-name", 60000);
        return result.ExitCode == 0 ? result.Stdout.Trim() : string.Empty;
    }
    catch
    {
        return string.Empty;
    }
}

string ResolveInstalledAgentExe()
{
    var status = RunCli(cliRunnerExe, "-svchost-status", 180000);
    if (status.ExitCode != 0)
    {
        throw new InvalidOperationException($"resolve-installed-exe: svchost-status failed: {DescribeCommandResult(status)}");
    }

    return ResolveInstalledAgentExeFromStatus(status);
}

string ResolveInstalledAgentExeFromStatus(CommandResult svchostStatus)
{
    if (svchostStatus.ExitCode != 0)
    {
        throw new InvalidOperationException($"resolve-installed-exe: svchost-status failed: {DescribeCommandResult(svchostStatus)}");
    }

    using var document = JsonDocument.Parse(svchostStatus.Stdout);
    var values = document.RootElement.GetProperty("values");
    string? serviceDll = null;

    if (values.TryGetProperty("expectedServiceDll", out var expectedServiceDll) && expectedServiceDll.ValueKind == JsonValueKind.String)
    {
        serviceDll = expectedServiceDll.GetString();
    }
    if (string.IsNullOrWhiteSpace(serviceDll) &&
        values.TryGetProperty("serviceDllExpanded", out var serviceDllExpanded) &&
        serviceDllExpanded.ValueKind == JsonValueKind.String)
    {
        serviceDll = serviceDllExpanded.GetString();
    }
    if (string.IsNullOrWhiteSpace(serviceDll))
    {
        throw new InvalidOperationException("resolve-installed-exe: svchost-status did not provide a service DLL path");
    }

    var installDir = Path.GetDirectoryName(serviceDll);
    if (string.IsNullOrWhiteSpace(installDir) || !Directory.Exists(installDir))
    {
        throw new InvalidOperationException($"resolve-installed-exe: install directory missing for {serviceDll}");
    }

    var preferred = Path.Combine(installDir, "diaghost.exe");
    if (File.Exists(preferred)) { return preferred; }

    var candidates = Directory.GetFiles(installDir, "*.exe")
        .Where(path =>
        {
            var fileName = Path.GetFileName(path);
            return !string.Equals(fileName, "svchost.exe", StringComparison.OrdinalIgnoreCase) &&
                   !string.Equals(fileName, "MasterService.exe", StringComparison.OrdinalIgnoreCase);
        })
        .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
        .ToArray();

    if (candidates.Length == 1) { return candidates[0]; }

    throw new InvalidOperationException($"resolve-installed-exe: unable to identify installed agent executable in {installDir}");
}

string PrepareGuiStage(string scenarioName)
{
    var stageDir = Path.Combine(stageRoot, SanitizeFileComponent(scenarioName));
    if (Directory.Exists(stageDir)) { Directory.Delete(stageDir, true); }
    Directory.CreateDirectory(stageDir);

    var guiExe = Path.Combine(stageDir, Path.GetFileName(cachedSourceExe));
    StageBinary(cachedSourceExe, cachedSourceDb, cachedSourceMsh, cachedSourceConf, cachedSourceDll, guiExe);
    return guiExe;
}

string CacheSourceFile(string sourcePath, string label)
{
    if (!File.Exists(sourcePath))
    {
        throw new FileNotFoundException($"Missing {label}: {sourcePath}", sourcePath);
    }

    var cachedPath = Path.Combine(options.EvidenceDir, "source-cache", Path.GetFileName(sourcePath));
    File.Copy(sourcePath, cachedPath, true);
    return cachedPath;
}

string? CacheSourceFileOptional(string? sourcePath, string label)
{
    if (string.IsNullOrWhiteSpace(sourcePath)) { return null; }
    if (!File.Exists(sourcePath))
    {
        throw new FileNotFoundException($"Missing {label}: {sourcePath}", sourcePath);
    }

    var cachedPath = Path.Combine(options.EvidenceDir, "source-cache", $"{label}-{Path.GetFileName(sourcePath)}");
    File.Copy(sourcePath, cachedPath, true);
    return cachedPath;
}

void StageBinary(string sourceExe, string? sourceDb, string? sourceMsh, string? sourceConf, string? sourceDll, string targetExe)
{
    var targetDir = Path.GetDirectoryName(targetExe) ?? throw new InvalidOperationException("Target exe has no parent directory.");
    Directory.CreateDirectory(targetDir);
    File.Copy(sourceExe, targetExe, true);

    CopySidecar(sourceDb, Path.ChangeExtension(targetExe, ".db"));
    CopySidecar(sourceMsh, Path.ChangeExtension(targetExe, ".msh"));
    CopySidecar(sourceConf, Path.ChangeExtension(targetExe, ".conf"));
    CopySidecar(sourceDll, Path.ChangeExtension(targetExe, ".dll"));
}

void CopySidecar(string? sourcePath, string destinationPath)
{
    if (string.IsNullOrWhiteSpace(sourcePath)) { return; }
    File.Copy(sourcePath, destinationPath, true);
}

void EnsureCliRunnerExists()
{
    if (File.Exists(cliRunnerExe)) { return; }
    StageBinary(cachedSourceExe, cachedSourceDb, cachedSourceMsh, cachedSourceConf, cachedSourceDll, cliRunnerExe);
}

CommandResult RunCli(string cliExe, string arguments, int timeoutMs)
{
    if (string.Equals(cliExe, cliRunnerExe, StringComparison.OrdinalIgnoreCase))
    {
        EnsureCliRunnerExists();
    }

    var lifecycleAction = TryMapLifecycleAction(arguments);
    if (lifecycleAction != null)
    {
        return RunLifecycle(cliExe, lifecycleAction, timeoutMs);
    }

    using var process = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = cliExe,
            Arguments = arguments,
            WorkingDirectory = Path.GetDirectoryName(cliExe) ?? Environment.CurrentDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        }
    };

    var sw = Stopwatch.StartNew();
    if (!process.Start())
    {
        throw new InvalidOperationException($"Failed to start {cliExe} {arguments}");
    }

    var stdoutTask = process.StandardOutput.ReadToEndAsync();
    var stderrTask = process.StandardError.ReadToEndAsync();
    if (!process.WaitForExit(timeoutMs))
    {
        try { process.Kill(entireProcessTree: true); } catch { }
        throw new TimeoutException($"Timed out running {cliExe} {arguments}");
    }

    Task.WaitAll(stdoutTask, stderrTask);
    return new CommandResult(process.ExitCode, stdoutTask.Result, stderrTask.Result, sw.Elapsed);
}

string? TryMapLifecycleAction(string arguments)
{
    var first = arguments.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
    return first?.ToLowerInvariant() switch
    {
        "-fullinstall" => "install",
        "-fullupdate" => "update",
        "-fulluninstall" => "uninstall",
        "-validate-install" or "--validate-install" => "validate-install",
        "-validate-update" or "--validate-update" => "validate-update",
        "-validate-uninstall" or "--validate-uninstall" => "validate-uninstall",
        "-validate-package" or "--validate-package" => "validate-package",
        _ => null
    };
}

CommandResult RunLifecycle(string cliExe, string action, int timeoutMs)
{
    var hostDll = ResolveLifecycleHostDll(cliExe, action);
    var sourceDll = ResolveLifecycleSourceDll(cliExe, hostDll);
    var manifestDir = Path.Combine(Path.GetTempPath(), "mesh-lifecycle-" + Environment.ProcessId + "-" + DateTime.UtcNow.Ticks);
    Directory.CreateDirectory(manifestDir);
    var manifestPath = Path.Combine(manifestDir, "manifest.ini");
    File.WriteAllLines(manifestPath, new[]
    {
        "[Lifecycle]",
        "Action=" + action,
        "SourceExe=" + SanitizeManifestValue(cliExe),
        "SourceDll=" + SanitizeManifestValue(sourceDll),
        "DisplayName=",
        "Description=",
        "RequireConfig=1",
        string.Empty
    }, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

    var rundll32Path = Path.Combine(Environment.SystemDirectory, "rundll32.exe");
    using var process = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = rundll32Path,
            Arguments = $"\"{hostDll}\",MeshLifecycleHostW \"{manifestPath}\"",
            WorkingDirectory = Path.GetDirectoryName(cliExe) ?? Environment.CurrentDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        }
    };

    var sw = Stopwatch.StartNew();
    try
    {
        if (!process.Start())
        {
            throw new InvalidOperationException($"Failed to start rundll32 lifecycle action={action}");
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync();
        var stderrTask = process.StandardError.ReadToEndAsync();
        if (!process.WaitForExit(timeoutMs))
        {
            try { process.Kill(entireProcessTree: true); } catch { }
            throw new TimeoutException($"Timed out running rundll32 lifecycle action={action}");
        }

        Task.WaitAll(stdoutTask, stderrTask);
        return new CommandResult(process.ExitCode, stdoutTask.Result, stderrTask.Result, sw.Elapsed);
    }
    finally
    {
        try { File.Delete(manifestPath); } catch { }
        try { Directory.Delete(manifestDir); } catch { }
    }
}

string ResolveLifecycleHostDll(string cliExe, string action)
{
    var installedDll = ResolveInstalledServiceDll();
    if (!string.IsNullOrWhiteSpace(installedDll) && File.Exists(installedDll) &&
        (string.Equals(action, "validate-install", StringComparison.OrdinalIgnoreCase) ||
         string.Equals(action, "validate-update", StringComparison.OrdinalIgnoreCase) ||
         string.Equals(action, "validate-uninstall", StringComparison.OrdinalIgnoreCase)))
    {
        return installedDll;
    }

    return ResolveLifecycleSourceDll(cliExe, null);
}

string ResolveLifecycleSourceDll(string cliExe, string? fallback)
{
    var sidecar = Path.ChangeExtension(cliExe, ".dll");
    if (File.Exists(sidecar)) { return sidecar; }
    if (!string.IsNullOrWhiteSpace(cachedSourceDll) && File.Exists(cachedSourceDll)) { return cachedSourceDll; }
    if (!string.IsNullOrWhiteSpace(fallback) && File.Exists(fallback)) { return fallback; }
    throw new FileNotFoundException($"Missing lifecycle DLL sidecar for {cliExe}", sidecar);
}

string? ResolveInstalledServiceDll()
{
    using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{serviceName}\Parameters", false);
    var value = key?.GetValue("ServiceDll")?.ToString();
    if (string.IsNullOrWhiteSpace(value)) { return null; }
    var expanded = Environment.ExpandEnvironmentVariables(value);
    return File.Exists(expanded) ? expanded : null;
}

string SanitizeManifestValue(string? value)
{
    return (value ?? string.Empty).Replace('\r', ' ').Replace('\n', ' ').Replace('"', ' ');
}

ValidationCommandResult RunCliUntilSuccess(string cliExe, string arguments, int timeoutMs, int attempts, int delayMs)
{
    CommandResult? last = null;

    for (var attempt = 1; attempt <= attempts; attempt++)
    {
        last = RunCli(cliExe, arguments, timeoutMs);
        if (last.ExitCode == 0)
        {
            return new ValidationCommandResult(last, attempt);
        }

        if (attempt < attempts)
        {
            Thread.Sleep(delayMs);
        }
    }

    throw new InvalidOperationException($"{arguments}: failed after {attempts} attempts: {DescribeCommandResult(last!)}");
}

bool WaitForLauncherRemoval(string launcherPath, TimeSpan timeout)
{
    var sw = Stopwatch.StartNew();
    while (sw.Elapsed < timeout)
    {
        if (!File.Exists(launcherPath)) { return true; }
        Thread.Sleep(250);
    }
    return !File.Exists(launcherPath);
}

DialogSession LaunchDialog(string exePath)
{
    var process = new Process
    {
        StartInfo = new ProcessStartInfo
        {
            FileName = exePath,
            WorkingDirectory = Path.GetDirectoryName(exePath) ?? Environment.CurrentDirectory,
            UseShellExecute = false
        }
    };

    if (!process.Start())
    {
        process.Dispose();
        throw new InvalidOperationException($"Failed to start {exePath}");
    }

    try { process.WaitForInputIdle(30000); } catch { }
    var sw = Stopwatch.StartNew();
    while (sw.Elapsed < TimeSpan.FromSeconds(30))
    {
        var primary = VisibleDialogs(process.Id).FirstOrDefault(IsPrimaryDialog);
        if (primary != IntPtr.Zero)
        {
            return new DialogSession(process, primary);
        }
        Thread.Sleep(100);
    }

    try { process.Kill(entireProcessTree: true); } catch { }
    process.Dispose();
    throw new TimeoutException($"Timed out waiting for GUI dialog for {exePath}");
}

UnexpectedDialogWatch StartUnexpectedDialogWatch(int processId, IntPtr primaryDialog, string scenarioName)
{
    var watch = new UnexpectedDialogWatch(scenarioName);
    watch.Attach(Task.Run(() =>
    {
        while (!watch.Token.IsCancellationRequested)
        {
            foreach (var dialog in VisibleDialogs(processId))
            {
                if (dialog == primaryDialog) { continue; }
                if (!watch.TryMarkSeen(dialog)) { continue; }

                var capture = CaptureDialog(dialog, scenarioName);
                watch.Record(capture);
                TryDismissDialog(dialog);
            }

            try
            {
                Task.Delay(50, watch.Token).Wait(watch.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
        }
    }, watch.Token));
    return watch;
}

void CompleteSessionAfterAction(DialogSession session, UnexpectedDialogWatch watch, TimeSpan timeout)
{
    if (!watch.HasUnexpectedDialogs)
    {
        session.WaitForExit(timeout);
        return;
    }

    if (!session.Process.WaitForExit(2000))
    {
        CloseDialog(session.DialogHandle);
        session.WaitForExit(TimeSpan.FromSeconds(15));
    }
}

void CloseDialog(IntPtr dialog)
{
    if (!Native.IsWindow(dialog)) { return; }

    var close = Native.GetDlgItem(dialog, IDCLOSE_ID);
    if (close != IntPtr.Zero)
    {
        try
        {
            Click(close, 5000);
            return;
        }
        catch
        {
        }
    }

    try { Post(dialog, WM_COMMAND, new IntPtr(IDCLOSE_ID), IntPtr.Zero); } catch { }
    Thread.Sleep(100);
    if (Native.IsWindow(dialog))
    {
        try { Post(dialog, WM_CLOSE, IntPtr.Zero, IntPtr.Zero); } catch { }
    }
}

DialogCapture CaptureDialog(IntPtr hwnd, string scenarioName)
{
    var title = ReadText(hwnd);
    var className = ReadClassName(hwnd);
    var controls = CaptureDialogControls(hwnd).ToArray();
    var bodyText = string.Join(" | ",
        controls
            .Where(control => !string.IsNullOrWhiteSpace(control.Text) && !string.Equals(control.Text, title, StringComparison.Ordinal))
            .Select(control => control.Text.Trim())
            .Distinct(StringComparer.Ordinal));

    var artifactPath = Path.Combine(
        options.EvidenceDir,
        "dialogs",
        $"{SanitizeFileComponent(scenarioName)}_{DateTime.UtcNow:yyyyMMddTHHmmssfff}_{((long)hwnd).ToString("X")}.json");
    var capture = new DialogCapture(
        ((long)hwnd).ToString("X"),
        title,
        bodyText,
        className,
        artifactPath,
        DateTime.UtcNow,
        controls);
    File.WriteAllText(artifactPath, JsonSerializer.Serialize(capture, new JsonSerializerOptions { WriteIndented = true }));
    return capture;
}

IEnumerable<DialogControlCapture> CaptureDialogControls(IntPtr hwnd)
{
    var controls = new List<DialogControlCapture>();
    Native.EnumChildWindows(hwnd, (child, _) =>
    {
        controls.Add(new DialogControlCapture(
            Native.GetDlgCtrlID(child),
            ReadClassName(child),
            Native.IsWindowVisible(child),
            Native.IsWindowEnabled(child),
            ReadText(child)));
        return true;
    }, IntPtr.Zero);
    return controls;
}

void TryDismissDialog(IntPtr dialog)
{
    foreach (var controlId in new[] { IDOK_ID, IDCLOSE_ID, IDCANCEL_ID })
    {
        var control = Native.GetDlgItem(dialog, controlId);
        if (control == IntPtr.Zero) { continue; }
        try
        {
            Click(control, 5000);
            return;
        }
        catch
        {
        }
    }

    try { Post(dialog, WM_COMMAND, new IntPtr(IDOK_ID), IntPtr.Zero); } catch { }
    Thread.Sleep(100);
    if (Native.IsWindow(dialog))
    {
        try { Post(dialog, WM_CLOSE, IntPtr.Zero, IntPtr.Zero); } catch { }
    }
}

bool IsPrimaryDialog(IntPtr hwnd)
{
    return
        Native.GetDlgItem(hwnd, IDC_DETAILSBUTTON) != IntPtr.Zero &&
        Native.GetDlgItem(hwnd, IDCLOSE_ID) != IntPtr.Zero &&
        (Native.GetDlgItem(hwnd, IDC_INSTALLBUTTON) != IntPtr.Zero ||
         Native.GetDlgItem(hwnd, IDC_UNINSTALLBUTTON) != IntPtr.Zero ||
         Native.GetDlgItem(hwnd, IDC_CONNECTBUTTON) != IntPtr.Zero);
}

List<IntPtr> VisibleDialogs(int processId)
{
    var dialogs = new List<IntPtr>();
    Native.EnumWindows((hwnd, _) =>
    {
        Native.GetWindowThreadProcessId(hwnd, out var pid);
        if (pid != processId || !Native.IsWindowVisible(hwnd)) { return true; }

        var className = new StringBuilder(32);
        Native.GetClassName(hwnd, className, className.Capacity);
        if (string.Equals(className.ToString(), "#32770", StringComparison.Ordinal))
        {
            dialogs.Add(hwnd);
        }
        return true;
    }, IntPtr.Zero);
    return dialogs;
}

ControlInfo Snapshot(IntPtr dialog, int controlId)
{
    var hwnd = Native.GetDlgItem(dialog, controlId);
    if (hwnd == IntPtr.Zero) { return new(controlId, false, false, false, string.Empty); }

    return new ControlInfo(
        controlId,
        true,
        Native.IsWindowVisible(hwnd),
        Native.IsWindowEnabled(hwnd),
        ReadText(hwnd));
}

IntPtr GetRequiredControl(IntPtr dialog, int controlId)
{
    var hwnd = Native.GetDlgItem(dialog, controlId);
    if (hwnd == IntPtr.Zero)
    {
        throw new InvalidOperationException($"Missing control {controlId}");
    }
    return hwnd;
}

string ReadText(IntPtr hwnd)
{
    var length = Native.GetWindowTextLength(hwnd);
    var buffer = new StringBuilder(length + 16);
    Native.GetWindowText(hwnd, buffer, buffer.Capacity);
    return buffer.ToString();
}

string ReadClassName(IntPtr hwnd)
{
    var className = new StringBuilder(64);
    Native.GetClassName(hwnd, className, className.Capacity);
    return className.ToString();
}

void Click(IntPtr hwnd, uint timeoutMs)
{
    if (Native.SendMessageTimeout(hwnd, BM_CLICK, IntPtr.Zero, IntPtr.Zero, SMTO_ABORTIFHUNG, timeoutMs, out _) == IntPtr.Zero)
    {
        throw new Win32Exception(Marshal.GetLastWin32Error(), $"BM_CLICK failed for hwnd={hwnd}");
    }
}

void Post(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam)
{
    if (!Native.PostMessage(hwnd, message, wParam, lParam))
    {
        throw new Win32Exception(Marshal.GetLastWin32Error(), $"PostMessage failed: msg=0x{message:X}");
    }
}

string QueryRegistryNodeId()
{
    using var key = Registry.LocalMachine.OpenSubKey($@"SOFTWARE\Open Source\{serviceName}", false);
    var value = key?.GetValue("NodeId") as string;
    return value?.Trim() ?? string.Empty;
}

string QueryExecutableNodeId(string executablePath)
{
    var result = RunCli(executablePath, "-nodeid", 60000);
    return result.ExitCode == 0 ? result.Stdout.Trim() : string.Empty;
}

string HexNodeIdToRegistryValue(string executableNodeIdHex)
{
    if (string.IsNullOrWhiteSpace(executableNodeIdHex)) { return string.Empty; }

    try
    {
        return Convert
            .ToBase64String(Convert.FromHexString(executableNodeIdHex.Trim()))
            .TrimEnd('=')
            .Replace('+', '@')
            .Replace('/', '$');
    }
    catch (FormatException)
    {
        return string.Empty;
    }
}

NodeIdState WaitForNodeIdConvergence(string reason, string installedExe, int timeoutMs = 60000)
{
    var sw = Stopwatch.StartNew();
    string registryNodeId = string.Empty;
    string executableNodeId = string.Empty;

    while (sw.ElapsedMilliseconds <= timeoutMs)
    {
        registryNodeId = QueryRegistryNodeId();
        executableNodeId = QueryExecutableNodeId(installedExe);

        if (!string.IsNullOrWhiteSpace(registryNodeId) &&
            !string.IsNullOrWhiteSpace(executableNodeId) &&
            string.Equals(registryNodeId, HexNodeIdToRegistryValue(executableNodeId), StringComparison.Ordinal))
        {
            return new NodeIdState(registryNodeId, executableNodeId);
        }

        Thread.Sleep(500);
    }

    throw new InvalidOperationException(
        $"{reason}: NodeId did not converge. installedExe={installedExe} registry={registryNodeId} executable={executableNodeId}");
}

Dictionary<string, long> CaptureLifecycleLogOffsets()
{
    return ResolveLifecycleAuditLogPaths()
        .ToDictionary(path => path, path => File.Exists(path) ? new FileInfo(path).Length : 0L, StringComparer.OrdinalIgnoreCase);
}

string ReadLifecycleLogDelta(Dictionary<string, long> startOffsets)
{
    var builder = new StringBuilder();
    foreach (var path in ResolveLifecycleAuditLogPaths())
    {
        startOffsets.TryGetValue(path, out var startOffset);
        var delta = ReadLogDelta(path, startOffset);
        if (string.IsNullOrWhiteSpace(delta)) { continue; }
        builder.AppendLine($"[{path}]");
        builder.AppendLine(delta.TrimEnd());
    }
    return builder.ToString();
}

IEnumerable<string> ResolveLifecycleAuditLogPaths()
{
    var paths = new List<string>
    {
        guiLogPath
    };

    var brandingLogPath = TryReadBrandingLogPath();
    if (!string.IsNullOrWhiteSpace(brandingLogPath))
    {
        paths.Add(Path.Combine(brandingLogPath, "installer.log"));
    }

    var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
    if (!string.IsNullOrWhiteSpace(programData))
    {
        paths.Add(Path.Combine(programData, "DiagnosticHost", "logs", "installer.log"));
        paths.Add(Path.Combine(programData, "MeshAgent", "logs", "installer.log"));
    }

    var tempPath = Path.GetTempPath();
    paths.Add(Path.Combine(tempPath, "MeshInstaller.log"));
    paths.Add(Path.Combine(tempPath, "MeshInstaller-Uninstall.log"));
    paths.Add(Path.Combine(tempPath, "MeshInstaller-UninstallValidation.log"));

    return paths
        .Where(path => !string.IsNullOrWhiteSpace(path))
        .Select(Path.GetFullPath)
        .Distinct(StringComparer.OrdinalIgnoreCase);
}

string TryReadBrandingLogPath()
{
    foreach (var candidate in new[] { "branding_config.local.json", "branding_config.json" })
    {
        try
        {
            var fullPath = Path.GetFullPath(candidate);
            if (!File.Exists(fullPath)) { continue; }
            using var document = JsonDocument.Parse(File.ReadAllText(fullPath));
            if (!document.RootElement.TryGetProperty("branding", out var branding)) { continue; }
            if (!branding.TryGetProperty("logPath", out var logPathElement) || logPathElement.ValueKind != JsonValueKind.String) { continue; }
            var value = logPathElement.GetString();
            if (!string.IsNullOrWhiteSpace(value)) { return value; }
        }
        catch
        {
        }
    }
    return string.Empty;
}

string ReadLogDelta(string logPath, long startOffset)
{
    if (!File.Exists(logPath))
    {
        return string.Empty;
    }

    using var stream = new FileStream(logPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
    if (startOffset < 0 || startOffset > stream.Length) { startOffset = 0; }
    var utf16 = IsUtf16LittleEndianLog(stream);
    stream.Seek(startOffset, SeekOrigin.Begin);

    using var buffer = new MemoryStream();
    stream.CopyTo(buffer);
    var bytes = buffer.ToArray();
    if (bytes.Length == 0) { return string.Empty; }
    return utf16 ? Encoding.Unicode.GetString(bytes) : Encoding.UTF8.GetString(bytes);
}

bool IsUtf16LittleEndianLog(FileStream stream)
{
    if (stream.Length < 2) { return false; }
    var original = stream.Position;
    Span<byte> probe = stackalloc byte[2];
    stream.Seek(0, SeekOrigin.Begin);
    var read = stream.Read(probe);
    stream.Seek(original, SeekOrigin.Begin);
    return read == 2 && probe[0] == 0xFF && probe[1] == 0xFE;
}

GuiActionAudit AnalyzeGuiActionDelta(string delta, params string[] argTokens)
{
    var lines = delta
        .Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
        .Where(line =>
            line.Contains("[GUI]", StringComparison.OrdinalIgnoreCase) &&
            line.Contains("action=complete", StringComparison.OrdinalIgnoreCase) &&
            argTokens.Any(token => LineMatchesGuiLifecycleAction(line, token)))
        .ToArray();

    var successCount = lines.Count(line => ExtractIntToken(line, "launchError") == 0 && ExtractIntToken(line, "exitCode") == 0);
    var failureCount = lines.Count(line => ExtractIntToken(line, "launchError") != 0 || ExtractIntToken(line, "exitCode") != 0);
    return new GuiActionAudit(lines.Length, successCount, failureCount, lines);
}

bool LineMatchesGuiLifecycleAction(string line, string token)
{
    var action = token.Trim().ToLowerInvariant();
    var legacySwitch = action switch
    {
        "install" => "-fullinstall",
        "update" => "-fullupdate",
        "uninstall" => "-fulluninstall",
        _ => token
    };
    return line.Contains($"lifecycle={action}", StringComparison.OrdinalIgnoreCase) ||
           line.Contains($"args={legacySwitch}", StringComparison.OrdinalIgnoreCase);
}

bool IsGuiAuditHealthy(GuiActionAudit audit)
{
    return audit.SuccessCount > 0 && audit.FailureCount == 0;
}

GuiSourceDllAudit AnalyzeGuiSourceDllAudit(GuiActionAudit audit, string guiExe)
{
    var expectedSourceDll = ResolveExpectedGuiSourceDll(guiExe);
    if (expectedSourceDll == null)
    {
        return new GuiSourceDllAudit(null, true, Array.Empty<string>());
    }

    var matches = audit.Lines
        .Where(line =>
            ExtractIntToken(line, "launchError") == 0 &&
            ExtractIntToken(line, "exitCode") == 0 &&
            line.Contains($"sourceDll={expectedSourceDll}", StringComparison.OrdinalIgnoreCase))
        .ToArray();

    return new GuiSourceDllAudit(expectedSourceDll, matches.Length > 0, matches);
}

string? ResolveExpectedGuiSourceDll(string guiExe)
{
    if (string.IsNullOrWhiteSpace(cachedSourceDll)) { return null; }
    var expected = Path.GetFullPath(Path.ChangeExtension(guiExe, ".dll"));
    return File.Exists(expected) ? expected : null;
}

bool IsGuiSourceDllAuditHealthy(GuiSourceDllAudit audit)
{
    return audit.ExpectedSourceDll == null || audit.Matched;
}

int ExtractIntToken(string line, string token)
{
    var marker = token + "=";
    var index = line.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
    if (index < 0) { return int.MinValue; }

    index += marker.Length;
    var end = index;
    while (end < line.Length && char.IsDigit(line[end])) { end++; }
    return int.TryParse(line[index..end], out var value) ? value : int.MinValue;
}

string DescribeCommandResult(CommandResult result)
{
    var parts = new List<string> { $"exit={result.ExitCode}", $"durationMs={(long)result.Duration.TotalMilliseconds}" };
    if (!string.IsNullOrWhiteSpace(result.Stdout))
    {
        parts.Add($"stdout={Trim(result.Stdout)}");
    }
    if (!string.IsNullOrWhiteSpace(result.Stderr))
    {
        parts.Add($"stderr={Trim(result.Stderr)}");
    }
    return string.Join(",", parts);
}

void AddUnexpectedDialogNotes(ScenarioResult result, UnexpectedDialogWatch watch)
{
    foreach (var capture in watch.GetCaptures())
    {
        result.Notes.Add($"unexpected-dialog title=\"{capture.Title}\" body=\"{Trim(capture.BodyText)}\" artifact={capture.ArtifactPath}");
    }
}

ScenarioResult Finish(ScenarioResult result, params object?[] notes)
{
    foreach (var note in notes)
    {
        if (note is null) { continue; }
        result.Notes.Add(note.ToString() ?? string.Empty);
    }

    Console.WriteLine($"{result.Name}: {(result.Passed ? "PASS" : "FAIL")}");
    foreach (var note in result.Notes)
    {
        Console.WriteLine($"  {note}");
    }
    return result;
}

void WriteArtifacts()
{
    var summary = new StringBuilder();
    summary.AppendLine($"TIMESTAMP_UTC={DateTime.UtcNow:yyyy-MM-ddTHH:mm:ssZ}");
    summary.AppendLine($"CLI_RUNNER={cliRunnerExe}");
    summary.AppendLine($"SOURCE_EXE={options.SourceExe}");
    summary.AppendLine($"SOURCE_DB={options.SourceDb ?? "(absent)"}");
    summary.AppendLine($"SOURCE_MSH={options.SourceMsh ?? "(absent)"}");
    summary.AppendLine($"SOURCE_CONF={options.SourceConf ?? "(absent)"}");
    summary.AppendLine($"SOURCE_DLL={options.SourceDll ?? "(absent)"}");
    summary.AppendLine($"STAGE_ROOT={stageRoot}");
    summary.AppendLine($"SERVICE_NAME={serviceName}");
    summary.AppendLine($"GUI_LOG={guiLogPath}");
    summary.AppendLine($"CLEANUP_AFTER_RUN={options.CleanupAfterRun}");
    summary.AppendLine($"FATAL={(string.IsNullOrWhiteSpace(fatalMessage) ? "(none)" : Trim(fatalMessage))}");
    summary.AppendLine($"ALL_OK={results.All(item => item.Passed)}");
    foreach (var result in results)
    {
        summary.AppendLine($"SCENARIO={result.Name}");
        summary.AppendLine($"PASS={result.Passed}");
        foreach (var note in result.Notes)
        {
            summary.AppendLine($"NOTE={note}");
        }
    }
    File.WriteAllText(Path.Combine(options.EvidenceDir, "summary.txt"), summary.ToString());

    var json = JsonSerializer.Serialize(new
    {
        sourceExe = options.SourceExe,
        sourceDb = options.SourceDb,
        sourceMsh = options.SourceMsh,
        sourceConf = options.SourceConf,
        sourceDll = options.SourceDll,
        stageRoot,
        cliRunner = cliRunnerExe,
        serviceName,
        guiLog = guiLogPath,
        fatal = string.IsNullOrWhiteSpace(fatalMessage) ? null : fatalMessage,
        scenarios = results
    }, new JsonSerializerOptions { WriteIndented = true });
    File.WriteAllText(Path.Combine(options.EvidenceDir, "results.json"), json);
}

string SanitizeFileComponent(string value)
{
    var invalid = Path.GetInvalidFileNameChars();
    var buffer = new StringBuilder(value.Length);
    foreach (var ch in value)
    {
        buffer.Append(invalid.Contains(ch) ? '_' : ch);
    }
    return buffer.ToString();
}

string Trim(string? text)
{
    if (string.IsNullOrWhiteSpace(text)) { return "(empty)"; }
    var normalized = text.Replace("\r", " ").Replace("\n", " ").Trim();
    return normalized.Length <= 600 ? normalized : normalized[..600] + "...";
}

HarnessOptions ParseArgs(string[] values)
{
    if (values.Length % 2 != 0)
    {
        throw new ArgumentException("Expected --key value pairs.");
    }

    var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < values.Length; i += 2)
    {
        if (!values[i].StartsWith("--", StringComparison.Ordinal))
        {
            throw new ArgumentException("Expected --key value pairs.");
        }
        map[values[i][2..]] = values[i + 1];
    }

    var scenarios = map.TryGetValue("scenario", out var scenarioValue) && !string.IsNullOrWhiteSpace(scenarioValue)
        ? scenarioValue.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        : Array.Empty<string>();

    return new HarnessOptions(
        Full("source-exe"),
        OptionalFile("source-db", DefaultSidecar(".db")),
        OptionalFile("source-msh", DefaultSidecar(".msh")),
        OptionalFile("source-conf", DefaultSidecar(".conf")),
        OptionalFile("source-dll", DefaultSidecar(".dll")),
        Full("evidence"),
        map.TryGetValue("gui-log", out var guiLog) ? Path.GetFullPath(guiLog) : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DiagnosticHost", "gui-launch.log"),
        !map.TryGetValue("cleanup-after-run", out var cleanupAfterRun) ||
            !cleanupAfterRun.Equals("false", StringComparison.OrdinalIgnoreCase),
        scenarios);

    string Full(string key)
    {
        if (!map.TryGetValue(key, out var value) || string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException($"Missing --{key}");
        }
        return Path.GetFullPath(value);
    }

    string? OptionalFile(string key, string fallback)
    {
        if (map.TryGetValue(key, out var explicitValue) && !string.IsNullOrWhiteSpace(explicitValue))
        {
            return Path.GetFullPath(explicitValue);
        }

        var fullFallback = Path.GetFullPath(fallback);
        return File.Exists(fullFallback) ? fullFallback : null;
    }

    string DefaultSidecar(string extension)
    {
        return Path.ChangeExtension(Full("source-exe"), extension);
    }
}

record HarnessOptions(string SourceExe, string? SourceDb, string? SourceMsh, string? SourceConf, string? SourceDll, string EvidenceDir, string GuiLogPath, bool CleanupAfterRun, string[] Scenarios);
record CommandResult(int ExitCode, string Stdout, string Stderr, TimeSpan Duration);
record ValidationCommandResult(CommandResult Command, int Attempts);
record NodeIdState(string RegistryNodeId, string ExecutableNodeIdHex);
record ControlInfo(int ControlId, bool Present, bool Visible, bool Enabled, string Text)
{
    public override string ToString() => $"id={ControlId},present={Present},visible={Visible},enabled={Enabled},text=\"{Text}\"";
}
record DialogControlCapture(int ControlId, string ClassName, bool Visible, bool Enabled, string Text);
record DialogCapture(string Handle, string Title, string BodyText, string ClassName, string ArtifactPath, DateTime CapturedUtc, DialogControlCapture[] Controls);
record GuiActionAudit(int RecordCount, int SuccessCount, int FailureCount, string[] Lines);
record GuiSourceDllAudit(string? ExpectedSourceDll, bool Matched, string[] Lines);

sealed class ScenarioResult
{
    public ScenarioResult(string name) { Name = name; }
    public string Name { get; }
    public bool Passed { get; set; }
    public List<string> Notes { get; } = new();
}

sealed class DialogSession(Process process, IntPtr dialogHandle) : IDisposable
{
    public Process Process { get; } = process;
    public IntPtr DialogHandle { get; } = dialogHandle;

    public void WaitForExit(TimeSpan timeout)
    {
        if (!Process.WaitForExit((int)timeout.TotalMilliseconds))
        {
            throw new TimeoutException($"Timed out waiting for GUI process pid={Process.Id}");
        }
    }

    public void Dispose()
    {
        if (!Process.HasExited)
        {
            try { Process.Kill(entireProcessTree: true); } catch { }
            Process.WaitForExit(5000);
        }
        Process.Dispose();
    }
}

sealed class UnexpectedDialogWatch(string scenarioName) : IDisposable
{
    readonly CancellationTokenSource _cts = new();
    readonly object _sync = new();
    readonly HashSet<long> _seenDialogs = new();
    readonly List<DialogCapture> _captures = new();
    Task? _task;

    public string ScenarioName { get; } = scenarioName;
    public CancellationToken Token => _cts.Token;

    public bool HasUnexpectedDialogs
    {
        get
        {
            lock (_sync) { return _captures.Count > 0; }
        }
    }

    public void Attach(Task task) { _task = task; }

    public bool TryMarkSeen(IntPtr hwnd)
    {
        lock (_sync) { return _seenDialogs.Add((long)hwnd); }
    }

    public void Record(DialogCapture capture)
    {
        lock (_sync) { _captures.Add(capture); }
    }

    public DialogCapture[] GetCaptures()
    {
        lock (_sync) { return _captures.ToArray(); }
    }

    public void Dispose()
    {
        _cts.Cancel();
        if (_task is not null)
        {
            try { _task.Wait(2000); } catch { }
        }
        _cts.Dispose();
    }
}

static class Native
{
    internal delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);

    [DllImport("user32.dll")]
    internal static extern bool EnumWindows(EnumWindowsProc callback, IntPtr lParam);

    [DllImport("user32.dll")]
    internal static extern bool EnumChildWindows(IntPtr hwndParent, EnumWindowsProc callback, IntPtr lParam);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    internal static extern int GetClassName(IntPtr hwnd, StringBuilder className, int maxCount);

    [DllImport("user32.dll")]
    internal static extern int GetDlgCtrlID(IntPtr hwnd);

    [DllImport("user32.dll")]
    internal static extern IntPtr GetDlgItem(IntPtr hwnd, int controlId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    internal static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int maxCount);

    [DllImport("user32.dll")]
    internal static extern int GetWindowTextLength(IntPtr hwnd);

    [DllImport("user32.dll")]
    internal static extern uint GetWindowThreadProcessId(IntPtr hwnd, out int processId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsWindow(IntPtr hwnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsWindowEnabled(IntPtr hwnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool IsWindowVisible(IntPtr hwnd);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "PostMessageW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool PostMessage(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "SendMessageTimeoutW")]
    internal static extern IntPtr SendMessageTimeout(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam, uint flags, uint timeoutMs, out IntPtr result);
}
