using System;
using System.IO;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Text;

namespace PsHost
{
    public static class Runner
    {
        // Signature required by CLR ExecuteInDefaultAppDomain: int Method(string arg)
        public static int Run(string command)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(command)) { return 1; }

                using (var runspace = RunspaceFactory.CreateRunspace())
                {
                    runspace.Open();
                    using (var ps = PowerShell.Create())
                    {
                        ps.Runspace = runspace;
                        ps.AddScript(command);
                        ps.AddCommand("Out-String");
                        var results = ps.Invoke();

                        var sb = new StringBuilder();
                        foreach (var r in results) { sb.AppendLine(r?.ToString()); }
                        if (ps.Streams.Error != null && ps.Streams.Error.Count > 0)
                        {
                            foreach (var e in ps.Streams.Error) { sb.AppendLine(e?.ToString()); }
                        }

                        var outPath = Path.Combine(Path.GetTempPath(), "pshost.out");
                        File.WriteAllText(outPath, sb.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));

                        return (ps.HadErrors ? 2 : 0);
                    }
                }
            }
            catch (Exception ex)
            {
                try
                {
                    File.WriteAllText(Path.Combine(Path.GetTempPath(), "pshost.out"), ex.ToString(), new UTF8Encoding(false));
                }
                catch { }
                return 3;
            }
        }
    }
}

