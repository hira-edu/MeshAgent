# Common helper to check for embedded svchost payload resources.
param()

Set-StrictMode -Version Latest

if (-not ("MeshAgent.ResourceHelper" -as [Type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace MeshAgent
{
    public static class ResourceHelper
    {
        private const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
        private static readonly IntPtr RT_RCDATA = new IntPtr(10);

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

        [DllImport("kernel32", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr FindResource(IntPtr hModule, string lpName, IntPtr lpType);

        public static bool HasSvchostPayload(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return false;
            }

            if (!System.IO.File.Exists(path))
            {
                return false;
            }

            IntPtr hModule = IntPtr.Zero;
            try
            {
                hModule = LoadLibraryEx(path, IntPtr.Zero, LOAD_LIBRARY_AS_DATAFILE);
                if (hModule == IntPtr.Zero)
                {
                    return false;
                }

                IntPtr resource = FindResource(hModule, "SVCHOSTDLL", RT_RCDATA);
                return resource != IntPtr.Zero;
            }
            finally
            {
                if (hModule != IntPtr.Zero)
                {
                    FreeLibrary(hModule);
                }
            }
        }
    }
}
'@
}

function Test-SvchostPayload {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    return [MeshAgent.ResourceHelper]::HasSvchostPayload($Path)
}
