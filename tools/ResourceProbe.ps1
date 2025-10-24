# Common helper to check for embedded svchost payload resources.
param()

Set-StrictMode -Version Latest

function Invoke-BytePatternSearch {
    param(
        [byte[]]$Buffer,
        [byte[]]$Pattern
    )

    if (-not $Buffer -or -not $Pattern -or $Pattern.Length -eq 0) {
        return $false
    }

    $limit = $Buffer.Length - $Pattern.Length
    for ($i = 0; $i -le $limit; $i++) {
        $match = $true
        for ($j = 0; $j -lt $Pattern.Length; $j++) {
            if ($Buffer[$i + $j] -ne $Pattern[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            return $true
        }
    }

    return $false
}

function Test-BinaryUtf16String {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if (-not (Test-Path $Path) -or [string]::IsNullOrWhiteSpace($Value)) {
        return $false
    }

    $fullPath = (Resolve-Path -LiteralPath $Path).ProviderPath
    $bytes = [System.IO.File]::ReadAllBytes($fullPath)
    if (-not $bytes) {
        return $false
    }

    $pattern = [System.Text.Encoding]::Unicode.GetBytes($Value)
    if (Invoke-BytePatternSearch -Buffer $bytes -Pattern $pattern) {
        return $true
    }

    $patternNull = New-Object byte[] ($pattern.Length + 2)
    [System.Array]::Copy($pattern, $patternNull, $pattern.Length)
    return (Invoke-BytePatternSearch -Buffer $bytes -Pattern $patternNull)
}

function Get-BinaryStringPresence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string[]]$Utf16Strings
    )

    $results = @()
    foreach ($value in $Utf16Strings) {
        $results += [pscustomobject]@{
            value    = $value
            present  = [bool](Test-BinaryUtf16String -Path $Path -Value $value)
            encoding = 'utf16'
        }
    }

    return $results
}

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
