<#
    read_vm_password.ps1 - recover a VMware VM-encryption password that
    Workstation saved into Windows Credential Manager.

    Credential Manager masks Windows Credentials in its UI, and `cmdkey /list`
    shows only target names. Both the Win32 CredRead and CredEnumerate APIs
    return the secret in plaintext to the user who owns the credential, which
    is the supported way to read back your own saved password.

    This enumerates the current user's credentials and prints any whose target
    matches a filter, so you do not have to guess the exact target string.
    `cmdkey` displays generic credentials with a "LegacyGeneric:target="
    prefix that may or may not be part of the stored name; matching on a
    substring sidesteps that ambiguity entirely.

    Usage:
        powershell -ExecutionPolicy Bypass -File .\read_vm_password.ps1
        powershell -ExecutionPolicy Bypass -File .\read_vm_password.ps1 -Filter "Windows 11 x64"

    Scope: it reads only credentials belonging to the account running it, and
    only on this machine. It cannot reach another user's credential store.

    NOTE: the password is printed to the console. Clear your scrollback
    afterwards if the terminal history is shared or logged.
#>

param(
    # Substring matched case-insensitively against the credential target name.
    [string]$Filter = "VMware"
)

$ErrorActionPreference = 'Stop'

# The CREDENTIALW layout differs between x86 and x64 because of pointer
# alignment, so the struct is declared in C# and the .NET marshaller computes
# the offsets rather than hardcoding them.
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class WiperTraceCredMan {

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL {
        public uint   Flags;
        public uint   Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint   CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint   Persist;
        public uint   AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredEnumerateW(
        string filter, uint flags, out uint count, out IntPtr credentials);

    [DllImport("advapi32.dll", SetLastError = false)]
    private static extern void CredFree(IntPtr buffer);

    // Returns {target, userName, secretAsUnicode, blobSizeBytes, blobAsHex}
    public static List<string[]> Find(string needle) {
        var results = new List<string[]>();
        uint count;
        IntPtr pCreds;

        // filter = null with flags = 0 enumerates every credential in the
        // calling user's credential set.
        if (!CredEnumerateW(null, 0, out count, out pCreds)) {
            int err = Marshal.GetLastWin32Error();
            throw new Exception("CredEnumerate failed, Win32 error " + err +
                (err == 1168 ? " (ERROR_NOT_FOUND: no credentials stored)" : ""));
        }

        try {
            for (uint i = 0; i < count; i++) {
                IntPtr entry = Marshal.ReadIntPtr(pCreds, (int)(i * (uint)IntPtr.Size));
                CREDENTIAL c = (CREDENTIAL)Marshal.PtrToStructure(entry, typeof(CREDENTIAL));

                string target = c.TargetName == IntPtr.Zero
                    ? "" : Marshal.PtrToStringUni(c.TargetName);
                if (!String.IsNullOrEmpty(needle) &&
                    target.IndexOf(needle, StringComparison.OrdinalIgnoreCase) < 0) {
                    continue;
                }

                string user = c.UserName == IntPtr.Zero
                    ? "" : Marshal.PtrToStringUni(c.UserName);

                string asText = "";
                string asHex  = "";
                if (c.CredentialBlobSize > 0 && c.CredentialBlob != IntPtr.Zero) {
                    byte[] blob = new byte[c.CredentialBlobSize];
                    Marshal.Copy(c.CredentialBlob, blob, 0, (int)c.CredentialBlobSize);
                    asHex = BitConverter.ToString(blob).Replace("-", " ");
                    // Generic credentials are conventionally UTF-16LE, but the
                    // raw bytes are also returned so a different encoding is
                    // still recoverable.
                    try {
                        asText = System.Text.Encoding.Unicode.GetString(blob);
                    } catch { asText = ""; }
                }

                results.Add(new string[] {
                    target, user, asText,
                    c.CredentialBlobSize.ToString(), asHex
                });
            }
        } finally {
            CredFree(pCreds);
        }
        return results;
    }
}
'@

Write-Host ""
Write-Host "Searching the current user's credential store for targets matching '$Filter'" -ForegroundColor Cyan
Write-Host ""

try {
    $hits = [WiperTraceCredMan]::Find($Filter)
} catch {
    Write-Host "FAILED: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "If this cannot read the credential, fall back to rebuilding the VM" -ForegroundColor Yellow
    Write-Host "with an encryption password you choose and record." -ForegroundColor Yellow
    exit 1
}

if (-not $hits -or $hits.Count -eq 0) {
    Write-Host "No credential target matched '$Filter'." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "List every target to pick a better filter:" -ForegroundColor Gray
    Write-Host "  cmdkey /list" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Note that a credential saved with 'Local machine persistence'" -ForegroundColor Gray
    Write-Host "belongs to the account that saved it - run this as that user." -ForegroundColor Gray
    exit 1
}

$i = 0
foreach ($h in $hits) {
    $i++
    Write-Host "[$i] Target  : $($h[0])"
    if ($h[1]) { Write-Host "    User    : $($h[1])" }
    Write-Host "    Bytes   : $($h[3])"
    if ($h[2]) {
        Write-Host "    Password: $($h[2])" -ForegroundColor Green
    } else {
        Write-Host "    Password: (empty blob)" -ForegroundColor Yellow
    }
    # A blob that is not UTF-16 renders as mojibake; the hex lets you tell.
    if ($h[4] -and $h[3] -ne "0") {
        $preview = if ($h[4].Length -gt 96) { $h[4].Substring(0, 96) + " ..." } else { $h[4] }
        Write-Host "    Hex     : $preview" -ForegroundColor DarkGray
    }
    Write-Host ""
}

Write-Host "Put the matching password into config.yaml as vm.encryption_password," -ForegroundColor Cyan
Write-Host "quoted if it contains : # @ { } or starts with a special character." -ForegroundColor Cyan
Write-Host ""
Write-Host "If the password above looks like garbled characters, the blob is not" -ForegroundColor Gray
Write-Host "UTF-16 - read it from the Hex line instead." -ForegroundColor Gray
Write-Host ""
Write-Host "Verify it before editing config.yaml:" -ForegroundColor Gray
Write-Host '  & "<vmrun.exe>" -T ws -vp "<password>" listSnapshots "<vmx>"' -ForegroundColor Gray
Write-Host ""
Write-Host "The password was printed in clear text. Clear your scrollback if this" -ForegroundColor DarkYellow
Write-Host "terminal's history is shared or logged." -ForegroundColor DarkYellow
