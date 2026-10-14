<#
    diagnose_tool.ps1 - work out why a tool fails to run in the guest.

    Run in the guest after a tool misbehaves. Answers three questions:

      1. Which architecture of a given runtime DLL is present, and where.
         SysWOW64 holds the 32-bit copy, System32 the 64-bit one. A 64-bit
         executable cannot load the SysWOW64 copy and vice versa, so
         "DLL not found" can be reported while the file plainly exists.

      2. The architecture of each of the tool's own binaries, read from the
         PE header rather than guessed from the install directory - a
         64-bit binary can ship inside Program Files (x86).

      3. Whether the binary the HARNESS actually calls works. The harness
         never invokes the GUI or its helpers, so a failure in, say, a font
         cache builder may be irrelevant to the experiment.

    Usage:
      powershell -ExecutionPolicy Bypass -File .\diagnose_tool.ps1
#>

function Get-PEArch {
    <#
        Read the PE header's Machine field to determine a binary's
        architecture. Offset 0x3C holds the PE header offset; the Machine
        word sits 4 bytes into that header.
          0x014c = i386 (32-bit), 0x8664 = x64, 0xAA64 = ARM64
    #>
    param([string]$Path)
    try {
        $fs = [IO.File]::OpenRead($Path)
        $br = New-Object IO.BinaryReader($fs)
        $fs.Seek(0x3C, 'Begin') | Out-Null
        $peOffset = $br.ReadInt32()
        $fs.Seek($peOffset + 4, 'Begin') | Out-Null
        $machine = $br.ReadUInt16()
        $br.Close(); $fs.Close()
        switch ($machine) {
            0x014c  { "x86 (32-bit)" }
            0x8664  { "x64 (64-bit)" }
            0xAA64  { "ARM64" }
            default { ("unknown 0x{0:X4}" -f $machine) }
        }
    } catch { "unreadable: $_" }
}

Write-Host "=== msvcr100.dll presence ===" -ForegroundColor Cyan
foreach ($d in @("$env:SystemRoot\System32\msvcr100.dll",
                 "$env:SystemRoot\SysWOW64\msvcr100.dll")) {
    $bits = if ($d -match 'SysWOW64') { '32-bit store' } else { '64-bit store' }
    if (Test-Path $d) {
        Write-Host ("  PRESENT  {0,-14} {1}  arch={2}" -f $bits, $d, (Get-PEArch $d))
    } else {
        Write-Host ("  MISSING  {0,-14} {1}" -f $bits, $d) -ForegroundColor Yellow
    }
}

Write-Host "`n=== BleachBit binaries and their architecture ===" -ForegroundColor Cyan
$roots = @("C:\Program Files (x86)\BleachBit", "C:\Program Files\BleachBit")
foreach ($r in $roots) {
    if (-not (Test-Path $r)) { continue }
    Get-ChildItem $r -Filter *.exe -Recurse -ErrorAction SilentlyContinue |
      ForEach-Object { Write-Host ("  {0,-22} {1}" -f $_.Name, (Get-PEArch $_.FullName)) }
}

Write-Host "`n=== does the console binary actually work? ===" -ForegroundColor Cyan
$con = Get-ChildItem "C:\Program Files (x86)\BleachBit","C:\Program Files\BleachBit" `
        -Filter bleachbit_console.exe -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
if (-not $con) {
    Write-Host "  bleachbit_console.exe not found" -ForegroundColor Yellow
} else {
    Write-Host "  found: $con"
    Write-Host "  arch : $(Get-PEArch $con)"
    Write-Host "  --- running --version (watch for a dialog) ---"
    & $con --version 2>&1 | Select-Object -First 5
    Write-Host "  exit code: $LASTEXITCODE"
}


# ---------------------------------------------------------------------------
# Where did a program actually install?
#
# Guessing an install path is how several hours get lost. Windows records the
# answer in three places; this checks all of them, cheapest first.
# ---------------------------------------------------------------------------

function Find-InstalledProgram {
    param([Parameter(Mandatory)][string]$NameLike)

    Write-Host "`n=== Looking for '$NameLike' ===" -ForegroundColor Cyan

    # 1. Uninstall registry - authoritative, and includes the version.
    Write-Host "`n-- uninstall registry --"
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $found = Get-ItemProperty $keys -ErrorAction SilentlyContinue |
             Where-Object { $_.DisplayName -like "*$NameLike*" }
    if ($found) {
        $found | ForEach-Object {
            Write-Host ("  {0}  v{1}" -f $_.DisplayName, $_.DisplayVersion)
            Write-Host ("    InstallLocation : {0}" -f $_.InstallLocation)
            Write-Host ("    UninstallString : {0}" -f $_.UninstallString)
        }
    } else {
        Write-Host "  no uninstall entry - the install may not have completed" -ForegroundColor Yellow
    }

    # 2. Desktop and Start Menu shortcuts - resolve them to their real target.
    Write-Host "`n-- shortcuts --"
    $shortcutDirs = @(
        "$env:PUBLIC\Desktop", "$env:USERPROFILE\Desktop",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
    )
    $ws = New-Object -ComObject WScript.Shell
    $shortcutTargets = New-Object System.Collections.Generic.List[string]
    $any = $false
    foreach ($d in $shortcutDirs) {
        if (-not (Test-Path $d)) { continue }
        Get-ChildItem $d -Filter "*$NameLike*.lnk" -Recurse -ErrorAction SilentlyContinue |
          ForEach-Object {
            $any = $true
            $target = $ws.CreateShortcut($_.FullName).TargetPath
            if ($target) { $shortcutTargets.Add($target) }
            Write-Host ("  {0}" -f $_.Name)
            Write-Host ("    -> {0}" -f $target)
            if ($target -and (Test-Path $target)) {
                Write-Host ("       exists, arch = {0}" -f (Get-PEArch $target)) -ForegroundColor Green
            } elseif ($target) {
                Write-Host "       TARGET DOES NOT EXIST" -ForegroundColor Yellow
            }
          }
    }
    if (-not $any) { Write-Host "  none found" }

    # 3. Filesystem sweep, as a fallback.
    Write-Host "`n-- executables on disk --"
    $roots = @("C:\Program Files", "C:\Program Files (x86)",
               "$env:LOCALAPPDATA\Programs", "$env:APPDATA")
    $exes = foreach ($r in $roots) {
        if (Test-Path $r) {
            Get-ChildItem $r -Filter "*$NameLike*.exe" -Recurse -ErrorAction SilentlyContinue -Depth 3
        }
    }
    if (-not $exes) { $exes = @() }
    if ($exes) {
        $exes | Select-Object -First 15 | ForEach-Object {
            Write-Host ("  {0,-58} {1}" -f $_.FullName, (Get-PEArch $_.FullName))
        }
    } else {
        Write-Host "  none found"
    }

    Write-Host "`n-- all executables in the install directory --"

    # Build the candidate directory list defensively. -ExpandProperty throws
    # outright when a matched registry entry lacks the property, and plenty of
    # uninstall entries either omit InstallLocation or leave it empty - BCWipe
    # does exactly that. So collect from three sources and keep whatever
    # resolves: the registry value, the directory of each shortcut target, and
    # the directory of each executable found on disk.
    $dirs = New-Object System.Collections.Generic.List[string]

    foreach ($entry in $found) {
        $loc = $entry.PSObject.Properties |
               Where-Object Name -eq 'InstallLocation' |
               ForEach-Object Value
        if ($loc) { $dirs.Add($loc.TrimEnd('\')) }
    }
    foreach ($t in $shortcutTargets) {
        if ($t -and (Test-Path $t)) { $dirs.Add((Split-Path $t -Parent)) }
    }
    foreach ($e in $exes) { $dirs.Add($e.DirectoryName) }

    $unique = $dirs | Where-Object { $_ } | Sort-Object -Unique
    if (-not $unique) {
        Write-Host "  no install directory could be determined"
    }
    foreach ($d in $unique) {
        if (-not (Test-Path $d)) { continue }
        Write-Host "  $d"
        Get-ChildItem $d -Filter *.exe -ErrorAction SilentlyContinue |
          ForEach-Object { Write-Host ("    {0,-36} {1}" -f $_.Name, (Get-PEArch $_.FullName)) }
    }
}

# Run for whichever tool you are chasing:
#   Find-InstalledProgram "CCleaner"
#   Find-InstalledProgram "BCWipe"
#   Find-InstalledProgram "Eraser"
#   Find-InstalledProgram "BleachBit"
