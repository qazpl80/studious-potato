<#
    prepare_baseline.ps1 - one-time baseline preparation, run INSIDE the VM.

    Run this once, in an elevated PowerShell session, BEFORE taking the
    'clean' snapshot. It is idempotent: re-running it is safe.

        powershell -ExecutionPolicy Bypass -File .\prepare_baseline.ps1

    WHAT IT DOES AND WHY
    --------------------
    Two categories of change:

    (a) TRACE CAPACITY. Pins $UsnJrnl and $LogFile on the evidence volume to
        fixed sizes. NTFS otherwise scales $LogFile with volume size, so a
        small evidence disk would get a small circular log that wraps
        mid-experiment and silently truncates the records being measured.
        Pinning both decouples trace capacity from disk size, which is what
        makes a 2 GB evidence volume viable.

    (b) FOOTPRINT AND NOISE REDUCTION. Disables the pagefile, hibernation,
        Windows Update, Defender real-time protection and UAC. The first two
        reclaim several GB; the rest remove background filesystem churn that
        would otherwise contaminate the journals, and allow the harness's
        silent installers to elevate.

    Every change in (b) is a deviation from a realistic endpoint and MUST be
    declared in the report's limitations. The script prints a summary block
    at the end for pasting into that section.
#>

[CmdletBinding()]
param(
    [string]$EvidenceDrive = 'D',
    [string]$CorpusDir     = 'D:\corpus',
    # Journal sizes in MB. 16 MB gives roughly 20x headroom over the ~0.8 MB
    # of $LogFile records a 40-file wipe generates, and ~60x over its USN
    # records. Raise only if you increase corpus.wipe_count substantially.
    [int]$UsnJournalMB     = 16,
    [int]$LogFileMB        = 16,
    [switch]$KeepPagefile,
    [switch]$SkipDefender,
    # Visual C++ 2010 x86 runtime, required by BleachBit 4.x. Defaults to the
    # installers ISO; override if you staged it elsewhere.
    [string]$VCRedist2010 = 'E:\vcredist\vcredist_x86.exe'
)

$ErrorActionPreference = 'Stop'
$notes = [System.Collections.Generic.List[string]]::new()

function Step($n, $msg) { Write-Host "`n[$n] $msg" -ForegroundColor Cyan }
function Ok($msg)       { Write-Host "    OK   $msg" -ForegroundColor Green }
function Warn($msg)     { Write-Host "    WARN $msg" -ForegroundColor Yellow }
function Note($msg)     { $script:notes.Add($msg) }

# Guest ops and most of what follows require an elevated token.
$admin = ([Security.Principal.WindowsPrincipal] `
          [Security.Principal.WindowsIdentity]::GetCurrent()
         ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    throw "Run this in an ELEVATED PowerShell session (right-click > Run as administrator)."
}

Write-Host "WiperTrace baseline preparation" -ForegroundColor White
Write-Host "evidence volume: ${EvidenceDrive}:  corpus: $CorpusDir"

# ---------------------------------------------------------------------------
Step 1 "Verify the evidence volume"
# ---------------------------------------------------------------------------

$vol = Get-Volume -DriveLetter $EvidenceDrive -ErrorAction SilentlyContinue
if (-not $vol) {
    throw "Drive ${EvidenceDrive}: not found. Initialise and format the second " +
          "virtual disk as NTFS and assign it letter $EvidenceDrive first."
}
if ($vol.FileSystemType -ne 'NTFS') {
    throw "Drive ${EvidenceDrive}: is $($vol.FileSystemType), not NTFS. " +
          "The experiment measures NTFS journal structures."
}
$sizeGB = [math]::Round($vol.Size / 1GB, 2)
$freeGB = [math]::Round($vol.SizeRemaining / 1GB, 2)
Ok "${EvidenceDrive}: is NTFS, $sizeGB GB total, $freeGB GB free"

# Free-space wiping modes (cipher /w, CCleaner /WIPEFREESPACE) overwrite all
# unallocated clusters. Below ~500 MB free these finish so fast that the
# resulting journal activity is unrepresentative.
if ($vol.SizeRemaining -lt 500MB) {
    Warn "under 500 MB free; free-space wiping modes will be unrealistically brief"
    Note "Evidence volume had under 500 MB free space, limiting the realism of free-space wiping modes."
}

# ---------------------------------------------------------------------------
Step 2 "Pin the USN change journal"
# ---------------------------------------------------------------------------

# m = maximum size, a = allocation delta (growth increment). Both in bytes,
# passed as hex. Deleting first guarantees a known starting state rather than
# inheriting whatever size Windows chose at format time.
$usnMax   = '0x{0:X}' -f ($UsnJournalMB * 1MB)
$usnDelta = '0x{0:X}' -f (1MB)

& fsutil usn deletejournal /d "${EvidenceDrive}:" 2>&1 | Out-Null
& fsutil usn createjournal "m=$usnMax" "a=$usnDelta" "${EvidenceDrive}:" 2>&1 | Out-Null

$usnInfo = (& fsutil usn queryjournal "${EvidenceDrive}:") -join "`n"
if ($LASTEXITCODE -ne 0) { throw "could not query USN journal after creation" }
Ok "USN journal pinned at $UsnJournalMB MB"
Write-Host ($usnInfo -split "`n" | Where-Object { $_ -match 'Maximum Size|Allocation Delta|Usn Journal ID' } |
             ForEach-Object { "         $($_.Trim())" }) -Separator "`n"

# ---------------------------------------------------------------------------
Step 3 "Resize the NTFS transaction log (`$LogFile)"
# ---------------------------------------------------------------------------

# NTFS sizes $LogFile as a function of volume size at format time: a 2 GB
# volume gets only a few MB. $LogFile is a CIRCULAR buffer, so once it wraps,
# the oldest transaction records are overwritten - exactly the records a wipe
# signature lives in. chkdsk /L:<KB> sets it explicitly.
#
# `chkdsk <vol> /L` with no size REPORTS the current value, which is the only
# supported way to read it back.

$before = (& chkdsk "${EvidenceDrive}:" /L) -join "`n"
$beforeKB = if ($before -match '(\d[\d,]*)\s*KB') { $Matches[1] -replace ',','' } else { 'unknown' }
Write-Host "    current `$LogFile size: $beforeKB KB"

$targetKB = $LogFileMB * 1024
if ($beforeKB -ne 'unknown' -and [int]$beforeKB -ge $targetKB) {
    Ok "`$LogFile already >= $LogFileMB MB; leaving it alone"
} else {
    $out = (& chkdsk "${EvidenceDrive}:" "/L:$targetKB") -join "`n"
    $after = (& chkdsk "${EvidenceDrive}:" /L) -join "`n"
    $afterKB = if ($after -match '(\d[\d,]*)\s*KB') { $Matches[1] -replace ',','' } else { 'unknown' }
    if ($afterKB -ne 'unknown' -and [int]$afterKB -ge ($targetKB * 0.9)) {
        Ok "`$LogFile resized to $afterKB KB"
    } else {
        # NTFS can refuse an outsized log on a small volume. This is not
        # fatal: the default still holds a single run's records, but headroom
        # is reduced and journal wrap becomes a risk worth checking for.
        Warn "requested $targetKB KB, got $afterKB KB - NTFS capped the request"
        Warn "watch runs.csv for low usn_event_count, which indicates wrap"
        Note "NTFS capped the \$LogFile resize request at $afterKB KB on the evidence volume."
    }
}

# ---------------------------------------------------------------------------
Step 4 "Reclaim disk space: pagefile and hibernation"
# ---------------------------------------------------------------------------

# hiberfil.sys is ~40% of RAM; the pagefile defaults to roughly RAM size.
# On a 4 GB-RAM guest that is ~5.5 GB of the system volume for no benefit in
# a short-lived lab VM.
& powercfg /h off 2>&1 | Out-Null
Ok "hibernation disabled (hiberfil.sys removed)"
Note "Hibernation disabled in the guest."

if ($KeepPagefile) {
    Ok "pagefile left at system default (-KeepPagefile)"
} else {
    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.AutomaticManagedPagefile) {
        $cs | Set-CimInstance -Property @{ AutomaticManagedPagefile = $false }
    }
    Get-CimInstance Win32_PageFileSetting -ErrorAction SilentlyContinue |
        Remove-CimInstance -ErrorAction SilentlyContinue
    Ok "pagefile disabled (takes effect after reboot)"
    Note "Pagefile disabled in the guest to reduce the virtual disk footprint."
}

# Cap VSS storage on C:. The harness uses a shadow copy to read the locked
# Amcache hive, so VSS must stay enabled - but it does not need gigabytes.
try {
    & vssadmin resize shadowstorage /for=C: /on=C: /maxsize=2GB 2>&1 | Out-Null
    Ok "VSS shadow storage on C: capped at 2 GB"
} catch {
    Warn "could not cap VSS shadow storage: $_"
}

# ---------------------------------------------------------------------------
Step 5 "Suppress background filesystem churn"
# ---------------------------------------------------------------------------

# Windows Update, Defender scans and Search indexing write to the filesystem
# continuously. On the evidence volume that churn is indistinguishable, at
# parse time, from tool activity.
#
# SysMain is deliberately NOT disabled. It is the service that writes
# Prefetch files, and Prefetch execution evidence (SDELETE64.EXE-*.pf etc.)
# is one of the artefact classes WiperTrace correlates. With SysMain off,
# no run produces a tool Prefetch file at all. Its writes go to C:, not to
# the evidence volume D:.
foreach ($svc in 'wuauserv', 'WSearch', 'DiagTrack') {
    try {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop
        Ok "service $svc stopped and disabled"
    } catch {
        Warn "could not disable $svc (may not exist on this edition)"
    }
}
Note "Windows Update, Search indexing and DiagTrack disabled in the guest."

# Make sure Prefetch is ON (3 = applications + boot). A previous version of
# this script disabled SysMain, which silently stopped Prefetch creation.
try {
    $pf = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
    Set-ItemProperty -Path $pf -Name EnablePrefetcher -Value 3 -Type DWord -ErrorAction Stop
    Set-Service -Name SysMain -StartupType Automatic -ErrorAction Stop
    Start-Service -Name SysMain -ErrorAction SilentlyContinue
    Ok "Prefetch enabled (SysMain automatic, EnablePrefetcher=3)"
} catch {
    Warn "could not enable Prefetch: $_ - tool Prefetch evidence will be missing"
}

# Exclude the evidence volume from Search indexing even if WSearch returns.
try {
    $d = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='${EvidenceDrive}:'"
    if ($d) { $d.IndexingEnabled = $false; $d.Put() | Out-Null
              Ok "content indexing disabled on ${EvidenceDrive}:" }
} catch { Warn "could not disable indexing on ${EvidenceDrive}:" }

if ($SkipDefender) {
    Warn "Defender left enabled (-SkipDefender) - expect quarantined wiping tools"
} else {
    # Several wiping tools are flagged as PUPs. Defender will silently
    # quarantine them mid-matrix, producing runs that wipe nothing.
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
        Set-MpPreference -DisableScanOnRealtimeEnable $true -ErrorAction SilentlyContinue
        Add-MpPreference -ExclusionPath $CorpusDir, 'C:\_run', 'E:\' -ErrorAction SilentlyContinue
        Ok "Defender real-time monitoring disabled; exclusions added"
        Note "Microsoft Defender real-time protection disabled in the guest; several wiping tools are flagged as potentially unwanted programs."
    } catch {
        Warn "could not disable Defender via Set-MpPreference: $_"
        Warn "if Tamper Protection is on, disable it in Windows Security first"
    }
}

# ---------------------------------------------------------------------------
Step 6 "Disable UAC for unattended installation"
# ---------------------------------------------------------------------------

# vmrun runProgramInGuest launches processes with the user's FILTERED token.
# With UAC active, every silent installer in the matrix fails to elevate and
# exits without a diagnosable error.
$polKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Set-ItemProperty -Path $polKey -Name EnableLUA -Value 0 -Type DWord
Set-ItemProperty -Path $polKey -Name ConsentPromptBehaviorAdmin -Value 0 -Type DWord
Ok "UAC disabled (requires reboot)"
Note "UAC disabled in the guest so the harness can install wiping tools unattended."

# ---------------------------------------------------------------------------
Step 7 "Suppress blocking error dialogs"
# ---------------------------------------------------------------------------

# A modal dialog is fatal to an unattended run: nothing dismisses it, and the
# step blocks until the harness times out and kills the process tree. Missing
# DLLs, crashes and Windows Error Reporting all raise such dialogs.
#
# ErrorMode=2 sets SEM_FAILCRITICALERRORS system-wide, so hard errors are
# returned to the calling process as failures instead of being presented to a
# user who is not there. DontShowUI does the same for Windows Error Reporting.
#
# This makes failures LOUD-but-recoverable rather than silent-and-hanging:
# the tool still fails, the harness still records a non-zero exit, but the
# matrix keeps moving. Declare it in the limitations - a real endpoint would
# show these dialogs.

try {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Windows' `
                     -Name 'ErrorMode' -Value 2 -Type DWord
    Ok "ErrorMode=2 - hard-error dialogs suppressed system-wide"
} catch {
    Warn "could not set ErrorMode: $_"
}

try {
    $wer = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting'
    if (-not (Test-Path $wer)) { New-Item -Path $wer -Force | Out-Null }
    Set-ItemProperty -Path $wer -Name 'DontShowUI' -Value 1 -Type DWord
    Set-ItemProperty -Path $wer -Name 'Disabled' -Value 1 -Type DWord
    Ok "Windows Error Reporting UI disabled"
} catch {
    Warn "could not disable WER UI: $_"
}
Note "Hard-error and Windows Error Reporting dialogs suppressed in the guest (ErrorMode=2, WER DontShowUI=1) so that a failing tool cannot block an unattended run with a modal dialog."

# ---------------------------------------------------------------------------
Step 8 "Check third-party runtime dependencies"
# ---------------------------------------------------------------------------

# Some wiping tools are built against older C runtimes that a clean Windows 11
# does not ship. BleachBit 4.x bundles a GTK stack whose fc-cache.exe links
# against msvcr100.dll - the Visual C++ 2010 x86 runtime. Without it the
# installer raises a MODAL ERROR DIALOG, which on an unattended run blocks
# until the step times out, once per repeat.
#
# Installing the runtime into the BASELINE rather than per-run is deliberate:
# a per-run install would add redistributable installation traces to only
# those runs, which is a confound. In the baseline it is uniform across the
# whole matrix.

$msvcr100 = Join-Path $env:SystemRoot 'SysWOW64\msvcr100.dll'
if (Test-Path $msvcr100) {
    Ok "Visual C++ 2010 x86 runtime present (msvcr100.dll)"
} else {
    Warn "msvcr100.dll NOT found - BleachBit 4.x will fail with a modal dialog"
    if (Test-Path -LiteralPath $VCRedist2010) {
        Write-Host "    installing $VCRedist2010"
        $proc = Start-Process -FilePath $VCRedist2010 `
                              -ArgumentList '/q', '/norestart' `
                              -PassThru -Wait -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        if (Test-Path $msvcr100) {
            Ok "Visual C++ 2010 x86 runtime installed"
            Note "Visual C++ 2010 x86 redistributable installed in the baseline, required by BleachBit 4.x."
        } else {
            Warn "install ran (exit $($proc.ExitCode)) but msvcr100.dll still absent"
        }
    } else {
        Warn "installer not found at $VCRedist2010"
        Warn "download 'Microsoft Visual C++ 2010 SP1 Redistributable (x86)'"
        Warn "  https://www.microsoft.com/en-us/download/details.aspx?id=26999"
        Warn "stage it on the ISO as vcredist\vcredist_x86.exe, or pass"
        Warn "  -VCRedist2010 <path>, then re-run this script"
        Note "BleachBit 4.x requires the Visual C++ 2010 x86 runtime, which a clean Windows 11 does not ship."
    }
}

# ---------------------------------------------------------------------------
Step 9 "Verify the corpus"
# ---------------------------------------------------------------------------

if (Test-Path -LiteralPath $CorpusDir) {
    $files = Get-ChildItem -LiteralPath $CorpusDir -File
    $mb = [math]::Round((($files | Measure-Object Length -Sum).Sum) / 1MB, 1)
    $exts = ($files | Group-Object Extension | Sort-Object Count -Descending |
             Select-Object -First 6 | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' '
    Ok "$($files.Count) files, $mb MB"
    Write-Host "         types: $exts"
    if ($files.Count -lt 60) {
        Warn "fewer than 60 files; the harness targets 40 per run and the " +
             "remainder provides background realism"
    }
} else {
    Warn "$CorpusDir does not exist - create it and copy govdocs1 files in"
}

# ---------------------------------------------------------------------------
Step 10 "Confirm VMware Tools"
# ---------------------------------------------------------------------------

$tools = Get-Service -Name 'VMTools' -ErrorAction SilentlyContinue
if ($tools -and $tools.Status -eq 'Running') {
    Ok "VMware Tools service is running"
} else {
    Warn "VMware Tools is NOT running - the harness cannot drive this VM without it"
    Warn "install via VM > Install VMware Tools in Workstation"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host "`n" ("=" * 72)
Write-Host "Baseline preparation complete." -ForegroundColor White
Write-Host ("=" * 72)
# Emitted as a string array rather than a here-string: here-string parsing is
# sensitive to line endings, and Windows PowerShell 5.1 mis-parses one in a
# file saved with LF-only endings, which cascades into spurious syntax errors
# elsewhere in the file.
$nextSteps = @(
    '',
    'NEXT STEPS',
    '  1. Reboot the guest so the pagefile and UAC changes take effect.',
    '  2. Confirm no wiping tool is installed: this baseline must be clean, or',
    '     every captured image will carry traces of all of them.',
    '  3. Shut down the guest cleanly.',
    "  4. In Workstation: VM > Snapshot > Take Snapshot, named exactly 'clean'.",
    '',
    "FOR THE REPORT'S LIMITATIONS SECTION"
)
foreach ($line in $nextSteps) { Write-Host $line -ForegroundColor Gray }

$i = 1
foreach ($n in $notes) { Write-Host "  $i. $n" -ForegroundColor Gray; $i++ }

$summary = @{
    generated     = (Get-Date).ToUniversalTime().ToString('o')
    evidence_drive = "${EvidenceDrive}:"
    volume_size_gb = $sizeGB
    usn_journal_mb = $UsnJournalMB
    logfile_mb     = $LogFileMB
    limitations    = $notes
}
$outFile = 'C:\baseline_prep.json'
$summary | ConvertTo-Json -Depth 4 | Set-Content -Path $outFile -Encoding UTF8
Write-Host "`nMachine-readable summary: $outFile" -ForegroundColor Gray
