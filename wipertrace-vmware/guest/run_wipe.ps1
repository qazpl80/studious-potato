<#
    run_wipe.ps1 - guest-side agent. Executes inside the VM, once per run.

    Invoked by the host via:
        vmrun ... runProgramInGuest <vmx> -interactive powershell.exe
               -File C:\_run\run_wipe.ps1 <RunId> <ToolId> <Mode> <PlanPath>

    CONTRACT WITH THE HOST
    ----------------------
    VMware's VIX API discards guest stdout/stderr, so this script cannot
    report back through its return channel. It therefore persists everything
    the host needs to disk under C:\_run:

        guest.log       append-only trace of every step
        manifest.json   ground truth + provenance for this run (the answer key)
        collected.zip   Prefetch + Amcache, archived because VIX cannot
                        transfer directory trees
        _STATUS.txt     terminal sentinel: "OK" or "FAIL <reason>"

    The host treats absence of _STATUS.txt, or any content other than OK, as
    a failed run. Never infer success from vmrun's exit code.

    VOLUME DISCIPLINE
    -----------------
    Everything this script writes goes to C:. The volume under study is D:,
    which must see only the corpus and the wipe itself. Reading or writing
    anything else on D: would contaminate $MFT, $LogFile and $UsnJrnl - the
    exact structures being measured.
#>

param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][string]$ToolId,
    [Parameter(Mandatory = $true)][string]$Mode,
    [Parameter(Mandatory = $true)][string]$PlanPath
)

$ErrorActionPreference = 'Stop'
$Work      = 'C:\_run'
$Collected = Join-Path $Work 'collected'
$Status    = Join-Path $Work '_STATUS.txt'

New-Item -ItemType Directory -Force -Path $Work, $Collected | Out-Null
Remove-Item -LiteralPath $Status -Force -ErrorAction SilentlyContinue

function Write-Log($msg) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'o'), $msg
    Write-Host $line
    Add-Content -Path (Join-Path $Work 'guest.log') -Value $line
}

function Set-Status($text) {
    Set-Content -Path $Status -Value $text -Encoding ASCII
}

function Get-NtfsFileReference($path) {
    <#
        Returns the NTFS file reference for a path.

        `fsutil file queryfileid` emits a 128-bit FILE_ID_128. On NTFS only
        the low 64 bits are populated and they decompose as:
            bits  0-47  MFT record number (the entry index)
            bits 48-63  sequence number (incremented on record reuse)

        The record number is the join key for the whole dataset. Filenames are
        precisely what wiping tools destroy, but the MFT record number persists
        in $UsnJrnl and $LogFile records, so labelling on it is what lets us
        later assert "record 1042 was wiped by Eraser" rather than merely
        "40 files disappeared".
    #>
    try {
        $raw = (& fsutil file queryfileid $path) 2>$null
        if (-not $raw) { return $null }
        $hex = ($raw -split 'is\s+')[-1].Trim() -replace '^0x', ''
        if ($hex.Length -lt 16) { return $null }
        $low64 = [Convert]::ToUInt64($hex.Substring($hex.Length - 16), 16)
        # Integer bit-shift, not division by [math]::Pow(2,48): Pow returns a
        # Double, and values near the top of the UInt64 range exceed the
        # 53-bit mantissa, so the quotient rounds up and the sequence number
        # comes out one too high. -shr keeps the arithmetic integral and is
        # available from PowerShell 3.0 onward.
        return [ordered]@{
            file_id_hex = "0x$hex"
            mft_record  = [int64]($low64 -band 0xFFFFFFFFFFFF)
            sequence    = [int]($low64 -shr 48)
        }
    } catch { return $null }
}

function Get-Sha256($path) {
    try { return (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash }
    catch { return $null }
}

function Expand-Template($text, $target, $dir) {
    if (-not $text) { return $null }
    # Literal substitution only. Regex replacement would mangle Windows
    # path separators, which are regex escape characters.
    return $text.Replace('{target}', $target).Replace('{dir}', $dir)
}

function Get-InstallerPath($cmd) {
    <#
        Extract the installer path from a configured install command so its
        existence can be verified before execution.

        Matches a drive-qualified path ending in .exe or .msi, with or without
        surrounding quotes. This covers direct invocation
        ("E:\tool\setup.exe /S") and msiexec forms
        ("msiexec /i E:\tool\pkg.msi /qn").
    #>
    if (-not $cmd) { return $null }
    $m = [regex]::Match($cmd, '(?i)"?([a-z]:\\[^"]*?\.(?:exe|msi))"?')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}

function Invoke-Step($cmd, $label, $timeoutSec = 300) {
    <#
        Dispatches a configured command to PowerShell (our control scenarios,
        which are cmdlet pipelines) or to cmd.exe (the wiping tools, which are
        external executables). The heuristic inspects the leading token;
        multi-line blocks are always treated as PowerShell.

        EXTERNAL COMMANDS ARE RUN UNDER A TIMEOUT. An installer that falls
        back to its GUI, or raises a modal error dialog, blocks forever on a
        machine with nobody at the keyboard. Without a timeout a single such
        dialog consumes the whole run timeout - and once per repeat, so one
        bad installer can waste hours of an unattended matrix. On timeout the
        process tree is killed and the step reported as failed, which is
        recoverable; a hang is not.
    #>
    $isPs = $cmd -match '\n' -or
            $cmd -match '^\s*(Remove-Item|Rename-Item|Get-ChildItem|Add-Type|Clear-RecycleBin|New-Item|Set-Content|\$|\[)'
    try {
        if ($isPs) {
            Invoke-Expression $cmd
            return 0
        }

        # QUOTING. Windows PowerShell 5.1 joins an -ArgumentList array with
        # spaces and adds no quotes, and cmd.exe /c then applies its own
        # rule: if the command line holds more than two quote characters it
        # strips the FIRST and LAST quote. A command such as
        #     "C:\Program Files\Eraser\Eraser.exe" erase ... "file=D:\x"
        # becomes  C:\Program Files\Eraser\Eraser.exe" erase ... "file=D:\x
        # and fails with "'C:\Program' is not recognized" - which is why the
        # same command works when typed by hand but not here. /s plus one
        # extra pair of outer quotes makes cmd strip exactly that pair and
        # run the configured command verbatim.
        $cmdLine = '/s /c "' + $cmd + '"'
        $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList $cmdLine `
                              -PassThru -WindowStyle Hidden -ErrorAction Stop

        if (-not $proc.WaitForExit($timeoutSec * 1000)) {
            Write-Log "TIMEOUT after ${timeoutSec}s in ${label} - killing process tree"
            # taskkill /T reaches children; an installer's real work is
            # usually in a child process, and killing only the parent would
            # leave a dialog on screen to block the next step too.
            & taskkill /PID $proc.Id /T /F 2>&1 | Out-Null
            Start-Sleep -Seconds 2
            return -2
        }

        # The timed WaitForExit overload returns as soon as the process
        # signals, but .NET does not guarantee ExitCode is settled until the
        # parameterless overload has also returned. Calling it here is
        # effectively free - the process has already exited - and avoids
        # reading a stale or zero exit code.
        $proc.WaitForExit()
        return $proc.ExitCode

    } catch {
        Write-Log "ERROR in ${label}: $_"
        return -1
    }
}

function Wait-ForPath($path, $timeoutSec) {
    <#
        Poll until $path exists. Returns elapsed seconds, or -1 on timeout.

        Silent installers commonly return while a child process is still
        copying files, and msiexec may hand work to the Windows Installer
        service. A fixed sleep is either too short (the first wipe hits a
        missing binary and every per-file call fails) or wastes time on
        every run; polling for the binary the wipe actually needs is both
        faster and a positive confirmation that the install succeeded.
    #>
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $timeoutSec) {
        if (Test-Path -LiteralPath $path) {
            return [math]::Round($sw.Elapsed.TotalSeconds, 1)
        }
        Start-Sleep -Seconds 2
    }
    return -1
}

function Wait-TargetsGone($paths, $timeoutSec) {
    <#
        Poll until none of $paths exist. Returns the paths still present when
        the wait ended (empty array = all gone).

        Used for asynchronous wipers. Eraser's CLI hands each task to its
        background service and exits 0 immediately, so the per-file loop
        finishes long before any data is overwritten. Without this wait the
        settle period would expire and the host would power the VM off with
        the wipe still in progress - the image would then record a partial
        wipe while the manifest claimed a complete one.
    #>
    $sw = [Diagnostics.Stopwatch]::StartNew()
    do {
        $left = @($paths | Where-Object { Test-Path -LiteralPath $_ })
        if ($left.Count -eq 0) { return @() }
        Start-Sleep -Seconds 5
    } while ($sw.Elapsed.TotalSeconds -lt $timeoutSec)
    return @($paths | Where-Object { Test-Path -LiteralPath $_ })
}

try {
    # -----------------------------------------------------------------------
    # STEP 0 - Load the run plan
    #
    # The host serialises the resolved tool/mode definition to plan.json so
    # the guest never has to parse config.yaml (no YAML parser is guaranteed
    # present in a stock Windows PowerShell 5.1 install).
    # -----------------------------------------------------------------------

    $plan   = Get-Content -Raw -Encoding UTF8 -LiteralPath $PlanPath | ConvertFrom-Json
    $corpus = $plan.corpus_dir
    $count  = [int]$plan.wipe_count
    $settle = if ($plan.settle_seconds) { [int]$plan.settle_seconds } else { 15 }

    Write-Log "run=$RunId tool=$ToolId mode=$Mode corpus=$corpus count=$count"

    if (-not (Test-Path -LiteralPath $corpus)) {
        throw "corpus directory $corpus not found - is the evidence disk mounted as D:?"
    }

    # -----------------------------------------------------------------------
    # STEP 1 - Capture ground truth BEFORE anything mutates the volume
    #
    # This ordering is non-negotiable. Once a wiper runs, the filename,
    # timestamps and often the MFT record contents are gone; the answer key
    # cannot be reconstructed after the fact.
    # -----------------------------------------------------------------------

    $targets = Get-ChildItem -LiteralPath $corpus -File |
               Sort-Object Name |
               Select-Object -First $count

    if ($targets.Count -eq 0) { throw "no files found in $corpus" }

    $truth = @()
    foreach ($f in $targets) {
        $ref = Get-NtfsFileReference $f.FullName
        $truth += [ordered]@{
            path        = $f.FullName
            name        = $f.Name
            size        = $f.Length
            sha256      = Get-Sha256 $f.FullName
            mft_record  = if ($ref) { $ref.mft_record }  else { $null }
            sequence    = if ($ref) { $ref.sequence }    else { $null }
            file_id_hex = if ($ref) { $ref.file_id_hex } else { $null }
            created     = $f.CreationTimeUtc.ToString('o')
            modified    = $f.LastWriteTimeUtc.ToString('o')
        }
    }
    Write-Log "ground truth recorded for $($truth.Count) files"

    # Journal watermark before the wipe. Comparing NextUsn before/after shows
    # how far the journal advanced; comparing MaximumSize against the delta
    # reveals whether it wrapped, which would silently truncate evidence.
    $usnBefore = (& fsutil usn queryjournal D:) -join "`n"

    # -----------------------------------------------------------------------
    # STEP 2 - Install the assigned tool
    #
    # Installation happens per run, inside the disposable snapshot, so each
    # image carries traces of exactly one wiping tool. Baking all tools into
    # the baseline would make every image indistinguishable and destroy the
    # attribution experiment.
    # -----------------------------------------------------------------------

    $installStart = (Get-Date).ToUniversalTime().ToString('o')
    $installCode  = $null
    if ($plan.install) {
        # Verify the installer is actually present. Without this check a
        # mistyped filename or a version bump on the ISO yields a run that
        # installs nothing, wipes nothing, and still produces a complete
        # looking run folder - the hardest failure mode to notice later.
        $installer = Get-InstallerPath $plan.install
        if ($installer -and -not (Test-Path -LiteralPath $installer)) {
            throw ("installer not found: $installer - check that the filename " +
                   "on the installers ISO matches config.yaml for '$ToolId'")
        }
        if ($installer) { Write-Log "installer present: $installer" }
        $installTimeout = if ($plan.install_timeout_sec) { [int]$plan.install_timeout_sec } else { 300 }
        Write-Log "installing (timeout ${installTimeout}s): $($plan.install)"
        $installCode = Invoke-Step $plan.install 'install' $installTimeout
        if ($installCode -eq -2) {
            throw ("installer timed out after ${installTimeout}s - it is " +
                   "probably showing a GUI or a modal dialog. Verify the " +
                   "silent switch by hand (see PART4-MANUAL-TESTS.md) and " +
                   "check that its runtime dependencies are present in the " +
                   "baseline.")
        }
        Write-Log "install returned $installCode"

        if ($plan.binary) {
            # Positive confirmation the install worked. Installer exit codes
            # are not trusted: BCWipe's installer inverts them unless -Z is
            # passed, and a bootstrapper can exit 0 having shown a wizard
            # that the timeout then killed.
            $waited = Wait-ForPath $plan.binary 180
            if ($waited -lt 0) {
                throw ("installed binary not found after 180s: $($plan.binary) " +
                       "(install exit code $installCode). The silent install " +
                       "failed or installed elsewhere - locate it with " +
                       "Find-InstalledProgram from guest\diagnose_tool.ps1.")
            }
            Write-Log "binary present after ${waited}s: $($plan.binary)"
            # Short grace period for the installer's trailing writes
            # (shortcuts, registry, service registration).
            Start-Sleep -Seconds 5
        } else {
            # No binary declared: fall back to a fixed wait, since silent
            # installers frequently return before their children finish.
            Start-Sleep -Seconds 12
        }
    } elseif ($plan.binary -and -not (Test-Path -LiteralPath $plan.binary)) {
        # Portable tool run straight off the installers ISO.
        throw ("tool binary not found: $($plan.binary) - is the installers " +
               "ISO connected as E:?")
    }
    $installEnd = (Get-Date).ToUniversalTime().ToString('o')

    # -----------------------------------------------------------------------
    # STEP 3 - Execute the wipe
    #
    # Two shapes of command are supported:
    #   per_file : invoked once per target; the normal case for file wipers
    #   once     : invoked once for the whole volume; used by free-space
    #              scrubbers (cipher /w, CCleaner /WIPEFREESPACE) which never
    #              touch a named file and therefore leave no rename chain
    # A 'pre' command runs first where the mode requires a particular starting
    # state (e.g. deleting the corpus so free space exists to scrub).
    # -----------------------------------------------------------------------

    if ($plan.pre) {
        $cmd = Expand-Template $plan.pre '' $corpus
        Write-Log "pre-step: $cmd"
        Invoke-Step $cmd 'pre' 600 | Out-Null
    }

    $wipeStart      = (Get-Date).ToUniversalTime().ToString('o')
    $perFileResults = @()
    $wipeTimeout    = if ($plan.wipe_timeout_sec) { [int]$plan.wipe_timeout_sec } else { 300 }
    # Volume-wide scrubbers legitimately run far longer than a per-file wipe.
    $onceTimeout    = if ($plan.once_timeout_sec) { [int]$plan.once_timeout_sec } else { 3600 }

    if ($plan.per_file) {
        foreach ($t in $truth) {
            $cmd  = Expand-Template $plan.per_file $t.path $corpus
            $code = Invoke-Step $cmd "wipe $($t.name)" $wipeTimeout
            $perFileResults += [ordered]@{
                path       = $t.path
                mft_record = $t.mft_record
                exit_code  = $code
                at_utc     = (Get-Date).ToUniversalTime().ToString('o')
            }
        }
        $failed = ($perFileResults | Where-Object { $_.exit_code -ne 0 }).Count
        Write-Log "per-file stage: $($perFileResults.Count) attempted, $failed non-zero"
    }

    $onceCode = $null
    if ($plan.once) {
        $cmd = Expand-Template $plan.once '' $corpus
        Write-Log "volume-level command"
        $onceCode = Invoke-Step $cmd 'once' $onceTimeout
        Write-Log "volume-level command returned $onceCode"
    }

    $targetPaths = @($truth | ForEach-Object { $_.path })

    $awaitSec    = if ($plan.await_targets_sec) { [int]$plan.await_targets_sec } else { 0 }
    $awaitResult = $null
    if ($awaitSec -gt 0) {
        Write-Log "asynchronous tool: waiting up to ${awaitSec}s for targets to disappear"
        $sw   = [Diagnostics.Stopwatch]::StartNew()
        $left = Wait-TargetsGone $targetPaths $awaitSec
        $awaitResult = [ordered]@{
            timeout_sec = $awaitSec
            waited_sec  = [math]::Round($sw.Elapsed.TotalSeconds, 1)
            remaining   = $left.Count
        }
        if ($left.Count -gt 0) {
            Write-Log ("WARNING: $($left.Count) target(s) still present after " +
                       "${awaitSec}s; the wipe may be incomplete when the VM " +
                       "stops. Recorded in manifest.await_targets.")
        } else {
            Write-Log "all targets gone after $($awaitResult.waited_sec)s"
        }
    }

    $wipeEnd = (Get-Date).ToUniversalTime().ToString('o')

    # GUARD: a wiping tool that removed none of its targets did not run.
    # Exit codes cannot detect this (Eraser returns 0 for a task it never
    # queued; an unquoted path returns a cmd.exe error the tool never sees),
    # and the resulting image would be labelled "wiped by <tool>" while
    # containing nothing but the corpus. Controls are exempt: control_churn
    # renames files back to their original names by design.
    $isControl = $ToolId -like 'control_*'
    if (-not $isControl -and $plan.per_file) {
        $stillThere = @($targetPaths | Where-Object { Test-Path -LiteralPath $_ })
        if ($stillThere.Count -eq $targetPaths.Count) {
            throw ("no target was removed - the wipe command did not take " +
                   "effect. Run it by hand from PART4-MANUAL-TESTS.md. " +
                   "First per-file exit code: $($perFileResults[0].exit_code)")
        }
    }

    # Allow the NTFS log writer and any tool worker threads to quiesce before
    # the host cuts power. Without this, a hard stop can truncate the very
    # records we are trying to observe.
    Start-Sleep -Seconds $settle

    $usnAfter = (& fsutil usn queryjournal D:) -join "`n"

    # -----------------------------------------------------------------------
    # STEP 4 - Collect C: execution artefacts via VSS
    #
    # Amcache.hve is held open by the system. A shadow copy provides a
    # crash-consistent point-in-time view without rebooting. This touches
    # C: only; the D: journals are collected by the host offline, after
    # power-off, because reading $MFT from a live volume writes to $MFT.
    # -----------------------------------------------------------------------

    $shadowOk = $false
    try {
        $cls    = [WMICLASS]"root\cimv2:Win32_ShadowCopy"
        $res    = $cls.Create("C:\", "ClientAccessible")
        $shadow = Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $res.ShadowID }
        if (-not $shadow) { throw "shadow copy created but not enumerable" }

        # The shadow DeviceObject is a raw NT device path; Win32 file APIs
        # need a symbolic link to traverse it.
        $device = $shadow.DeviceObject + "\"
        $link   = Join-Path $Work 'shadow'
        if (Test-Path $link) { cmd /c rmdir "$link" | Out-Null }
        cmd /c mklink /d "$link" "$device" | Out-Null

        Copy-Item -Path (Join-Path $link 'Windows\Prefetch') `
                  -Destination $Collected -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item -Path (Join-Path $link 'Windows\appcompat\Programs\Amcache.hve') `
                  -Destination $Collected -Force -ErrorAction SilentlyContinue

        cmd /c rmdir "$link" | Out-Null
        $shadow | Remove-CimInstance -ErrorAction SilentlyContinue
        $shadowOk = $true
        Write-Log "collected Prefetch + Amcache via VSS"
    } catch {
        # Fall back to a live copy and record the degradation, since locked
        # hives may be skipped or captured torn.
        Write-Log "VSS failed ($_); falling back to live copy"
        Copy-Item -Path 'C:\Windows\Prefetch' -Destination $Collected `
                  -Recurse -Force -ErrorAction SilentlyContinue
        Copy-Item -Path 'C:\Windows\appcompat\Programs\Amcache.hve' `
                  -Destination $Collected -Force -ErrorAction SilentlyContinue
    }

    # Which target paths still resolve. A tool that truncates a file in place
    # behaves very differently from one that unlinks it, and that difference
    # is visible here before any parsing happens.
    $survivors = @()
    foreach ($t in $truth) {
        if (Test-Path -LiteralPath $t.path) { $survivors += $t.path }
    }
    Write-Log "$($survivors.Count)/$($truth.Count) target paths still exist"

    # -----------------------------------------------------------------------
    # STEP 5 - Write the manifest
    # -----------------------------------------------------------------------

    $os = Get-CimInstance Win32_OperatingSystem

    $manifest = [ordered]@{
        run_id           = $RunId
        tool_id          = $ToolId
        mode             = $Mode
        tool_display     = $plan.display
        is_control       = [bool]($ToolId -like 'control_*')
        corpus_dir       = $corpus
        hypervisor       = 'VMware Workstation'
        windows_build    = $os.BuildNumber
        windows_caption  = $os.Caption
        windows_version  = $os.Version
        install_command  = $plan.install
        install_exit     = $installCode
        tool_binary      = $plan.binary
        pre_command      = $plan.pre
        wipe_command     = $plan.per_file
        volume_command   = $plan.once
        volume_exit      = $onceCode
        await_targets    = $awaitResult
        settle_seconds   = $settle
        times_utc        = [ordered]@{
            install_start = $installStart
            install_end   = $installEnd
            wipe_start    = $wipeStart
            wipe_end      = $wipeEnd
        }
        usn_before       = $usnBefore
        usn_after        = $usnAfter
        shadow_copy_used = $shadowOk
        surviving_paths  = $survivors
        targets          = $truth
        per_file_results = $perFileResults
    }

    $manifest | ConvertTo-Json -Depth 6 |
        Set-Content -Path (Join-Path $Work 'manifest.json') -Encoding UTF8

    # -----------------------------------------------------------------------
    # STEP 6 - Archive for transfer
    #
    # VIX copyFileFromGuestToHost handles one file at a time, so the artefact
    # tree is collapsed into a single zip. Compress-Archive is used rather
    # than a loop of per-file transfers because each VIX round trip costs
    # roughly a second and Prefetch alone can hold hundreds of entries.
    # -----------------------------------------------------------------------

    $zip = Join-Path $Work 'collected.zip'
    Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
    if ((Get-ChildItem -LiteralPath $Collected -Recurse -File -ErrorAction SilentlyContinue).Count -gt 0) {
        Compress-Archive -Path (Join-Path $Collected '*') -DestinationPath $zip `
                         -CompressionLevel Optimal -Force
        Write-Log "collected.zip written ($([math]::Round((Get-Item $zip).Length / 1MB, 1)) MB)"
    } else {
        Write-Log "WARNING: nothing collected to archive"
    }

    Set-Status 'OK'
    Write-Log "guest side complete"
    exit 0

} catch {
    # Any unhandled fault must still leave a readable verdict on disk,
    # because the host has no other channel to learn what went wrong.
    $msg = "FAIL $($_.Exception.Message)"
    try { Write-Log $msg } catch { }
    try { Set-Status $msg } catch { }
    exit 1
}
