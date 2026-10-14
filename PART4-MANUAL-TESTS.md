# Part 4 — Manual tool verification

Work through these **inside the guest VM**, in an **elevated PowerShell**, one
tool at a time. The point is to confirm each tool's silent-install switch and
wipe command actually work before committing to the matrix.

> **Status: testing complete.** Results are in section 9 and are applied to
> `config.yaml`. Five tools are in the matrix (SDelete, cipher, BleachBit
> 6.0.4, BleachBit 4.6.0, Eraser); CCleaner and BCWipe were tested and
> disabled. The matrix is **60 runs, about 9-10 hours**. What remains is one
> smoke run per tool through the harness itself and the control checks in
> section 8 - see section 10.

> **Why this matters.** A run whose install silently fails, or whose wipe
> command is wrong, still produces a complete-looking run folder full of
> plausible files. That is the hardest failure to notice after the fact. Ten
> minutes here saves re-running the matrix.

> **A silent switch is often not one switch.** BleachBit needed `/allusers /S`
> rather than `/S`, because the installer also has to be told the install
> scope before it will skip its wizard. Expect the same pattern elsewhere: if
> a documented silent switch still shows a GUI, the installer is usually
> waiting on one more unanswered choice (scope, licence, install path), not
> ignoring the switch.

> **Run the installer with a deliberately wrong switch.** BCWipe, Eraser and
> BleachBit each needed something non-obvious, and in BCWipe's case feeding
> it `/VERYSILENT` made it print its complete usage - including the fact that
> it inverts exit codes. One wrong switch is faster than any amount of
> searching.

> **A setup .exe is not necessarily an installer.** Eraser's is a wrapper
> around an MSI: it discards every silent switch and writes no log, because
> nothing in it parses switches. When an installer ignores *all* switches
> *and* produces no log, stop trying switches and look inside the package -
> `7z l setup.exe` usually reveals an MSI you can drive directly.

> **Older tools carry older runtime dependencies.** BleachBit 4.x needs the
> Visual C++ 2010 x86 runtime, absent from a clean Windows 11, and fails with
> a *modal dialog* rather than an error code. Any dialog is fatal to an
> unattended run - the harness now kills a step that exceeds its timeout
> rather than hanging, but a killed step still means a wasted run. When you
> test a tool, watch for dialogs as carefully as for exit codes, and put any
> runtime it needs into the baseline.

Every command below is given in **PowerShell-safe form**. Several start with a
quoted path, which PowerShell parses as a string expression unless prefixed
with the call operator `&`. The harness itself runs these through
`cmd.exe /s /c "<command>"`, where no `&` is needed, so the forms differ
slightly — that is expected. (The `/s` matters: without it `cmd.exe` strips
the first and last quote from any command that starts with a quoted path,
so a command that works here would fail inside the harness.)

---

## 0. Before you start

**On the host**, confirm the baseline is clean and note the snapshot:

```powershell
$vmrun = "C:\Program Files\VMware\VMware Workstation\vmrun.exe"
$vmx   = "C:\Users\bepos\Desktop\VM-Folder\Windows 11 x64\Windows 11 x64.vmx"
$vp    = "<encryption password>"

& $vmrun -T ws -vp $vp listSnapshots $vmx
```

Start the VM with a GUI (or just press Play in Workstation):

```powershell
& $vmrun -T ws -vp $vp start $vmx gui
```

**In the guest**, set up a scratch area so you never burn corpus files:

```powershell
# Elevated PowerShell. Scratch dir on the evidence volume.
New-Item -ItemType Directory -Force -Path D:\t | Out-Null

function New-TestFile {
    param([string]$Name = "probe.bin", [int]$KB = 256)
    $p = "D:\t\$Name"
    $bytes = New-Object byte[] ($KB * 1024)
    (New-Object Random).NextBytes($bytes)
    [IO.File]::WriteAllBytes($p, $bytes)
    $id = (& fsutil file queryfileid $p) 2>$null
    Write-Host "created $p"
    Write-Host "  size   : $((Get-Item $p).Length) bytes"
    Write-Host "  fileid : $id"
    return $p
}

function Test-Gone {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        Write-Host "STILL PRESENT: $Path  ($((Get-Item $Path).Length) bytes)" -ForegroundColor Yellow
    } else {
        Write-Host "GONE: $Path" -ForegroundColor Green
    }
}
```

Confirm the installers ISO is mounted as **E:**:

```powershell
Get-ChildItem E:\ -Recurse -File | Select-Object FullName, Length
```

**After each tool**, revert to `clean` on the host before testing the next
one, so each tool is tested against a pristine baseline:

```powershell
& $vmrun -T ws -vp $vp stop $vmx soft
& $vmrun -T ws -vp $vp revertToSnapshot $vmx clean
& $vmrun -T ws -vp $vp start $vmx gui
```

---

## 1. SDelete — portable, expected to work

No installation. This is the reference case: if the rename signature appears
anywhere, it appears here.

```powershell
$f = New-TestFile "sdelete_p1.bin"

E:\sdelete\sdelete64.exe -accepteula -nobanner -p 1 "$f"
Write-Host "exit code: $LASTEXITCODE"

Test-Gone $f
```

Then the 3-pass mode:

```powershell
$f = New-TestFile "sdelete_p3.bin"

E:\sdelete\sdelete64.exe -accepteula -nobanner -p 3 "$f"
Write-Host "exit code: $LASTEXITCODE"

Test-Gone $f
```

**Record:** exit code 0, file gone. If `-accepteula` is omitted on a first run
SDelete shows a licence dialog and blocks forever, which is why it is in the
command.

---

## 2. cipher.exe — built in, free-space mode

`cipher /w` scrubs unallocated clusters only; it never touches a named file,
so there is no per-file signature to observe. Delete first, then scrub.

```powershell
# Create a few files, then delete them normally to make free space dirty.
1..5 | ForEach-Object { New-TestFile "cipher_$_.bin" 128 | Out-Null }
Remove-Item -Path "D:\t\*" -Force -Recurse

# This is the slow one: it writes the whole free space three times.
Measure-Command { cipher.exe /w:D:\ } | Select-Object TotalMinutes
```

**Record:** how long it took. On a 2 GB volume with ~1.8 GB free this should
be minutes, not tens of minutes. If it runs much longer than expected, note
it — `settle_seconds` and the run timeout may need raising.

---

## 3. BleachBit 6.0.4

**`/S` alone does not work** - the installer still shows its wizard. It needs
an install-scope switch to proceed non-interactively, and `/allusers` must
come **before** `/S`:

```powershell
E:\bleachbit\bleachbit-6.0.4-setup.exe /allusers /S
Start-Sleep -Seconds 15
Write-Host "exit code: $LASTEXITCODE"

Test-Path "C:\Program Files (x86)\BleachBit\bleachbit_console.exe"
```

`/allusers` installs to `%ProgramFiles(x86)%\BleachBit`, which is the path the
wipe command below assumes. `/currentuser` installs under AppData instead and
would require changing that path in `config.yaml`.

If the wizard still appears, try in order:

```powershell
E:\bleachbit\bleachbit-6.0.4-setup.exe /currentuser /S
```

```powershell
E:\bleachbit\bleachbit-6.0.4-setup.exe /allusers /S /D=C:\BleachBit
```

> `/D=` sets the install directory and **must be the last switch**, unquoted,
> even if the path contains spaces. That is an NSIS convention, not a typo.

Find the console binary wherever it landed:

```powershell
Get-ChildItem "C:\Program Files","C:\Program Files (x86)","$env:LOCALAPPDATA","$env:APPDATA" `
  -Recurse -Filter bleachbit_console.exe -ErrorAction SilentlyContinue |
  Select-Object -ExpandProperty FullName
```

Then the wipe:

```powershell
$f = New-TestFile "bb6.bin"

& "C:\Program Files (x86)\BleachBit\bleachbit_console.exe" --shred "$f"
Write-Host "exit code: $LASTEXITCODE"

Test-Gone $f
```

**Record:** the switch combination that worked, the console path, wipe exit
code, file gone.

### Fallback: the portable build

If no switch combination installs silently, BleachBit also ships a portable
zip (`BleachBit-<version>-portable.zip`, same download folders). Stage it on
the ISO and unpack it in the guest instead of installing:

```powershell
Expand-Archive E:\bleachbit\bleachbit-6.0.4-portable.zip -DestinationPath C:\bb6 -Force
& "C:\bb6\bleachbit_console.exe" --shred "$f"
```

Then set `install: null` for that tool and point `per_file` at `C:\bb6`.

> **This changes the trace profile and must be declared.** A portable build
> leaves no installer footprint - no Amcache entry for the setup executable,
> no uninstall registry key, no Program Files directory. That is a legitimate
> and arguably realistic scenario (a suspect running a wiper from a USB
> stick), but it is a *different* scenario from an installed tool, and your
> report must say which one each run represents. Prefer the installed form if
> any switch works.

---

## 4. BleachBit 4.6.0

Revert to `clean` first - **do not install this over 6.0.4.** The whole point
of the version pair is two independent observations.

> **Known dependency: Visual C++ 2010 x86 runtime.** BleachBit 4.x bundles a
> GTK stack whose `fc-cache.exe` links against `msvcr100.dll`, which a clean
> Windows 11 does not ship. Without it the install raises:
>
> ```
> fc-cache.exe - System Error
> The code execution cannot proceed because msvcr100.dll was not found.
> ```
>
> That dialog is **modal**, so in an unattended run it blocks until the step
> times out - once for each of the six bleachbit4 runs.

Check first - **and check both architectures**, because `SysWOW64` holds the
32-bit copy and `System32` the 64-bit one. A 64-bit binary cannot load the
SysWOW64 copy, so "DLL not found" can be reported while the file plainly
exists:

```powershell
Test-Path "$env:SystemRoot\SysWOW64\msvcr100.dll"   # 32-bit copy
Test-Path "$env:SystemRoot\System32\msvcr100.dll"   # 64-bit copy
```

If the DLL is present but the error persists, run the diagnostic, which reads
each binary's PE header to report its true architecture and then tests the
binary the harness actually calls:

```powershell
powershell -ExecutionPolicy Bypass -File .\diagnose_tool.ps1
```

> **`fc-cache.exe` may not matter.** It builds a font cache for the GTK *GUI*.
> The harness only ever invokes `bleachbit_console.exe`. If the console binary
> runs and shreds correctly, a broken `fc-cache` is cosmetic - note it and move
> on. What *does* matter is that its dialog blocks an unattended install, which
> `prepare_baseline.ps1` step 7 now prevents system-wide.

If `False`, install the runtime. Download **Microsoft Visual C++ 2010 SP1
Redistributable (x86)** from
<https://www.microsoft.com/en-us/download/details.aspx?id=26999>, stage it on
the ISO as `vcredist\vcredist_x86.exe`, then:

```powershell
E:\vcredist\vcredist_x86.exe /q /norestart
Start-Sleep -Seconds 10
Test-Path "$env:SystemRoot\SysWOW64\msvcr100.dll"
```

> **Install this into the baseline, not per run.** `prepare_baseline.ps1`
> step 7 does it automatically if the installer is on the ISO. Installing it
> per run would add redistributable-installation traces to only the six
> bleachbit4 runs, which is a confound: those runs would differ from the rest
> in ways unrelated to the wiper. In the baseline it is uniform across the
> whole matrix. Declare it in the limitations either way.
>
> **It is also x86, not x64** - BleachBit is a 32-bit application, so the DLL
> lands in `SysWOW64`. Installing the x64 redistributable will not help.

Then install BleachBit 4.6.0:

```powershell
E:\bleachbit\bleachbit-4.6.0-setup.exe /allusers /S
Start-Sleep -Seconds 15
Write-Host "exit code: $LASTEXITCODE"

Test-Path "C:\Program Files (x86)\BleachBit\bleachbit_console.exe"
```

```powershell
$f = New-TestFile "bb4.bin"

& "C:\Program Files (x86)\BleachBit\bleachbit_console.exe" --shred "$f"
Write-Host "exit code: $LASTEXITCODE"

Test-Gone $f
```

**Record:** whether 4.6.0 accepts the same switches and installs to the same
path as 6.0.4, and that the VC++ 2010 runtime is in the baseline. A difference
in switches or path is itself evidence about how much a signature can depend
on version - which is the point of running the pair.

---

## 5. Eraser - the .exe is a wrapper, not an installer

**Do not waste time on switches.** The distributed `.exe` is a **wrapper
around an MSI**, not an installer engine. It discards `/quiet`, `/silent`,
`/passive`, `/S` and `/qn` alike - the switches never reach anything that
understands them, which is also why `/log` produces no file - and it simply
shows its wizard.

### 5a. Extract the MSI (on the HOST, once)

Needs 7-Zip: <https://www.7-zip.org/>

The payload is **nested**: the `.exe` is a PE whose resource section holds a
7z archive, which in turn holds the MSIs. Recent 7-Zip versions unwrap both
layers in one pass; older ones leave the inner archive as a file. So extract,
then **list what you actually got** rather than assuming either outcome.

> **Extract to a path with NO SPACES.** 7-Zip's `-o` switch does not tolerate
> an unquoted path containing spaces: it takes the first word as the output
> directory and treats the rest as a *file filter*, matches nothing, and
> reports `No files to process` / `Files: 0` while still exiting
> `Everything is Ok`. A short temporary path sidesteps it entirely.

```powershell
$7z  = "C:\Program Files\7-Zip\7z.exe"
$exe = "C:\path\to\Eraser 6.2.0.2996.exe"
$tmp = "C:\eraser_extract"          # deliberately no spaces

& $7z x $exe "-o$tmp" -y
```

**Read the summary line.** `Files: 2` with a `Size:` of tens of MB means both
layers were unwrapped and the MSIs are already on disk. `Files: 0` means a
filter matched nothing - check the `-o` quoting above.

Now list the result:

```powershell
Get-ChildItem $tmp -Recurse -File |
  Select-Object FullName, @{n='MB';e={[math]::Round($_.Length/1MB,1)}} |
  Sort-Object MB -Descending
```

**If you see `.msi` files**, you are done - skip to the copy step below.

**If instead you see a single large extensionless file** such as
`.rsrc\1024\RCDATA\101`, your 7-Zip left the inner archive intact. Extract
that one too:

```powershell
$inner = Get-ChildItem $tmp -Recurse -File |
         Sort-Object Length -Descending | Select-Object -First 1
& $7z x $inner.FullName "-o$tmp\inner" -y
Get-ChildItem "$tmp\inner" -Recurse -Filter *.msi | Select-Object FullName, Length
```

Copy the x64 MSI to the staging folder under the canonical name:

```powershell
$staging = "C:\path\to\iso_staging\eraser"
New-Item -ItemType Directory -Force -Path $staging | Out-Null

# Search the whole extraction tree, so this works whether the MSIs landed in
# one pass or two.
$msi = Get-ChildItem $tmp -Recurse -Filter *.msi |
       Where-Object Name -match 'x64|64' |
       Select-Object -First 1
if (-not $msi) { throw "no x64 MSI found under $tmp - list the tree and check" }
Write-Host "using $($msi.FullName)"
Copy-Item $msi.FullName -Destination "$staging\eraser-x64.msi" -Force

# Drop the wrapper - it is no longer staged.
Remove-Item "$staging\Eraser*.exe" -ErrorAction SilentlyContinue
Get-ChildItem $staging
```

> **Check `Files:` in 7-Zip's summary, not just "Everything is Ok".** 7-Zip
> exits successfully having extracted nothing when a filter matches no
> members. `Files: 0` means the command did nothing.

Then rebuild the ISO (section 2.9) and re-run `check_installers.py`.

**If the nested archive will not open**, fall back on the fact that a
bootstrapper extracts its payload to `%TEMP%` before showing UI. Launch the
installer, and *while the wizard is on screen*:

```powershell
Get-ChildItem $env:TEMP -Recurse -Filter *.msi -ErrorAction SilentlyContinue |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 5 FullName, Length, LastWriteTime
```

Copy the MSI out, then cancel the wizard.

### 5b. Silent install from the MSI (in the guest)

```powershell
msiexec /i "E:\eraser\eraser-x64.msi" /qn /norestart
Start-Sleep -Seconds 20
Write-Host "exit code: $LASTEXITCODE"

Test-Path "C:\Program Files\Eraser\Eraser.exe"
```

`msiexec` exit codes worth knowing: `0` success, `3010` success but a reboot
is pending (harmless here), `1603` fatal error, `1619` the package could not
be opened (wrong path).

If it fails, log it - and unlike the wrapper, an MSI really does log:

```powershell
msiexec /i "E:\eraser\eraser-x64.msi" /qn /norestart /l*v C:\eraser_msi.log
Select-String -Path C:\eraser_msi.log -Pattern "return value 3" -Context 6,2 |
  Select-Object -First 3
```

> `return value 3` marks the action that actually failed; the lines before it
> name the cause. That is the standard way to read an MSI log.

### 5c. Wipe syntax - confirmed from `Eraser.exe help`

Four things differ from the obvious guess, and **each one alone** produces
`Tasks must contain at least one erasure target`:

| | Wrong | Right |
|---|---|---|
| Switch prefix | `--method=` | **`/method=`** - single forward slash |
| File target | `file --file="path"` or a bare path | **`"file=path"`** - one token |
| Case | `/Method=`, `FILE=` | arguments are **case sensitive** |
| Console | omitted | **`/quiet`** or it waits on a keypress |

`erase` is simpler than `addtask /schedule=now` - the help states they are
equivalent.

**Use method GUIDs, not names.** Several names contain spaces and parentheses
("Pseudorandom Data", "US DoD 5220.22-M (8-306./E, C & E)") which would need
quoting inside an already-quoted command. GUIDs are also stable across
locales:

| Method | GUID |
|---|---|
| Gutmann | `1407fc4e-feff-4375-b4fb-d7efbb7e9922` |
| Pseudorandom Data | `bf8ba267-231a-4085-9bf9-204de65a6641` |
| US DoD 5220.22-M (8-306./E, C & E) | `d1583631-702e-4dbf-a0e9-c35dba481702` |
| Schneier 7 pass | `b1bfab4a-31d3-43a5-914c-e9892c78afd8` |
| British HMG IS5 (Enhanced) | `45671da4-9401-46e4-9c0d-89b94e89c8b5` |

Run `Eraser.exe help` for the full list. Methods marked `U` can also erase
unused disk space.

Test it, polling rather than waiting a fixed interval:

```powershell
$eraser = "C:\Program Files\Eraser\Eraser.exe"
$f = New-TestFile "eraser_g.bin"

$sw = [Diagnostics.Stopwatch]::StartNew()
& $eraser erase /quiet /method=1407fc4e-feff-4375-b4fb-d7efbb7e9922 "file=$f"
Write-Host "exit code: $LASTEXITCODE"

# Eraser queues through a background service, so the call returns long
# before the file is gone. Poll for up to two minutes.
for ($i = 0; $i -lt 24; $i++) {
    if (-not (Test-Path -LiteralPath $f)) { break }
    Start-Sleep -Seconds 5
}
$sw.Stop()
Test-Gone $f
Write-Host "elapsed: $([int]$sw.Elapsed.TotalSeconds)s"
```

> **If `/quiet` placement is rejected**, try it before the action
> (`& $eraser /quiet erase ...`). The help lists it under "global
> parameters" separately from the per-action parameters, so either position
> may be accepted.

> **Exit code 0 means nothing here.** Your first attempt returned 0 while
> creating no task at all. Eraser queues asynchronously, so a successful
> return says nothing about whether anything was erased. Judge only by
> whether the file disappeared - which is exactly why `manifest.json`
> records which target paths survived each run.

**Record the elapsed time.** It sets `vm.settle_seconds`:

> If Eraser needs 60s for one file, the harness must wait longer than that
> after the last target before the host cuts power. Otherwise the journals
> are truncated mid-wipe and the run captures a partial signature - worse
> than a failed run, because it looks valid.

Then the pseudorandom mode:

```powershell
$f = New-TestFile "eraser_p.bin"
& $eraser erase /quiet /method=bf8ba267-231a-4085-9bf9-204de65a6641 "file=$f"
for ($i = 0; $i -lt 24; $i++) {
    if (-not (Test-Path -LiteralPath $f)) { break }
    Start-Sleep -Seconds 5
}
Test-Gone $f
```

**If the file still never disappears**, check whether the Eraser service is
running - it does the actual work:

```powershell
Get-Service -Name Eraser* | Select-Object Name, Status, StartType
Get-EventLog -LogName Application -Source Eraser* -Newest 10 -ErrorAction SilentlyContinue |
  Select-Object TimeGenerated, EntryType, Message
```

---

## 6. CCleaner - tested and EXCLUDED (no wipe CLI)

```powershell
E:\ccleaner\ccleaner-offline-setup.exe /S
Start-Sleep -Seconds 20
```

**`/S` works.** The GUI that appears afterwards is CCleaner itself
auto-launching, not the installer still waiting - a Desktop shortcut
appearing is the giveaway that something installed successfully.

**The install path is not where you would guess.** Confirmed by reading the
uninstall registry:

```
C:\Program Files\Piriform\CCleaner 7\CCleaner.exe
```

Three surprises in one path: a `Piriform` vendor subfolder, the **major
version in the folder name**, and the binary being `CCleaner.exe` rather than
`CCleaner64.exe` despite being a 64-bit build.

> **The version in the folder name makes this brittle.** It is stable for
> this matrix because the baseline pins one offline installer and Windows
> Update is disabled - but re-verify it if you ever restage CCleaner, and
> record the exact version in your report.

Find it yourself rather than trusting the above:

```powershell
# Dot-sourcing loads the file into THIS session, which the execution policy
# blocks by default. -ExecutionPolicy Bypass only applies when launching a
# script with -File, so relax it for this process first. Process scope
# reverts when the window closes and leaves the baseline unchanged.
Set-ExecutionPolicy -Scope Process Bypass -Force

. .\diagnose_tool.ps1
Find-InstalledProgram "CCleaner"
```

Or skip the script entirely and paste this directly - no file, no policy
change:

```powershell
$name = "CCleaner"

Write-Host "`n-- uninstall registry --"
Get-ItemProperty @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
) -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName -like "*$name*" } |
  Select-Object DisplayName, DisplayVersion, InstallLocation | Format-List

Write-Host "-- shortcut targets --"
$ws = New-Object -ComObject WScript.Shell
@("$env:PUBLIC\Desktop", "$env:USERPROFILE\Desktop",
  "$env:ProgramData\Microsoft\Windows\Start Menu\Programs") |
  Where-Object { Test-Path $_ } |
  ForEach-Object { Get-ChildItem $_ -Filter "*$name*.lnk" -Recurse -ErrorAction SilentlyContinue } |
  ForEach-Object {
    $tp = $ws.CreateShortcut($_.FullName).TargetPath
    Write-Host ("  {0} -> {1}  exists={2}" -f $_.Name, $tp, (Test-Path $tp))
  }

Write-Host "`n-- executables on disk --"
@("C:\Program Files", "C:\Program Files (x86)", "$env:LOCALAPPDATA\Programs") |
  Where-Object { Test-Path $_ } |
  ForEach-Object { Get-ChildItem $_ -Filter "*$name*.exe" -Recurse -Depth 3 -ErrorAction SilentlyContinue } |
  Select-Object -First 15 FullName, Length
```

That checks three sources in order of reliability: the **uninstall registry**
(authoritative, and gives the version), **shortcut targets** resolved to their
real paths, and a filesystem sweep. It also reports each binary's
architecture, and lists every `.exe` in the install directory - which is how
you find the right executable name rather than guessing `CCleaner64.exe`.

Quick version if you only want the shortcut target:

```powershell
$ws = New-Object -ComObject WScript.Shell
Get-ChildItem "$env:PUBLIC\Desktop","$env:USERPROFILE\Desktop" -Filter "*CCleaner*.lnk" |
  ForEach-Object { $ws.CreateShortcut($_.FullName).TargetPath }
```

Update `config.yaml` to whatever path that reports.

> **If the GUI that appeared was CCleaner itself rather than its installer**,
> the silent switch worked and the application simply auto-launched after
> installing. Check whether a setup wizard is still waiting, or whether it is
> the finished product. Only the former is a problem.

> **If the uninstall registry has no CCleaner entry**, the install genuinely
> did not complete - and the most likely cause is that this is still the
> **online** installer. Re-check the filename: anything containing `online`
> is a downloader stub (section 1.5).

> **CCleaner installs a background service and network components.** The
> install directory also contains `CCleaner_service.exe`, `wa_3rd_party_host_32/64.exe`
> and `webview2_check.exe`. The service runs continuously and the others can
> phone home, so the ccleaner runs will carry filesystem and network activity
> the other tools do not. That is genuinely part of installing CCleaner, so it
> belongs in the data - but see the network-adapter note below, and record it
> in the limitations.

### Free-space wipe

```powershell
$cc = "C:\Program Files\Piriform\CCleaner 7\CCleaner.exe"

1..5 | ForEach-Object { New-TestFile "cc_$_.bin" 128 | Out-Null }
Remove-Item -Path "D:\t\*" -Force -Recurse

$before = (Get-Volume -DriveLetter D).SizeRemaining
$elapsed = Measure-Command { & $cc /DRIVE D: /WIPEFREESPACE }
$after = (Get-Volume -DriveLetter D).SizeRemaining

Write-Host ("elapsed : {0:n1} s" -f $elapsed.TotalSeconds)
Write-Host ("free before : {0:n0}" -f $before)
Write-Host ("free after  : {0:n0}" -f $after)
Write-Host ("changed     : {0}" -f ($before -ne $after))
```

> **`$LASTEXITCODE` is not evidence here.** If the command cannot even be
> found, PowerShell raises a `CommandNotFoundException` and leaves
> `$LASTEXITCODE` holding its *previous* value - so it can read `0` for a
> command that never ran. Judge by elapsed time and free space only.

**Interpreting the result:**

| Observation | Meaning |
|---|---|
| Runs for minutes, free space dips then recovers | `/WIPEFREESPACE` works - keep it |
| Returns in under a second, free space unchanged | switches accepted and ignored, or CCleaner opened its GUI |
| GUI appears | no CLI support for this operation |

**RESULT ON CCLEANER 7.12: it does nothing.** The process returns in 0.0 s
and free space is byte-identical before and after. The switches are accepted
without complaint and ignored.

`ccleaner` is therefore **disabled** in `config.yaml`:

```yaml
  ccleaner:
    enabled: false
    disabled_reason: |
      No CLI for secure deletion or free-space wiping...
```

`py runner.py --list` prints disabled tools and their reasons beneath the
matrix, so the exclusion stays visible rather than being forgotten. To
re-test without editing the file:

```bat
py runner.py --tool ccleaner --mode wipefree --limit 1 -v
```

> **Why not use `/AUTO` instead.** CCleaner's `/AUTO` does run the standard
> cleaner, and secure deletion can be enabled through
> `HKCU\Software\Piriform\CCleaner`. But the cleaner works from CCleaner's
> own list of locations on the **system volume** - temp directories, browser
> caches - not the evidence volume this harness images. It cannot produce a
> wiping signature on D: however it is configured, so it would cost six runs
> and yield nothing measurable.

**Record this in the report as a finding, not a gap:**

> CCleaner 7.12 exposes no command-line interface for secure deletion or
> free-space wiping; its Drive Wiper is GUI-only. It was therefore excluded
> from the automated matrix.

That inference is useful to an examiner in its own right: a GUI-only wiper
implies an interactive user at the keyboard rather than a script, which
narrows how the tool could have been run on a suspect system.

`config.yaml` now carries `enabled: false` and this reason for CCleaner.
With BCWipe also excluded (section 7) the matrix is **60 runs**.

---

## 6b. Disconnect the VM's network adapter

Worth doing before the matrix, prompted by CCleaner's network components but
useful for every tool:

**In Workstation: VM Settings > Network Adapter > untick "Connect at power
on"**, with the VM powered off. Or in the `.vmx`:

```
ethernet0.startConnected = "FALSE"
```

**The harness does not need the network.** VMware guest operations travel over
the VMX backdoor channel through VMware Tools, not TCP/IP, so `vmrun` keeps
working on a VM with no connectivity. Installers come from the ISO.

What this buys:

- **No telemetry or update traffic** from CCleaner's service, Defender, or
  anything else, so none of it lands in the journals.
- **No DNS, HTTP or browser-cache artefacts** to confound the measurement.
- **An online installer fails loudly** instead of silently fetching a
  different version mid-matrix - the reproducibility risk from section 1.5.
- **Deterministic runs**: nothing can change between run 1 and run 60 because
  something downloaded an update.

Declare it: a real endpoint is usually networked, and some wiping tools might
behave differently with connectivity.

---

## 7. BCWipe - tested and EXCLUDED (errors are modal dialogs)

`/VERYSILENT` is rejected: this is **not** an Inno Setup installer. Running it
with an unrecognised switch makes it print its usage, which is the
authoritative list:

| Switch | Effect |
|---|---|
| `-S` | silent setup with default values |
| `-H` | hidden and silent - use if a window still appears with `-S` |
| `-Z` | **treat zero exit code as success** - see the warning below |
| `-T` | force make trusted publisher for the BCBUS driver |
| `-A` | skip checking of Administrator Privileges |
| `-P "folder"` / `-G "group"` | install and Start Menu folders |
| `-NoPrivacyGuard` / `-NoSwapFile` | skip optional components |
| `-U` | uninstall |

> ### `-Z` is not optional
>
> The installer's own help states that **without** `-Z` the exit code is
> inverted: *"exit code 0 - error, 1 - success"*. The harness records
> `install_exit` in `manifest.json` for every run, so omitting `-Z` would
> record every successful BCWipe install as a failure and every failure as a
> success - silently inverting the one field that says whether the tool was
> installed at all.
>
> With `-Z`: `0` success, `1` error, and **`2` or `3` mean success but a
> reboot is required**.

> ### `-T` prevents a blocking dialog
>
> BCWipe installs the **BCBUS kernel driver**. Without the publisher being
> trusted, Windows raises a driver-installation consent dialog - which blocks
> an unattended run exactly as BleachBit's missing-DLL dialog did.

Install:

```powershell
E:\bcwipe\bcwipe-setup.exe -S -Z -T -NoPrivacyGuard -NoSwapFile
Start-Sleep -Seconds 30
Write-Host "exit code: $LASTEXITCODE   (with -Z: 0=success, 1=error, 2/3=success+reboot)"
```

If a window still appears, swap `-S` for `-H`.

> **If the exit code is 2 or 3, the driver needs a reboot.** That matters: a
> wipe attempted before the driver loads may silently do nothing. Reboot the
> guest and re-test. If BCWipe genuinely requires a reboot after install,
> the harness cannot drive it in a single run as currently designed - note
> that and consider disabling the tool, as with CCleaner.

Find the binary - do not guess the path:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force   # if not already done
. .\diagnose_tool.ps1
Find-InstalledProgram "BCWipe"
```

Check the driver actually loaded:

```powershell
Get-Service | Where-Object { $_.Name -match 'bc|jetico' } |
  Select-Object Name, DisplayName, Status, StartType
Get-CimInstance Win32_SystemDriver |
  Where-Object { $_.Name -match 'bcbus|bcwipe' } |
  Select-Object Name, State, Started, PathName
```

**Confirmed install path** (32-bit build, so `Program Files (x86)`):

```
C:\Program Files (x86)\Jetico\BCWipe\BCWipe.exe
```

The directory also holds `BCWipeSvc.exe` (a service), `BCWipeGUI.exe` and
`BCWipeTM.exe` (task manager). Only `BCWipe.exe` is the command-line tool.

### The blocking problem: BCWipe reports errors as modal dialogs

`BCWipe.exe -help` produces a **message box** reading
*"Invalid wiping type 'help'"* - not console output. Two consequences:

**1. The error tells us `-help` is not a switch**, and that the parser read
`help` as a wiping-type value. The real syntax is something else.

**2. Far more seriously, every CLI error becomes a modal dialog.** In an
unattended run nothing dismisses it, so the step blocks until the harness
times out and kills the process tree - wasting that run, and potentially one
per target.

> **The dialog suppression added for BleachBit does not help here.**
> `ErrorMode=2` sets `SEM_FAILCRITICALERRORS`, which governs dialogs Windows
> raises *on a process's behalf* - missing DLL, device not ready, unhandled
> crash. It does not suppress a dialog the application creates itself by
> calling `MessageBox()`, which is exactly what BCWipe does. The only
> backstop is the per-step timeout.

A tool that works correctly raises no dialog, so this is survivable **if** the
syntax is exactly right every time. But a single mistyped argument, an
expired trial, or an unreadable file would each produce a blocking dialog
mid-matrix.

### One cheap attempt before deciding

Look for documentation shipped with the product - cheaper than guessing when
each wrong guess costs a dialog to dismiss:

```powershell
$dir = "C:\Program Files (x86)\Jetico\BCWipe"
Get-ChildItem $dir -Recurse -Include *.chm,*.pdf,*.txt,*.htm,*.html,*.rtf -ErrorAction SilentlyContinue |
  Select-Object FullName, Length
```

Check whether the binary carries embedded usage text:

```powershell
$s = Select-String -Path "$dir\BCWipe.exe" -Pattern 'usage|Usage|-md|wiping type' `
     -Encoding unicode -AllMatches -ErrorAction SilentlyContinue
$s | Select-Object -First 20 | ForEach-Object { $_.Line.Trim() }
```

And try the two most likely help forms, dismissing any dialog that appears:

```powershell
& $bc /?
```

```powershell
& $bc
```

### Decision - applied

**BCWipe is disabled in `config.yaml`.** The syntax could not be confirmed
without a dialog per guess, and the dialog behaviour is itself a legitimate,
reportable reason. The entry now reads:

```yaml
  bcwipe:
    enabled: false
    disabled_reason: |
      BCWipe 7.60 reports command-line errors through modal GUI dialogs
      rather than console output or exit codes. Any malformed argument,
      expired trial or unreadable target would block an unattended run until
      the harness timeout killed it. Its CLI syntax is also undocumented in
      the shipped files. Excluded as unsafe to automate.
```

The matrix is therefore **60 runs, about 9-10 hours**: five tools with seven
modes plus three controls - still including the BleachBit version
pair, which is the comparison the project depends on.

> **This is a finding, like CCleaner's.** Two of six candidate tools proved
> unsuitable for automation, for different reasons: one has no CLI for the
> operation at all, the other has a CLI that communicates failure only to a
> human. Both observations matter to an examiner reasoning about how a tool
> was actually run on a suspect machine.

---

## 8. Controls — no install, must still be checked

These define your false-positive baseline, so verify they behave as intended.

**Ordinary delete:**

```powershell
$f = New-TestFile "ctrl_del.bin"
Remove-Item -LiteralPath "$f" -Force
Test-Gone $f
```

**Recycle bin:**

```powershell
1..3 | ForEach-Object { New-TestFile "ctrl_rec_$_.bin" 64 | Out-Null }

Add-Type -AssemblyName Microsoft.VisualBasic
Get-ChildItem -Path "D:\t" -File | Select-Object -First 3 | ForEach-Object {
  [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile(
    $_.FullName, 'OnlyErrorDialogs', 'SendToRecycleBin')
}
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

Get-ChildItem D:\t
```

> **Check this one carefully.** A recycle bin on a *data* volume behaves
> differently from one on the system volume, and `Clear-RecycleBin` may not
> target D: as expected. If files vanish without passing through
> `D:\$Recycle.Bin`, this mode is really a second ordinary-delete control —
> worth knowing, and worth saying in the report.

**Benign rename churn** — the key confounder:

```powershell
1..5 | ForEach-Object { New-TestFile "ctrl_churn_$_.bin" 64 | Out-Null }

$files = Get-ChildItem -Path "D:\t" -File | Select-Object -First 5
foreach ($f in $files) {
  $tmp = Join-Path $f.DirectoryName ("~$" + [guid]::NewGuid().ToString("N").Substring(0,8) + ".tmp")
  Rename-Item -LiteralPath $f.FullName -NewName (Split-Path $tmp -Leaf)
  Start-Sleep -Milliseconds 20
  Rename-Item -LiteralPath $tmp -NewName $f.Name
}

Get-ChildItem D:\t | Select-Object Name
```

**Record:** all five files should still exist under their original names. This
run must generate rename traffic *without* deleting anything — that is what
makes it a false-positive probe.

---

## 9. Results table

Results from the manual testing, as applied to `config.yaml`. The control
rows are still yours to fill in (section 8).

| Tool | Install | Binary (confirmed) | Wipe verified by | Result |
|---|---|---|---|---|
| sdelete p1 / p3 | portable | `E:\sdelete\sdelete64.exe` | test file gone | **in matrix** |
| cipher freespace | built in | `cipher.exe` | runs to completion; scrubs free space only, by design | **in matrix** |
| bleachbit6 | `/allusers /S` (`/S` alone shows wizard) | `C:\Program Files (x86)\BleachBit\bleachbit_console.exe` | test file gone | **in matrix** |
| bleachbit4 | `/allusers /S`; needs VC++ 2010 x86 (baseline step 8) | same as above | test file gone | **in matrix** |
| eraser gutmann / pseudorandom | MSI extracted from wrapper, `msiexec /i ... /qn /norestart` | `C:\Program Files\Eraser\Eraser.exe` | test file gone after a delay (asynchronous) | **in matrix** |
| ccleaner | `/S` (GUI afterwards is the app auto-launching) | `C:\Program Files\Piriform\CCleaner 7\CCleaner.exe` | `/DRIVE /WIPEFREESPACE`: 0.0 s, free space unchanged | **excluded** - no wipe CLI |
| bcwipe | `-S -Z -T -NoPrivacyGuard -NoSwapFile` | `C:\Program Files (x86)\Jetico\BCWipe\BCWipe.exe` | not reached - CLI errors are modal dialogs | **excluded** - unsafe unattended |
| control_delete explorer | n/a | n/a | | *to check* |
| control_delete recycle | n/a | n/a | used `D:\$Recycle.Bin`? | *to check* |
| control_churn | n/a | n/a | all files must still exist | *to check* |

---

## 10. Finish up

Revert to `clean` so the baseline carries no trace of this testing:

```powershell
& $vmrun -T ws -vp $vp stop $vmx hard
& $vmrun -T ws -vp $vp revertToSnapshot $vmx clean
```

Rebuild the installer ISO if anything in it changed (README 2.9), validate
the staging folder, and check the host side:

```bat
py tools\check_installers.py --staging C:\iso_staging
py runner.py --check
py runner.py --list
```

`--list` should show 60 runs and the two disabled tools with their reasons.

### One harness run per tool before the matrix

Your manual tests ran each command in PowerShell; the harness runs it through
`cmd.exe` inside the agent, adds a binary check, and (for Eraser) waits for
the targets to disappear. Prove that path once per tool - each takes about
nine minutes:

```bat
py runner.py --tool sdelete    --mode p1           --limit 1 -v
py runner.py --tool cipher                         --limit 1 -v
py runner.py --tool bleachbit6                     --limit 1 -v
py runner.py --tool bleachbit4                     --limit 1 -v
py runner.py --tool eraser     --mode pseudorandom --limit 1 -v
py runner.py --tool control_churn                  --limit 1 -v
```

For each, open `runs\<run_id>\` and confirm:

- `status.json` has `"result": "ok"`.
- `guest.log` shows `binary present after ...s` (installed tools) and, for
  Eraser, `all targets gone after ...s`. Note that figure: if it is close to
  900, raise `await_targets_sec` for Eraser before running Gutmann mode, which
  is far slower.
- `manifest.json` has 40 `targets` and an empty `surviving_paths` - except
  `control_churn`, where all 40 must survive.
- `evidence\` holds the three carved journals.

A run that fails with **"no target was removed"** means the wipe command
never took effect inside the harness even though it worked by hand; the
first per-file exit code is in the message and `guest.log`. Then start the
full matrix:

```bat
py runner.py --all
```
