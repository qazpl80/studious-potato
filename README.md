# WiperTrace data-generation harness — VMware Workstation on Windows

Generates the labelled dataset WiperTrace is evaluated against. No public
corpus of wiper-attributed NTFS volumes exists, so we synthesise one: execute
a known wiping tool against a known set of files inside a VM, carve the NTFS
journals from a cold image, and retain the answer key.

**Host assumed:** Windows PC with VMware Workstation Pro and Python already
installed.

| | |
|---|---|
| Matrix | 60 runs (5 wiping tools + 2 controls), ~9-10 hours unattended |
| Baseline VM | 32 GB + 2 GB declared, **~15 GB actually consumed** on LTSC (~21 GB on a consumer Windows 11 build) |
| Peak host usage | ~20 GB (VM + snapshot deltas + 2 GB flatten scratch); ~26 GB on a consumer build |
| Dataset output | a few hundred MB across all 60 runs (gzipped) |

```
config.yaml                 tool matrix, paths, experimental variables
runner.py                   host orchestrator (six stages per run)
vmware.py                   vmrun wrapper, .vmx disk resolution, VMDK flattening
extract.py                  cold NTFS carving via The Sleuth Kit
guest/prepare_baseline.ps1  one-time baseline prep, run inside the VM
guest/run_wipe.ps1          per-run agent: ground truth, install, wipe, collect
parse/parse_runs.py         parses evidence into a labelled dataset
tests/make_fixtures.py      exercises the labelling join with no VM required
```

---

# Part 1 — Host prerequisites

### 1.0 What runs where

Everything in this Part is done **on the host PC**. Nothing in it is
installed inside the VM.

| Component | Lives on | Installed by |
|---|---|---|
| Python + PyYAML | **host** | you, once |
| The Sleuth Kit | **host** | you, once (portable) |
| EZ Tools + .NET 9 Desktop Runtime | **host** | you, once |
| This harness (`runner.py` etc.) | **host** | — |
| Windows 11 ISO | downloaded on host | installs the guest |
| Wiping tool installers | **downloaded on host**, burned to ISO | the harness, inside the guest, per run |
| VMware Tools | guest | you, once (step 2.5) |
| `prepare_baseline.ps1` | guest | you copy it in and run once (step 2.6) |
| `run_wipe.ps1` | guest | the harness copies it in every run |

> **The analysis tooling must stay on the host.** Never install The Sleuth
> Kit or EZ Tools inside the VM. They would write their own executables,
> Prefetch entries and registry keys into the volume being measured, and the
> whole point of Stage 6's cold extraction is that analysis happens outside
> the evidence. The wiping tools are the deliberate exception: they belong in
> the guest, which is what the experiment is about.

Workstation being installed already satisfies the disk-flattening dependency
(`vmware-vdiskmanager.exe` ships with it), so `qemu_img` stays `null`. Four
things remain.

### 1.1 Python: add PyYAML

A Windows PC often has more than one Python — an Anaconda base environment, a
python.org install reached via the `py` launcher, and possibly a Store build.
`pip install` targets whichever one is first on PATH, which is frequently not
the one you later run the harness with. That mismatch produces exactly this:

```
ModuleNotFoundError: No module named 'yaml'
```

**Fix: pick one interpreter and install into it by name**, using
`<interpreter> -m pip` so pip cannot target a different install:

```bat
rem Decide which Python you will use, and confirm which one it is:
py -c "import sys; print(sys.executable)"
python -c "import sys; print(sys.executable)"
```

Then install into that same command:

```bat
py -m pip install pyyaml
py -c "import yaml, sys; print('pyyaml', yaml.__version__, '|', sys.executable)"
```

If you prefer Anaconda, open **Anaconda Prompt** and use `python` throughout:

```bat
python -m pip install pyyaml
python -c "import yaml, sys; print('pyyaml', yaml.__version__, '|', sys.executable)"
```

**Whichever command you used, use that same one for every harness command in
Parts 3-7.** This README writes `py` throughout; substitute `python` if that
is the interpreter you installed PyYAML into. Do not mix them - the two
`sys.executable` values printed above must match, or you are looking at two
different Pythons.

> **Always name the interpreter; never run `.\runner.py` directly.** On most
> Windows installs `.py` is associated with an editor rather than the Python
> launcher, so `.\runner.py --show-disks` silently *opens the file* instead of
> executing it - typically launching VS Code and printing pages of unrelated
> startup logs, with no error indicating what went wrong. Always write
> `py runner.py --show-disks`.

> **Keep the harness files together.** `runner.py` imports `vmware.py` and
> `extract.py` as siblings and reads `config.yaml`, `guest\`, `parse\` and
> `tools\` by relative path. Extract the whole `wipertrace-vmware` folder from
> the archive rather than copying individual files, and run the harness from
> inside it. Verify with:
>
> ```powershell
> 'runner.py','vmware.py','extract.py','config.yaml','guest\run_wipe.ps1',
> 'guest\prepare_baseline.ps1','parse\parse_runs.py','tools\check_installers.py' |
>   ForEach-Object { "{0,-34} {1}" -f $_, $(if (Test-Path $_) { 'OK' } else { 'MISSING' }) }
> ```

Nothing else is needed; the harness uses only the standard library plus
PyYAML.

### 1.2 The Sleuth Kit — carves the journals

**There is no installer.** TSK ships as a zip of portable executables: you
extract it and point the config at the folder.

1. Go to **<https://github.com/sleuthkit/sleuthkit/releases>** (current
   release 4.15.0).
2. Under **Assets**, download the Windows zip — the one with `win32` in the
   filename, e.g. `sleuthkit-4.15.0-win32.zip`. Despite the name it contains
   64-bit binaries. (If GitHub's assets don't expand, the
   [SourceForge mirror](https://sourceforge.net/projects/sleuthkit/files/sleuthkit/)
   carries the same files.)
3. Extract to `C:\tools\sleuthkit`. Use **7-Zip**, not Explorer's built-in
   extractor — see the note in 1.3 about blocked DLLs.
4. Find the folder containing `icat.exe`. It is usually `bin\`, so:

```
C:\tools\sleuthkit\bin\mmls.exe
C:\tools\sleuthkit\bin\fls.exe
C:\tools\sleuthkit\bin\istat.exe
C:\tools\sleuthkit\bin\icat.exe
```

5. Verify, then set `paths.tsk_bin` to whatever that folder actually is:

```bat
C:\tools\sleuthkit\bin\mmls.exe -V
```

No PATH changes are needed — the harness invokes these by absolute path.
`py runner.py --check` confirms all four are found.

### 1.3 Eric Zimmerman's tools — parse the journals into CSV

Needed by `parse/parse_runs.py`, not by capture, so this can wait until you
have runs on disk. Also portable — no installer — but it has one real
prerequisite.

**First, install the .NET 9 Desktop Runtime.** EZ Tools now default to .NET 9
builds and will not start without it:

<https://dotnet.microsoft.com/en-us/download/dotnet/9.0> → **Desktop
Runtime**, x64. Install the *Desktop* runtime, not the plain one.

**Then fetch the tools.** Paste this whole block into PowerShell. It does not
depend on your current directory, which is the usual cause of
*"The argument '.\Get-ZimmermanTools.ps1' to the -File parameter does not
exist"*:

```powershell
$ezt = 'C:\tools\ezt'
$zip = Join-Path $ezt 'Get-ZimmermanTools.zip'
New-Item -ItemType Directory -Force -Path $ezt | Out-Null

Invoke-WebRequest -Uri 'https://download.ericzimmermanstools.com/Get-ZimmermanTools.zip' `
                  -OutFile $zip -UseBasicParsing

# Clear mark-of-the-web BEFORE extracting: a zip carrying a Zone.Identifier
# stream propagates it to the extracted files, and .NET then refuses to load
# the tools' DLLs with an opaque error much later.
Unblock-File -LiteralPath $zip
Expand-Archive -LiteralPath $zip -DestinationPath $ezt -Force

# Locate the script wherever the archive put it rather than assuming a path.
$script = Get-ChildItem -LiteralPath $ezt -Recurse -Filter 'Get-ZimmermanTools.ps1' |
          Select-Object -First 1 -ExpandProperty FullName
if (-not $script) { throw "Get-ZimmermanTools.ps1 not found under $ezt" }
Write-Host "running: $script"

& $script -Dest $ezt

# The tools themselves are downloaded from the internet, so clear MOTW again.
Get-ChildItem -LiteralPath $ezt -Recurse -Include *.exe, *.dll |
    Unblock-File -ErrorAction SilentlyContinue

# Print the two paths needed for config.yaml.
Get-ChildItem -LiteralPath $ezt -Recurse -Include MFTECmd.exe, PECmd.exe |
    Select-Object -ExpandProperty FullName
```

`Unblock-File` here replaces the usual advice to extract with 7-Zip: it
strips the same alternate data stream, and unlike a manual extraction it is
reproducible.

`-NetVersion` defaults to `9`. Pass `-NetVersion 4` to `& $script` only if you
cannot install the .NET 9 runtime; those builds are legacy and no longer
updated.

The final command prints the paths to set as `paths.mftecmd` and
`paths.pecmd` — they usually sit in a `net9` subfolder. Verify one:

```bat
C:\tools\ezt\net9\MFTECmd.exe --help
```

**If the block fails**, run each part separately. The most common causes are
an execution-policy block (prefix with
`Set-ExecutionPolicy -Scope Process Bypass -Force`), a proxy intercepting
`Invoke-WebRequest`, or antivirus removing the tools as they download.
Worst case, download the zip in a browser and run:

```powershell
Get-ChildItem C:\ -Recurse -Filter Get-ZimmermanTools.ps1 -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty FullName
```

then call that full path directly — `powershell -File "<full path>" -Dest C:\tools\ezt`.

`$LogFile` is collected but **not** parsed by MFTECmd. For that stage use
[dfir_ntfs](https://github.com/msuhanov/dfir_ntfs): `pip install dfir_ntfs`
from the Anaconda Prompt.

### 1.4 Guest OS ISO — does a normal Windows 11 ISO work?

**Yes**, a standard consumer ISO works, and the project does not depend on
any Enterprise-only feature. Two practical frictions and one cost:

- **Use Pro, not Home.** Pro's setup offers *"Set up for work or school"* →
  *"Domain join instead"*, which creates a local account with no registry
  tricks. Home has no such path, and the Shift+F10 workarounds
  (`BypassNRO`, `ms-cxh:localonly`) are build-dependent and being actively
  closed by Microsoft, so relying on one is a gamble on your particular
  build.
- **Skip the product key** — click *"I don't have a product key"*.
  Unactivated Windows shows a watermark and locks personalisation, but every
  filesystem behaviour this project measures works normally.
- **Cost:** roughly **20 GB consumed instead of ~14 GB**, plus inbox apps,
  Store updates and consumer telemetry generating continuous background
  filesystem churn. `prepare_baseline.ps1` disables the services it can, but
  it cannot remove the apps.

Consumer ISO: <https://www.microsoft.com/software-download/windows11>

**Still preferred — Windows 11 IoT Enterprise LTSC Evaluation:**
<https://www.microsoft.com/en-us/evalcenter/download-windows-11-iot-enterprise-ltsc-eval>

LTSC wins on both of your stated goals at once: it installs ~6 GB leaner, it
ships without the Store and inbox apps whose churn is indistinguishable from
tool activity at parse time, and it takes a local account during setup
without any workaround. Free 90-day evaluation, no product key, registration
required.

**Fallback — Windows 11 Enterprise Evaluation:**
<https://www.microsoft.com/en-us/evalcenter/evaluate-windows-11-enterprise>

Whichever you choose, the account you create must have a **non-empty
password** (step 2.4) — the VIX guest-operations API rejects blank-password
authentication outright.

#### If Pro setup demands a Microsoft account

It will. Windows 11 Home and Pro force an MSA sign-in during OOBE, and the
Shift+F10 workarounds (`BypassNRO`, `ms-cxh:localonly`) are build-specific —
Microsoft has closed several and `ms-cxh:localonly` is already dead on recent
builds. Three routes, best first:

**A. Use the IoT Enterprise LTSC evaluation ISO instead.** Enterprise and
LTSC editions offer a local account directly, with no workaround at all. This
is the cleanest fix, and it also gives you the ~6 GB saving and the quieter
journals described above. If you have not already committed to the Pro media,
switch.

**B. Use the supplied answer file — `guest/autounattend.xml`.** An unattend
file is the *supported* mechanism, so unlike the registry tricks it does not
depend on your build. It is included in this repo, pre-filled to match
`config.yaml`, and it solves a second problem at the same time: VIX guest
operations launched with `-interactive` need an active console session, so the
file also configures auto-logon, which makes the harness noticeably more
reliable than a VM sitting at a lock screen.

1. Open `guest/autounattend.xml` and check the three values marked `EDIT`
   against `config.yaml` (`vm.guest_user`, `vm.guest_pass`, time zone). They
   already match the shipped defaults.
2. Put it, named exactly `autounattend.xml`, at the **root of a small ISO**:

   ```bat
   mkdir C:\unattend
   copy guest\autounattend.xml C:\unattend\
   oscdimg -n -m C:\unattend C:\unattend.iso
   ```

   `oscdimg` comes with the Windows ADK; ImgBurn or PowerISO work equally
   well. (A floppy image also works, but a second CD drive is simpler.)
3. In VM Settings, add a **second CD/DVD drive** pointing at `unattend.iso`,
   leaving the Windows installer on the first. Setup searches every attached
   removable device for `autounattend.xml`.
4. Install as normal. Setup still prompts for language, edition and target
   disk — deliberately, so you pick the disk yourself — then OOBE completes
   with no account prompt.
5. **After taking the `clean` snapshot, detach that second CD drive**, so the
   answer file is not present during the experiment runs.

   The password sits in plain text in that file. Acceptable for a disposable
   lab VM, but do not reuse a password from elsewhere.

**C. Quick attempt, build-dependent.** Before the first boot, uncheck
*Connect at power on* on the VM's network adapter. With no network, OOBE
usually falls back to offering a local account ("Continue with limited
setup"). If the network screen has no skip option on your build, press
Ctrl+Shift+F3 at the first OOBE screen to enter Audit Mode, then:

```bat
net user analyst Analyst!2026 /add
net localgroup Administrators analyst /add
sysprep /generalize /oobe /shutdown
```

Reconnect the adapter only once setup is complete. Note that `sysprep
/generalize` regenerates machine SIDs, which is harmless here but worth
recording if you document the baseline build precisely.

> I have validated the answer file's structure, namespaces and consistency
> with `config.yaml`, but could not run a Windows install from this
> environment. If Setup ignores it, the usual causes are the filename not
> being exactly `autounattend.xml`, it not being at the ISO root, or the ISO
> not being attached as removable media.

### 1.5 Wiping tools and corpus

Download these **on the host**, then burn them to an ISO (step 2.9). The
harness installs them inside the guest, one per run. **Never download them
inside the VM** — that would add browser, DNS and cache artefacts to every
single run.

| Tool | Link | Note |
|---|---|---|
| SDelete | <https://learn.microsoft.com/en-us/sysinternals/downloads/sdelete> | |
| BleachBit **6.0.4** | <https://www.bleachbit.org/download/windows> | current release |
| BleachBit **4.6.0** | <https://sourceforge.net/projects/bleachbit/files/bleachbit/4.6.0/> | take `BleachBit-4.6.0-setup.exe` |
| Eraser | <https://eraser.heidi.ie/download/> | upstream name contains **spaces** |
| CCleaner Free | <https://www.ccleaner.com/ccleaner/builds> | *optional* - tested and excluded, see Part 4 |
| BCWipe (trial) | <https://www.jetico.com/products/personal-privacy/bcwipe> | *optional* - tested and excluded, see Part 4 |
| `cipher.exe` | already in Windows | |

> **CCleaner and BCWipe are not needed for the matrix.** Both were tested by
> hand and disabled in `config.yaml` (Part 4 explains why), so the harness
> never schedules them and `check_installers.py` reports them as SKIP. Stage
> them only if you want to re-test them with `--tool`. If you do stage
> CCleaner, use the offline installer:
>
> The builds page lists both
> a "Standard online installer" and a separate "CCleaner, offline installer".
> A filename containing **`online`** is a downloader stub and is unusable
> here for two reasons. It needs network access during every install, which
> injects DNS, HTTP and cache artefacts into the volume under study. More
> seriously, it fetches whatever version is current *at install time*, so
> runs executed on different days would install different CCleaner versions
> while all being labelled identically - silently destroying the
> reproducibility the whole dataset rests on.

### Rename each download to a canonical filename

Upstream installer names change with every release and several contain spaces,
so the harness does not track them. Rename each file as you stage the ISO:

```
sdelete\sdelete64.exe
bleachbit\bleachbit-6.0.4-setup.exe
bleachbit\bleachbit-4.6.0-setup.exe
eraser\eraser-x64.msi                    <- EXTRACT from "Eraser 6.2.0.2996.exe" with 7-Zip
vcredist\vcredist_x86.exe                <- baseline prerequisite (BleachBit 4.x)

optional, only to re-test the disabled tools:
ccleaner\ccleaner-offline-setup.exe
bcwipe\bcwipe-setup.exe
```

All lowercase, no spaces. Record each file's real upstream version in your
report; the canonical name deliberately drops it except where two versions
must coexist.

### Validate the staging folder before burning

```bat
py tools\check_installers.py --staging C:\iso_staging
py tools\check_installers.py --staging C:\iso_staging --fix-names
```

The checker reads the install commands out of `config.yaml`, maps `E:\` onto
your staging folder, and reports each file as OK, RENAME, WRONG BUILD or
MISSING. Tools marked `enabled: false` are listed as SKIP and not required
(add `--include-disabled` to check them too). `--fix-names` renames unambiguous near-matches after confirmation.
It will not rename a file that already serves as another entry's canonical
name (so the two BleachBit versions cannot cannibalise each other), and it
refuses to rename a wrong *build* - such as the CCleaner online stub - because
renaming that would hide the problem rather than fix it.

Catching a wrong filename here costs seconds. Catching it during the matrix
costs a run that installs nothing, wipes nothing, and still produces a
complete-looking run folder. The guest agent now also verifies the installer
exists before running it, so such a run fails loudly rather than silently.

**Why two BleachBit versions.** Running one tool at two releases is what
demonstrates whether a signature survives a version bump, rather than being
an artefact of a single build - a portability claim your write-up can make
only with the pair. The bleachbit.org download page offers just the current
release; SourceForge keeps the full archive (4.0.0 onward), so pull the older
build from there.

Your host antivirus may object to SDelete or Eraser. Keep them in a
folder you have excluded, or they will be quarantined before you can build
the ISO.

**Corpus — govdocs1:** <https://digitalcorpora.org/corpora/file-corpora/files/>

Download **one** zip from
`https://downloads.digitalcorpora.org/corpora/files/govdocs1/zipfiles/`
(each holds 1000 files) and extract ~150 of them, ≈100 MB. Real filenames and
sizes matter: both filename length and file size influence rename and
overwrite behaviour, so a corpus of `test001.txt` would bias the signatures.

### 1.6 Confirm the host is ready

```bat
py -c "import yaml; print('pyyaml ok')"
C:\tools\sleuthkit\bin\mmls.exe -V
```

For the two VMware executables, **do not assume the install path.**
Workstation 17 and later install under `C:\Program Files\...`, while older
releases used `C:\Program Files (x86)\...`. Let the harness find them:

```bat
py runner.py --find-vmware
```

This searches PATH, the registry `InstallPath`, and both Program Files trees,
then prints the exact values to paste into `paths.vmrun` and
`paths.vdiskmanager`. If it reports NOT FOUND, search directly:

```bat
where /r "C:\Program Files" vmrun.exe
where /r "C:\Program Files (x86)" vmrun.exe
```

To test vmrun by hand, the invocation differs by shell. **PowerShell** needs
the call operator `&` before a quoted executable path, or it parses the line
as a string expression and reports *"Unexpected token '-T'"*:

```powershell
& "C:\Program Files\VMware\VMware Workstation\vmrun.exe" -T ws list
```

**cmd.exe** takes the quoted path directly, with no `&`:

```bat
"C:\Program Files\VMware\VMware Workstation\vmrun.exe" -T ws list
```

In cmd, a wrong path gives the misleading *"is not recognized as an internal
or external command"*, which means the file is not there rather than that the
quoting is wrong.

A working vmrun prints `Total running VMs: 0` (or lists running VMs).

Once `--find-vmware` and the two commands above all succeed, every host-side
dependency is in place. Part 3's `py runner.py --check` re-verifies them
against your config and now names the correct path when one is misconfigured.

---

# Part 2 — Build the baseline VM (once)

### 2.1 Create the VM

Workstation → **Create a New Virtual Machine** → Custom → point at your ISO.
Windows 11 x64, **4 GB RAM, 2 vCPU**. Workstation enables UEFI and TPM
automatically for a Windows 11 guest; confirm both, because Setup aborts
without them.

### 2.2 Disk 1 — system volume, 32 GB

Set **32 GB**, select **"Store virtual disk as a single file"**, and leave
**"Allocate all disk space now" UNTICKED.**

> **Thin provisioning is why 32 GB is cheap.** The declared size is a ceiling,
> not a reservation — the VMDK grows only as blocks are written. A 32 GB
> declared disk running LTSC with the pagefile and hibernation disabled
> consumes roughly 14–16 GB. Ticking "allocate now" would reserve the full
> 32 GB immediately and defeat the whole point.
>
> 32 GB is comfortably above what Setup needs while leaving room for the
> per-run tool installations.

### 2.3 Disk 2 — evidence volume, 2 GB

VM Settings → Add → Hard Disk → **2 GB**, single file, not pre-allocated.

> **Why the evidence volume is separate, and why 2 GB suffices.**
>
> Flattening a 32 GB system disk 60 times is not tractable. D: carries its own
> `$MFT`, `$LogFile` and `$UsnJrnl` — precisely the structures under study —
> and flattens in well under a minute.
>
> The instinct is that a small volume means small journals, and by default
> that is true: NTFS sizes `$LogFile` as a function of volume size, so a 2 GB
> volume would get a log of only a few MB. `$LogFile` is a **circular
> buffer**, so once it wraps, the oldest records are overwritten — and those
> are exactly where a wipe signature lives.
>
> Step 2.6 removes that coupling by pinning both journals explicitly. A
> 40-file wipe generates roughly **0.8 MB** of `$LogFile` records and
> **0.26 MB** of USN records; pinned at 16 MB each, that is ~20× and ~60×
> headroom. Trace capacity is therefore set by the pinning, not by the disk
> size, and 2 GB is sufficient.
>
> 2 GB also leaves ~1.8 GB free for the free-space wiping modes
> (`cipher /w`, `CCleaner /WIPEFREESPACE`) to scrub. Going below ~1 GB makes
> those modes finish so quickly that their journal activity stops being
> representative — see the limitation in Part 11.

### 2.4 Install Windows

Create a **local** account with a **non-empty password** - the VIX
guest-operations API rejects blank-password authentication outright. Make it a
**local administrator**. The defaults in `config.yaml` are
`analyst` / `Analyst!2026`.

> **Note the VM-encryption password.** Workstation requires a virtual machine
> to be encrypted before it will attach a virtual TPM, and Windows 11 requires
> a TPM - so a Workstation-created Windows 11 guest is normally **encrypted**,
> even if you never asked for encryption. Workstation may prompt for this
> password once and then store it in Windows Credential Manager, so the GUI
> opens the VM without asking while `vmrun` still needs it explicitly.
>
> Record it and put it in `config.yaml`:
>
> ```yaml
> vm:
>   encryption_password: "<the VM encryption password>"
> ```
>
> Without it, every harness operation fails with:
>
> ```
> Error: Cannot open VM: ...\Windows 11 x64.vmx, Incorrect password
> ```
>
> This is **not** the guest account password; it is separate, and both are
> needed. Leave it `null` only if the VM is genuinely unencrypted. The harness
> passes it to `vmrun` as `-vp`.

**Verify the password outside the harness first.** This isolates the password
from any config or code problem:

```powershell
$vmrun = "C:\Program Files\VMware\VMware Workstation\vmrun.exe"
$vmx   = "C:\path\to\Windows 11 x64.vmx"
& $vmrun -T ws -vp "<the password>" listSnapshots $vmx
```

Success prints `Total snapshots: N`. If it still says `Incorrect password`,
the password is wrong - not the config.

**If you do not know the password:**

| Route | How |
|---|---|
| Credential Manager (scripted) | Credential Manager masks Windows Credentials in its UI and `cmdkey /list` shows only target names, so read the secret back with the bundled helper: `powershell -ExecutionPolicy Bypass -File .\tools\read_vm_password.ps1`. It enumerates the current user's credentials via the Win32 `CredEnumerate` API and prints any target matching `VMware`, so you need not guess the exact target string. |
| Credential Manager (by hand) | If you know the target, `Get-StoredCredential -Target "VMware Encrypted VM: C:\path\to\vm.vmx" -AsCredentialObject` from the PSGallery `CredentialManager` module. Strip the `LegacyGeneric:target=` prefix that `cmdkey` adds for display. |
| Change it | With the VM **powered off**: VM Settings > Options > **Access Control** > Change Password. Requires the current password. |
| Remove encryption | Same screen, **Remove Encryption**. Requires the current password, and you must remove the virtual TPM first - which Windows 11 may then refuse to boot without. |
| Last resort | An encrypted VM whose password is lost cannot be recovered. Rebuild the VM (Part 2), choosing your own encryption password and recording it. |

**A YAML quoting trap.** If the password contains `:`, `#`, `@`, `{`, `}` or
begins with a special character, it must be quoted in `config.yaml`:

```yaml
encryption_password: "p@ss:word#1"
```

`py runner.py --check` prints how many characters it parsed. If that count
does not match your actual password, YAML mangled it - quote it and re-run.
When the password is rejected rather than missing, `--check` says which case
you are in, so you can tell a config problem from a wrong password.

### 2.5 Install VMware Tools

**VM → Install VMware Tools**, then run the installer in the guest and
reboot. Mandatory: every guest operation in this harness runs over the Tools
channel. Without it the harness cannot copy a file or start a process.

### 2.6 Format D: and run the preparation script

In the guest: Disk Management → initialise disk 2 → **NTFS**, letter **D:** →
create `D:\corpus` and copy your ~150 govdocs1 files in.

**Attach the installers ISO before running this** (section 2.9), or at least
stage `vcredist\vcredist_x86.exe` somewhere reachable: step 7 installs the
Visual C++ 2010 x86 runtime that BleachBit 4.x needs. Without it that
installer raises a modal dialog, which blocks an unattended run.

Copy `guest/prepare_baseline.ps1` into the VM, then in an **elevated**
PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\prepare_baseline.ps1
```

This does in one pass what would otherwise be ten error-prone manual steps:

| Step | Action | Why |
|---|---|---|
| 1 | Verify D: is NTFS, warn under 500 MB free | free-space modes need room to be realistic |
| 2 | `fsutil usn createjournal m=16MB a=1MB D:` | pins `$UsnJrnl` independently of volume size |
| 3 | `chkdsk D: /L:16384` | pins `$LogFile` at 16 MB so it cannot wrap mid-run |
| 4 | `powercfg /h off`, pagefile off, VSS capped at 2 GB | reclaims ~5.5 GB on a 4 GB-RAM guest |
| 5 | Disables Update, Search, SysMain, DiagTrack, Defender RTP | removes background churn; Defender quarantines several wiping tools |
| 6 | `EnableLUA = 0` | `runProgramInGuest` uses a filtered token; silent installers cannot elevate under UAC |
| 7 | `ErrorMode=2`, WER `DontShowUI=1` | a modal dialog blocks an unattended run until the step times out; this turns hard errors into ordinary failures |
| 8 | Checks `msvcr100.dll`; installs VC++ 2010 x86 if absent | BleachBit 4.x needs it |
| 9 | Reports corpus file count, size, type mix | catches an empty or tiny corpus before 9 hours of runs |
| 10 | Confirms VMware Tools is running | the single hardest dependency to diagnose later |

It prints a **limitations block** listing every deviation it introduced, ready
to paste into the report, and writes the same to `C:\baseline_prep.json`.

Useful flags: `-KeepPagefile`, `-SkipDefender`, `-UsnJournalMB`,
`-LogFileMB`, `-EvidenceDrive`.

> **If the script reports syntax errors**, the file's line endings were
> changed in transit. Windows PowerShell 5.1 can mis-parse a `.ps1` saved
> with LF-only endings, and the resulting errors point at innocent lines far
> from the real cause. Both scripts ship with CRLF endings; if you edited or
> re-saved one, confirm it is still CRLF, or re-run it through:
>
> ```powershell
> $f = '.\prepare_baseline.ps1'
> (Get-Content -Raw $f) -replace "`r`n","`n" -replace "`n","`r`n" |
>     Set-Content -NoNewline $f
> ```
>
> Copying the file into the guest with the harness's own transfer, or with
> copy/paste into Notepad, both preserve CRLF.

> If `chkdsk /L` reports a smaller size than requested, NTFS capped it on
> this volume. Not fatal — the default still holds one run's records — but
> watch `runs.csv` for a low `usn_event_count`, which indicates wrap.

### 2.7 Reboot

The pagefile and UAC changes need it.

### 2.8 Verify

```powershell
fsutil usn queryjournal D:     # Maximum Size should read ~16 MB
chkdsk D: /L                   # reports current $LogFile size, changes nothing
Get-Volume -DriveLetter D
```

### 2.9 Build and attach the installer ISO

Stage the renamed installers (section 1.5) in a local folder, **validate it**,
then burn it.

```
C:\iso_staging\
  sdelete\sdelete64.exe
  bleachbit\bleachbit-6.0.4-setup.exe
  bleachbit\bleachbit-4.6.0-setup.exe
  eraser\eraser-x64.msi             <- extracted from the .exe, see PART4 5a
  vcredist\vcredist_x86.exe        <- Visual C++ 2010 SP1 x86, for BleachBit 4.x
  ccleaner\...  bcwipe\...         <- optional; disabled tools, re-testing only
```

> `vcredist_x86.exe` is a **baseline prerequisite**, not a wiping tool, so
> `check_installers.py` does not look for it - it is installed once by
> `prepare_baseline.ps1` step 8 rather than per run. Get it from
> <https://www.microsoft.com/en-us/download/details.aspx?id=26999>.

Validate before burning - this is far cheaper than discovering a wrong name
during the matrix:

```bat
py tools\check_installers.py --staging C:\iso_staging
```

It must print `All 6 ISO files present. Safe to build the ISO.` Anything
reported as RENAME, WRONG BUILD or MISSING will produce a run that installs
nothing and wipes nothing. Use `--fix-names` to rename unambiguous
near-matches after confirmation.

Then build the ISO.

**With `oscdimg`** (ships with the Windows ADK's Deployment Tools feature).
It is not added to PATH, so call it by full path.

In **PowerShell**, a command line that starts with a quoted string is parsed
as a string expression rather than a command, so it needs the call operator
`&`. Omitting it gives
*"Unexpected token '-lWIPERTOOLS' in expression or statement"*. Using
variables also keeps long paths with spaces readable:

```powershell
$oscdimg = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe"
$staging = "C:\path\to\iso_staging"
$iso     = "C:\path\to\wipertools.iso"

& $oscdimg -lWIPERTOOLS -j1 -m $staging $iso
```

In **cmd.exe** the quoted path works as-is, with no `&`:

```bat
"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe" -lWIPERTOOLS -j1 -m C:\iso_staging C:\VMs\wipertools.iso
```

Or, from the Start menu's **"Deployment and Imaging Tools Environment"**
(a cmd session with PATH already set):

```bat
oscdimg -lWIPERTOOLS -j1 -m C:\iso_staging C:\VMs\wipertools.iso
```

| Flag | Effect |
|---|---|
| `-lWIPERTOOLS` | volume label. **No space after `-l`** - `-l WIPERTOOLS` fails |
| `-j1` | write both Joliet and ISO 9660. Required: plain ISO 9660 truncates to 8.3, which would mangle `bleachbit-6.0.4-setup.exe` and break every install command |
| `-m` | ignore the default ~680 MB image-size cap. Harmless here, useful if you add more tools |

No `-b` boot-sector flag: this is a data ISO, not bootable.

**Without the ADK**, any burner tool produces an equivalent ISO - ImgBurn,
AnyBurn or PowerISO. Choose "data ISO", add the staging folder's *contents*
(not the folder itself), set the label, and ensure Joliet or UDF is enabled
so long filenames survive.

### Verify the ISO itself, not just the staging folder

Mount it on the host and re-run the checker against the mounted drive letter.
This confirms the burn preserved the filenames, which is what the earlier
staging check cannot tell you:

```powershell
$iso = Mount-DiskImage -ImagePath C:\VMs\wipertools.iso -PassThru
$drive = ($iso | Get-Volume).DriveLetter
py tools\check_installers.py --staging "${drive}:\"
Dismount-DiskImage -ImagePath C:\VMs\wipertools.iso
```

It must again report `All 6 ISO files present.` A file that passed in staging
but fails here means the burn truncated the names - rebuild with `-j1`.

Attach the ISO via **VM Settings > CD/DVD > Use ISO image**, and tick
**Connect at power on** so it is present on every run.

> **The optical drive must be E:.** If you moved it to E: when freeing up D:
> for the evidence volume (section 2.6), it already is. Confirm inside the
> guest with `Get-Volume | Where-Object DriveType -eq 'CD-ROM'`. If it is on
> another letter, either change it in Disk Management or update every `E:\`
> path in `config.yaml` to match.

Filenames must match `config.yaml` exactly. The guest agent verifies each
installer exists before running it, so a mismatch now fails the run loudly
rather than silently - but the checker above catches it before you burn.

### 2.10 Disconnect the network, then snapshot

With the VM powered off, open **VM Settings > Network Adapter** and untick
**"Connect at power on"**.

> The harness does not need the network: VMware guest operations travel over
> the VMX backdoor channel through VMware Tools rather than TCP/IP, and every
> installer comes from the ISO. Disconnecting removes telemetry and update
> traffic from the journals, stops any tool changing version mid-matrix, and
> makes an accidentally-staged online installer fail loudly instead of
> silently succeeding.

Shut down cleanly, then **VM → Snapshot → Take Snapshot**, named exactly
**`clean`**.

> **Do not install any wiping tool into the baseline.** A real suspect
> installs one tool and uses it. If all six sat in the baseline, every image
> would show traces of all six and the attribution experiment would be void.
> Each run installs its own tool; the snapshot revert discards it.

> **Keep exactly one snapshot.** Each extra level adds a hop to every read
> while flattening, and the harness reverts 60 times. If `--show-disks` reports
> a backing file like `...-000005.vmdk`, you are five levels deep: open
> **Snapshot Manager** and delete everything except `clean`. `py runner.py
> --check` prints a note when more than one snapshot exists.

---

# Part 3 — Configure and validate

Edit `config.yaml`: `vm.vmx`, `vm.guest_user`, `vm.guest_pass`, and the
`paths:` block. Forward slashes are fine on Windows.

> **Shell note.** Commands marked `powershell` need PowerShell; those marked
> `bat` are for cmd.exe or the Anaconda Prompt. The one difference that bites:
> PowerShell requires the call operator `&` before a **quoted** executable
> path, because a line beginning with a quote is parsed as a string
> expression. Unquoted paths with no spaces work the same in both.

> **Keep `runs\` off a synced folder.** If the harness sits under OneDrive,
> Desktop or Documents with sync enabled, the 60 run folders will be uploaded
> as they are written, and sync can hold a file open while the harness writes
> to it. Either move the harness to a plain local path such as `C:\wipertrace`,
> or point `paths.work` at one:
>
> ```yaml
> paths:
>   work: "C:/wipertrace_runs"
> ```
>
> Absolute `work` paths are used as given; relative ones resolve against the
> harness folder.

From the harness folder:

```bat
py runner.py --find-vmware
py runner.py --show-disks
py runner.py --snapshots
py runner.py --check
py runner.py --list
```

**`--find-vmware`** locates both Workstation executables *and* your VM. It
searches PATH, the registry `InstallPath` and both Program Files trees for
`vmrun.exe` and `vmware-vdiskmanager.exe`, then reads Workstation's own
`preferences.ini` recent-VM list to find your `.vmx`. It prints the exact
values to paste into `paths.vmrun`, `paths.vdiskmanager` and `vm.vmx`.

**`--show-disks`** reports each attached disk's declared capacity, read from
the VMDK header:

```
  device     backing file                        capacity   on host  chain
  ---------- ---------------------------------- --------- ---------  -----
  nvme0:0    Windows 11 x64-000005.vmdk           32.0 GB    0.0 GB      5
  nvme0:1    Windows 11 x64-0-000005.vmdk          2.0 GB    0.0 GB      5  <-- configured
```

Set `disks.data_device` to the **smaller** disk's controller address; the
command flags it if your choice is not the smaller one.

> **Why capacity rather than file size.** A snapshot delta holds only the
> writes made since the snapshot, so its file size is near zero whatever the
> underlying disk's capacity - which is why `on host` reads `0.0 GB` for both.
> The declared capacity lives in the VMDK header, and that is what
> distinguishes the 32 GB system disk from the 2 GB evidence disk. The `chain`
> column counts files from the delta back to the base.

**`--check`** validates the whole setup and **opens the VM** to prove it is
reachable. It verifies `vmrun`, the `.vmx`, the configured device, the
flattening backend, all four Sleuth Kit binaries, and the guest agent's
encoding - then runs a live `vmrun listSnapshots`. That last step matters:
a `.vmx` existing on disk is not the same as one Workstation can open, so
without it an encrypted VM passes preflight and fails 60 times at run time.
It also confirms the `clean` snapshot exists.

Keep running `--check` until it prints `preflight OK`. A typo surfaces in two
seconds rather than at run 40 of 60.

Config keys you must set before `--check` passes:

| Key | Value |
|---|---|
| `vm.vmx` | full path to your `.vmx` (forward slashes are fine) |
| `vm.guest_user` / `vm.guest_pass` | the local admin account from 2.4 |
| `vm.encryption_password` | the VM-encryption password from 2.4, or `null` |
| `vm.snapshot` | `clean` |
| `disks.data_device` | the ~2 GB disk's controller address |
| `paths.vmrun` / `paths.vdiskmanager` | from `--find-vmware` |
| `paths.tsk_bin` | folder holding `icat.exe` |

# Part 4 — Verify each tool by hand (do not skip)

> **A full command-by-command checklist is in `PART4-MANUAL-TESTS.md`**, with
> every install and wipe command generated from `config.yaml`, a scratch-file
> helper so you never burn corpus files, the fallback silent-install switches
> per installer framework, and a results table to fill in. Work through that
> rather than the summary below if you want to test one command at a time.

### Verified results (these are what `config.yaml` now contains)

Every tool was installed and run by hand in the guest before being admitted
to the matrix. Success was judged by evidence - the target file gone, or free
space scrubbed - never by exit code, because several of these tools return
exit codes that mean nothing.

| Tool | Silent install | Wipe command (per target) | Status |
|---|---|---|---|
| SDelete 2.05 | portable, none | `sdelete64.exe -accepteula -nobanner -p 1\|3 "<file>"` | **in matrix** (p1, p3) |
| cipher.exe | built in | delete corpus, then `cipher.exe /w:D:\` | **in matrix** (free space) |
| BleachBit 6.0.4 | NSIS: `/allusers /S` | `bleachbit_console.exe --shred "<file>"` | **in matrix** |
| BleachBit 4.6.0 | NSIS: `/allusers /S` + VC++ 2010 x86 in baseline | same as 6.0.4 | **in matrix** |
| Eraser 6.2.0.2996 | bootstrapper ignores switches; extract MSI, `msiexec /i ... /qn` | `Eraser.exe erase /quiet /method=<GUID> "file=<file>"` | **in matrix** (Gutmann, pseudorandom) |
| CCleaner 7.12.1526 | `/S` works | none - `/DRIVE /WIPEFREESPACE` is a no-op (0.0 s, free space unchanged) | **excluded**: GUI-only wiper |
| BCWipe 7.60 | own switches: `-S -Z -T -NoPrivacyGuard -NoSwapFile` | undocumented; errors appear as modal dialogs | **excluded**: unsafe unattended |

Install locations confirmed with `Find-InstalledProgram`
(`guest\diagnose_tool.ps1`) are recorded per tool as `binary:` in
`config.yaml`. The agent waits for that file after installing and fails the
run if it never appears.

Things learned the hard way, now handled by the harness:

- **Eraser is asynchronous.** `Eraser.exe erase` hands each task to its
  service and returns 0 at once. The tool has `await_targets_sec: 900`, so the
  agent polls until every target is gone before settling; how long that took
  is recorded in `manifest.json` under `await_targets`.
- **Exit codes lie.** BCWipe's installer inverts them unless `-Z` is given;
  Eraser returns 0 for a task it never queued. The agent therefore fails any
  wiping run in which *no* target disappeared, whatever the exit codes say.
- **Quoted paths through `cmd.exe /c`.** A command that starts with a quoted
  path and contains more quotes - every BleachBit and Eraser command - is
  mangled by `cmd.exe /c`, which strips the first and last quote. The command
  works when typed in PowerShell but fails inside the agent. The agent now
  launches `cmd.exe /s /c "<command>"`, which runs it verbatim.
- **Modal dialogs.** `ErrorMode=2` suppresses Windows hard-error dialogs (such
  as BleachBit 4's missing `msvcr100.dll`), but not a tool's own message
  boxes - which is why BCWipe is excluded rather than wrapped.

Re-run one disabled tool on its own with, for example,
`py runner.py --tool bcwipe --limit 1 -v`.

### Re-testing a tool by hand

For each tool:

1. **Start the VM with a GUI.** The simplest route is to open Workstation and
   press Play - it has the encryption password cached, so nothing else is
   needed. From PowerShell instead:

   ```powershell
   $vmrun = "C:\Program Files\VMware\VMware Workstation\vmrun.exe"
   $vmx   = "C:\path\to\Windows 11 x64.vmx"

   & $vmrun -T ws -vp "<encryption password>" start $vmx gui
   ```

   Three things that each break this on their own: PowerShell needs `&` before
   a quoted path; `-vp` is required because the VM is encrypted (section 2.4);
   and Workstation 17+ lives under `Program Files`, not `Program Files (x86)`.
   Drop `-vp` only if `vm.encryption_password` is `null`.

2. Install from E:, run the exact command from `config.yaml` by hand.
3. Confirm the target file is actually gone. Note the exit code.
4. Revert to `clean` (Snapshot Manager, or
   `& $vmrun -T ws -vp "<password>" revertToSnapshot $vmx clean`).

If a tool has no scriptable per-file interface, restrict it to a free-space
mode or drive its GUI, and **state that in the write-up.** "This tool exposes
no scriptable per-file interface" is a finding, not a failure.

**Silent-install switches differ by installer framework.** If you add a tool
or a new version and its installer opens a GUI instead of running silently,
work through:

| Framework | Typical switches | Used by |
|---|---|---|
| NSIS | `/S`, often with a scope switch first | BleachBit: **`/allusers /S`** |
| Inno Setup | `/VERYSILENT` `/SILENT` | - |
| Vendor-specific | read the installer's own usage dialog | BCWipe: `-S -Z -T` |
| WiX Burn bundle | `/quiet` `/silent` `/passive` | - |
| **Wrapper around an MSI** | none work - extract the MSI and use `msiexec /i ... /qn` | **Eraser** |
| Windows Installer | `/qn` `/quiet` | any `.msi` |

> **A silent switch is often not one switch.** BleachBit's `/S` alone still
> shows its wizard; it needs `/allusers` (or `/currentuser`) first, because
> the installer must also be told the install scope before it will run
> unattended. If a documented silent switch still shows a GUI, the installer
> is usually waiting on one more unanswered choice - scope, licence, or
> install path - rather than ignoring the switch. NSIS also requires `/D=`,
> if used, to be the **last** switch and unquoted.

Diagnose a stubborn one by logging the attempt, e.g.
`eraser-setup.exe /quiet /log C:\install.log`, then read the log. Once a
switch works, put it in `config.yaml` and note the installer framework in
your report - it is part of what makes the matrix reproducible.

> **The failure mode this guards against:** a run that wipes nothing still
> produces a complete-looking folder of plausible files. That is why
> `manifest.json` records every exit code and which target paths survived,
> and why `parse_runs.py` warns about runs yielding zero USN events.

---

# Part 5 — Running

```bat
rem One run first. Always. Watch it work before trusting the matrix.
py runner.py --tool sdelete --mode p3 --limit 1 -v

rem One tool, all its modes and shutdown variants
py runner.py --tool sdelete

rem Full matrix, overnight
py runner.py --all

rem Resume after a crash, a reboot, or the host sleeping
py runner.py --all --resume
```

Disable host sleep for the overnight run: `powercfg /change standby-timeout-ac 0`.

A failed run is logged and the matrix continues. The VM is always left powered
off on failure — a running VM holds VMDK locks, and the next revert would
fail, cascading one bad run into the rest of the matrix.

Diagnosing: `runs\<run_id>\status.json` gives the stage and exception;
`runs\<run_id>\guest.log` gives the guest's own trace.

**Stuck at "waiting for guest operations" with only `checkToolsState` lines.**
This is not a credentials problem: the guest password is only used once Tools
reports `running`, and the harness then fails immediately on a bad password.
Repeated `checkToolsState` calls mean VMware Tools in the guest never
started, so Windows has not finished booting or is stuck before reaching the
desktop. Find out which with:

```bat
py runner.py --tool sdelete --mode p3 --limit 1 -v
```

Runs open the VM's window by default, so you can see its screen. Typical causes:

| What you see | Fix |
|---|---|
| A VMware dialog ("moved or copied", "CD-ROM image not found") | Answer it, or add `msg.autoAnswer = "TRUE"` and `uuid.action = "keep"` to the `.vmx` while the VM is off. The harness also reads `vmware.log` and stops with the question text when this happens. |
| Windows login screen | Not the cause of *this* symptom (Tools runs at the login screen), but it will fail the next step: `-interactive` needs a logged-on user. Turn on auto-logon in the baseline - see below - and re-take `clean`. |
| Windows still booting or applying updates | Raise `vm.boot_timeout`; the first boot after reverting can be slow. |
| Desktop, but Tools tray icon missing | Reinstall VMware Tools in the baseline and re-take `clean`. |

Auto-logon, if you did not install with `guest/autounattend.xml` (elevated
PowerShell in the guest, then shut down and re-take `clean`):

```powershell
$k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $k AutoAdminLogon  '1'
Set-ItemProperty $k DefaultUserName '<vm.guest_user>'
Set-ItemProperty $k DefaultPassword '<vm.guest_pass>'
```

This stores the password in the registry in plain text - acceptable for an
isolated lab VM, and worth one line in the limitations.

**VM only progresses while its window is open.** Symptom: in a headless
run Tools stays `installed` for minutes, but the moment you open the VM in
Workstation it reports `running` and the run continues. Windows 11 throttles
processes it considers background work ("power throttling" / efficiency
mode), and a VM with no window is exactly that. On hybrid CPUs (performance
and efficiency cores) it can also be moved to the slow cores. Exempt the VM
process once, in an **elevated** PowerShell on the host:

```powershell
powercfg /powerthrottling disable /path "C:\Program Files\VMware\VMware Workstation\x64\vmware-vmx.exe"
powercfg /powerthrottling list
```

and set the host power mode to **Best performance** (Settings > System >
Power & battery) and keep it plugged in for the overnight run.

This is why runs show the VM's window **by default** (`vm.gui: true`).
Leave the Workstation window open and **not minimised** during the matrix -
a minimised window can be throttled the same way. Once the exemption above
is in place you can try `--headless` (or `vm.gui: false`); the evidence is
identical either way.

If you stop a run with Ctrl+C, the harness now powers the VM off. Older
versions left it running headless; if that happened, stop it in Workstation
before the next run.

---

# Part 6 — What each stage does, and why

### Stage 1 — REVERT  (`_stage_revert` → `vmware.revert`)

`vmrun revertToSnapshot` rolls back to `clean`, discarding both the previous
run's tool installation and the evidence volume's journal state, so every run
observes a wipe against a byte-identical starting point. The harness then
waits for Workstation to release its `*.lck` lock directories.

### Stage 2 — BOOT  (`_stage_boot` → `vmware.wait_for_guest`)

Powers on (with its window by default; `--headless` for none), then polls
until guest operations actually work.
`checkToolsState` returning `running` is necessary but **not sufficient** —
Tools answers before the interactive logon session that guest ops bind to is
ready. The authoritative test is executing a trivial program, so that is what
the harness polls on. Authentication failures abort immediately rather than
retrying for seven minutes, since bad credentials will not fix themselves.

### Stage 3 — GUEST  (`_stage_guest` → `guest/run_wipe.ps1`)

The host serialises the resolved tool/mode definition to `plan.json`, copies
it and the agent into `C:\_run`, and launches the agent with `-interactive`
(required for installers that touch the interactive desktop). The agent then:

1. **Reads the plan.** JSON, not YAML — stock Windows PowerShell 5.1 has no
   YAML parser.
2. **Records ground truth,** *before anything mutates the volume.* For each
   target: path, size, SHA-256, and the NTFS file reference from
   `fsutil file queryfileid`. The 128-bit ID decomposes as bits 0–47 = MFT
   record number, bits 48–63 = sequence number.

   > **This is the keystone of the dataset.** Filenames are precisely what
   > wipers destroy; the MFT record number survives in `$UsnJrnl` and
   > `$LogFile` records. Labelling on it is what lets you later assert
   > *"record 1042 was wiped by Eraser"* rather than merely *"40 files
   > disappeared"* — and it is what turns 60 runs into tens of thousands of
   > labelled rows.

3. **Captures the journal watermark** (`fsutil usn queryjournal D:`) so the
   host can tell how far the journal advanced and whether it wrapped.
4. **Installs the tool,** inside the disposable snapshot, under a timeout so
   a wizard or modal dialog cannot hang the run. It then waits for the
   tool's `binary` to appear and fails the run if it does not.
5. **Executes the wipe.** `per_file` commands run once per target; `once`
   commands run against the whole volume, for free-space scrubbers that never
   touch a named file and therefore leave no rename chain. External commands
   go through `cmd.exe /s /c "..."` so quoted paths survive intact.
6. **Waits for asynchronous tools** (`await_targets_sec`, used by Eraser)
   until every target is gone, then **fails the run if a wiping tool removed
   none of its targets** - the one failure exit codes cannot reveal.
7. **Quiesces** for `settle_seconds` (per-tool override allowed), letting the
   NTFS log writer finish, then re-reads the watermark.
8. **Collects C: artefacts via VSS.** `Amcache.hve` is held open by the
   system; a shadow copy gives a crash-consistent view without rebooting.
   This touches C: only — D:'s journals stay pristine for Stage 6.
9. **Writes `manifest.json`** (the answer key) and **`collected.zip`.**
10. **Writes `_STATUS.txt`** containing `OK` or `FAIL <reason>`.

> **Why the sentinel file exists.** VMware's VIX API **discards guest stdout
> and stderr** — there is no equivalent of VirtualBox's `--wait-stdout`. The
> agent cannot report back through its return channel, and `vmrun`'s exit
> code reflects only whether the process *launched*. The host treats
> `_STATUS.txt` as the sole authority on success.

### Stage 4 — RETRIEVE  (`_stage_retrieve`)

Copies `manifest.json`, `guest.log` and `collected.zip` out, then unpacks the
archive into `artifacts\`.

> **Why a zip.** `copyFileFromGuestToHost` has **no recursive mode**. Prefetch
> alone holds hundreds of files and each VIX round trip costs about a second,
> so the agent archives the tree in-guest and the host transfers one file.
> Missing C: artefacts degrade a run but do not invalidate it; the journal
> evidence is the primary measurement.

### Stage 5 — SHUTDOWN  (`_stage_shutdown`)

`vmrun stop ... soft` or `hard`, per the matrix. An **experimental variable,
not a convenience**:

- **clean** — ACPI shutdown. NTFS flushes and checkpoints `$LogFile`.
- **hard** — power cut. In-flight transaction records survive.

That is the difference between a gracefully shut down machine and one seized
live, and it is a legitimate secondary finding.

### Stage 6 — EXTRACT  (`_stage_extract` → `resolve_active_disk`, `extract.py`)

With the VM **off**:

1. **Resolve the live disk.** Parse the `.vmx` for the evidence device's
   `fileName`.

   > **The single most dangerous step in the harness.** When you take a
   > VMware snapshot, Workstation **freezes the base VMDK** and redirects all
   > writes to a copy-on-write child (`data-000001.vmdk`), rewriting the
   > `.vmx` to point at that child. Imaging `data.vmdk` post-wipe would
   > return the *pristine baseline* — producing 60 immaculate run folders in
   > which no wipe ever occurred, with no error anywhere. The harness reads
   > the chain head from the `.vmx` rather than trusting a configured path,
   > which is why `config.yaml` takes a controller address (`nvme0:1`) and
   > not a filename.

2. **Flatten the chain.** TSK cannot traverse sparse or delta-linked VMDKs,
   so `vmware-vdiskmanager -r -t 2` (or `qemu-img convert -f vmdk -O raw`)
   collapses it. Both follow the `parentFileNameHint` automatically. With a
   2 GB evidence disk this takes well under a minute and needs 2 GB of
   scratch.
3. **Carve the journals** with `mmls` → `fls` → `istat` → `icat`: `$MFT`
   (record 0), `$LogFile` (record 2), and `$UsnJrnl:$J`, whose record number
   and `$DATA` stream address are discovered at runtime under `$Extend`
   rather than hardcoded. A wiper that *deletes* the journal is recorded as a
   finding, not an error.
4. **Compress** each artefact (`extract.compress`, default on) and **delete
   the raw image.**

   > Carved artefacts are highly compressible — `$J` is a sparse stream whose
   > unallocated extents `icat` materialises as zero runs, and `$MFT` /
   > `$LogFile` are repetitive fixed-layout records. This takes the matrix
   > from ~3.4 GB of output to a few hundred MB. `parse_runs.py` decompresses
   > transparently into a scratch directory, so the parsing stage is
   > unaffected. Set `compress: false` if you need to point external tools
   > straight at `runs\<id>\evidence\`.

> **Why cold extraction at all.** Reading `$MFT` or `$UsnJrnl` from inside a
> running Windows **writes to those same structures**. Anything collected
> that way is contaminated by the act of collecting it, and is worthless as
> evidence of what the wiper did.

---

# Part 7 — Parsing and labelling

```bat
cd parse
py parse_runs.py --runs ..\runs --config ..\config.yaml
```

Produces `runs\_dataset\`:

| File | One row per | Use |
|---|---|---|
| `events.csv` | USN record | raw sequences, rule development |
| `files.csv` | file reference per run | features, evaluation |
| `runs.csv` | run | provenance, sanity checks |

`--label-only` re-joins without re-invoking the parsers — what you want after
editing the feature code.

The join is on **MFT record number**, giving each row `is_target` (was this
file reference one we deliberately wiped?) and the tool as the label. Derived
features include `distinct_name_count`, `rename_event_count`, name-length
extremes, and `DataTruncation` / `DataOverwrite` / `FileDelete` flags.

Expected contrast: a per-file wiper that renames through a fixed alphabet
yields a high `distinct_name_count` and `rename_event_count` on every target,
while ordinary deletion yields one event and no renames.

### If you add a machine learning component

- **Split on `run_id`, never randomly.** Events from one wipe landing on both
  sides of a split will hand you 99% accuracy that means nothing. Use
  leave-one-run-out or grouped cross-validation.
- **Vary the environment deliberately** across baselines — Windows build,
  cluster size, corpus profile — or the model learns your VM, not the tool.

---

# Part 8 — Negative controls

`control_delete` and `control_churn` are not filler. Without runs in which
*nothing* was wiped, the false-positive rate of any rule is unmeasurable.

`control_churn` deliberately generates rename bursts of the kind produced by
Office autosave, Git checkouts and installers — the principal confounder for
any rename-chain signature. **If a rule fires on `control_churn`, the rule is
too permissive.** Your marker will ask about false positives; these runs are
the answer.

---

# Part 9 — Testing without a VM

```bat
cd tests && py make_fixtures.py .\tmp_runs
cd ..\parse && py parse_runs.py --runs ..\tests\tmp_runs --label-only
```

Fabricates a run whose `usn.csv` holds a 26-step rename chain, plus a control
run with an ordinary delete. `files.csv` should show ~27 distinct names and
~52 rename events for the wiper fixture, 1 and 0 for the control. If not, the
labelling join is broken. This lets the feature and rule code be developed
before the VM exists.

---

# Part 10 — Publishing

**Do not redistribute the disk images** — they contain a licensed copy of
Windows. Publish `evidence\`, `artifacts\`, `manifest.json` and `_dataset\`:
smaller, no licensing exposure, and sufficient to reproduce the evaluation.
The gzipped evidence is already in a convenient form for this.

---

# Part 11 — Limitations to declare in the report

`prepare_baseline.ps1` prints the guest-side items; these are the full set.

- Synthetic VM images, not seized media; no organic wear or background usage.
- UAC disabled, Defender real-time protection off, Windows Update / Search /
  SysMain / DiagTrack disabled — all deviate from a realistic endpoint and
  remove update and indexing churn from the journals.
- Pagefile and hibernation disabled to reduce the virtual disk footprint.
- The VM's network adapter is disconnected for the matrix, so no tool can
  fetch updates or send telemetry. This removes DNS, HTTP and cache artefacts
  from the journals and makes runs reproducible, but a real endpoint is
  usually networked and some tools may behave differently online.
- Hard-error and Windows Error Reporting dialogs are suppressed in the guest
  (`ErrorMode=2`, WER `DontShowUI=1`) so a failing tool cannot block an
  unattended run. A real endpoint would display these dialogs; here a tool
  that would have prompted instead fails with a non-zero exit code.
- The Visual C++ 2010 x86 redistributable is installed in the baseline because
  BleachBit 4.x depends on it. It is therefore present for every run, not only
  those six - a deliberate choice, since installing it per run would add
  redistributable-installation traces to one tool's runs and confound the
  comparison.
- `$LogFile` and `$UsnJrnl` pinned to 16 MB rather than left at NTFS defaults,
  so journal capacity does not scale with volume size as it would on a real
  machine. This was required to make a 2 GB evidence volume viable.
- **2 GB evidence volume with ~1.8 GB free.** Free-space wiping modes
  therefore complete far faster than on a real multi-hundred-GB disk, and
  their observed journal activity is correspondingly compressed. Per-file
  wiping signatures, which are the project's focus, are unaffected.
- Single Windows build and edition unless the matrix is re-run against others.
  State which edition was used: LTSC carries substantially less background
  software than a consumer Pro build, so a signature validated only on LTSC
  has been validated against a quieter filesystem than a real suspect
  machine would present. If a consumer build was used, note that inbox apps
  and Store updates remain active and contribute journal churn that
  `prepare_baseline.ps1` cannot suppress.
- Virtual disks, so SSD TRIM and wear levelling are out of scope — material,
  because free-space wiping behaves differently on physical SSDs.
- Free-space modes have no per-file rename chain; their ground truth is the
  pre-deletion record set.
- Tools whose CLI could not be verified are excluded or restricted to a
  scriptable subset; recorded per tool in `config.yaml` via `enabled: false`
  and `disabled_reason`, which `py runner.py --list` prints beneath the
  matrix.
- **CCleaner 7.12 was tested and excluded**: it exposes no command-line
  interface for secure deletion or free-space wiping, and its Drive Wiper is
  GUI-only. This is reported as a finding about the tool rather than a gap in
  method - a GUI-only wiper implies an interactive user rather than a script.
- **BCWipe 7.60 was tested and excluded**: it installs silently, but reports
  command-line errors through modal dialogs rather than console output or
  exit codes, and its CLI syntax is undocumented in the shipped files. One
  malformed argument or expired trial would block an unattended run. The
  attribution results therefore cover five tools (six builds counting both
  BleachBit versions), not every wiper in the proposal.
- **Eraser is measured as it really behaves - asynchronously.** Wipes run in
  its background service after the CLI returns. In `hard` shutdown runs the
  agent has already waited for every target to disappear, so the power cut
  does not truncate the wipe itself; any target still present is recorded in
  `manifest.json` (`await_targets.remaining`, `surviving_paths`).
