"""VMware Workstation control layer for the WiperTrace harness.

All interaction with the hypervisor funnels through this module, so there is
exactly one place to look when VMware changes its CLI contract.

Three behaviours of Workstation drive the design here and differ materially
from VirtualBox, so they are worth stating up front:

1.  GUEST OPERATIONS ARE BLIND.  `vmrun runProgramInGuest` returns the VIX
    API result, not the guest process's stdout/stderr. There is no equivalent
    of `VBoxManage --wait-stdout`. Consequently the guest agent must persist
    its own log and a terminal status sentinel to disk, which the host then
    retrieves. Never infer guest success from vmrun's exit code alone.

2.  FILE TRANSFER IS SINGLE-FILE ONLY.  `copyFileFromGuestToHost` has no
    recursive mode. Directory trees (e.g. %SystemRoot%\\Prefetch) must be
    archived in-guest into one file before transfer. The guest agent emits
    collected.zip for this reason.

3.  SNAPSHOTS REDIRECT WRITES TO A DELTA.  Taking a snapshot freezes the base
    VMDK and creates a copy-on-write child (`<disk>-00000N.vmdk`). Workstation
    rewrites the .vmx `fileName` entry to point at that child. Imaging the
    base VMDK post-wipe therefore yields the pristine baseline, not the
    evidence — a silent, total loss of the experiment. See
    resolve_active_disk(), which parses the .vmx to find the live chain head.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
from pathlib import Path

log = logging.getLogger("vmware")

# VIX guest-ops error codes worth distinguishing from generic failure.
VIX_E_GUEST_AUTH = "Invalid user name or password"
VM_ENCRYPTED = "Incorrect password"
VIX_E_TOOLS = "VMware Tools are not running"

# .vmx disk attachment keys, e.g. 'nvme0:1.fileName = "data.vmdk"'.
# Windows 11 guests created by Workstation 17 default to NVMe; older
# templates use SCSI or SATA. All four controller families are matched.
_VMX_DISK_RE = re.compile(
    r'^\s*((?:scsi|sata|nvme|ide)\d+:\d+)\.fileName\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)


class VMwareError(RuntimeError):
    pass


class VMware:
    def __init__(self, vmrun: str, vmx: str, user: str, password: str,
                 host_type: str = "ws", vm_password: str | None = None):
        self.exe = vmrun
        self.vmx = str(Path(vmx))
        self.user = user
        self.password = password
        # VM-encryption password. Workstation requires a VM to be encrypted
        # before a virtual TPM can be attached, and Windows 11 needs a TPM,
        # so a Workstation-created Windows 11 guest is normally encrypted.
        # Without -vp, every vmrun operation fails with "Incorrect password".
        self.vm_password = vm_password or None
        # -T selects the VIX provider. 'ws' = Workstation; 'player' for the
        # free Player, which supports a reduced command set.
        self.host_type = host_type

    # -- low level ---------------------------------------------------------

    def _base(self) -> list[str]:
        # Authentication flags must precede the command and its parameters.
        base = [self.exe, "-T", self.host_type]
        if self.vm_password:
            base += ["-vp", self.vm_password]
        return base

    def _creds(self) -> list[str]:
        """Credential flags must precede the subcommand, not follow it."""
        return ["-gu", self.user, "-gp", self.password]

    def _run(self, args: list[str], timeout: int = 600, check: bool = True,
             redact: bool = True) -> subprocess.CompletedProcess:
        cmd = self._base() + args
        if log.isEnabledFor(logging.DEBUG):
            secrets = {x for x in (self.password, self.vm_password) if x}
            shown = ["***" if redact and a in secrets else a for a in cmd]
            log.debug("%s", " ".join(shown))

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        # vmrun reports most failures as exit 255 with a human-readable
        # 'Error: ...' line on stdout rather than stderr.
        combined = f"{proc.stdout}\n{proc.stderr}".strip()
        if check and proc.returncode != 0:
            hint = ""
            if VM_ENCRYPTED in combined or ("Cannot open VM" in combined
                                            and "password" in combined.lower()):
                # vmrun reports "Incorrect password" both when -vp is absent
                # and when it is wrong, so distinguish the two cases here -
                # otherwise the user cannot tell whether their config was read.
                if not self.vm_password:
                    hint = (
                        "\n    This VM is ENCRYPTED, and "
                        "vm.encryption_password is NOT SET in config.yaml.\n"
                        "    Workstation encrypts a VM in order to attach a "
                        "virtual TPM, which\n    Windows 11 requires, so this "
                        "is the normal state for a\n    Workstation-created "
                        "Windows 11 guest.\n\n"
                        "    Set vm.encryption_password to the VM's encryption "
                        "password. The harness\n    passes it to vmrun as "
                        "-vp.")
                else:
                    hint = (
                        f"\n    vm.encryption_password IS set "
                        f"({len(self.vm_password)} characters) but vmrun "
                        "rejected it.\n\n"
                        "    Check, in order:\n"
                        "      1. Test it outside the harness:\n"
                        "           & \"<vmrun.exe>\" -T ws -vp \"<password>\" "
                        "listSnapshots \"<vmx>\"\n"
                        "      2. YAML quoting. A password containing : # @ or "
                        "starting with a\n         special character must be "
                        "quoted in config.yaml. Compare the\n         "
                        "character count above against your actual password.\n"
                        "      3. This is the VM-ENCRYPTION password, not the "
                        "guest account\n         password - they are "
                        "different values.\n"
                        "      4. Recover it from Windows Credential Manager > "
                        "Windows Credentials,\n         where Workstation "
                        "stores it if you ticked remember.")
            elif VIX_E_GUEST_AUTH in combined:
                hint = (" - check vm.guest_user/guest_pass; the account needs "
                        "a non-empty password")
            elif VIX_E_TOOLS in combined:
                hint = " - VMware Tools is not running in the guest"
            raise VMwareError(
                f"vmrun {args[0]} failed ({proc.returncode}){hint}\n{combined}"
            )
        return proc

    # -- power state -------------------------------------------------------

    def is_running(self) -> bool:
        """`vmrun list` prints the absolute .vmx path of each running VM."""
        out = self._run(["list"], check=False).stdout
        target = Path(self.vmx).resolve()
        for line in out.splitlines()[1:]:          # line 0 is the count header
            line = line.strip()
            if line and Path(line).resolve() == target:
                return True
        return False

    def list_snapshots(self) -> list[str]:
        out = self._run(["listSnapshots", self.vmx]).stdout
        return [l.strip() for l in out.splitlines()[1:] if l.strip()]

    def revert(self, snapshot: str):
        """Discard the delta and re-anchor the VM to a known baseline.

        Must be done with the VM powered off; reverting a live VM is
        permitted by vmrun but leaves the guest in an inconsistent state.
        """
        if self.is_running():
            self.stop(hard=True)
        log.info("reverting to snapshot %r", snapshot)
        self._run(["revertToSnapshot", self.vmx, snapshot], timeout=900)
        # revertToSnapshot can leave a stale lock directory momentarily.
        self._wait_unlocked()

    def start(self, headless: bool = True):
        log.info("starting VM (%s)", "nogui" if headless else "gui")
        self._run(["start", self.vmx, "nogui" if headless else "gui"],
                  timeout=900)

    def stop(self, hard: bool = False):
        """soft = ACPI shutdown request via Tools; hard = power cut.

        The distinction is forensically load-bearing. A soft stop lets NTFS
        flush and checkpoint $LogFile; a hard stop preserves in-flight
        transaction records, which is what a seized machine looks like.
        """
        if not self.is_running():
            return
        mode = "hard" if hard else "soft"
        log.info("stopping VM (%s)", mode)
        self._run(["stop", self.vmx, mode], timeout=300, check=False)
        self._wait_stopped()
        self._wait_unlocked()

    def _wait_stopped(self, timeout: int = 180):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.is_running():
                return
            time.sleep(2)
        log.warning("VM still listed as running; forcing hard stop")
        self._run(["stop", self.vmx, "hard"], check=False)
        time.sleep(5)

    def _wait_unlocked(self, timeout: int = 120):
        """Block until Workstation releases its *.lck directories.

        Workstation holds exclusive locks on the VMDK chain via sibling
        '<disk>.vmdk.lck' directories. Any attempt to read or convert the
        disk while these exist fails or, worse, reads a torn image.
        """
        vm_dir = Path(self.vmx).parent
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not list(vm_dir.glob("*.lck")):
                return
            time.sleep(2)
        log.warning("lock directories still present in %s after %ds",
                    vm_dir, timeout)

    # -- guest operations --------------------------------------------------

    def tools_state(self) -> str:
        """One of: running | installed | notInstalled | unknown."""
        proc = self._run(["checkToolsState", self.vmx], check=False)
        lines = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
        if not lines:
            # vmrun printed nothing (e.g. an error on stderr); never let an
            # empty reply crash the wait loop with an IndexError.
            return f"unknown ({proc.stderr.strip()[:120] or 'no output'})"
        return lines[-1]

    def pending_question(self) -> str | None:
        """Return the text of an unanswered VMware question, if any.

        In `nogui` mode Workstation cannot show its own dialogs, so a VM that
        hits one - "This virtual machine might have been moved or copied",
        "the CD-ROM image could not be found", a paused-for-disk-space
        warning - simply waits forever. The guest never boots, Tools never
        starts, and from vmrun's side the VM is merely "running" with Tools
        not ready. The only trace is vmware.log next to the .vmx, which
        records each question as a "Msg_Question:" block and each answer as
        a "MsgQuestion: ... reply=" line. A question with no reply after it
        is what is blocking the boot.
        """
        log_path = Path(self.vmx).parent / "vmware.log"
        try:
            lines = log_path.read_text(encoding="utf-8",
                                       errors="replace").splitlines()
        except OSError:
            return None

        last_q = None
        for i, line in enumerate(lines):
            if "Msg_Question:" in line:
                last_q = i
            elif last_q is not None and "reply=" in line and "MsgQuestion" in line:
                last_q = None      # that question was answered
        if last_q is None:
            return None

        text = []
        for line in lines[last_q + 1:last_q + 10]:
            # Drop the "<timestamp> In(05) vmx " / "| vmx| I005: " prefix.
            body = re.sub(r"^.*?\bvmx\|?\s+(?:I\d+:\s+)?", "", line).strip()
            if body.startswith("---"):
                break
            if body:
                text.append(body)
        return " ".join(text) or "(question text not found in vmware.log)"

    def wait_for_guest(self, timeout: int = 300):
        """Poll until the VIX guest-ops channel will actually execute code.

        checkToolsState reporting 'running' is necessary but not sufficient:
        Tools answers before the interactive logon session that guest ops
        bind to is ready. The authoritative test is a trivial program
        execution, so that is what we poll on.
        """
        log.info("waiting for guest operations to become available "
                 "(up to %ds)", timeout)
        started = time.time()
        deadline = started + timeout
        last = ""
        prev_state = None
        next_hint = started + 60

        while time.time() < deadline:
            # A pending VMware dialog blocks the boot indefinitely in nogui
            # mode; detect it rather than waiting out the whole timeout.
            question = self.pending_question()
            if question:
                raise VMwareError(
                    "the VM is waiting on a VMware dialog that cannot be shown "
                    f"in nogui mode:\n    {question}\n"
                    "    Open the VM in Workstation, answer the dialog, then "
                    "power it off and re-take the 'clean' snapshot - or add\n"
                    "    msg.autoAnswer = \"TRUE\"   (and, for the "
                    "moved/copied question, uuid.action = \"keep\")\n"
                    "    to the .vmx while the VM is powered off.")

            state = self.tools_state()
            elapsed = int(time.time() - started)
            if state != prev_state:
                log.info("VMware Tools state: %s (%ds after power-on)",
                         state, elapsed)
                prev_state = state
            if state != "running" and time.time() >= next_hint:
                log.info("still waiting for Tools after %ds. To see why, open "
                         "the VM in Workstation (it is running headless) and "
                         "look at its screen.", elapsed)
                next_hint += 60
            if state == "running":
                proc = self._run(
                    ["-gu", self.user, "-gp", self.password,
                     "runProgramInGuest", self.vmx,
                     "C:\\Windows\\System32\\cmd.exe", "/c", "exit 0"],
                    timeout=90, check=False,
                )
                if proc.returncode == 0:
                    log.info("guest ready")
                    return
                last = f"{proc.stdout} {proc.stderr}".strip()
                if VIX_E_GUEST_AUTH in last:
                    # Credentials will not fix themselves; fail fast.
                    raise VMwareError(
                        "guest authentication rejected — verify "
                        "vm.guest_user / vm.guest_pass in config.yaml"
                    )
            else:
                last = f"tools state: {state}"
            time.sleep(5)

        raise TimeoutError(f"guest not ready after {timeout}s; last: {last}")

    def mkdir_guest(self, guest_dir: str):
        # Returns non-zero if the directory already exists; benign.
        self._run(["-gu", self.user, "-gp", self.password,
                   "createDirectoryInGuest", self.vmx, guest_dir], check=False)

    def file_exists_in_guest(self, guest_path: str) -> bool:
        return self._run(["-gu", self.user, "-gp", self.password,
                          "fileExistsInGuest", self.vmx, guest_path],
                         check=False).returncode == 0

    def copy_to_guest(self, host_path: Path, guest_path: str):
        self._run(["-gu", self.user, "-gp", self.password,
                   "copyFileFromHostToGuest", self.vmx,
                   str(host_path), guest_path], timeout=900)

    def copy_from_guest(self, guest_path: str, host_path: Path):
        """Single file only — VIX has no recursive transfer. See module docs."""
        host_path.parent.mkdir(parents=True, exist_ok=True)
        self._run(["-gu", self.user, "-gp", self.password,
                   "copyFileFromGuestToHost", self.vmx,
                   guest_path, str(host_path)], timeout=1800)

    def run_powershell(self, guest_script: str, args: list[str],
                       timeout: int = 5400) -> int:
        """Execute a .ps1 already staged in the guest.

        Returns vmrun's exit code. This reflects whether the VIX call and the
        guest process launch succeeded; it is NOT a reliable proxy for what
        the script actually did, because stdout is discarded by the API. The
        caller must verify the sentinel file the script writes.

        -interactive binds the program to the console session, which is
        required for MSI/EXE installers that touch the interactive desktop.
        """
        ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        proc = self._run(
            ["-gu", self.user, "-gp", self.password,
             "runProgramInGuest", self.vmx, "-interactive", ps,
             "-NoProfile", "-ExecutionPolicy", "Bypass",
             "-File", guest_script, *args],
            timeout=timeout, check=False,
        )
        if proc.returncode != 0:
            log.warning("runProgramInGuest returned %d: %s",
                        proc.returncode,
                        f"{proc.stdout} {proc.stderr}".strip()[:400])
        return proc.returncode


# ---------------------------------------------------------------------------
# Disk resolution and flattening
# ---------------------------------------------------------------------------

def parse_vmx_disks(vmx: Path) -> dict[str, str]:
    """Map controller address -> backing file, for attached virtual disks.

    Optical drives and unpopulated slots are filtered out. The returned paths
    are as written in the .vmx: usually relative to the VM directory.
    """
    disks: dict[str, str] = {}
    text = vmx.read_text(encoding="utf-8", errors="replace")
    for line in text.splitlines():
        m = _VMX_DISK_RE.match(line)
        if not m:
            continue
        device, backing = m.group(1).lower(), m.group(2)
        if backing.lower().endswith(".iso") or backing.lower() == "auto detect":
            continue
        if not backing.lower().endswith(".vmdk"):
            continue
        disks[device] = backing
    return disks


def resolve_active_disk(vmx: Path, device: str) -> Path:
    """Return the live head of the VMDK snapshot chain for one device.

    Rationale: after a snapshot exists, Workstation rewrites the device's
    fileName to the copy-on-write child (data-000001.vmdk). That child's
    descriptor carries a parentFileNameHint back to the base. Reading the
    child therefore yields the current state; reading the base yields the
    snapshot. Both qemu-img and vmware-vdiskmanager follow the parent chain
    when handed the child, so this function just has to find the child.
    """
    disks = parse_vmx_disks(vmx)
    key = device.lower()
    if key not in disks:
        raise VMwareError(
            f"device {device!r} not found in {vmx.name}. "
            f"Attached disks: {', '.join(sorted(disks)) or '(none)'}. "
            "Run `python runner.py --show-disks` to list them."
        )
    resolved = (vmx.parent / disks[key]).resolve()
    if not resolved.exists():
        raise VMwareError(f"backing file for {device} missing: {resolved}")
    log.debug("%s -> %s", device, resolved.name)
    return resolved


class DiskFlattener:
    """Converts a VMDK snapshot chain into a raw image The Sleuth Kit can read.

    TSK cannot traverse sparse or delta-linked VMDKs, so the chain must be
    collapsed into a flat sector-for-sector image first. Two backends:

      qemu-img            convert -f vmdk -O raw   (preferred: single output
                          file, well-defined behaviour, no VM registration)
      vmware-vdiskmanager -r -t 0                  (ships with Workstation,
                          so needs no extra install; emits a descriptor plus
                          a '-flat.vmdk' payload which IS raw sectors)
    """

    def __init__(self, qemu_img: str | None, vdiskmanager: str | None):
        self.qemu_img = qemu_img if qemu_img and self._usable(qemu_img) else None
        self.vdiskmanager = (vdiskmanager
                             if vdiskmanager and self._usable(vdiskmanager)
                             else None)

    @staticmethod
    def _usable(path: str) -> bool:
        return Path(path).exists() or shutil.which(Path(path).name) is not None

    def available(self) -> bool:
        return bool(self.qemu_img or self.vdiskmanager)

    def backend(self) -> str:
        return "qemu-img" if self.qemu_img else (
            "vmware-vdiskmanager" if self.vdiskmanager else "none")

    def flatten(self, source_vmdk: Path, out_raw: Path) -> Path:
        """Produce a raw image at (or alongside) out_raw and return its path."""
        out_raw.parent.mkdir(parents=True, exist_ok=True)
        for stale in (out_raw, out_raw.with_suffix(".vmdk"),
                      Path(str(out_raw.with_suffix("")) + "-flat.vmdk")):
            if stale.exists():
                stale.unlink()

        if self.qemu_img:
            log.info("flattening %s with qemu-img", source_vmdk.name)
            cmd = [self.qemu_img, "convert", "-f", "vmdk", "-O", "raw",
                   str(source_vmdk), str(out_raw)]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=7200)
            if proc.returncode != 0:
                raise VMwareError(
                    "qemu-img convert failed: "
                    f"{(proc.stderr or proc.stdout).strip()[:500]}"
                )
            return out_raw

        if self.vdiskmanager:
            # -t 0 = monolithic flat. Output is '<stem>.vmdk' (text descriptor)
            # + '<stem>-flat.vmdk' (raw sectors). TSK reads the latter.
            log.info("flattening %s with vmware-vdiskmanager", source_vmdk.name)
            target_desc = out_raw.with_suffix(".vmdk")
            cmd = [self.vdiskmanager, "-r", str(source_vmdk), "-t", "0",
                   str(target_desc)]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=7200)
            flat = Path(str(target_desc.with_suffix("")) + "-flat.vmdk")
            if proc.returncode != 0 or not flat.exists():
                raise VMwareError(
                    "vmware-vdiskmanager failed: "
                    f"{(proc.stdout or proc.stderr).strip()[:500]}"
                )
            return flat

        raise VMwareError(
            "no disk flattening backend available; install qemu-img or set "
            "paths.vdiskmanager to vmware-vdiskmanager.exe"
        )

    @staticmethod
    def cleanup(raw_path: Path):
        """Remove the flattened image and any sidecar descriptor.

        A 4 GB raw per run would exhaust the host disk within ~20 runs. The
        extracted journals are the artefact worth keeping, not the image.
        """
        for p in (raw_path,
                  raw_path.with_suffix(".vmdk"),
                  Path(str(raw_path).replace("-flat.vmdk", ".vmdk"))):
            try:
                if p.exists() and p.is_file():
                    p.unlink()
            except OSError as exc:
                log.warning("could not remove %s: %s", p.name, exc)

# ---------------------------------------------------------------------------
# Installation discovery
#
# Workstation's install location moved: 17.x and later install the 64-bit
# binaries under %ProgramFiles%, whereas older releases used
# %ProgramFiles(x86)%. Hardcoding either is wrong for half of installs, so
# the harness discovers the real path and reports it rather than failing with
# a bare "not found".
# ---------------------------------------------------------------------------

_VMWARE_DIRS = [
    r"C:\Program Files\VMware\VMware Workstation",
    r"C:\Program Files (x86)\VMware\VMware Workstation",
    r"C:\Program Files\VMware\VMware Player",
    r"C:\Program Files (x86)\VMware\VMware Player",
]

_VMWARE_REG_KEYS = [
    (r"SOFTWARE\VMware, Inc.\VMware Workstation", "InstallPath"),
    (r"SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation", "InstallPath"),
]


def _registry_install_dirs() -> list[Path]:
    """Read Workstation's InstallPath from the registry. Windows only."""
    dirs: list[Path] = []
    try:
        import winreg  # noqa: PLC0415 - Windows-only, imported lazily
    except ImportError:
        return dirs
    for subkey, value in _VMWARE_REG_KEYS:
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    path, _ = winreg.QueryValueEx(key, value)
                    if path:
                        dirs.append(Path(path))
            except OSError:
                continue
    return dirs


def find_vmware_tool(exe: str = "vmrun.exe",
                     configured: str | None = None) -> Path | None:
    """Locate a Workstation executable, preferring an explicit config value.

    Search order: the configured path, PATH, the registry InstallPath, then
    the known install directories for both Program Files variants.
    """
    if configured:
        candidate = Path(configured)
        if candidate.exists():
            return candidate

    on_path = shutil.which(exe)
    if on_path:
        return Path(on_path)

    for base in _registry_install_dirs() + [Path(d) for d in _VMWARE_DIRS]:
        candidate = base / exe
        if candidate.exists():
            return candidate
    return None

def find_vmx_files() -> list[tuple[Path, str]]:
    """Locate .vmx files on this host, most authoritative source first.

    Returns (path, source) pairs. Three sources, in order of reliability:

      1. Workstation's own preferences.ini, which records a most-recently-used
         list as pref.mruVM<N>.filename. This is exact: it names VMs the
         installed Workstation actually knows about.
      2. The configured default VM directory from the same file
         (prefvmx.defaultVMPath), scanned one level deep.
      3. The documented default location, %USERPROFILE%\\Documents\\Virtual
         Machines, plus a couple of conventional roots.

    A whole-drive recursive scan is deliberately avoided: it takes minutes and
    the MRU list almost always answers first.
    """
    import os

    found: list[tuple[Path, str]] = []
    seen: set[Path] = set()

    def add(path: Path, source: str):
        try:
            resolved = path.resolve()
        except OSError:
            return
        if resolved.exists() and resolved.suffix.lower() == ".vmx" \
                and resolved not in seen:
            seen.add(resolved)
            found.append((resolved, source))

    appdata = os.environ.get("APPDATA")
    prefs = Path(appdata) / "VMware" / "preferences.ini" if appdata else None

    default_vm_dir: Path | None = None
    if prefs and prefs.exists():
        try:
            text = prefs.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        for line in text.splitlines():
            m = re.match(r'\s*pref\.mruVM\d+\.filename\s*=\s*"(.+?)"', line)
            if m:
                add(Path(m.group(1)), "Workstation recent-VM list")
                continue
            m = re.match(r'\s*prefvmx\.defaultVMPath\s*=\s*"(.+?)"', line)
            if m:
                default_vm_dir = Path(m.group(1))

    search_dirs: list[Path] = []
    if default_vm_dir:
        search_dirs.append(default_vm_dir)
    home = os.environ.get("USERPROFILE")
    if home:
        search_dirs.append(Path(home) / "Documents" / "Virtual Machines")
    search_dirs += [Path(r"C:\VMs"), Path(r"D:\VMs")]

    for base in search_dirs:
        if not base.is_dir():
            continue
        try:
            # One level of VM folders, which is how Workstation lays them out.
            for child in base.iterdir():
                if child.is_dir():
                    for vmx in child.glob("*.vmx"):
                        add(vmx, f"found under {base}")
                elif child.suffix.lower() == ".vmx":
                    add(child, f"found under {base}")
        except OSError:
            continue

    return found

# ---------------------------------------------------------------------------
# VMDK geometry
#
# A snapshot delta holds only the writes made since the snapshot, so its file
# size is near zero regardless of the underlying disk's capacity and cannot be
# used to tell a 32 GB system disk from a 2 GB evidence disk. The declared
# capacity is recorded inside the VMDK itself, in one of two forms:
#
#   monolithicSparse : binary SparseExtentHeader, magic "KDMV", with capacity
#                      as a uint64 sector count at offset 12
#   flat / split     : a plain-text descriptor whose extent lines read
#                      RW <sectors> FLAT|SPARSE "<file>"
#
# Both a base disk and its deltas record the full virtual capacity, so reading
# whichever file the .vmx points at gives the right answer.
# ---------------------------------------------------------------------------

_SECTOR = 512
_VMDK_MAGIC = b"KDMV"
_EXTENT_RE = re.compile(r'^\s*(?:RW|RDONLY|NOACCESS)\s+(\d+)\s+\w+',
                        re.IGNORECASE | re.MULTILINE)


def vmdk_capacity_bytes(path: Path) -> int | None:
    """Declared virtual capacity of a VMDK, or None if it cannot be read."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(2048)
    except OSError:
        return None

    if head[:4] == _VMDK_MAGIC:
        import struct
        try:
            (sectors,) = struct.unpack_from("<Q", head, 12)
        except struct.error:
            return None
        return sectors * _SECTOR if sectors else None

    # Text descriptor: sum the extent sector counts.
    try:
        text = head.decode("ascii", errors="ignore")
    except Exception:
        return None
    sectors = sum(int(m.group(1)) for m in _EXTENT_RE.finditer(text))
    return sectors * _SECTOR if sectors else None


def vmdk_chain(path: Path) -> list[Path]:
    """Walk parentFileNameHint from a delta back to its base disk."""
    chain, seen, current = [], set(), path
    while current and current.exists() and current not in seen:
        seen.add(current)
        chain.append(current)
        parent = None
        try:
            with open(current, "rb") as fh:
                blob = fh.read(2048).decode("ascii", errors="ignore")
            m = re.search(r'parentFileNameHint\s*=\s*"(.+?)"', blob)
            if m:
                parent = (current.parent / m.group(1)).resolve()
        except OSError:
            parent = None
        current = parent
    return chain


def vmdk_consumed_bytes(path: Path) -> int:
    """Total bytes the whole snapshot chain actually occupies on the host."""
    total = 0
    for part in vmdk_chain(path):
        try:
            total += part.stat().st_size
        except OSError:
            continue
        # Split extents sit beside the descriptor as <stem>-s###.vmdk.
        for extent in part.parent.glob(part.stem + "-s*.vmdk"):
            try:
                total += extent.stat().st_size
            except OSError:
                continue
    return total
