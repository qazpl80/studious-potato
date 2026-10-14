#!/usr/bin/env python3
"""WiperTrace data-generation harness — host orchestrator (VMware Workstation).

Produces a labelled corpus of NTFS volumes wiped by known tools, for
evaluating wiper-attribution signatures. One run executes six stages:

    1  REVERT    roll the VM back to the clean baseline snapshot
    2  BOOT      power on headless and wait for VIX guest operations
    3  GUEST     stage and execute the guest agent (ground truth -> install
                 -> wipe -> VSS collection -> manifest -> zip)
    4  RETRIEVE  pull manifest.json, guest.log and collected.zip out
    5  SHUTDOWN  stop the VM, clean or hard per the matrix
    6  EXTRACT   flatten the live VMDK chain and carve $MFT, $LogFile and
                 $UsnJrnl:$J out of the cold image with The Sleuth Kit

Usage
-----
    python runner.py --check                    validate the environment
    python runner.py --show-disks               list .vmx disk attachments
    python runner.py --snapshots                list snapshots
    python runner.py --list                     print the matrix, run nothing
    python runner.py --tool sdelete --mode p3 --limit 1 -v
    python runner.py --all
    python runner.py --all --resume             skip runs already completed

Design invariant: nothing reads the evidence volume while the guest is
running. Journals are carved from a cold, flattened image only.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
import time
import zipfile
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")

# The harness is a package of sibling modules, not a single script. Copying
# runner.py alone produces a bare ModuleNotFoundError that does not say why,
# so the import is guarded to name exactly what is missing and where it
# should sit.
try:
    from vmware import (VMware, VMwareError, DiskFlattener,
                        parse_vmx_disks, resolve_active_disk, find_vmware_tool,
                        find_vmx_files, vmdk_capacity_bytes,
                        vmdk_consumed_bytes, vmdk_chain)
    from extract import extract_journals, extract_system_artifacts
except ImportError as _exc:
    _here = Path(__file__).resolve().parent
    _required = {
        "vmware.py": "VMware Workstation control layer",
        "extract.py": "offline NTFS carving via The Sleuth Kit",
        "config.yaml": "tool matrix and paths",
        "guest/run_wipe.ps1": "per-run guest agent",
        "guest/prepare_baseline.ps1": "one-time baseline preparation",
        "parse/parse_runs.py": "parsing and labelling stage",
        "tools/check_installers.py": "ISO staging validator",
    }
    _missing = [(f, d) for f, d in _required.items() if not (_here / f).exists()]

    print(f"Import failed: {_exc}\n", file=sys.stderr)
    print(f"The harness expects its files together in one folder:\n  {_here}\n",
          file=sys.stderr)
    if _missing:
        print("Missing from that folder:", file=sys.stderr)
        for f, d in _missing:
            print(f"  {f:<30} {d}", file=sys.stderr)
        print("\nExtract the whole wipertrace-vmware folder from the archive "
              "rather than copying\nindividual files, then run the harness "
              "from inside it.", file=sys.stderr)
    else:
        print("All expected files are present, so this is likely a name "
              "collision: another\nfile or installed package called 'vmware' "
              "or 'extract' is shadowing ours.\nRun with -v and check "
              "sys.path.", file=sys.stderr)
    sys.exit(1)

log = logging.getLogger("runner")

# The guest agent ships beside this file, so it is resolved relative to the
# module rather than to config.yaml. This keeps --config pointing anywhere
# (a per-operator override, a CI copy) from breaking the agent lookup.
REPO_DIR = Path(__file__).resolve().parent
GUEST_AGENT = REPO_DIR / "guest" / "run_wipe.ps1"

# Guest-side layout. Must agree with guest/run_wipe.ps1.
GUEST_WORK = "C:\\_run"
GUEST_SCRIPT = GUEST_WORK + "\\run_wipe.ps1"
GUEST_PLAN = GUEST_WORK + "\\plan.json"
GUEST_MANIFEST = GUEST_WORK + "\\manifest.json"
GUEST_LOG = GUEST_WORK + "\\guest.log"
GUEST_ZIP = GUEST_WORK + "\\collected.zip"
GUEST_STATUS = GUEST_WORK + "\\_STATUS.txt"


# ---------------------------------------------------------------------------
# Experimental matrix
# ---------------------------------------------------------------------------

@dataclass
class Run:
    index: int
    tool_id: str
    mode: str
    shutdown: str
    repeat: int

    @property
    def run_id(self) -> str:
        return (f"{self.index:04d}_{self.tool_id}_{self.mode}"
                f"_{self.shutdown}_r{self.repeat}")


def build_matrix(cfg: dict, only_tool: str | None = None,
                 only_mode: str | None = None) -> list[Run]:
    """Cartesian product of tool x mode x shutdown x repeat.

    Repeats are not redundancy: wiper behaviour varies with cluster
    allocation state and timing, so a single observation per configuration
    cannot distinguish a tool's signature from an artefact of one run.
    """
    repeats = int(cfg["matrix"]["repeats"])
    shutdowns = cfg["matrix"]["shutdown_modes"]
    runs, index = [], 0
    for tool_id, tool in cfg["tools"].items():
        # A tool can be disabled rather than deleted, so the config keeps a
        # record of what was evaluated and why it was excluded. --tool still
        # selects a disabled tool explicitly, which is useful for re-testing.
        if tool.get("enabled", True) is False and tool_id != only_tool:
            continue
        if only_tool and tool_id != only_tool:
            continue
        for mode in tool.get("modes", {}):
            if only_mode and mode != only_mode:
                continue
            for shutdown in shutdowns:
                for repeat in range(1, repeats + 1):
                    index += 1
                    runs.append(Run(index, tool_id, mode, shutdown, repeat))
    return runs


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class Harness:
    def __init__(self, cfg: dict, cfg_path: Path):
        self.cfg = cfg
        self.cfg_dir = cfg_path.parent
        # Relative work paths anchor to the repo, not the caller's cwd, so
        # runs land in the same place regardless of where python is invoked.
        work = Path(cfg["paths"]["work"])
        self.root = work.resolve() if work.is_absolute() else (REPO_DIR / work).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

        self.script = GUEST_AGENT
        if not self.script.exists():
            sys.exit(f"missing guest agent: {self.script}")

        vm = cfg["vm"]
        self.vmx = Path(vm["vmx"]).resolve()
        self.vm = VMware(cfg["paths"]["vmrun"], str(self.vmx),
                         vm["guest_user"], vm["guest_pass"],
                         vm.get("host_type", "ws"),
                         vm.get("encryption_password"))
        self.flattener = DiskFlattener(cfg["paths"].get("qemu_img"),
                                       cfg["paths"].get("vdiskmanager"))
        self.tsk_bin = cfg["paths"].get("tsk_bin")
        self.compress = bool(cfg.get("extract", {}).get("compress", True))
        # Show the VM window during runs (default). Windows 11 hosts throttle
        # a VM with no window - it can sit at "Tools installed" for minutes
        # until the window is opened - so a visible window is the reliable
        # default. Has no effect on the evidence; guest ops are identical.
        # config vm.gui sets the default; --gui / --headless override it.
        self.gui = bool(cfg["vm"].get("gui", True))

    # -- run plan ----------------------------------------------------------

    def _plan(self, run: Run) -> dict:
        """Flatten config.yaml into the single-run contract the guest reads."""
        tool = self.cfg["tools"][run.tool_id]
        mode = tool["modes"][run.mode]
        # Per-tool settle overrides the VM-wide default: an asynchronous
        # wiper (Eraser) keeps its service busy after the targets vanish.
        settle = tool.get("settle_seconds",
                          self.cfg["vm"].get("settle_seconds", 15))
        return {
            "display": tool.get("display", run.tool_id),
            "install": tool.get("install"),
            # Path that must exist after install; the agent fails the run if
            # it never appears instead of "wiping" with a missing binary.
            "binary": tool.get("binary"),
            # Seconds to wait for targets to disappear after the wipe
            # commands return (0 = do not wait; synchronous tools).
            "await_targets_sec": int(tool.get("await_targets_sec", 0)),
            "install_timeout_sec": int(tool.get("install_timeout_sec", 300)),
            "wipe_timeout_sec": int(tool.get("wipe_timeout_sec", 300)),
            "once_timeout_sec": int(tool.get("once_timeout_sec", 3600)),
            "pre": mode.get("pre"),
            "per_file": mode.get("per_file"),
            "once": mode.get("once"),
            "corpus_dir": self.cfg["corpus"]["guest_dir"],
            "wipe_count": int(self.cfg["corpus"]["wipe_count"]),
            "settle_seconds": int(settle),
        }

    # -- the six stages ----------------------------------------------------

    def execute(self, run: Run) -> dict:
        out = self.root / run.run_id
        out.mkdir(parents=True, exist_ok=True)
        status = {
            "run_id": run.run_id,
            "hypervisor": "VMware Workstation",
            "started_utc": datetime.now(timezone.utc).isoformat(),
            "matrix": asdict(run),
            "stages": {},
        }

        try:
            self._stage_revert(run, status)
            self._stage_boot(run, status)
            self._stage_guest(run, out, status)
            self._stage_retrieve(run, out, status)
            self._stage_shutdown(run, status)
            self._stage_extract(run, out, status)
            status["result"] = "ok"
        except Exception as exc:
            log.error("[%s] FAILED: %s", run.run_id, exc)
            status["result"] = "failed"
            status["error"] = f"{type(exc).__name__}: {exc}"
            # Leave the VM powered off unconditionally: a VM left running
            # holds VMDK locks and the next revert would fail, cascading one
            # bad run into the rest of the matrix.
            try:
                self.vm.stop(hard=True)
            except Exception:
                pass
        except KeyboardInterrupt:
            # Ctrl+C is not an Exception subclass, so without this branch an
            # interrupted run leaves the VM running headless and invisible -
            # holding its locks, so the next revert fails.
            log.warning("[%s] interrupted - powering the VM off", run.run_id)
            status["result"] = "interrupted"
            try:
                self.vm.stop(hard=True)
            except Exception:
                log.warning("could not stop the VM; power it off in "
                            "Workstation before the next run")
            raise
        finally:
            status["finished_utc"] = datetime.now(timezone.utc).isoformat()
            (out / "status.json").write_text(json.dumps(status, indent=2),
                                             encoding="utf-8")
        return status

    def _stage_revert(self, run: Run, status: dict):
        """STAGE 1. Re-anchor to the baseline.

        This both discards the previous run's wiping tool installation and
        resets the evidence volume's journals, so each run observes a wipe
        against an identical starting state.
        """
        self.vm.revert(self.cfg["vm"]["snapshot"])
        status["stages"]["revert"] = "ok"

    def _stage_boot(self, run: Run, status: dict):
        """STAGE 2. Power on and wait for the guest-ops channel."""
        self.vm.start(headless=not self.gui)
        self.vm.wait_for_guest(int(self.cfg["vm"].get("boot_timeout", 420)))
        # The guest answers the instant the desktop session exists, while
        # Explorer, startup apps and logon scheduled tasks are still running.
        # Starting the agent then puts that burst of activity alongside the
        # ground-truth capture and the install, and makes runs less alike.
        # A fixed quiet period lets every run start from a settled desktop.
        settle = int(self.cfg["vm"].get("post_logon_settle", 45))
        if settle > 0:
            log.info("[%s] desktop up; letting logon activity settle for %ds",
                     run.run_id, settle)
            time.sleep(settle)
        status["stages"]["boot"] = "ok"

    def _stage_guest(self, run: Run, out: Path, status: dict):
        """STAGE 3. Stage the agent and run it.

        vmrun discards guest stdout, so success is determined solely by the
        _STATUS.txt sentinel the agent writes. The vmrun return code is
        recorded but treated as advisory.
        """
        log.info("[%s] staging guest agent", run.run_id)
        plan_local = out / "plan.json"
        plan_local.write_text(json.dumps(self._plan(run), indent=2),
                              encoding="utf-8")

        self.vm.mkdir_guest(GUEST_WORK)
        self.vm.copy_to_guest(self.script, GUEST_SCRIPT)
        self.vm.copy_to_guest(plan_local, GUEST_PLAN)

        log.info("[%s] executing wipe in guest (no stdout; see guest.log)",
                 run.run_id)
        rc = self.vm.run_powershell(
            GUEST_SCRIPT, [run.run_id, run.tool_id, run.mode, GUEST_PLAN])
        status["stages"]["guest_vmrun_rc"] = rc

        # Authoritative verdict: the sentinel.
        verdict = "(absent)"
        sentinel = out / "_STATUS.txt"
        try:
            self.vm.copy_from_guest(GUEST_STATUS, sentinel)
            verdict = sentinel.read_text(encoding="utf-8",
                                         errors="replace").strip()
        except VMwareError as exc:
            log.error("[%s] could not read guest status sentinel: %s",
                      run.run_id, exc)

        status["stages"]["guest_verdict"] = verdict
        if verdict != "OK":
            # Retrieve the log before raising, so the failure is diagnosable.
            try:
                self.vm.copy_from_guest(GUEST_LOG, out / "guest.log")
            except VMwareError:
                pass
            raise RuntimeError(f"guest agent reported: {verdict}")

    def _stage_retrieve(self, run: Run, out: Path, status: dict):
        """STAGE 4. Pull the manifest, log and artefact archive.

        These all originate on C:. Transferring them over the VIX channel
        does not perturb the evidence volume (D:), whose journals are still
        untouched at this point.
        """
        log.info("[%s] retrieving guest outputs", run.run_id)
        self.vm.copy_from_guest(GUEST_MANIFEST, out / "manifest.json")
        self.vm.copy_from_guest(GUEST_LOG, out / "guest.log")

        zip_local = out / "collected.zip"
        try:
            self.vm.copy_from_guest(GUEST_ZIP, zip_local)
            with zipfile.ZipFile(zip_local) as zf:
                zf.extractall(out / "artifacts")
            zip_local.unlink()
            status["stages"]["retrieve"] = "ok"
        except (VMwareError, zipfile.BadZipFile, OSError) as exc:
            # Missing C: artefacts degrade the run but do not invalidate the
            # journal evidence, which is the primary measurement.
            log.warning("[%s] artefact archive unavailable: %s", run.run_id, exc)
            status["stages"]["retrieve"] = f"degraded: {exc}"

    def _stage_shutdown(self, run: Run, status: dict):
        """STAGE 5. Stop the VM in the mode this run is testing."""
        self.vm.stop(hard=(run.shutdown == "hard"))
        status["stages"]["shutdown"] = run.shutdown

    def _stage_extract(self, run: Run, out: Path, status: dict):
        """STAGE 6. Cold extraction from the flattened snapshot chain head.

        resolve_active_disk() is the critical call: it reads the .vmx to find
        the delta file that Workstation redirected writes to when the
        baseline snapshot was created. Imaging the base VMDK instead would
        return the pristine baseline and silently produce a dataset in which
        no wipe ever occurred.
        """
        log.info("[%s] resolving evidence disk", run.run_id)
        device = self.cfg["disks"]["data_device"]
        active = resolve_active_disk(self.vmx, device)
        log.info("[%s] %s -> %s", run.run_id, device, active.name)

        raw = self.flattener.flatten(active, out / "data.raw")
        try:
            status["stages"]["extract"] = extract_journals(
                raw, out / "evidence", self.tsk_bin, compress=self.compress)
            status["stages"]["extract_source"] = active.name
            status["stages"]["flatten_backend"] = self.flattener.backend()
        finally:
            # A 4 GB raw per run exhausts host storage within ~20 runs; the
            # carved journals are the artefact worth retaining.
            self.flattener.cleanup(raw)

        if self.cfg["disks"].get("system_offline"):
            log.info("[%s] cold-imaging system disk", run.run_id)
            sys_active = resolve_active_disk(
                self.vmx, self.cfg["disks"]["system_device"])
            sys_raw = self.flattener.flatten(sys_active, out / "system.raw")
            try:
                status["stages"]["extract_system"] = extract_system_artifacts(
                    sys_raw, out / "artifacts_offline", self.tsk_bin)
            finally:
                self.flattener.cleanup(sys_raw)


# ---------------------------------------------------------------------------
# Environment validation
# ---------------------------------------------------------------------------

def preflight(cfg: dict, cfg_path: Path) -> list[str]:
    """Fail fast on misconfiguration rather than at run 40 of 72."""
    problems: list[str] = []

    # Workstation 17+ installs under %ProgramFiles%; older releases used
    # %ProgramFiles(x86)%. Rather than just reporting the configured path as
    # missing, discover the real one and name it, since that is the fix.
    configured_vmrun = cfg["paths"]["vmrun"]
    if not Path(configured_vmrun).exists():
        found = find_vmware_tool("vmrun.exe", configured_vmrun)
        if found:
            problems.append(
                f"vmrun not at the configured path ({configured_vmrun}) "
                f"but found at: {found}\n"
                f"    -> set paths.vmrun to: {str(found).replace(chr(92), '/')}")
        else:
            problems.append(
                f"vmrun not found at {configured_vmrun}, nor in PATH, the "
                "registry, or the standard install directories. Run "
                "`py runner.py --find-vmware`.")

    vmx = Path(cfg["vm"]["vmx"])
    if not vmx.exists():
        problems.append(f".vmx not found at {vmx}")
    else:
        disks = parse_vmx_disks(vmx)
        device = cfg["disks"]["data_device"].lower()
        if device not in disks:
            problems.append(
                f"disks.data_device {device!r} is not attached in {vmx.name}; "
                f"found {', '.join(sorted(disks)) or '(none)'} "
                "— run --show-disks")

    flat = DiskFlattener(cfg["paths"].get("qemu_img"),
                         cfg["paths"].get("vdiskmanager"))
    if not flat.available():
        found = find_vmware_tool("vmware-vdiskmanager.exe",
                                 cfg["paths"].get("vdiskmanager"))
        if found:
            problems.append(
                f"vmware-vdiskmanager found at: {found}\n"
                f"    -> set paths.vdiskmanager to: "
                f"{str(found).replace(chr(92), '/')}")
        else:
            problems.append("no disk flattening backend: set "
                            "paths.vdiskmanager or paths.qemu_img")

    tsk_bin = cfg["paths"].get("tsk_bin")
    for name in ("mmls", "fsstat", "fls", "istat", "icat"):
        found = shutil.which(name)
        if not found and tsk_bin:
            found = ((Path(tsk_bin) / f"{name}.exe").exists()
                     or (Path(tsk_bin) / name).exists())
        if not found:
            problems.append(f"Sleuth Kit binary '{name}' not found")

    problems.extend(check_guest_agent(GUEST_AGENT))

    if not cfg["vm"].get("guest_pass"):
        problems.append("vm.guest_pass is empty; VIX guest ops require a "
                        "non-empty password")

    # Live probe. A .vmx that exists on disk is not the same as a .vmx
    # Workstation can open: an encrypted VM needs -vp, and without it every
    # operation fails at run time while a file-existence check passes.
    vmrun_path = Path(configured_vmrun)
    vmrun_available = (vmrun_path.exists()
                       or shutil.which(vmrun_path.name) is not None)
    if vmx.exists() and vmrun_available:
        probe = VMware(cfg["paths"]["vmrun"], str(vmx),
                       cfg["vm"].get("guest_user", ""),
                       cfg["vm"].get("guest_pass", ""),
                       cfg["vm"].get("host_type", "ws"),
                       cfg["vm"].get("encryption_password"))
        try:
            snaps = probe.list_snapshots()
        except VMwareError as exc:
            problems.append(f"vmrun cannot open the VM:\n    {exc}")
        except Exception as exc:
            problems.append(f"vmrun probe failed: {type(exc).__name__}: {exc}")
        else:
            want = cfg["vm"]["snapshot"]
            if want not in snaps:
                listed = ", ".join(snaps) if snaps else "(none)"
                problems.append(
                    f"baseline snapshot {want!r} does not exist. "
                    f"Snapshots present: {listed}\n"
                    f"    -> take a snapshot named exactly {want!r} with the "
                    "VM powered off, or\n       change vm.snapshot to match "
                    "an existing one.")
            elif len(snaps) > 1:
                print(f"note: {len(snaps)} snapshots present "
                      f"({', '.join(snaps)}). A deep chain slows every revert "
                      "and\n      flatten; consider deleting all but "
                      f"{want!r} in Snapshot Manager.")

    return problems



def check_guest_agent(path: Path) -> list[str]:
    """Validate the guest agent's encoding before it is ever executed.

    Windows PowerShell 5.1 reads a .ps1 without a byte-order mark using the
    system ANSI code page, not UTF-8. A multi-byte UTF-8 character therefore
    decodes into mojibake, and because CP1252 maps 0x93/0x94 to curly quote
    characters, a stray em dash can break the tokenizer's quote pairing and
    produce cascading syntax errors pointing at unrelated lines.

    Keeping the agent pure ASCII with CRLF endings and a BOM makes it parse
    identically under every encoding. This check exists because the failure
    is silent until a run executes, and the reported error location is
    actively misleading.
    """
    problems: list[str] = []
    if not path.exists():
        return [f"guest agent missing: {path}"]

    raw = path.read_bytes()
    has_bom = raw.startswith(b"\xef\xbb\xbf")
    body = raw[3:] if has_bom else raw

    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [f"{path.name} is not valid UTF-8: {exc}"]

    non_ascii = sorted({c for c in text if ord(c) > 127})
    if non_ascii:
        shown = ", ".join(f"U+{ord(c):04X}" for c in non_ascii[:6])
        problems.append(
            f"{path.name} contains non-ASCII characters ({shown}). "
            "Windows PowerShell 5.1 may misread these and report syntax "
            "errors on unrelated lines. Replace them with ASCII.")

    crlf = body.count(b"\r\n")
    bare_lf = text.count("\n") - crlf
    if bare_lf:
        problems.append(
            f"{path.name} has {bare_lf} LF-only line ending(s); save it with "
            "CRLF, as PowerShell 5.1 mis-parses some constructs otherwise.")

    if not has_bom and non_ascii:
        problems.append(f"{path.name} has no UTF-8 BOM but is not ASCII.")

    if "@\"" in text or "@'" in text:
        problems.append(
            f"{path.name} contains a here-string; these parse differently "
            "depending on line endings. Prefer a string array.")

    return problems


def already_done(root: Path, run: Run) -> bool:
    status = root / run.run_id / "status.json"
    if not status.exists():
        return False
    try:
        return json.loads(status.read_text())["result"] == "ok"
    except Exception:
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="WiperTrace data-generation harness (VMware Workstation)")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--check", action="store_true",
                    help="validate paths, vmrun, flattener and TSK, then exit")
    ap.add_argument("--find-vmware", action="store_true",
                    help="locate the Workstation executables and exit")
    ap.add_argument("--show-disks", action="store_true",
                    help="list disk attachments in the .vmx and exit")
    ap.add_argument("--snapshots", action="store_true",
                    help="list the VM's snapshots and exit")
    ap.add_argument("--list", action="store_true",
                    help="print the run matrix and exit")
    ap.add_argument("--all", action="store_true", help="execute the full matrix")
    ap.add_argument("--tool", help="restrict to one tool id")
    ap.add_argument("--mode", help="restrict to one mode")
    ap.add_argument("--resume", action="store_true",
                    help="skip runs whose status.json reports ok")
    ap.add_argument("--limit", type=int, help="stop after N runs")
    ap.add_argument("--boot-test", action="store_true",
                    help="revert to the baseline, boot WITH a window, wait for "
                         "guest operations, and LEAVE THE VM RUNNING so you "
                         "can see why it is not becoming ready")
    view = ap.add_mutually_exclusive_group()
    view.add_argument("--gui", dest="gui", action="store_true", default=None,
                      help="show the VM window during runs (the default; "
                           "overrides vm.gui: false)")
    view.add_argument("--headless", dest="gui", action="store_false",
                      help="run the VM with no window (needs the power-"
                           "throttling exemption in README Part 5)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)-8s %(message)s",
        datefmt="%H:%M:%S",
    )

    cfg_path = Path(args.config).resolve()
    if not cfg_path.exists():
        sys.exit(f"config not found: {cfg_path}")
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))

    # -- informational modes (no VM state change) --------------------------

    if args.find_vmware:
        print("Locating VMware Workstation executables...\n")
        any_missing = False
        for exe, key in (("vmrun.exe", "vmrun"),
                         ("vmware-vdiskmanager.exe", "vdiskmanager")):
            configured = cfg["paths"].get(key)
            found = find_vmware_tool(exe, configured)
            if found:
                as_cfg = str(found).replace("\\", "/")
                match = "  (matches config)" if (
                    configured and Path(configured) == found) else ""
                print(f"  {exe:<28} {found}{match}")
                if not match:
                    print(f"  {'':<28} -> set paths.{key} to: {as_cfg}")
            else:
                any_missing = True
                print(f"  {exe:<28} NOT FOUND")
        if any_missing:
            print("\nIf Workstation is installed elsewhere, find it with:")
            print('  where /r "C:\\Program Files" vmrun.exe')

        # Also locate the VM itself, since vm.vmx is the other path that must
        # be set before anything runs.
        print("\nLocating virtual machines...\n")
        configured_vmx = Path(cfg["vm"]["vmx"])
        vms = find_vmx_files()
        if not vms:
            print("  no .vmx files found in Workstation's recent-VM list or "
                  "the default\n  VM directories. If your VM lives elsewhere, "
                  "search for it with:")
            print('    Get-ChildItem C:\\ -Recurse -Filter *.vmx '
                  '-ErrorAction SilentlyContinue | Select FullName')
        else:
            resolved_cfg = (configured_vmx.resolve()
                            if configured_vmx.exists() else None)
            for path, source in vms:
                match = "  (matches config)" if path == resolved_cfg else ""
                print(f"  {path}{match}")
                print(f"      via {source}")
            if not configured_vmx.exists():
                best = str(vms[0][0]).replace("\\", "/")
                print(f"\n  config.vm.vmx currently points at "
                      f"{cfg['vm']['vmx']}, which does not exist.")
                print(f"  -> set vm.vmx to: {best}")
        return

    if args.show_disks:
        vmx = Path(cfg["vm"]["vmx"])
        if not vmx.exists():
            sys.exit(f".vmx not found: {vmx}")
        disks = parse_vmx_disks(vmx)
        if not disks:
            sys.exit(f"no virtual disks found in {vmx.name}")
        print(f"disk attachments in {vmx.name}:\n")
        print(f"  {'device':<10} {'backing file':<34} {'capacity':>9} "
              f"{'on host':>9}  {'chain':>5}")
        print(f"  {'-'*10} {'-'*34} {'-'*9} {'-'*9}  {'-'*5}")

        configured = cfg["disks"]["data_device"].lower()
        smallest = (None, None)

        for device, backing in sorted(disks.items()):
            path = (vmx.parent / backing).resolve()
            if not path.exists():
                print(f"  {device:<10} {backing:<34} {'MISSING':>9}")
                continue

            # Capacity comes from the VMDK header, not the file size: a
            # snapshot delta holds only post-snapshot writes, so its size is
            # near zero whatever the disk's real capacity.
            cap = vmdk_capacity_bytes(path)
            consumed = vmdk_consumed_bytes(path)
            depth = len(vmdk_chain(path))

            cap_s = f"{cap / 1024**3:.1f} GB" if cap else "unknown"
            use_s = f"{consumed / 1024**3:.1f} GB"
            marker = "  <-- configured" if device == configured else ""
            print(f"  {device:<10} {backing:<34} {cap_s:>9} {use_s:>9}  "
                  f"{depth:>5}{marker}")

            if cap and (smallest[1] is None or cap < smallest[1]):
                smallest = (device, cap)

        print("\n  capacity = declared virtual size, read from the VMDK header")
        print("  on host  = bytes the whole snapshot chain occupies now")
        print("  chain    = files from this delta back to the base disk")

        if smallest[0]:
            if smallest[0] == configured:
                print(f"\nThe configured evidence disk ({configured}) is the "
                      f"smaller one. That looks right.")
            else:
                print(f"\nThe smallest disk is {smallest[0]} "
                      f"({smallest[1] / 1024**3:.1f} GB), but "
                      f"disks.data_device is set to {configured}.")
                print(f"  -> the evidence disk is normally the smaller one; "
                      f"set disks.data_device to: {smallest[0]}")

        print("\nNote: with a snapshot present, the backing file above is the "
              "copy-on-write delta,\nwhich is what the harness images - "
              "deliberately, since the base is frozen.")
        return

    if args.boot_test:
        vm = VMware(cfg["paths"]["vmrun"], cfg["vm"]["vmx"],
                    cfg["vm"]["guest_user"], cfg["vm"]["guest_pass"],
                    cfg["vm"].get("host_type", "ws"),
                    cfg["vm"].get("encryption_password"))
        print("BOOT TEST - the VM window will open. Watch it while this runs.\n")
        vm.revert(cfg["vm"]["snapshot"])
        vm.start(headless=False)
        timeout = int(cfg["vm"].get("boot_timeout", 420))
        try:
            vm.wait_for_guest(timeout)
            print("\nPASS: guest operations work. The boot stage is fine; "
                  "run the single test run again.")
        except Exception as exc:
            print(f"\nFAIL: {exc}")
            print("\nThe VM has been LEFT RUNNING. Look at its window:")
            print("  - boot logo / spinning dots  -> Windows is still starting; "
                  "raise vm.boot_timeout")
            print("  - blue recovery or BitLocker screen -> the baseline does "
                  "not boot cleanly; fix it and re-take the snapshot")
            print("  - login screen -> auto-logon missing (README Part 5)")
            print("  - desktop -> in the guest run:  Get-Service VMTools")
            print("    and from the host:  vmrun -T ws -vp <pw> "
                  "checkToolsState \"<vmx>\"")
        print("\nPower the VM off in Workstation when you are done.")
        return

    if args.snapshots:
        vm = VMware(cfg["paths"]["vmrun"], cfg["vm"]["vmx"],
                    cfg["vm"]["guest_user"], cfg["vm"]["guest_pass"],
                    cfg["vm"].get("host_type", "ws"),
                    cfg["vm"].get("encryption_password"))
        snaps = vm.list_snapshots()
        want = cfg["vm"]["snapshot"]
        print("snapshots:")
        for s in snaps:
            print(f"  {s}{'   <-- baseline' if s == want else ''}")
        if want not in snaps:
            print(f"\nWARNING: configured baseline {want!r} does not exist.")
        return

    runs = build_matrix(cfg, args.tool, args.mode)

    if args.list:
        print(f"{len(runs)} runs in the matrix\n")
        for r in runs:
            print(f"  {r.run_id}")
        print(f"\nestimated wall clock at ~9 min/run: "
              f"{len(runs) * 9 / 60:.1f} hours")

        disabled = [(t, d.get("display", t), d.get("disabled_reason", ""))
                    for t, d in cfg["tools"].items()
                    if d.get("enabled", True) is False]
        if disabled:
            print(f"\n{len(disabled)} tool(s) disabled and excluded:")
            for tid, display, reason in disabled:
                print(f"  {tid} ({display})")
                if reason:
                    for line in reason.strip().splitlines():
                        print(f"      {line.strip()}")
            print("\n  Run one anyway with --tool <id>. Each disabled tool's "
                  "reason belongs in\n  the report: tool scriptability is "
                  "itself a finding.")
        return

    if args.check:
        problems = preflight(cfg, cfg_path)
        if problems:
            print("preflight FAILED:")
            for p in problems:
                print(f"  - {p}")
            sys.exit(1)
        flat = DiskFlattener(cfg["paths"].get("qemu_img"),
                             cfg["paths"].get("vdiskmanager"))
        compress = bool(cfg.get("extract", {}).get("compress", True))
        enc = cfg["vm"].get("encryption_password")
        enc_s = f"set, {len(enc)} chars" if enc else "not set"
        print(f"preflight OK (flattening backend: {flat.backend()}; "
              f"evidence compression: {'on' if compress else 'off'}; "
              f"VM encryption password: {enc_s})")
        return

    # -- execution ---------------------------------------------------------

    if not (args.all or args.tool):
        sys.exit("specify --all, or --tool (optionally with --mode). "
                 "Use --list to inspect the matrix first.")

    problems = preflight(cfg, cfg_path)
    if problems:
        # State whether the encryption password was parsed, without printing
        # it: vmrun reports "Incorrect password" for both an absent and a
        # wrong -vp, and a YAML quoting mistake shows up as a wrong length.
        enc = cfg["vm"].get("encryption_password")
        enc_s = f"set, {len(enc)} characters" if enc else "NOT SET"
        print(f"vm.encryption_password: {enc_s}\n")
        print("preflight FAILED - resolve these before running the matrix:")
        for item in problems:
            print(f"  - {item}")
        sys.exit(1)

    harness = Harness(cfg, cfg_path)
    if args.gui is not None:
        harness.gui = args.gui

    if args.resume:
        before = len(runs)
        runs = [r for r in runs if not already_done(harness.root, r)]
        log.info("resume: skipping %d completed runs", before - len(runs))

    if args.limit:
        runs = runs[: args.limit]

    log.info("executing %d runs", len(runs))
    ok = failed = 0
    started = time.time()

    for i, run in enumerate(runs, 1):
        log.info("=== [%d/%d] %s ===", i, len(runs), run.run_id)
        result = harness.execute(run)
        if result["result"] == "ok":
            ok += 1
        else:
            failed += 1
            log.warning("continuing; see runs/%s/status.json", run.run_id)

    mins = (time.time() - started) / 60
    log.info("complete: %d ok, %d failed, %.1f min", ok, failed, mins)
    (harness.root / "_summary.json").write_text(json.dumps({
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "hypervisor": "VMware Workstation",
        "ok": ok, "failed": failed, "minutes": round(mins, 1),
    }, indent=2), encoding="utf-8")

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
