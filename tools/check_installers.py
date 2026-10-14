#!/usr/bin/env python3
"""Validate an ISO staging folder against config.yaml before burning.

Every tool's `install` command in config.yaml names an absolute guest path on
the installers ISO (E:\\... by default). This script maps that drive letter
onto a local staging folder and reports which files are present, missing, or
present under a different name.

    py tools\\check_installers.py --staging C:\\iso_staging
    py tools\\check_installers.py --staging C:\\iso_staging --fix-names

Run it before building the ISO. Catching a wrong filename here costs seconds;
catching it during the matrix costs a run that installs nothing, wipes
nothing, and still produces a complete-looking run folder.

With --fix-names, a file whose name differs but whose folder contains exactly
one plausible installer is renamed to the canonical name config.yaml expects.
Nothing is renamed without confirmation.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")

# Mirrors Get-InstallerPath in guest/run_wipe.ps1: a drive-qualified path
# ending in .exe or .msi, optionally quoted.
INSTALLER_RE = re.compile(r'"?([A-Za-z]:\\[^"]*?\.(?:exe|msi))"?')

# Per-file wipe commands also reference the ISO for portable tools such as
# SDelete, which need no installation but must still be present.
PORTABLE_RE = re.compile(r'"?([A-Za-z]:\\[^"\s]*?\.exe)"?')

INSTALLER_SUFFIXES = (".exe", ".msi")


def _wrap(text: str, width: int) -> list[str]:
    import textwrap
    return textwrap.wrap(text, width) or [""]


def guest_to_staging(guest_path: str, staging: Path) -> Path:
    """Map E:\\bleachbit\\x.exe onto <staging>\\bleachbit\\x.exe."""
    without_drive = guest_path[3:] if guest_path[1:3] == ":\\" else guest_path
    return staging / Path(without_drive.replace("\\", "/"))


def is_disabled(tool: dict) -> bool:
    return tool.get("enabled", True) is False


def collect_expected(cfg: dict, include_disabled: bool = False
                     ) -> tuple[list[tuple[str, str, str]], list[tuple[str, str]]]:
    """Return (expected, skipped).

    expected: (tool_id, kind, guest_path) for every ISO file the enabled
              tools need.
    skipped : (tool_id, disabled_reason) for tools marked enabled: false.
              Their installers are not required on the ISO, because the
              matrix never schedules them - mirroring runner.build_matrix.
    """
    expected: list[tuple[str, str, str]] = []
    skipped: list[tuple[str, str]] = []
    seen: set[str] = set()

    for tool_id, tool in cfg.get("tools", {}).items():
        if is_disabled(tool) and not include_disabled:
            reason = (tool.get("disabled_reason") or "").strip().splitlines()
            skipped.append((tool_id, reason[0] if reason else ""))
            continue
        install = tool.get("install")
        if install:
            m = INSTALLER_RE.search(install)
            if m and m.group(1) not in seen:
                seen.add(m.group(1))
                expected.append((tool_id, "installer", m.group(1)))

        # Portable tools are invoked straight off the ISO by the wipe command.
        for mode in (tool.get("modes") or {}).values():
            for key in ("per_file", "once", "pre"):
                cmd = mode.get(key)
                if not cmd:
                    continue
                for m in PORTABLE_RE.finditer(cmd):
                    path = m.group(1)
                    # Only ISO paths matter; C:\ paths are created by install.
                    if path[:1].upper() == "C":
                        continue
                    if path not in seen:
                        seen.add(path)
                        expected.append((tool_id, "portable", path))
    return expected, skipped


def candidates_in(folder: Path, reserved: set[Path]) -> list[Path]:
    """Installer-like files in a folder, excluding canonical names.

    `reserved` holds every path the config expects. A folder can legitimately
    hold several expected files - the two BleachBit versions share one - so a
    file already serving as another entry's canonical name must never be
    offered as a rename candidate, or accepting the suggestion would rename
    the 6.x installer to the 4.x name and silently collapse the version pair
    into two runs of the same build.
    """
    if not folder.is_dir():
        return []
    return sorted(p for p in folder.iterdir()
                  if p.is_file()
                  and p.suffix.lower() in INSTALLER_SUFFIXES
                  and p not in reserved)


def wrong_build_reason(tool_id: str, name: str) -> str | None:
    """Flag a file that is the wrong *build*, not merely the wrong name.

    Renaming such a file would hide the problem rather than fix it.
    """
    low = name.lower()
    if tool_id == "ccleaner" and "online" in low:
        return ("this is the ONLINE downloader stub. It needs network access "
                "during every install and fetches whatever version is current "
                "that day, so runs would install different versions while "
                "being labelled identically. Download the 'CCleaner, offline "
                "installer' build from https://www.ccleaner.com/ccleaner/builds")
    if low.endswith(".zip"):
        return "this is a portable archive, not an installer"
    return None


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Validate an ISO staging folder against config.yaml")
    ap.add_argument("--staging", required=True,
                    help="local folder that will become the installers ISO")
    ap.add_argument("--config", default=None,
                    help="path to config.yaml (default: alongside this repo)")
    ap.add_argument("--fix-names", action="store_true",
                    help="offer to rename near-matches to the canonical name")
    ap.add_argument("--include-disabled", action="store_true",
                    help="also require installers for tools marked "
                         "enabled: false (only needed to re-test them)")
    args = ap.parse_args()

    repo = Path(__file__).resolve().parent.parent
    cfg_path = Path(args.config).resolve() if args.config else repo / "config.yaml"
    if not cfg_path.exists():
        return print(f"config not found: {cfg_path}") or 1

    staging = Path(args.staging).resolve()
    if not staging.is_dir():
        return print(f"staging folder not found: {staging}") or 1

    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    expected, skipped = collect_expected(cfg, args.include_disabled)

    print(f"config  : {cfg_path}")
    print(f"staging : {staging}\n")

    ok, missing, renamable, wrong_build = [], [], [], []

    # Every canonical path, computed up front so near-match detection can
    # exclude files that already serve another entry.
    reserved = {guest_to_staging(g, staging) for _, _, g in expected}

    for tool_id, kind, guest_path in expected:
        local = guest_to_staging(guest_path, staging)
        if local.exists():
            ok.append((tool_id, kind, guest_path, local))
            continue

        others = candidates_in(local.parent, reserved)

        # Separate wrong-build files from merely misnamed ones.
        bad = [(c, wrong_build_reason(tool_id, c.name)) for c in others]
        flagged = [(c, r) for c, r in bad if r]
        clean = [c for c, r in bad if not r]

        if flagged:
            wrong_build.append((tool_id, guest_path, flagged))
        elif len(clean) == 1:
            renamable.append((tool_id, guest_path, clean[0], local))
        else:
            missing.append((tool_id, kind, guest_path, local, clean))

    width = max((len(t) for t, *_ in [*expected, *skipped]), default=10)

    for tool_id, first_line in skipped:
        print(f"  SKIP     {tool_id:<{width}}  disabled in config.yaml - "
              f"installer not required")

    for tool_id, kind, guest_path, local in ok:
        size = local.stat().st_size / 1e6
        print(f"  OK       {tool_id:<{width}}  {guest_path}  ({size:.1f} MB)")

    for tool_id, guest_path, found, local in renamable:
        print(f"  RENAME   {tool_id:<{width}}  expected {local.name}")
        print(f"           {'':<{width}}  found    {found.name}")

    for tool_id, guest_path, flagged in wrong_build:
        print(f"  WRONG    {tool_id:<{width}}  {guest_path}")
        for found, reason in flagged:
            print(f"           {'':<{width}}  found {found.name}:")
            for line in _wrap(reason, 64):
                print(f"           {'':<{width}}    {line}")

    for tool_id, kind, guest_path, local, others in missing:
        print(f"  MISSING  {tool_id:<{width}}  {guest_path}")
        if others:
            print(f"           {'':<{width}}  folder holds: "
                  f"{', '.join(o.name for o in others)}")
        elif not local.parent.is_dir():
            print(f"           {'':<{width}}  folder does not exist: "
                  f"{local.parent}")

    if renamable and args.fix_names:
        print("\nRename the files listed above to the canonical names? [y/N] ",
              end="")
        if input().strip().lower() == "y":
            for tool_id, guest_path, found, local in list(renamable):
                found.rename(local)
                print(f"  renamed {found.name} -> {local.name}")
            renamable.clear()
    elif renamable:
        print("\nRe-run with --fix-names to rename these automatically.")

    print()
    if not missing and not renamable and not wrong_build:
        print(f"All {len(ok)} ISO files present. Safe to build the ISO.")
        if skipped:
            print(f"({len(skipped)} disabled tool(s) skipped; keeping their "
                  "installers on the ISO is harmless and lets you re-test "
                  "them with --tool.)")
        return 0

    print(f"{len(ok)} present, {len(renamable)} need renaming, "
          f"{len(wrong_build)} wrong build, {len(missing)} missing.")
    print("Fix these before building the ISO, or those runs will install "
          "nothing and wipe nothing.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
