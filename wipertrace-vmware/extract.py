"""Offline extraction of NTFS artifacts from a powered-off virtual disk.

This is the part that has to be done from outside the VM. Copying $MFT or the
USN journal from inside a running Windows writes to those very structures, so
anything collected that way is contaminated by the act of collecting it.

Requires The Sleuth Kit on PATH or at paths.tsk_bin: mmls, fls, istat, icat.
"""

from __future__ import annotations

import gzip
import logging
import re
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger("extract")

# Fixed NTFS metadata record numbers. These never move.
INODE_MFT = 0
INODE_LOGFILE = 2
INODE_EXTEND = 11


class ExtractError(RuntimeError):
    pass


class Tsk:
    def __init__(self, bin_dir: str | None = None):
        self.bin = Path(bin_dir) if bin_dir else None

    def _exe(self, name: str) -> str:
        if self.bin:
            for candidate in (self.bin / name, self.bin / f"{name}.exe"):
                if candidate.exists():
                    return str(candidate)
        return name  # fall back to PATH

    def _run(self, name: str, args: list[str], binary: bool = False):
        cmd = [self._exe(name)] + args
        log.debug("%s", " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=not binary)
        if proc.returncode != 0:
            err = proc.stderr if not binary else proc.stderr.decode(errors="replace")
            raise ExtractError(f"{name} failed: {err.strip()}")
        return proc.stdout

    # -- discovery ---------------------------------------------------------

    def ntfs_offset(self, image: Path) -> int:
        """Find the start sector of the first NTFS partition."""
        out = self._run("mmls", ["-t", "dos", str(image)])
        for line in out.splitlines():
            if "NTFS" in line.upper() or "0x07" in line:
                parts = line.split()
                if len(parts) >= 3 and parts[2].isdigit():
                    offset = int(parts[2])
                    log.info("NTFS partition at sector %d", offset)
                    return offset
        # A disk formatted with no partition table (rare but possible).
        log.warning("no partition table found; assuming offset 0")
        return 0

    def find_usnjrnl(self, image: Path, offset: int) -> int:
        """Return the MFT record number of $Extend\\$UsnJrnl."""
        out = self._run("fls", ["-o", str(offset), "-f", "ntfs",
                                str(image), str(INODE_EXTEND)])
        for line in out.splitlines():
            if "$UsnJrnl" in line:
                m = re.search(r"(\d+)-\d+-\d+", line)
                if m:
                    return int(m.group(1))
        raise ExtractError("$UsnJrnl not found under $Extend")

    def find_j_stream(self, image: Path, offset: int, inode: int) -> str:
        """Return the full TSK address of the $J data stream, e.g. '35-128-4'."""
        out = self._run("istat", ["-o", str(offset), "-f", "ntfs",
                                  str(image), str(inode)])
        for line in out.splitlines():
            if "$DATA" in line and "$J" in line:
                m = re.search(r"\$DATA\s+\((\d+)-(\d+)\)", line)
                if m:
                    return f"{inode}-{m.group(1)}-{m.group(2)}"
        raise ExtractError(f"no $J stream on inode {inode}")

    # -- extraction --------------------------------------------------------

    def icat(self, image: Path, offset: int, address: str, out_path: Path):
        cmd = [self._exe("icat"), "-o", str(offset), "-f", "ntfs",
               str(image), address]
        log.debug("%s > %s", " ".join(cmd), out_path.name)
        with open(out_path, "wb") as fh:
            proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            raise ExtractError(
                f"icat {address} failed: {proc.stderr.decode(errors='replace').strip()}"
            )
        size = out_path.stat().st_size
        log.info("extracted %s (%.1f MB)", out_path.name, size / 1e6)

    def recover_dir(self, image: Path, offset: int, guest_dir: str, out_dir: Path):
        out_dir.mkdir(parents=True, exist_ok=True)
        self._run("tsk_recover", ["-e", "-o", str(offset), "-d", guest_dir,
                                  str(image), str(out_dir)])


def gzip_in_place(path: Path, level: int = 6) -> Path:
    """Replace a carved artefact with its gzip, returning the new path.

    Carved journals compress extremely well: $UsnJrnl:$J is a sparse stream
    whose unallocated extents icat materialises as runs of zeroes, and
    $LogFile/$MFT consist of highly repetitive fixed-layout records. Observed
    ratios are roughly 5-10x, which takes the 72-run matrix from ~3.4 GB of
    output to well under 1 GB.

    Parsers cannot read gzip directly, so parse_runs.py transparently
    decompresses into a scratch directory before invoking MFTECmd.
    """
    gz = path.with_suffix(path.suffix + ".gz")
    with open(path, "rb") as src, gzip.open(gz, "wb", compresslevel=level) as dst:
        shutil.copyfileobj(src, dst, length=4 * 1024 * 1024)
    before, after = path.stat().st_size, gz.stat().st_size
    path.unlink()
    if before:
        log.info("compressed %s: %.1f -> %.1f MB (%.1fx)", path.name,
                 before / 1e6, after / 1e6, before / max(after, 1))
    return gz


def extract_journals(image: Path, out_dir: Path, tsk_bin: str | None = None,
                     compress: bool = False) -> dict:
    """Pull $MFT, $LogFile and $UsnJrnl:$J out of a raw NTFS image.

    Setting compress gzips each artefact after carving, which matters on a
    space-constrained host: see gzip_in_place().
    """
    tsk = Tsk(tsk_bin)
    out_dir.mkdir(parents=True, exist_ok=True)
    offset = tsk.ntfs_offset(image)

    results = {"compressed": bool(compress)}

    def emit(address: str, name: str) -> str:
        target = out_dir / name
        tsk.icat(image, offset, address, target)
        return gzip_in_place(target).name if compress else name

    results["mft"] = emit(str(INODE_MFT), "$MFT")
    results["logfile"] = emit(str(INODE_LOGFILE), "$LogFile")

    try:
        inode = tsk.find_usnjrnl(image, offset)
        address = tsk.find_j_stream(image, offset, inode)
        results["usnjrnl"] = emit(address, "$J")
        results["usnjrnl_address"] = address
    except ExtractError as exc:
        # Worth recording rather than crashing: some wipers delete the journal
        # outright, and "the journal was gone" is itself a finding.
        log.warning("USN journal not recovered: %s", exc)
        results["usnjrnl"] = None
        results["usnjrnl_error"] = str(exc)

    return results


def extract_system_artifacts(image: Path, out_dir: Path,
                             tsk_bin: str | None = None) -> dict:
    """Pull Prefetch and Amcache from an offline image of the system disk."""
    tsk = Tsk(tsk_bin)
    offset = tsk.ntfs_offset(image)
    results = {}
    for label, guest_dir in [
        ("prefetch", "/Windows/Prefetch"),
        ("amcache", "/Windows/appcompat/Programs"),
    ]:
        try:
            tsk.recover_dir(image, offset, guest_dir, out_dir / label)
            results[label] = label
        except ExtractError as exc:
            log.warning("could not recover %s: %s", guest_dir, exc)
            results[label] = None
    return results
