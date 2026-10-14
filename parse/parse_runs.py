#!/usr/bin/env python3
"""Turn raw run folders into a labelled dataset.

Stage 1 (parse):  run MFTECmd / PECmd over each run's evidence.
Stage 2 (label):  join the USN records against the run's ground truth by MFT
                  record number, producing one row per (run, file reference)
                  with the wiping tool as the label.

    python parse_runs.py --runs ../runs --config ../config.yaml
    python parse_runs.py --runs ../runs --config ../config.yaml --label-only

Output lands in <runs>/_dataset/:
    events.csv      one row per USN record, labelled
    files.csv       one row per file reference per run, with aggregate features
    runs.csv        one row per run, with metadata and counts

The grouping column in files.csv is `run_id`. Split on THAT, never randomly —
events from one wipe appearing on both sides of a split will hand you 99%
accuracy that means nothing.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import logging
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")

log = logging.getLogger("parse")

# Column names MFTECmd uses for the USN journal output. It has renamed these
# between versions, so we look for any of them.
USN_COLS = {
    "entry": ("EntryNumber", "Entry", "FileReferenceNumber"),
    "parent": ("ParentEntryNumber", "ParentEntry", "ParentFileReferenceNumber"),
    "name": ("Name", "FileName"),
    "reasons": ("UpdateReasons", "Reasons", "UpdateReason"),
    "timestamp": ("UpdateTimestamp", "Timestamp", "UpdateTime"),
    "usn": ("UpdateSequenceNumber", "Usn", "USN"),
    "attributes": ("FileAttributes", "Attributes"),
}


def pick(row: dict, names: tuple[str, ...]):
    for n in names:
        if n in row and row[n] not in (None, ""):
            return row[n]
    return None


# ---------------------------------------------------------------------------
# Stage 1: parsing
# ---------------------------------------------------------------------------

def run_tool(exe: str, args: list[str], label: str) -> bool:
    cmd = [exe] + args
    log.debug("%s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        log.warning("%s failed: %s", label,
                    (proc.stderr or proc.stdout).strip()[:300])
        return False
    return True


@contextmanager
def readable_artifact(evidence: Path, name: str):
    """Yield a plain-file path for a carved artefact, or None if absent.

    The capture stage may gzip artefacts to save host disk (extract.py's
    compress option). MFTECmd takes a file path and cannot read gzip, so a
    compressed artefact is staged into a temporary directory, handed over,
    then discarded. Uncompressed artefacts are used in place with no copy.
    """
    plain, packed = evidence / name, evidence / (name + ".gz")

    if plain.exists() and plain.stat().st_size > 0:
        yield plain
        return

    if not packed.exists():
        yield None
        return

    tmp = Path(tempfile.mkdtemp(prefix="wipertrace_"))
    try:
        staged = tmp / name
        with gzip.open(packed, "rb") as src, open(staged, "wb") as dst:
            shutil.copyfileobj(src, dst, length=4 * 1024 * 1024)
        log.debug("staged %s -> %s (%.1f MB)", packed.name, staged,
                  staged.stat().st_size / 1e6)
        yield staged if staged.stat().st_size > 0 else None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def parse_run(run_dir: Path, mftecmd: str | None, pecmd: str | None) -> dict:
    """Run the parsers over one run folder. Returns what succeeded."""
    evidence = run_dir / "evidence"
    parsed = run_dir / "parsed"
    parsed.mkdir(exist_ok=True)
    done = {}

    if mftecmd and Path(mftecmd).exists():
        with readable_artifact(evidence, "$MFT") as mft:
            if mft:
                done["mft"] = run_tool(mftecmd, [
                    "-f", str(mft), "--csv", str(parsed), "--csvf", "mft.csv",
                ], "MFTECmd($MFT)")

        with readable_artifact(evidence, "$J") as j:
            if j:
                done["usn"] = run_tool(mftecmd, [
                    "-f", str(j), "--csv", str(parsed), "--csvf", "usn.csv",
                ], "MFTECmd($J)")
            else:
                log.warning("%s: no $J artefact to parse", run_dir.name)
    else:
        log.warning("MFTECmd not configured; skipping $MFT/$J parsing")

    if pecmd and Path(pecmd).exists():
        pf = run_dir / "artifacts" / "Prefetch"
        if pf.is_dir():
            done["prefetch"] = run_tool(pecmd, [
                "-d", str(pf), "--csv", str(parsed), "--csvf", "prefetch.csv",
            ], "PECmd")

    # $LogFile needs dfir_ntfs, not MFTECmd. We only note whether it is there,
    # so the write-up can say what was collected even if not yet parsed.
    done["logfile_present"] = ((evidence / "$LogFile").exists()
                               or (evidence / "$LogFile.gz").exists())
    return done


# ---------------------------------------------------------------------------
# Stage 2: labelling
# ---------------------------------------------------------------------------

def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        return list(csv.DictReader(fh))


def label_run(run_dir: Path) -> tuple[list[dict], list[dict], dict | None]:
    """Join USN records to ground truth. Returns (events, files, run_row)."""
    manifest_path = run_dir / "manifest.json"
    status_path = run_dir / "status.json"
    if not manifest_path.exists():
        log.warning("%s: no manifest.json, skipping", run_dir.name)
        return [], [], None

    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    status = (json.loads(status_path.read_text(encoding="utf-8"))
              if status_path.exists() else {})

    run_id = manifest.get("run_id", run_dir.name)
    tool_id = manifest.get("tool_id", "unknown")
    mode = manifest.get("mode", "unknown")
    is_control = bool(manifest.get("is_control"))
    shutdown = status.get("matrix", {}).get("shutdown", "unknown")

    # Ground truth: MFT record -> the file we deliberately targeted.
    targets = {}
    for t in manifest.get("targets", []):
        rec = t.get("mft_record")
        if rec is not None:
            targets[int(rec)] = t

    usn_rows = read_csv(run_dir / "parsed" / "usn.csv")
    if not usn_rows:
        log.warning("%s: no parsed usn.csv", run_id)

    events = []
    by_entry: dict[int, list[dict]] = defaultdict(list)

    for row in usn_rows:
        entry_raw = pick(row, USN_COLS["entry"])
        try:
            entry = int(float(entry_raw))
        except (TypeError, ValueError):
            continue

        ev = {
            "run_id": run_id,
            "tool_id": tool_id,
            "mode": mode,
            "shutdown": shutdown,
            "is_control": int(is_control),
            "entry": entry,
            "name": pick(row, USN_COLS["name"]) or "",
            "reasons": pick(row, USN_COLS["reasons"]) or "",
            "timestamp": pick(row, USN_COLS["timestamp"]) or "",
            "usn": pick(row, USN_COLS["usn"]) or "",
            # 1 = this file reference is one we deliberately wiped.
            # 0 = incidental churn from the OS during the same window.
            "is_target": int(entry in targets),
        }
        events.append(ev)
        by_entry[entry].append(ev)

    # Per-file aggregate features. These are the columns a classifier would
    # actually consume, and the ones a rule engine is asserting about.
    files = []
    for entry, evs in by_entry.items():
        names = [e["name"] for e in evs if e["name"]]
        distinct = sorted(set(names))
        reasons = " ".join(e["reasons"] for e in evs)
        rename_events = sum(
            1 for e in evs
            if "RenameOldName" in e["reasons"] or "RenameNewName" in e["reasons"]
        )
        target = targets.get(entry)

        files.append({
            "run_id": run_id,
            "tool_id": tool_id,
            "mode": mode,
            "shutdown": shutdown,
            "is_control": int(is_control),
            "entry": entry,
            "is_target": int(target is not None),
            "original_name": target["name"] if target else "",
            "original_size": target["size"] if target else "",
            "event_count": len(evs),
            "distinct_name_count": len(distinct),
            "rename_event_count": rename_events,
            "max_name_len": max((len(n) for n in names), default=0),
            "min_name_len": min((len(n) for n in names), default=0),
            "has_data_truncation": int("DataTruncation" in reasons),
            "has_data_overwrite": int("DataOverwrite" in reasons),
            "has_data_extend": int("DataExtend" in reasons),
            "has_file_delete": int("FileDelete" in reasons),
            "has_file_create": int("FileCreate" in reasons),
            "has_security_change": int("SecurityChange" in reasons),
            "has_basic_info_change": int("BasicInfoChange" in reasons),
            "first_name": names[0] if names else "",
            "last_name": names[-1] if names else "",
            "name_sequence": "|".join(distinct[:40]),
        })

    run_row = {
        "run_id": run_id,
        "tool_id": tool_id,
        "mode": mode,
        "shutdown": shutdown,
        "is_control": int(is_control),
        "tool_display": manifest.get("tool_display", ""),
        "windows_build": manifest.get("windows_build", ""),
        "result": status.get("result", "unknown"),
        "target_count": len(targets),
        "surviving_count": len(manifest.get("surviving_paths", [])),
        "usn_event_count": len(events),
        "distinct_entries": len(by_entry),
        "target_entries_seen": sum(1 for e in by_entry if e in targets),
        "wipe_start": manifest.get("times_utc", {}).get("wipe_start", ""),
        "wipe_end": manifest.get("times_utc", {}).get("wipe_end", ""),
        "logfile_present": int((run_dir / "evidence" / "$LogFile").exists()
                               or (run_dir / "evidence" / "$LogFile.gz").exists()),
        "usnjrnl_recovered": int((run_dir / "evidence" / "$J").exists()
                                 or (run_dir / "evidence" / "$J.gz").exists()),
        "shadow_copy_used": int(bool(manifest.get("shadow_copy_used"))),
    }

    return events, files, run_row


def write_csv(path: Path, rows: list[dict]):
    if not rows:
        log.warning("nothing to write to %s", path.name)
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    log.info("wrote %s (%d rows)", path.name, len(rows))


# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Parse and label WiperTrace runs")
    ap.add_argument("--runs", default="../runs")
    ap.add_argument("--config", default="../config.yaml")
    ap.add_argument("--label-only", action="store_true",
                    help="skip MFTECmd/PECmd, just re-join existing CSVs")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)-7s %(message)s",
    )

    runs_root = Path(args.runs).resolve()
    if not runs_root.is_dir():
        sys.exit(f"runs directory not found: {runs_root}")

    cfg_path = Path(args.config).resolve()
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
    mftecmd = cfg.get("paths", {}).get("mftecmd")
    pecmd = cfg.get("paths", {}).get("pecmd")

    run_dirs = sorted(d for d in runs_root.iterdir()
                      if d.is_dir() and not d.name.startswith("_"))
    if not run_dirs:
        sys.exit(f"no run folders in {runs_root}")

    log.info("found %d run folders", len(run_dirs))

    all_events, all_files, all_runs = [], [], []

    for d in run_dirs:
        if not args.label_only:
            log.info("parsing %s", d.name)
            parse_run(d, mftecmd, pecmd)
        events, files, run_row = label_run(d)
        all_events += events
        all_files += files
        if run_row:
            all_runs.append(run_row)

    out = runs_root / "_dataset"
    write_csv(out / "events.csv", all_events)
    write_csv(out / "files.csv", all_files)
    write_csv(out / "runs.csv", all_runs)

    # A short readout, because a silent success tells you nothing about
    # whether the data is any good.
    if all_runs:
        print("\nper-tool summary")
        print(f"{'tool':<18}{'mode':<14}{'runs':>6}{'events':>10}{'targets seen':>14}")
        agg: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0, 0])
        for r in all_runs:
            key = (r["tool_id"], r["mode"])
            agg[key][0] += 1
            agg[key][1] += r["usn_event_count"]
            agg[key][2] += r["target_entries_seen"]
        for (tool, mode), (n, ev, seen) in sorted(agg.items()):
            print(f"{tool:<18}{mode:<14}{n:>6}{ev:>10}{seen:>14}")

        zero = [r["run_id"] for r in all_runs if r["usn_event_count"] == 0]
        if zero:
            print(f"\nWARNING: {len(zero)} runs produced no USN events. "
                  "Check the journal was enabled and did not roll over:")
            for z in zero[:10]:
                print(f"  {z}")


if __name__ == "__main__":
    main()
