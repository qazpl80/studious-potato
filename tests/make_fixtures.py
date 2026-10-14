"""Build synthetic run folders to smoke-test the labelling stage.

No VM needed. Fabricates a run folder whose usn.csv contains SDelete's known
rename pattern, plus a control run with an ordinary delete, then you run:

    python make_fixtures.py ./tmp_runs
    cd ../parse && python parse_runs.py --runs ../tests/tmp_runs --label-only

files.csv should show ~27 distinct names and ~52 rename events for the sdelete
run, and 1 and 0 for the control. If it does not, the labelling join is broken.
"""
import csv, json, string
from pathlib import Path

import sys
root = Path(sys.argv[1] if len(sys.argv) > 1 else "../runs").resolve()

def mk(run_id, tool_id, mode, shutdown, is_control, pattern):
    d = root / run_id
    (d / "parsed").mkdir(parents=True, exist_ok=True)
    (d / "evidence").mkdir(parents=True, exist_ok=True)
    (d / "evidence" / "$LogFile").write_bytes(b"\x00" * 16)
    (d / "evidence" / "$J").write_bytes(b"\x00" * 16)

    targets = [{"path": f"D:\\corpus\\doc{i}.pdf", "name": f"doc{i}.pdf",
                "size": 10000 + i, "sha256": "x" * 64,
                "mft_record": 1000 + i, "sequence": 1,
                "file_id_hex": "0x0", "created": "", "modified": ""}
               for i in range(5)]

    (d / "manifest.json").write_text(json.dumps({
        "run_id": run_id, "tool_id": tool_id, "mode": mode,
        "tool_display": tool_id, "is_control": is_control,
        "windows_build": "26100", "surviving_paths": [],
        "shadow_copy_used": True,
        "times_utc": {"wipe_start": "2026-09-26T10:00:00Z",
                      "wipe_end": "2026-09-26T10:02:00Z"},
        "targets": targets, "per_file_results": [],
    }, indent=2))

    (d / "status.json").write_text(json.dumps({
        "run_id": run_id, "result": "ok",
        "matrix": {"shutdown": shutdown}}, indent=2))

    rows = []
    usn = 1000
    for t in targets:
        rows += pattern(t["mft_record"], t["name"])
    # incidental OS churn on a file reference we never targeted
    rows.append({"EntryNumber": 9999, "Name": "WindowsUpdate.log",
                 "UpdateReasons": "DataExtend|Close",
                 "UpdateTimestamp": "2026-09-26 10:01:00", "UpdateSequenceNumber": 1})
    for i, r in enumerate(rows):
        r.setdefault("UpdateSequenceNumber", usn + i * 8)

    with open(d / "parsed" / "usn.csv", "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["EntryNumber", "Name",
                                           "UpdateReasons", "UpdateTimestamp",
                                           "UpdateSequenceNumber"])
        w.writeheader(); w.writerows(rows)

def sdelete_pattern(entry, name):
    """26 renames marching AAA.AAA -> ZZZ.ZZZ, then delete."""
    out = [{"EntryNumber": entry, "Name": name,
            "UpdateReasons": "DataOverwrite", "UpdateTimestamp": "2026-09-26 10:00:01"}]
    for ch in string.ascii_uppercase:
        n = f"{ch*3}.{ch*3}"
        out.append({"EntryNumber": entry, "Name": n,
                    "UpdateReasons": "RenameOldName", "UpdateTimestamp": "2026-09-26 10:00:02"})
        out.append({"EntryNumber": entry, "Name": n,
                    "UpdateReasons": "RenameNewName|Close", "UpdateTimestamp": "2026-09-26 10:00:02"})
    out.append({"EntryNumber": entry, "Name": "ZZZ.ZZZ",
                "UpdateReasons": "FileDelete|Close", "UpdateTimestamp": "2026-09-26 10:00:03"})
    return out

def plain_delete(entry, name):
    return [{"EntryNumber": entry, "Name": name,
             "UpdateReasons": "FileDelete|Close", "UpdateTimestamp": "2026-09-26 10:00:01"}]

mk("0007_sdelete_p3_clean_r1", "sdelete", "p3", "clean", False, sdelete_pattern)
mk("0061_control_delete_explorer_clean_r1", "control_delete", "explorer", "clean", True, plain_delete)
print(f"fixtures created in {root}")
