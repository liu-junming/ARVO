#!/usr/bin/env python3
"""
generate_dataset.py – Run the ARVO pipeline (reproduce + locate patch) for a
                      batch of issues, with resumability and parallel workers.

Usage:
    python3 generate_dataset.py                  # all Aug 2025–Mar 2026 issues
    python3 generate_dataset.py --workers 4      # 4 parallel workers (default: 1)
    python3 generate_dataset.py --ids-file /tmp/my_ids.txt
    python3 generate_dataset.py --localId 442253757  # single issue

Requirements:
    - Docker must be installed and running
    - arvo/_profile.py must be configured (ARVO_DIR, OSS_* paths)
    - Run from the repo root: python3 generate_dataset.py

Outputs:
    - Per-issue results written to arvo/arvo.db (SQLite)
    - Logs written to /tmp/arvo_batch/<localId>.log
    - Progress summary printed to stdout
"""

import argparse
import json
import multiprocessing
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(REPO_ROOT))

LOG_DIR = Path("/tmp/arvo_batch")


# ── Helpers ──────────────────────────────────────────────────────────────────

def get_new_issue_ids(start_lid: int = 440_000_000) -> list[int]:
    """Return sorted localIds that have 2 srcmaps and localId >= start_lid."""
    from arvo.utils_init import DATADIR, MetaDataFile

    issues_dir = DATADIR / "Issues"
    ids = []
    with open(MetaDataFile) as f:
        for line in f:
            d = json.loads(line)
            lid = d["localId"]
            if lid < start_lid:
                continue
            issue_dir = issues_dir / f"{lid}_files"
            if issue_dir.exists() and len(list(issue_dir.iterdir())) == 2:
                ids.append(lid)
    return sorted(ids)


def already_done(localId: int) -> bool:
    """Return True if this issue already has a report in the SQLite DB."""
    try:
        from arvo.utils import getReport
        result = getReport(localId)
        return bool(result and result.get("reproduced"))
    except Exception:
        return False


def run_one(localId: int) -> dict:
    """
    Run `arvo report <localId>` in a subprocess.
    Returns a dict with keys: localId, success, patch_url, elapsed, log_path.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / f"{localId}.log"

    start = time.time()
    try:
        result = subprocess.run(
            [sys.executable, "-m", "arvo.cli", "report", str(localId)],
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour hard limit per issue
            cwd=str(REPO_ROOT),
        )
        elapsed = time.time() - start
        output = result.stdout + result.stderr

        with open(log_path, "w") as f:
            f.write(f"# localId={localId}  exit={result.returncode}  "
                    f"elapsed={elapsed:.0f}s\n")
            f.write(output)

        # Parse patch URL from output
        patch_url = None
        for line in output.splitlines():
            if "github.com" in line and "/commit/" in line:
                patch_url = line.strip().split()[-1]
                break

        success = result.returncode == 0 and patch_url is not None
        return dict(
            localId=localId,
            success=success,
            patch_url=patch_url,
            elapsed=elapsed,
            log_path=str(log_path),
        )

    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        with open(log_path, "a") as f:
            f.write(f"\n[TIMEOUT after {elapsed:.0f}s]\n")
        return dict(localId=localId, success=False, patch_url=None,
                    elapsed=elapsed, log_path=str(log_path))

    except Exception as exc:
        elapsed = time.time() - start
        with open(log_path, "a") as f:
            f.write(f"\n[ERROR: {exc}]\n")
        return dict(localId=localId, success=False, patch_url=None,
                    elapsed=elapsed, log_path=str(log_path))


def _worker(queue, results, stop_event):
    """Worker process: pulls localIds from queue and runs the pipeline."""
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    while not stop_event.is_set():
        try:
            localId = queue.get(timeout=1)
        except Exception:
            continue
        if localId is None:
            break
        result = run_one(localId)
        results.append(result)
        status = "OK" if result["success"] else "FAIL"
        print(
            f"[{status}] {localId}  patch={result['patch_url'] or '-'}"
            f"  {result['elapsed']:.0f}s  log={result['log_path']}",
            flush=True,
        )


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate ARVO dataset for a batch of issues."
    )
    parser.add_argument(
        "--workers", type=int, default=1,
        help="Number of parallel workers (default: 1; each needs Docker headroom)"
    )
    parser.add_argument(
        "--ids-file", type=str, default=None,
        help="Path to a text file with one localId per line (default: auto-detect Aug2025+)"
    )
    parser.add_argument(
        "--localId", type=int, default=None,
        help="Run a single issue instead of a batch"
    )
    parser.add_argument(
        "--skip-done", action="store_true", default=True,
        help="Skip issues already reproduced in the DB (default: True)"
    )
    parser.add_argument(
        "--no-skip-done", dest="skip_done", action="store_false"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print issue list and exit without running"
    )
    args = parser.parse_args()

    # ── Build issue list ──────────────────────────────────────────────────────
    if args.localId:
        ids = [args.localId]
    elif args.ids_file:
        ids = [int(l.strip()) for l in open(args.ids_file) if l.strip().isdigit()]
    else:
        print("[*] Auto-detecting Aug 2025–Mar 2026 issues with complete srcmaps …")
        ids = get_new_issue_ids()

    if args.skip_done:
        before = len(ids)
        ids = [lid for lid in ids if not already_done(lid)]
        skipped = before - len(ids)
        if skipped:
            print(f"[*] Skipped {skipped} already-reproduced issues")

    print(f"[*] {len(ids)} issues to process  (workers={args.workers})")

    if args.dry_run:
        for lid in ids:
            print(lid)
        return

    if not ids:
        print("[*] Nothing to do.")
        return

    # ── Check Docker ──────────────────────────────────────────────────────────
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        print("[-] Docker is not available. "
              "Please install Docker and ensure the daemon is running.")
        sys.exit(1)

    # ── Run ───────────────────────────────────────────────────────────────────
    start_all = time.time()
    results = []

    if args.workers == 1:
        for i, lid in enumerate(ids, 1):
            print(f"[{i}/{len(ids)}] Processing {lid} …", flush=True)
            r = run_one(lid)
            results.append(r)
            status = "OK" if r["success"] else "FAIL"
            print(
                f"  [{status}] patch={r['patch_url'] or '-'}  "
                f"{r['elapsed']:.0f}s",
                flush=True,
            )
    else:
        mgr = multiprocessing.Manager()
        queue   = mgr.Queue()
        res_list = mgr.list()
        stop_ev  = mgr.Event()

        for lid in ids:
            queue.put(lid)
        for _ in range(args.workers):
            queue.put(None)  # sentinel

        procs = [
            multiprocessing.Process(target=_worker,
                                    args=(queue, res_list, stop_ev))
            for _ in range(args.workers)
        ]
        try:
            for p in procs:
                p.start()
            for p in procs:
                p.join()
        except KeyboardInterrupt:
            print("\n[!] Interrupted — waiting for workers to finish …")
            stop_ev.set()
            for p in procs:
                p.join(timeout=30)

        results = list(res_list)

    # ── Summary ───────────────────────────────────────────────────────────────
    total   = len(results)
    ok      = sum(1 for r in results if r["success"])
    failed  = total - ok
    elapsed = time.time() - start_all

    print()
    print("=" * 60)
    print(f"  Done in {elapsed/60:.1f} min")
    print(f"  Total   : {total}")
    print(f"  Success : {ok}")
    print(f"  Failed  : {failed}")
    print(f"  Logs    : {LOG_DIR}/")
    print("=" * 60)

    # Write summary JSON
    summary_path = LOG_DIR / "summary.json"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with open(summary_path, "w") as f:
        json.dump({
            "run_at": datetime.utcnow().isoformat(),
            "total": total, "success": ok, "failed": failed,
            "elapsed_s": round(elapsed),
            "results": results,
        }, f, indent=2)
    print(f"  Summary : {summary_path}")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
