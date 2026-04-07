#!/usr/bin/env python3
"""
collect_data.py – Collect ARVO data for a specific date range.

Usage:
    python3 collect_data.py                    # Aug 2025 – Mar 2026 (default)
    python3 collect_data.py --start 2025-08 --end 2026-03

Steps performed:
  1. Query issues.oss-fuzz.com month-by-month for the given range.
  2. Fetch full issue metadata for any new issue IDs found.
  3. Download srcmap JSON files from Google Cloud Storage for those issues.

Prerequisites:
  - arvo/_profile.py is configured (gcloud_key points to a valid service account key)
  - Google Cloud SDK / google-cloud-storage Python package is installed
  - Run from the repo root:  python3 collect_data.py
"""

import argparse
import json
import re
import sys
from calendar import monthrange
from datetime import datetime
from pathlib import Path

import requests

# ── Resolve repo root and import arvo ────────────────────────────────────────
REPO_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(REPO_ROOT))

from arvo.utils_meta import (
    meta_getIssues,
    data_download,
)
from arvo.utils_log import SUCCESS, WARN, INFO
from arvo.utils_init import MetaDataFile


# ── Helpers ──────────────────────────────────────────────────────────────────

def _month_ranges(start_ym: str, end_ym: str):
    """
    Yield (start_date_str, end_date_str) pairs, one per calendar month,
    from start_ym to end_ym inclusive.

    start_ym / end_ym format: 'YYYY-MM'
    """
    sy, sm = map(int, start_ym.split("-"))
    ey, em = map(int, end_ym.split("-"))

    year, month = sy, sm
    while (year, month) <= (ey, em):
        _, last_day = monthrange(year, month)
        next_month  = month + 1 if month < 12 else 1
        next_year   = year      if month < 12 else year + 1
        yield (f"{year}-{month:02d}-01", f"{next_year}-{next_month:02d}-01")
        year, month = next_year, next_month


def getIssueIdsByRange(start_ym: str, end_ym: str) -> list[int]:
    """
    Fetch OSS-Fuzz vulnerability issue IDs for every calendar month in
    [start_ym, end_ym].  Queries the issues.oss-fuzz.com API month-by-month
    to stay safely under the 2 500-issue-per-query limit.
    """
    session = requests.Session()
    session.get("https://issues.oss-fuzz.com/")
    xsrf_token = session.cookies.get("XSRF_TOKEN")
    headers = {
        "Content-Type": "application/json",
        "Origin":        "https://issues.oss-fuzz.com",
        "Referer":       "https://issues.oss-fuzz.com/",
        "X-XSRF-Token":  xsrf_token,
    }
    url = "https://issues.oss-fuzz.com/action/issues/list"

    all_ids: list[int] = []

    for start_date, end_date in _month_ranges(start_ym, end_ym):
        month_ids: list[int] = []
        start_index = 0

        while True:
            query = (
                f"type:vulnerability status:verified "
                f"created<{end_date} created>={start_date}"
            )
            payload = [
                None, None, None, None, None,
                ["391"],
                [query, None, 500, f"start_index:{start_index}"],
            ]
            resp   = session.post(url, headers=headers, json=payload)
            text   = resp.text
            text   = re.sub(r"\bnull\b", "null", text)
            text   = text.replace("'", '"')
            text   = re.sub(r",\s*]", "]", text)
            issues = re.findall(
                r'\[\s*null\s*,\s*(\d+),\s*\[\d+,\d+,\d+,\d+,\d+,"(.*?)"',
                text,
            )
            for issue_id, _ in issues:
                month_ids.append(int(issue_id))

            if len(issues) < 500:
                break
            start_index += 500
            if len(month_ids) >= 2500:
                WARN(
                    f"[!] {start_date}–{end_date}: hit 2500-issue limit – "
                    "split into smaller windows if you see missing data."
                )
                break

        SUCCESS(
            f"[+] {start_date} → {end_date}: found {len(month_ids):,} issues"
        )
        all_ids.extend(month_ids)

    # Deduplicate while preserving order
    seen:   set[int]  = set()
    unique: list[int] = []
    for i in all_ids:
        if i not in seen:
            seen.add(i)
            unique.append(i)

    SUCCESS(f"[+] Total unique issue IDs found: {len(unique):,}")
    return unique


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Collect ARVO metadata + srcmaps for a date range."
    )
    parser.add_argument(
        "--start",
        default="2025-08",
        help="Start month inclusive, format YYYY-MM  (default: 2025-08)",
    )
    parser.add_argument(
        "--end",
        default="2026-03",
        help="End month inclusive, format YYYY-MM  (default: 2026-03)",
    )
    parser.add_argument(
        "--ids-only",
        action="store_true",
        help="Only print discovered issue IDs; skip metadata/srcmap download.",
    )
    args = parser.parse_args()

    INFO(f"[*] Collecting issues from {args.start} to {args.end} …")
    issue_ids = getIssueIdsByRange(args.start, args.end)

    if not issue_ids:
        WARN("[-] No issues found for the specified range.")
        return

    if args.ids_only:
        for i in issue_ids:
            print(i)
        return

    # ── Step 2: fetch metadata for new issues ────────────────────────────────
    INFO(f"[*] Fetching metadata for {len(issue_ids):,} issue IDs …")
    new_ids = meta_getIssues(issue_ids)
    SUCCESS(f"[+] {len(new_ids):,} new metadata entries written to {MetaDataFile}")

    # ── Step 3: download srcmaps from GCS ────────────────────────────────────
    if new_ids:
        INFO(f"[*] Downloading srcmaps for {len(new_ids):,} new issues …")
        data_download(new_ids)
        SUCCESS("[+] Srcmap download complete.")
    else:
        INFO("[*] No new issues – srcmap download skipped.")


if __name__ == "__main__":
    main()
