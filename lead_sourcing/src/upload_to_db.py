"""
Stage 4: Upload qualified leads to jascko_internal_scored_v2.
Reads all _extracted.json files, deduplicates, and inserts only Qualified=Yes rows.
"""

import json
import sys
from pathlib import Path

from src.config import SCRAPED_DIR, SCORED_TABLE
from src.db_utils import load_existing_urls, insert_qualified_lead


def collect_extractions() -> list:
    extractions = []
    for json_file in sorted(SCRAPED_DIR.rglob("*_extracted.json")):
        try:
            lead = json.loads(json_file.read_text(encoding="utf-8"))
            lead["_filepath"] = str(json_file)
            extractions.append(lead)
        except (json.JSONDecodeError, KeyError):
            continue
    return extractions


def run(dry_run: bool = True):
    print(f"\n{'='*60}")
    print(f"STAGE 4: UPLOAD TO DATABASE")
    if dry_run:
        print(f"  *** DRY RUN MODE — no data will be written ***")
        print(f"  *** Run with --confirm to actually insert ***")
    print(f"Table: {SCORED_TABLE}")
    print(f"{'='*60}")

    existing_urls = load_existing_urls()
    extractions = collect_extractions()
    print(f"  Found {len(extractions)} extraction results")

    qualified = [e for e in extractions if e.get("qualified", "").lower() == "yes"]
    not_qualified = [e for e in extractions if e.get("qualified", "").lower() != "yes"]
    print(f"  Qualified: {len(qualified)}")
    print(f"  Not qualified: {len(not_qualified)}")

    inserted = skipped = 0

    for lead in qualified:
        url = lead.get("article_link", "")
        if not url:
            skipped += 1
            continue

        if url in existing_urls:
            skipped += 1
            continue

        if dry_run:
            print(f"  DRY RUN: Would insert '{lead.get('project_name', 'Unknown')}' — {url[:80]}")
            skipped += 1
            continue

        ok = insert_qualified_lead(lead, existing_urls)
        if ok:
            inserted += 1
        else:
            skipped += 1

    print(f"\n{'='*60}")
    print(f"UPLOAD SUMMARY:")
    print(f"  Table: {SCORED_TABLE}")
    print(f"  Inserted: {inserted}")
    print(f"  Skipped (dup/error): {skipped}")
    if dry_run:
        print(f"\n  Run with --confirm to actually insert data")

    return inserted


if __name__ == "__main__":
    if str(Path(__file__).parent.parent) not in sys.path:
        sys.path.insert(0, str(Path(__file__).parent.parent))

    confirm = "--confirm" in sys.argv
    run(dry_run=not confirm)
