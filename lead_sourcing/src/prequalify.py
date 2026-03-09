"""
Stage 2: Pre-qualification
Loads all scraped articles, runs each through the fast LLM pre-filter,
and saves results to a cache file.
"""

import json
import sys
from pathlib import Path

from src.config import SCRAPED_DIR, PREQUALIFY_CACHE, OUTPUT_DIR
from src.llm import prequalify
from src.db_utils import load_existing_urls


def load_cache() -> dict:
    if PREQUALIFY_CACHE.exists():
        return json.loads(PREQUALIFY_CACHE.read_text(encoding="utf-8"))
    return {}


def save_cache(cache: dict):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    PREQUALIFY_CACHE.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def run():
    print(f"\n{'='*60}")
    print(f"STAGE 2: PRE-QUALIFICATION")
    print(f"{'='*60}")

    existing_urls = load_existing_urls()
    cache = load_cache()
    print(f"  Cache has {len(cache)} entries")

    # Collect all article JSON files
    articles = []
    for json_file in sorted(SCRAPED_DIR.rglob("*.json")):
        if "_extracted" in json_file.name:
            continue
        try:
            article = json.loads(json_file.read_text(encoding="utf-8"))
            article["_filepath"] = str(json_file)
            articles.append(article)
        except (json.JSONDecodeError, KeyError):
            continue

    print(f"  Found {len(articles)} scraped articles to check")

    pass_count = disqualify_count = skip_count = db_dup_count = 0

    for article in articles:
        url = article.get("url", "")
        if not url:
            continue

        if url in existing_urls:
            db_dup_count += 1
            continue

        if url in cache:
            if cache[url] == "pass":
                pass_count += 1
            else:
                disqualify_count += 1
            skip_count += 1
            continue

        title = article.get("title", "")
        print(f"  Checking: {title[:60]}...", flush=True)
        try:
            result = prequalify(url)
        except Exception as e:
            print(f"    → ERROR: {e}", flush=True)
            result = "disqualify"

        cache[url] = result
        if result == "pass":
            print(f"    → PASS", flush=True)
            pass_count += 1
        else:
            print(f"    → DISQUALIFY", flush=True)
            disqualify_count += 1

        if (pass_count + disqualify_count) % 50 == 0:
            save_cache(cache)

    save_cache(cache)

    print(f"\nResults:")
    print(f"  Passed:         {pass_count}")
    print(f"  Disqualified:   {disqualify_count}")
    print(f"  Already in DB:  {db_dup_count}")
    print(f"  Already cached: {skip_count}")
    return pass_count


if __name__ == "__main__":
    if str(Path(__file__).parent.parent) not in sys.path:
        sys.path.insert(0, str(Path(__file__).parent.parent))
    run()
