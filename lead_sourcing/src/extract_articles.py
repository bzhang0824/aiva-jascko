"""
Stage 3: Article text extraction + SOP analysis
For each pre-qualified article:
1. Fetch the full article HTML (or use prefetched_text for CBB articles)
2. Parse to clean text
3. Run SOP v4.2.2 South Florida extraction → JSON
4. Apply Python-level guard: disqualify if groundbreaking/completion year already passed
5. Save the extraction result to a _extracted.json file
"""

import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path

import requests

from src.config import (
    SCRAPED_DIR,
    PREQUALIFY_CACHE,
    HTTP_TIMEOUT,
    HTTP_MAX_RETRIES,
    HTTP_RETRY_DELAY,
)
from src.html_parser import extract_article_text
from src.llm import sop_extract
from src.db_utils import load_existing_urls


def _parse_year(year_str) -> int | None:
    if not year_str:
        return None
    s = str(year_str).strip()
    m = re.search(r"\b(20\d{2})\b", s)
    if m:
        return int(m.group(1))
    return None


def _is_past_year(year_str, current_year: int) -> bool:
    y = _parse_year(year_str)
    return y is not None and y < current_year


def load_prequalify_cache() -> dict:
    if PREQUALIFY_CACHE.exists():
        return json.loads(PREQUALIFY_CACHE.read_text(encoding="utf-8"))
    return {}


def fetch_article_html(url: str) -> str:
    """Fetch article HTML. Skip CBB pseudo-URLs (they use #anchors)."""
    if "#" in url and "condoblackbook.com" in url:
        return ""  # CBB articles use prefetched_text

    for attempt in range(1, HTTP_MAX_RETRIES + 1):
        try:
            resp = requests.get(
                url,
                timeout=HTTP_TIMEOUT,
                headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
                allow_redirects=True,
            )
            resp.raise_for_status()
            return resp.text
        except requests.RequestException as e:
            if attempt < HTTP_MAX_RETRIES:
                print(f"    Retry {attempt}/{HTTP_MAX_RETRIES}: {e}")
                time.sleep(HTTP_RETRY_DELAY)
            else:
                print(f"    FAILED to fetch article: {e}")
                return ""


def run():
    print(f"\n{'='*60}")
    print(f"STAGE 3: EXTRACT + SOP ANALYSIS")
    print(f"{'='*60}")

    pq_cache = load_prequalify_cache()
    passed_urls = {url for url, result in pq_cache.items() if result == "pass"}
    print(f"  {len(passed_urls)} URLs passed pre-qualification")

    existing_urls = load_existing_urls()

    articles = []
    for json_file in sorted(SCRAPED_DIR.rglob("*.json")):
        if "_extracted" in json_file.name:
            continue
        try:
            article = json.loads(json_file.read_text(encoding="utf-8"))
            if article.get("url") in passed_urls and article.get("url") not in existing_urls:
                article["_filepath"] = str(json_file)
                articles.append(article)
        except (json.JSONDecodeError, KeyError):
            continue

    print(f"  {len(articles)} articles to process (passed pre-qual + not in DB)")

    extracted_count = skipped_count = error_count = 0

    for i, article in enumerate(articles, 1):
        url = article["url"]
        title = article.get("title", "Unknown")
        prefetched_text = article.get("prefetched_text", "")

        # Check if already extracted
        extract_path = (
            Path(article["_filepath"]).parent /
            f"{Path(article['_filepath']).stem}_extracted.json"
        )
        if extract_path.exists():
            skipped_count += 1
            continue

        print(f"\n  [{i}/{len(articles)}] {title[:60]}...")
        print(f"    URL: {url}")

        # Step 1: Get article text
        if prefetched_text:
            # CBB articles — text already available
            parsed = extract_article_text("", prefetched_text=prefetched_text)
        else:
            html = fetch_article_html(url)
            if not html:
                error_count += 1
                continue
            parsed = extract_article_text(html)

        if parsed["status"] != "extracted":
            print(f"    SKIP: {parsed['status']} (text too short or parse error)")
            error_count += 1
            continue

        article_text = parsed["text"]
        article_date = parsed["date"] or article.get("pub_date", "")
        print(f"    Extracted {len(article_text)} chars, date: {article_date or 'unknown'}")

        # Step 2: SOP extraction
        print(f"    Running SOP extraction...")
        lead = sop_extract(title, url, article_date, article_text)

        if not lead:
            print(f"    ERROR: SOP extraction returned empty result")
            error_count += 1
            continue

        # Step 3: Python guard — disqualify if year already passed
        current_year = datetime.now().year
        gb = lead.get("groundbreaking_year", "")
        cp = lead.get("completion_year", "")
        if lead.get("qualified", "No") == "Yes" and (
            _is_past_year(gb, current_year) or _is_past_year(cp, current_year)
        ):
            past_val = gb if _is_past_year(gb, current_year) else cp
            parsed_yr = _parse_year(past_val)
            lead["qualified"] = "No"
            lead["justification"] = (
                f"Auto-disqualified: "
                f"{'groundbreaking' if _is_past_year(gb, current_year) else 'completion'} "
                f"year ({parsed_yr}) has already passed as of {current_year}."
            )
            print(f"    PAST-YEAR OVERRIDE → Disqualified (year: {past_val})")

        # Attach metadata
        lead["scraped_date"] = article.get("scraped_date", datetime.now().strftime("%Y-%m-%d"))
        lead["article_link"] = url
        lead["source"] = article.get("source", "")

        extract_path.write_text(json.dumps(lead, indent=2), encoding="utf-8")

        qualified = lead.get("qualified", "No")
        score = lead.get("confidence_score", "?")
        print(f"    → Qualified: {qualified} | Score: {score} | Project: {lead.get('project_name', 'N/A')}")
        extracted_count += 1

    print(f"\nResults:")
    print(f"  Extracted:       {extracted_count}")
    print(f"  Already done:    {skipped_count}")
    print(f"  Errors/skipped:  {error_count}")
    return extracted_count


if __name__ == "__main__":
    if str(Path(__file__).parent.parent) not in sys.path:
        sys.path.insert(0, str(Path(__file__).parent.parent))
    run()
