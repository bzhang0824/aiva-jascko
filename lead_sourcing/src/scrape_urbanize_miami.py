"""
Scraper: Urbanize Miami
Fetches homepage at https://miami.urbanize.city and extracts /post/ article links.
"""

import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

from src.config import SOURCES, SCRAPED_DIR, HTTP_TIMEOUT, HTTP_MAX_RETRIES, HTTP_RETRY_DELAY

SOURCE = SOURCES["Urbanize Miami"]
OUTPUT_DIR = SCRAPED_DIR / SOURCE["slug"]


def slug_from_url(url: str) -> str:
    path = urlparse(url).path.strip("/").replace("/", "_")
    path = re.sub(r"[^a-zA-Z0-9_-]", "", path)
    return path[:120]


def title_from_slug(url: str) -> str:
    path = urlparse(url).path.strip("/")
    if path.startswith("post/"):
        path = path[5:]
    path = re.sub(r"^\d+-", "", path)
    return path.replace("-", " ").title()


def fetch_homepage() -> str:
    for attempt in range(1, HTTP_MAX_RETRIES + 1):
        try:
            resp = requests.get(
                SOURCE["base_url"],
                timeout=HTTP_TIMEOUT,
                headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
            )
            resp.raise_for_status()
            return resp.text
        except requests.RequestException as e:
            if attempt < HTTP_MAX_RETRIES:
                time.sleep(HTTP_RETRY_DELAY)
            else:
                print(f"  FAILED: {e}")
                return ""


def scrape():
    print(f"\n{'='*60}")
    print(f"SCRAPING: Urbanize Miami")
    print(f"URL: {SOURCE['base_url']}")
    print(f"{'='*60}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    html = fetch_homepage()
    if not html:
        return 0

    article_pattern = re.compile(r'href="(/post/[^"]+)"', re.IGNORECASE)
    matches = article_pattern.findall(html)

    seen_paths, unique_paths = set(), []
    for path in matches:
        if path not in seen_paths:
            seen_paths.add(path)
            unique_paths.append(path)

    print(f"  Found {len(unique_paths)} unique article links")

    new_count = 0
    for path in unique_paths:
        url = f"{SOURCE['base_url']}{path}"
        slug = slug_from_url(url)
        filepath = OUTPUT_DIR / f"{slug}.json"
        if filepath.exists():
            continue

        article = {
            "title": title_from_slug(url),
            "url": url,
            "pub_date": "",
            "source": "Urbanize Miami",
            "source_slug": SOURCE["slug"],
            "scraped_date": datetime.now().strftime("%Y-%m-%d"),
        }
        filepath.write_text(json.dumps(article, indent=2), encoding="utf-8")
        print(f"  NEW: {article['title'][:80]}")
        new_count += 1

    print(f"\nResults: {new_count} new articles saved")
    return new_count


if __name__ == "__main__":
    if str(Path(__file__).parent.parent) not in sys.path:
        sys.path.insert(0, str(Path(__file__).parent.parent))
    scrape()
