"""
Scraper: Florida YIMBY
Fetches the homepage at https://floridayimby.com and extracts article links.
"""

import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup

from src.config import SOURCES, SCRAPED_DIR, HTTP_TIMEOUT, HTTP_MAX_RETRIES, HTTP_RETRY_DELAY

SOURCE = SOURCES["Florida YIMBY"]
OUTPUT_DIR = SCRAPED_DIR / SOURCE["slug"]

# Focus on South Florida content
SFL_KEYWORDS = [
    "miami", "fort lauderdale", "west palm", "boca raton", "broward",
    "palm beach", "dade", "coral gables", "hollywood", "pompano",
    "aventura", "hialeah", "hallandale", "deerfield", "delray",
    "south florida", "fl", "florida keys", "key biscayne",
]


def slug_from_url(url: str) -> str:
    path = urlparse(url).path.strip("/").replace("/", "_")
    path = re.sub(r"[^a-zA-Z0-9_-]", "", path)
    return path[:120]


def fetch_page(url: str) -> str:
    for attempt in range(1, HTTP_MAX_RETRIES + 1):
        try:
            resp = requests.get(
                url,
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


def is_south_florida(title: str, url: str) -> bool:
    """Quick check if article is likely South Florida related."""
    text = (title + " " + url).lower()
    return any(kw in text for kw in SFL_KEYWORDS)


def scrape():
    print(f"\n{'='*60}")
    print(f"SCRAPING: Florida YIMBY")
    print(f"URL: {SOURCE['base_url']}")
    print(f"{'='*60}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    html = fetch_page(SOURCE["base_url"])
    if not html:
        return 0

    soup = BeautifulSoup(html, "html.parser")
    seen_urls, articles_data = set(), []

    # Extract article links — Florida YIMBY uses /YYYY/MM/DD/slug/ pattern
    for link in soup.find_all("a", href=True):
        href = link["href"]
        full_url = urljoin(SOURCE["base_url"], href)

        # Match article URL pattern
        if not re.search(r"/20\d{2}/\d{2}/\d{2}/", full_url):
            continue
        if full_url in seen_urls:
            continue
        seen_urls.add(full_url)

        title = link.get_text(strip=True)
        if len(title) < 15:
            continue

        # Quick geographic filter
        if not is_south_florida(title, full_url):
            continue

        articles_data.append({"title": title, "url": full_url})

    print(f"  Found {len(articles_data)} South Florida articles")

    new_count = 0
    for art in articles_data:
        slug = slug_from_url(art["url"])
        filepath = OUTPUT_DIR / f"{slug}.json"
        if filepath.exists():
            continue

        article = {
            "title": art["title"],
            "url": art["url"],
            "pub_date": "",
            "source": "Florida YIMBY",
            "source_slug": SOURCE["slug"],
            "scraped_date": datetime.now().strftime("%Y-%m-%d"),
        }
        filepath.write_text(json.dumps(article, indent=2), encoding="utf-8")
        print(f"  NEW: {art['title'][:80]}")
        new_count += 1

    print(f"\nResults: {new_count} new articles saved")
    return new_count


if __name__ == "__main__":
    if str(Path(__file__).parent.parent) not in sys.path:
        sys.path.insert(0, str(Path(__file__).parent.parent))
    scrape()
