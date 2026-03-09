"""
Scraper: RE Business Online (rebusinessonline.com)
Targets the Southeast/Florida section for South Florida construction news.
"""

import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from src.config import SOURCES, SCRAPED_DIR, HTTP_TIMEOUT, HTTP_MAX_RETRIES, HTTP_RETRY_DELAY

SOURCE = SOURCES["RE Business Online"]
OUTPUT_DIR = SCRAPED_DIR / SOURCE["slug"]

# Try these section pages
TARGET_URLS = [
    "https://rebusinessonline.com/category/southeast/",
    "https://rebusinessonline.com/category/florida/",
    "https://rebusinessonline.com/",
]

SFL_KEYWORDS = [
    "miami", "fort lauderdale", "west palm", "boca raton", "broward",
    "palm beach", "dade", "coral gables", "aventura", "hialeah",
    "hollywood", "pompano", "south florida", "florida keys",
]

RELEVANT_KEYWORDS = [
    "construct", "develop", "build", "tower", "condo", "mixed-use",
    "office", "hotel", "apartment", "project", "groundbreak", "plan",
    "approv", "zoning", "propos", "real estate", "break ground",
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
                print(f"  FAILED {url}: {e}")
                return ""


def is_relevant(title: str, url: str) -> bool:
    text = (title + " " + url).lower()
    return (any(kw in text for kw in SFL_KEYWORDS) and
            any(kw in text for kw in RELEVANT_KEYWORDS))


def scrape():
    print(f"\n{'='*60}")
    print(f"SCRAPING: RE Business Online")
    print(f"{'='*60}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_articles = []
    seen_urls = set()

    for target_url in TARGET_URLS:
        html = fetch_page(target_url)
        if not html:
            continue

        soup = BeautifulSoup(html, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = urljoin(SOURCE["base_url"], href) if href.startswith("/") else href

            # rebusinessonline.com article pattern: /YYYY/MM/slug/
            if not re.search(r"rebusinessonline\.com/20\d{2}/\d{2}/", full_url):
                continue
            if full_url in seen_urls:
                continue
            seen_urls.add(full_url)

            title = link.get_text(strip=True)
            if len(title) < 15:
                continue

            if not is_relevant(title, full_url):
                continue

            all_articles.append({"title": title, "url": full_url})

        print(f"  Checked {target_url}: {len(all_articles)} articles so far")

    print(f"  Total relevant articles: {len(all_articles)}")

    new_count = 0
    for art in all_articles:
        slug = slug_from_url(art["url"])
        filepath = OUTPUT_DIR / f"{slug}.json"
        if filepath.exists():
            continue

        article = {
            "title": art["title"],
            "url": art["url"],
            "pub_date": "",
            "source": "RE Business Online",
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
