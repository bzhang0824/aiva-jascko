"""
Scraper: Bisnow Miami
Fetches article links from https://www.bisnow.com/miami
Adapted from DMI paving bisnow.py — changed to Miami region.
"""

import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from src.config import SOURCES, SCRAPED_DIR, HTTP_TIMEOUT, HTTP_MAX_RETRIES, HTTP_RETRY_DELAY

SOURCE = SOURCES["Bisnow Miami"]
OUTPUT_DIR = SCRAPED_DIR / SOURCE["slug"]

# Oxylabs proxy (global credentials from ~/.zshrc)
PROXY_SERVER = os.getenv("OXYLABS_SERVER", "pr.oxylabs.io:7777")
PROXY_USERNAME = os.getenv("OXYLABS_USERNAME", "")
PROXY_PASSWORD = os.getenv("OXYLABS_PASSWORD", "")

_use_proxy = False


def _get_proxies():
    if PROXY_USERNAME and PROXY_PASSWORD:
        proxy_url = f"http://{PROXY_USERNAME}:{PROXY_PASSWORD}@{PROXY_SERVER}"
        return {"http": proxy_url, "https": proxy_url}
    return None


def slug_from_url(url: str) -> str:
    path = urlparse(url).path.strip("/").replace("/", "_")
    path = re.sub(r"[^a-zA-Z0-9_-]", "", path)
    return path[:120]


def fetch_page(page_num: int, retry_count: int = 0) -> list:
    global _use_proxy
    url = f"{SOURCE['region_url']}?page={page_num}"

    if page_num > 1:
        time.sleep(2)

    try:
        proxies = _get_proxies() if _use_proxy else None
        resp = requests.get(
            url,
            timeout=HTTP_TIMEOUT,
            proxies=proxies,
            headers={
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        err = str(e).lower()
        if ("429" in err or "403" in err) and not _use_proxy and _get_proxies():
            print(f"  Rate limited — switching to proxy...")
            _use_proxy = True
            time.sleep(3)
            return fetch_page(page_num, retry_count + 1)
        if retry_count < HTTP_MAX_RETRIES:
            wait = 2 ** retry_count
            print(f"  Error, retrying in {wait}s: {e}")
            time.sleep(wait)
            return fetch_page(page_num, retry_count + 1)
        print(f"  FAILED page {page_num}: {e}")
        return []

    soup = BeautifulSoup(resp.text, "html.parser")
    articles = []
    seen_urls = set()

    for link in soup.find_all("a", href=True):
        href = link["href"]
        # Bisnow Miami article pattern: /miami/news/category/slug-id
        match = re.search(r"/(miami|national)/news/([^/]+)/([^/]+)-(\d+)$", href)
        if not match:
            continue

        title = link.get_text(strip=True)
        if len(title) < 15:
            continue

        full_url = urljoin(SOURCE["base_url"], href)
        if full_url in seen_urls:
            continue
        seen_urls.add(full_url)

        articles.append({"title": title, "url": full_url, "category": match.group(2)})

    return articles


def scrape(max_pages: int = 5):
    print(f"\n{'='*60}")
    print(f"SCRAPING: Bisnow Miami")
    print(f"URL: {SOURCE['region_url']}")
    print(f"{'='*60}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_articles = []
    seen_urls = set()

    for page_num in range(1, max_pages + 1):
        articles = fetch_page(page_num)
        if not articles:
            print(f"  No articles on page {page_num}, stopping")
            break
        for art in articles:
            if art["url"] not in seen_urls:
                seen_urls.add(art["url"])
                all_articles.append(art)
        print(f"  Page {page_num}: {len(articles)} articles, {len(all_articles)} total")
        if len(articles) < 5:
            break

    print(f"  Total unique: {len(all_articles)}")

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
            "source": "Bisnow Miami",
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
