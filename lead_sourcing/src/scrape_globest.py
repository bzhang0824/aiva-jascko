"""
Scraper: GlobeSt
Searches globest.com for South Florida construction news.
Adapted from DMI paving globest.py — changed to South Florida search queries.
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from src.config import SOURCES, SCRAPED_DIR, HTTP_TIMEOUT, HTTP_MAX_RETRIES, HTTP_RETRY_DELAY

SOURCE = SOURCES["GlobeSt"]
OUTPUT_DIR = SCRAPED_DIR / SOURCE["slug"]

SCRAPINGBEE_API_KEY = os.getenv("SCRAPINGBEE_API_KEY", "")

# South Florida search queries to rotate
SEARCH_QUERIES = ["miami", "fort+lauderdale", "west+palm+beach", "south+florida"]

SFL_KEYWORDS = [
    "miami", "fort lauderdale", "west palm", "boca raton", "broward",
    "palm beach", "dade", "coral gables", "aventura", "hialeah",
    "hollywood fl", "pompano", "south florida",
]


def slug_from_url(url: str) -> str:
    path = urlparse(url).path.strip("/").replace("/", "_")
    path = re.sub(r"[^a-zA-Z0-9_-]", "", path)
    return path[:120]


def fetch_with_scrapingbee(url: str) -> str | None:
    if not SCRAPINGBEE_API_KEY:
        return None
    try:
        resp = requests.get(
            "https://app.scrapingbee.com/api/v1/",
            params={"api_key": SCRAPINGBEE_API_KEY, "url": url, "render_js": "false"},
            timeout=60,
        )
        if resp.status_code == 200:
            return resp.text
    except Exception:
        pass
    return None


def fetch_search_page(query: str, page_num: int = 1) -> str:
    url = f"{SOURCE['search_url']}?q={query}&page={page_num}"

    # Try ScrapingBee first (GlobeSt has Cloudflare)
    html = fetch_with_scrapingbee(url)
    if html:
        return html

    # Fallback: direct request
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
                print(f"  FAILED search '{query}' page {page_num}: {e}")
                return ""


def is_south_florida(title: str, url: str) -> bool:
    text = (title + " " + url).lower()
    return any(kw in text for kw in SFL_KEYWORDS)


def parse_articles_from_html(html: str) -> list:
    soup = BeautifulSoup(html, "html.parser")
    articles = []
    seen_urls = set()

    for link in soup.find_all("a", href=True):
        href = link["href"]
        match = re.search(r"/(20\d{2})/(\d{2})/(\d{2})/([^/]+)/?$", href)
        if not match:
            continue
        year, month, day, slug = match.groups()
        title = link.get_text(strip=True)
        if len(title) < 15:
            continue
        full_url = urljoin(SOURCE["base_url"], href)
        if full_url in seen_urls:
            continue
        seen_urls.add(full_url)
        articles.append({
            "title": title,
            "url": full_url,
            "pub_date": f"{year}-{month}-{day}",
        })

    return articles


def scrape(max_pages: int = 3):
    print(f"\n{'='*60}")
    print(f"SCRAPING: GlobeSt (South Florida search)")
    print(f"{'='*60}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_articles = []
    seen_urls = set()
    cutoff = datetime.now() - timedelta(days=30)

    for query in SEARCH_QUERIES:
        for page_num in range(1, max_pages + 1):
            if page_num > 1:
                time.sleep(2)
            html = fetch_search_page(query, page_num)
            if not html:
                break

            articles = parse_articles_from_html(html)
            if not articles:
                break

            found_old = False
            for art in articles:
                if art["url"] in seen_urls:
                    continue
                try:
                    art_date = datetime.strptime(art["pub_date"], "%Y-%m-%d")
                    if art_date < cutoff:
                        found_old = True
                        continue
                except ValueError:
                    pass
                if is_south_florida(art["title"], art["url"]):
                    seen_urls.add(art["url"])
                    all_articles.append(art)

            print(f"  Query '{query}' page {page_num}: {len(articles)} articles")
            if found_old:
                break

    print(f"  Total South Florida articles: {len(all_articles)}")

    new_count = 0
    for art in all_articles:
        slug = slug_from_url(art["url"])
        filepath = OUTPUT_DIR / f"{slug}.json"
        if filepath.exists():
            continue

        article = {
            "title": art["title"],
            "url": art["url"],
            "pub_date": art.get("pub_date", ""),
            "source": "GlobeSt",
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
