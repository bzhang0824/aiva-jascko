"""
Scraper: The Real Deal Miami
Fetches the RSS feed at https://therealdeal.com/miami/feed/
"""

import json
import re
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

from src.config import SOURCES, SCRAPED_DIR, HTTP_TIMEOUT, HTTP_MAX_RETRIES, HTTP_RETRY_DELAY

SOURCE = SOURCES["The Real Deal Miami"]
OUTPUT_DIR = SCRAPED_DIR / SOURCE["slug"]


def slug_from_url(url: str) -> str:
    path = urlparse(url).path.strip("/").replace("/", "_")
    path = re.sub(r"[^a-zA-Z0-9_-]", "", path)
    return path[:120]


def fetch_feed() -> str:
    for attempt in range(1, HTTP_MAX_RETRIES + 1):
        try:
            resp = requests.get(
                SOURCE["feed_url"],
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


def parse_rss_date(date_str: str) -> str:
    """Parse RSS pub date to YYYY-MM-DD format."""
    if not date_str:
        return ""
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(date_str)
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return date_str[:10] if len(date_str) >= 10 else date_str


def scrape():
    print(f"\n{'='*60}")
    print(f"SCRAPING: The Real Deal Miami")
    print(f"URL: {SOURCE['feed_url']}")
    print(f"{'='*60}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    xml_text = fetch_feed()
    if not xml_text:
        return 0

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        print(f"  XML parse error: {e}")
        return 0

    ns = {"content": "http://purl.org/rss/1.0/modules/content/"}
    items = root.findall(".//item")
    print(f"  Found {len(items)} items in feed")

    new_count = 0
    for item in items:
        title_el = item.find("title")
        link_el = item.find("link")
        pub_date_el = item.find("pubDate")

        title = title_el.text.strip() if title_el is not None else ""
        url = link_el.text.strip() if link_el is not None else ""
        pub_date = parse_rss_date(pub_date_el.text) if pub_date_el is not None else ""

        if not url or len(title) < 10:
            continue

        slug = slug_from_url(url)
        filepath = OUTPUT_DIR / f"{slug}.json"
        if filepath.exists():
            continue

        article = {
            "title": title,
            "url": url,
            "pub_date": pub_date,
            "source": "The Real Deal Miami",
            "source_slug": SOURCE["slug"],
            "scraped_date": datetime.now().strftime("%Y-%m-%d"),
        }
        filepath.write_text(json.dumps(article, indent=2), encoding="utf-8")
        print(f"  NEW: {title[:80]}")
        new_count += 1

    print(f"\nResults: {new_count} new articles saved")
    return new_count


if __name__ == "__main__":
    if str(Path(__file__).parent.parent) not in sys.path:
        sys.path.insert(0, str(Path(__file__).parent.parent))
    scrape()
