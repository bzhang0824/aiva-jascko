"""
Scraper: Tavily AI Search
Runs rotating South Florida construction queries via Tavily API.
"""

import json
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

from src.config import (
    SOURCES, SCRAPED_DIR, TAVILY_API_KEY, TAVILY_QUERIES,
    TAVILY_SEARCH_DEPTH, TAVILY_MAX_RESULTS, TAVILY_EXCLUDE_DOMAINS,
    RATE_LIMIT_DELAY,
)

SOURCE = SOURCES["Tavily"]
OUTPUT_DIR = SCRAPED_DIR / SOURCE["slug"]


def slug_from_url(url: str) -> str:
    path = urlparse(url).path.strip("/").replace("/", "_")
    path = re.sub(r"[^a-zA-Z0-9_-]", "", path)
    return (path or "article")[:120]


def search_tavily(query: str) -> list:
    """Run a single Tavily search and return results."""
    if not TAVILY_API_KEY:
        print("  WARNING: TAVILY_API_KEY not set")
        return []

    try:
        resp = requests.post(
            "https://api.tavily.com/search",
            json={
                "api_key": TAVILY_API_KEY,
                "query": query,
                "search_depth": TAVILY_SEARCH_DEPTH,
                "max_results": TAVILY_MAX_RESULTS,
                "include_domains": [],
                "exclude_domains": TAVILY_EXCLUDE_DOMAINS,
            },
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("results", [])
    except Exception as e:
        print(f"  Tavily error for '{query}': {e}")
        return []


def scrape():
    print(f"\n{'='*60}")
    print(f"SCRAPING: Tavily AI Search")
    print(f"Queries: {len(TAVILY_QUERIES)}")
    print(f"{'='*60}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    all_results = []
    seen_urls = set()

    for i, query in enumerate(TAVILY_QUERIES):
        print(f"\n  Query {i+1}/{len(TAVILY_QUERIES)}: {query}")
        results = search_tavily(query)
        print(f"  → {len(results)} results")

        for result in results:
            url = result.get("url", "")
            title = result.get("title", "")
            content = result.get("content", "")

            if not url or url in seen_urls:
                continue
            seen_urls.add(url)
            all_results.append({"title": title, "url": url, "snippet": content})

        if i < len(TAVILY_QUERIES) - 1:
            time.sleep(RATE_LIMIT_DELAY)

    print(f"\n  Total unique results: {len(all_results)}")

    new_count = 0
    for art in all_results:
        slug = slug_from_url(art["url"])
        # Prefix with tavily_ to avoid collisions
        filepath = OUTPUT_DIR / f"tavily_{slug}.json"
        if filepath.exists():
            continue

        article = {
            "title": art["title"],
            "url": art["url"],
            "pub_date": "",
            "snippet": art.get("snippet", ""),
            "source": "Tavily",
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
