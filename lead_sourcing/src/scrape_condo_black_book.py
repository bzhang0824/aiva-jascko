"""
Scraper: Condo Black Book (monthly blog round-ups)

CBB publishes monthly blog posts listing new/planned condo projects:
- Miami: /blog/[month]-[year]-miami-new-development-and-pre-construction-condo-update/
- Ft. Lauderdale / Palm Beach: /blog/[month]-[year]-fort-lauderdale-and-palm-beach-...

This scraper:
1. Generates current and previous month URLs
2. Fetches each blog post
3. Extracts only "Approved" and "Planned/Proposed" sections (skips "Under Construction"/"Completed")
4. Each project within those sections = one lead entry
5. Deduplication is handled at upload time by Article Link
"""

import json
import re
import sys
import time
from datetime import datetime, date
from pathlib import Path
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from src.config import SOURCES, SCRAPED_DIR, HTTP_TIMEOUT, HTTP_MAX_RETRIES, HTTP_RETRY_DELAY

SOURCE = SOURCES["Condo Black Book"]
OUTPUT_DIR = SCRAPED_DIR / SOURCE["slug"]

# Sections we WANT to extract (early-stage projects)
QUALIFY_SECTIONS = ["approved", "planned", "proposed", "pre-construction", "announced"]

# Sections to SKIP (already built or under construction)
SKIP_SECTIONS = ["under construction", "completed", "sold out", "delivered", "open"]


def slug_from_url(url: str) -> str:
    path = urlparse(url).path.strip("/").replace("/", "_")
    path = re.sub(r"[^a-zA-Z0-9_-]", "", path)
    return path[:120]


def generate_month_urls() -> list[dict]:
    """Generate CBB blog URLs for current month and previous 2 months."""
    urls = []
    now = datetime.now()

    for months_back in range(0, 3):  # Current month + 2 previous months
        year = now.year
        month = now.month - months_back
        while month <= 0:
            month += 12
            year -= 1

        month_name = date(year, month, 1).strftime("%B").lower()
        year_str = str(year)

        miami_url = SOURCE["miami_url_template"].format(month=month_name, year=year_str)
        sfl_url = SOURCE["sfl_url_template"].format(month=month_name, year=year_str)

        urls.append({"url": miami_url, "region": "Miami", "month": month_name, "year": year_str})
        urls.append({"url": sfl_url, "region": "Ft. Lauderdale / Palm Beach", "month": month_name, "year": year_str})

    return urls


def fetch_page(url: str) -> str:
    for attempt in range(1, HTTP_MAX_RETRIES + 1):
        try:
            resp = requests.get(
                url,
                timeout=HTTP_TIMEOUT,
                headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
                allow_redirects=True,
            )
            # CBB returns 404 for months that don't have posts yet — that's OK
            if resp.status_code == 404:
                print(f"  404 (not published yet): {url}")
                return ""
            resp.raise_for_status()
            return resp.text
        except requests.RequestException as e:
            if attempt < HTTP_MAX_RETRIES:
                time.sleep(HTTP_RETRY_DELAY)
            else:
                print(f"  FAILED: {e}")
                return ""


def extract_sections(html: str, page_url: str, region: str, month: str, year: str) -> list:
    """
    Parse the CBB blog post HTML.
    Returns a list of project dicts extracted from qualifying sections.
    """
    soup = BeautifulSoup(html, "html.parser")
    projects = []

    # Find the main article body
    body = (
        soup.find("div", class_="entry-content")
        or soup.find("article")
        or soup.find("main")
        or soup
    )

    # Walk through all headings to identify sections
    current_section = None
    in_qualifying_section = False

    for element in body.descendants:
        if not hasattr(element, "name") or element.name is None:
            continue

        # Detect section headings (h2, h3, h4, strong)
        if element.name in ["h2", "h3", "h4"]:
            heading_text = element.get_text(strip=True).lower()

            # Determine if this section is qualifying or skippable
            if any(kw in heading_text for kw in QUALIFY_SECTIONS):
                current_section = element.get_text(strip=True)
                in_qualifying_section = True
            elif any(kw in heading_text for kw in SKIP_SECTIONS):
                current_section = None
                in_qualifying_section = False
            # If heading doesn't match either, keep current state

        # Extract project info from qualifying sections
        if in_qualifying_section and element.name in ["h3", "h4", "strong"]:
            project_name = element.get_text(strip=True)

            # Skip if this is a section header itself
            if (len(project_name) < 5 or
                    any(kw in project_name.lower() for kw in QUALIFY_SECTIONS + SKIP_SECTIONS)):
                continue

            # Get the description (next sibling paragraphs)
            description_parts = []
            next_el = element.find_next_sibling()
            while next_el and next_el.name in ["p", "ul", "ol"]:
                text = next_el.get_text(strip=True)
                if text:
                    description_parts.append(text)
                next_el = next_el.find_next_sibling()
                if next_el and next_el.name in ["h3", "h4", "h2"]:
                    break  # Hit next project

            description = " ".join(description_parts[:3])  # Cap at 3 paragraphs

            if project_name and len(project_name) > 5:
                # Create a pseudo-URL using the page URL + project slug
                project_slug = re.sub(r"[^a-z0-9]+", "-", project_name.lower()).strip("-")
                pseudo_url = f"{page_url}#{project_slug}"

                projects.append({
                    "title": f"[CBB] {project_name} — {region} {month.title()} {year}",
                    "url": pseudo_url,
                    "page_url": page_url,
                    "project_name": project_name,
                    "description": description,
                    "section": current_section,
                    "region": region,
                    "month": month,
                    "year": year,
                })

    return projects


def scrape():
    print(f"\n{'='*60}")
    print(f"SCRAPING: Condo Black Book (monthly blog)")
    print(f"{'='*60}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    month_urls = generate_month_urls()
    print(f"  Checking {len(month_urls)} blog post URLs (current + 2 prior months)")

    new_count = 0

    for entry in month_urls:
        url = entry["url"]
        print(f"\n  Fetching: {url}")

        html = fetch_page(url)
        if not html:
            continue

        projects = extract_sections(html, url, entry["region"], entry["month"], entry["year"])
        print(f"  Found {len(projects)} projects in qualifying sections")

        for project in projects:
            slug = slug_from_url(project["url"])
            filepath = OUTPUT_DIR / f"{slug}.json"
            if filepath.exists():
                continue

            # The article text for extraction = description from blog post
            article = {
                "title": project["title"],
                "url": project["url"],
                "pub_date": f"{project['year']}-{datetime.strptime(project['month'], '%B').month:02d}-01",
                "source": "Condo Black Book",
                "source_slug": SOURCE["slug"],
                "scraped_date": datetime.now().strftime("%Y-%m-%d"),
                # Pre-populated article text from the blog post (no need to fetch full article)
                "prefetched_text": (
                    f"Project: {project['project_name']}\n"
                    f"Region: {project['region']}\n"
                    f"Status Section: {project['section']}\n"
                    f"Month/Year: {project['month'].title()} {project['year']}\n\n"
                    f"{project['description']}"
                ),
            }
            filepath.write_text(json.dumps(article, indent=2), encoding="utf-8")
            print(f"  NEW: {project['project_name'][:80]}")
            new_count += 1

        time.sleep(2)  # Be polite between requests

    print(f"\nResults: {new_count} new projects saved")
    return new_count


if __name__ == "__main__":
    if str(Path(__file__).parent.parent) not in sys.path:
        sys.path.insert(0, str(Path(__file__).parent.parent))
    scrape()
