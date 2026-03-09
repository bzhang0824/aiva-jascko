"""
HTML → clean article text parser.
"""

import re
from html import unescape
from bs4 import BeautifulSoup

from src.config import MAX_ARTICLE_TEXT_LENGTH, MIN_ARTICLE_TEXT_LENGTH


def extract_article_date(html: str) -> str:
    """Extract publication date from HTML meta tags or JSON-LD."""
    match = re.search(r'<meta\s+property=["\']article:published_time["\']\s+content=["\']([^"\']+)', html)
    if match:
        return match.group(1)[:10]

    match = re.search(r'"datePublished"\s*:\s*"([^"]+)"', html)
    if match:
        return match.group(1)[:10]

    return ""


def extract_article_text(html: str, prefetched_text: str = "") -> dict:
    """
    Extract clean article text from raw HTML.

    If prefetched_text is provided (e.g. from CBB blog scraper),
    it's used directly without re-parsing HTML.

    Returns dict:
        - text: cleaned article text
        - date: article date (YYYY-MM-DD or empty)
        - status: 'extracted' | 'parse_error' | 'empty'
    """
    # CBB articles come with pre-extracted text — use it directly
    if prefetched_text and len(prefetched_text) >= MIN_ARTICLE_TEXT_LENGTH:
        return {"text": prefetched_text[:MAX_ARTICLE_TEXT_LENGTH], "date": "", "status": "extracted"}

    if not html or len(html) < 50:
        return {"text": "", "date": "", "status": "empty"}

    article_date = extract_article_date(html)
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup.find_all(["script", "style", "nav", "footer", "header", "aside"]):
        tag.decompose()

    text = ""

    # Priority 1: WordPress entry-content
    content_div = soup.find("div", class_="entry-content")
    if content_div:
        paragraphs = content_div.find_all("p")
        text = "\n\n".join(p.get_text(strip=True) for p in paragraphs if p.get_text(strip=True))

    # Priority 2: Schema.org articleBody
    if not text:
        body_div = soup.find("div", attrs={"itemprop": "articleBody"})
        if body_div:
            paragraphs = body_div.find_all("p")
            text = "\n\n".join(p.get_text(strip=True) for p in paragraphs if p.get_text(strip=True))

    # Priority 3: article or main tag
    if not text:
        container = soup.find("article") or soup.find("main")
        if container:
            paragraphs = container.find_all("p")
            text = "\n\n".join(p.get_text(strip=True) for p in paragraphs if p.get_text(strip=True))

    # Priority 4: all p tags
    if not text:
        paragraphs = soup.find_all("p")
        text = "\n\n".join(p.get_text(strip=True) for p in paragraphs if p.get_text(strip=True))

    text = unescape(text)
    text = re.sub(r"\s+", " ", text).strip()

    if len(text) > MAX_ARTICLE_TEXT_LENGTH:
        text = text[:MAX_ARTICLE_TEXT_LENGTH]

    if len(text) < MIN_ARTICLE_TEXT_LENGTH:
        return {"text": text, "date": article_date, "status": "parse_error"}

    return {"text": text, "date": article_date, "status": "extracted"}
