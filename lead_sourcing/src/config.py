"""
Central configuration for the JASCKO South Florida lead sourcing pipeline.
"""

import os
from pathlib import Path

# --- Database ---
# DATABASE_URL is injected via GitHub Secrets or ~/.zshrc
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://neondb_owner:npg_s8CycEkWUDP5@ep-lively-bonus-af0wprvc-pooler.c-2.us-west-2.aws.neon.tech/neondb?sslmode=require",
)

# Target table (v2 — upgraded schema with Canonical Project Name)
SCORED_TABLE = "jascko_internal_scored_v2"

# --- LLM Models (via OpenRouter) ---
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1/chat/completions"

PREQUALIFY_MODEL = "qwen/qwen-turbo"          # Fast + cheap for URL-based filtering
SOP_MODEL = "x-ai/grok-4.1-fast"             # Reliable for structured extraction
SOP_TEMPERATURE = 0.1                          # Low temp = deterministic output

# --- Sources ---
SOURCES = {
    "Urbanize Miami": {
        "slug": "urbanize_miami",
        "base_url": "https://miami.urbanize.city",
        "method": "homepage_html",
    },
    "Florida YIMBY": {
        "slug": "florida_yimby",
        "base_url": "https://floridayimby.com",
        "method": "homepage_html",
    },
    "The Real Deal Miami": {
        "slug": "therealdeal_miami",
        "base_url": "https://therealdeal.com/miami/",
        "feed_url": "https://therealdeal.com/miami/feed/",
        "method": "rss",
    },
    "Bisnow Miami": {
        "slug": "bisnow_miami",
        "base_url": "https://www.bisnow.com",
        "region_url": "https://www.bisnow.com/miami",
        "region_path": "/miami/",
        "method": "html",
    },
    "South Florida Business Journal": {
        "slug": "sfbj",
        "base_url": "https://www.bizjournals.com/southflorida",
        "method": "html",
    },
    "GlobeSt": {
        "slug": "globest",
        "base_url": "https://www.globest.com",
        "search_url": "https://www.globest.com/search/",
        "method": "search_html",
    },
    "RE Business Online": {
        "slug": "rebusiness",
        "base_url": "https://rebusinessonline.com",
        "method": "html",
    },
    "Condo Black Book": {
        "slug": "condo_black_book",
        "base_url": "https://www.condoblackbook.com",
        "miami_url_template": "https://www.condoblackbook.com/blog/{month}-{year}-miami-new-development-and-pre-construction-condo-update/",
        "sfl_url_template": "https://www.condoblackbook.com/blog/{month}-{year}-fort-lauderdale-and-palm-beach-pre-construction-condo-news-update/",
        "method": "monthly_blog",
    },
    "Tavily": {
        "slug": "tavily",
        "method": "ai_search",
    },
}

# --- Tavily ---
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY")
TAVILY_SEARCH_DEPTH = "advanced"
TAVILY_MAX_RESULTS = 20

# Domains we already scrape directly — skip these in Tavily results
TAVILY_EXCLUDE_DOMAINS = [
    # Our own scrapers — already covered
    "miami.urbanize.city",
    "floridayimby.com",
    "therealdeal.com",
    "bisnow.com",
    "bizjournals.com",
    "globest.com",
    "rebusinessonline.com",
    "condoblackbook.com",
    # Social media — can't scrape content
    "instagram.com",
    "facebook.com",
    "tiktok.com",
    "youtube.com",
    "twitter.com",
    "x.com",
    "threads.com",
    "linkedin.com",
    # Real estate listing sites — not news articles
    "zillow.com",
    "realtor.com",
    "redfin.com",
    "trulia.com",
    "livabl.com",
    "condosandcondos.com",
    "miamiresidential.com",
    "manhattanmiami.com",
    "luxlifemiamiblog.com",
    # Government docs / zoning PDFs — not useful as leads
    "broward.org",
    "fortlauderdale.legistar.com",
    "cloudfront.net",
    # General event / calendar noise
    "planhub.com",
    "brgintl.com",
]

TAVILY_QUERIES = [
    "Miami new construction project planned 2027 2028",
    "Fort Lauderdale mixed-use development zoning filed",
    "West Palm Beach tower development approved 2027",
    "Broward County condo development planned 2027",
    "South Florida commercial construction groundbreaking planned",
]

# --- Paths ---
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
SCRAPED_DIR = DATA_DIR / "scraped"
OUTPUT_DIR = DATA_DIR / "output"
PREQUALIFY_CACHE = OUTPUT_DIR / "prequalify_cache.json"

# --- Guardrails ---
MAX_ARTICLE_AGE_DAYS = 30
MAX_ARTICLE_TEXT_LENGTH = 15000
MIN_ARTICLE_TEXT_LENGTH = 100
RATE_LIMIT_DELAY = 1
HTTP_TIMEOUT = 30
HTTP_MAX_RETRIES = 3
HTTP_RETRY_DELAY = 5
