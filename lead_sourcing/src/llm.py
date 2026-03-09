"""
LLM API wrapper for the JASCKO South Florida pipeline.
- prequalify(): Fast Qwen Turbo via OpenRouter (cheap, URL-only)
- sop_extract(): Full SOP v4.2.2 via Grok/Claude (structured JSON)
"""

import json
import re
import time

import requests

from src.config import (
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    PREQUALIFY_MODEL,
    SOP_MODEL,
    SOP_TEMPERATURE,
    HTTP_MAX_RETRIES,
    HTTP_RETRY_DELAY,
    RATE_LIMIT_DELAY,
)
from src.prompts import PREQUALIFY_PROMPT, build_sop_system_prompt, SOP_USER_TEMPLATE


def call_openrouter(model: str, system_prompt: str, user_prompt: str, temperature: float = 0.1) -> str:
    """Make a chat completion call to OpenRouter. Returns response text."""
    if not OPENROUTER_API_KEY:
        raise ValueError("OPENROUTER_API_KEY not set")

    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://aiva-jascko.local",
        "X-Title": "JASCKO South Florida Lead Sourcing",
    }

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
    }

    for attempt in range(1, HTTP_MAX_RETRIES + 1):
        try:
            resp = requests.post(OPENROUTER_BASE_URL, headers=headers, json=payload, timeout=120)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]

            usage = data.get("usage", {})
            if usage:
                print(f"    [{model}] tokens: {usage.get('prompt_tokens', 0)} in / {usage.get('completion_tokens', 0)} out")

            time.sleep(RATE_LIMIT_DELAY)
            return content.strip()

        except requests.exceptions.HTTPError as e:
            if resp.status_code == 429:
                wait = HTTP_RETRY_DELAY * attempt * 2
                print(f"    Rate limited. Waiting {wait}s...")
                time.sleep(wait)
            elif attempt < HTTP_MAX_RETRIES:
                print(f"    HTTP {resp.status_code}: {e}. Retry {attempt}...")
                time.sleep(HTTP_RETRY_DELAY)
            else:
                raise
        except Exception as e:
            if attempt < HTTP_MAX_RETRIES:
                print(f"    Error: {e}. Retry {attempt}...")
                time.sleep(HTTP_RETRY_DELAY)
            else:
                raise

    return ""


def prequalify(url: str) -> str:
    """
    Pre-qualify an article URL.
    Returns: "pass" | "disqualify"
    """
    result = call_openrouter(
        model=PREQUALIFY_MODEL,
        system_prompt=PREQUALIFY_PROMPT,
        user_prompt=f"URL: {url}",
        temperature=0.0,
    )
    result_lower = result.lower().strip().strip('"').strip("'")
    return "pass" if "pass" in result_lower and "disqualify" not in result_lower else "disqualify"


# Cache the SOP system prompt (it's 115KB — only build once per run)
_SOP_SYSTEM_PROMPT = None


def _get_sop_prompt() -> str:
    global _SOP_SYSTEM_PROMPT
    if _SOP_SYSTEM_PROMPT is None:
        _SOP_SYSTEM_PROMPT = build_sop_system_prompt()
    return _SOP_SYSTEM_PROMPT


def sop_extract(title: str, url: str, article_date: str, article_text: str) -> dict:
    """
    Run the full SOP v4.2.2 South Florida extraction on an article.
    Returns a dict matching the jascko_internal_scored_v2 schema (snake_case keys).
    """
    user_prompt = SOP_USER_TEMPLATE.format(
        title=title,
        url=url,
        article_date=article_date,
        article_text=article_text,
    )

    result = call_openrouter(
        model=SOP_MODEL,
        system_prompt=_get_sop_prompt(),
        user_prompt=user_prompt,
        temperature=SOP_TEMPERATURE,
    )

    # Strip markdown code fences if present
    json_str = result
    if "```json" in json_str:
        json_str = json_str.split("```json")[1].split("```")[0]
    elif "```" in json_str:
        json_str = json_str.split("```")[1].split("```")[0]

    try:
        parsed = json.loads(json_str.strip())
    except json.JSONDecodeError:
        print(f"    WARNING: Failed to parse SOP JSON for {url}")
        print(f"    Raw response (first 500 chars): {result[:500]}")
        return {}

    # Map SOP output to our snake_case schema
    return {
        "project_name":        parsed.get("project_name", ""),
        "developer":           parsed.get("developer", ""),
        "architect":           parsed.get("architect", ""),
        "contractor":          parsed.get("contractor", ""),
        "possible_engineer":   "",  # Filled by engineer_lead.py
        "address":             parsed.get("address", ""),
        "city":                parsed.get("city", ""),
        "territory":           parsed.get("territory", ""),
        "use_type":            parsed.get("use_type", ""),
        "total_units":         parsed.get("total_units", ""),
        "square_footage":      parsed.get("square_footage", ""),
        "building_height":     parsed.get("building_height", ""),
        "groundbreaking_year": parsed.get("groundbreaking_year", ""),
        "completion_year":     parsed.get("completion_year", ""),
        "article_title":       parsed.get("article_title", title),
        "article_date":        parsed.get("article_date", article_date),
        "article_link":        url,
        "article_summary":     parsed.get("article_summary", ""),
        "milestone_mentions":  parsed.get("milestone_mentions", ""),
        "planned_mentions":    parsed.get("planned_mentions", ""),
        "confidence_score":    str(parsed.get("confidence_score", "")),
        "qualified":           parsed.get("qualified", "No"),
        "justification":       parsed.get("justification", parsed.get("reasoning", "")),
        "lead_score":          "",  # Filled by engineer_lead.py
        "structural_engineer": "",  # Future: doc_checker
        "civil_engineer":      "",  # Future: doc_checker
        "canonical_project_name": "",  # Filled by group_projects.py
    }
