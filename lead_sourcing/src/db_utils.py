"""
Database utilities for the JASCKO South Florida lead sourcing pipeline.
Handles connection to Neon Postgres, dedup checks, and inserts.

Target table: jascko_internal_scored_v2
"""

import psycopg2
from datetime import datetime
from src.config import DATABASE_URL, SCORED_TABLE
from src.column_map import normalize_record


def get_connection():
    """Get a connection to the Neon PostgreSQL database."""
    return psycopg2.connect(DATABASE_URL)


def load_existing_urls() -> set:
    """
    Load all existing Article Link values from jascko_internal_scored_v2.
    Returns a set of URLs for fast dedup lookups.
    """
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            f'SELECT DISTINCT "Article Link" FROM {SCORED_TABLE} '
            f'WHERE "Article Link" IS NOT NULL'
        )
        urls = {row[0] for row in cur.fetchall()}
        print(f"  Loaded {len(urls)} existing URLs from {SCORED_TABLE}")
        return urls
    except Exception as e:
        print(f"  WARNING: Could not load existing URLs: {e}")
        return set()
    finally:
        conn.close()


def _insert_to_table(table: str, record: dict, conn) -> bool:
    """Generic insert to any table. Returns True if inserted, False if skipped."""
    if not record:
        return False
    try:
        columns = [col for col in record if record[col] is not None and record[col] != ""]
        values = [record[col] for col in columns]

        col_str = ", ".join(f'"{c}"' for c in columns)
        placeholder_str = ", ".join(["%s"] * len(columns))
        sql = f'INSERT INTO {table} ({col_str}) VALUES ({placeholder_str})'

        cur = conn.cursor()
        cur.execute(sql, values)
        conn.commit()
        return True
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        return False
    except Exception as e:
        conn.rollback()
        print(f"  ERROR inserting to {table}: {e}")
        return False


def insert_qualified_lead(lead: dict, existing_urls: set) -> bool:
    """
    Insert a QUALIFIED lead to jascko_internal_scored_v2.
    Returns True if inserted, False if duplicate or error.
    """
    url = lead.get("article_link", "")
    if not url:
        print(f"  SKIP: No article_link for '{lead.get('project_name', 'Unknown')}'")
        return False

    if url in existing_urls:
        return False

    if "scraped_date" not in lead or not lead["scraped_date"]:
        lead["scraped_date"] = datetime.now().strftime("%Y-%m-%d")

    conn = get_connection()
    try:
        record = normalize_record(lead)
        ok = _insert_to_table(SCORED_TABLE, record, conn)
        if ok:
            existing_urls.add(url)
            print(f"  INSERTED: '{lead.get('project_name', 'Unknown')}' — {url[:80]}")
        return ok
    finally:
        conn.close()
