"""
One-time setup script: Create the jascko_internal_scored_v2 table in Neon.

Run once before the pipeline starts:
    source ~/.zshrc && python3 lead_sourcing/src/create_v2_table.py
"""

import sys
from pathlib import Path

# Allow running from repo root
if str(Path(__file__).parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).parent.parent))

import psycopg2
from src.config import DATABASE_URL, SCORED_TABLE


CREATE_TABLE_SQL = f"""
CREATE TABLE IF NOT EXISTS {SCORED_TABLE} (
    id                      SERIAL PRIMARY KEY,

    -- Core project fields
    "Project Name"          TEXT,
    "Developer"             TEXT,
    "Architect"             TEXT,
    "Contractor"            TEXT,
    "Possible Engineer"     TEXT,
    "Address"               TEXT,
    "City"                  TEXT,
    "Territory"             TEXT,

    -- Project details (v2 new)
    "Use Type"              TEXT,
    "Total Units"           TEXT,
    "Square Footage"        TEXT,
    "Building Height"       TEXT,

    -- Timeline
    "Groundbreaking Year"   TEXT,
    "Completion Year"       TEXT,

    -- Article metadata
    "Article Title"         TEXT,
    "Article Date"          TEXT,
    "Article Link"          TEXT UNIQUE,
    "Article Summary"       TEXT,
    "Scraped Date"          TEXT,
    "Source"                TEXT,

    -- Government portal fields (for future use)
    "Case Number"           TEXT,
    "Case Type"             TEXT,

    -- Scoring / qualification
    "Milestone Mentions"    TEXT,
    "Planned Mentions"      TEXT,
    "Confidence Score"      TEXT,
    "Qualified"             TEXT,
    "Justification"         TEXT,
    "Lead Score"            TEXT,

    -- Engineer data
    "Structural Engineer"   TEXT,
    "Civil Engineer"        TEXT,

    -- Grouping (assigned by group_projects.py)
    "Canonical Project Name" TEXT,

    -- Timestamps
    "Created At"            TIMESTAMP DEFAULT NOW()
);
"""

INDEX_SQLS = [
    f'CREATE INDEX IF NOT EXISTS idx_{SCORED_TABLE}_article_link ON {SCORED_TABLE} ("Article Link");',
    f'CREATE INDEX IF NOT EXISTS idx_{SCORED_TABLE}_qualified ON {SCORED_TABLE} ("Qualified");',
    f'CREATE INDEX IF NOT EXISTS idx_{SCORED_TABLE}_canonical ON {SCORED_TABLE} ("Canonical Project Name");',
    f'CREATE INDEX IF NOT EXISTS idx_{SCORED_TABLE}_territory ON {SCORED_TABLE} ("Territory");',
    f'CREATE INDEX IF NOT EXISTS idx_{SCORED_TABLE}_scraped_date ON {SCORED_TABLE} ("Scraped Date");',
]


def create_table():
    print(f"Connecting to Neon database...")
    conn = psycopg2.connect(DATABASE_URL)
    try:
        cur = conn.cursor()

        print(f"Creating table: {SCORED_TABLE}...")
        cur.execute(CREATE_TABLE_SQL)

        print("Creating indexes...")
        for idx_sql in INDEX_SQLS:
            cur.execute(idx_sql)

        conn.commit()
        print(f"\n✓ Table '{SCORED_TABLE}' created successfully (or already exists)")

        # Verify
        cur.execute(f"""
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_name = '{SCORED_TABLE}'
            ORDER BY ordinal_position;
        """)
        cols = cur.fetchall()
        print(f"\nColumns ({len(cols)} total):")
        for col_name, col_type in cols:
            print(f"  {col_name}: {col_type}")

    finally:
        conn.close()


if __name__ == "__main__":
    create_table()
