"""
Column mapping for the jascko_internal_scored_v2 Neon table.
The DB uses Title Case with spaces for all column names (not snake_case).
"""

# Maps our internal snake_case field names → Neon's Title Case column names
COLUMN_MAP = {
    # Core fields (shared with legacy table)
    "project_name":        "Project Name",
    "developer":           "Developer",
    "architect":           "Architect",
    "contractor":          "Contractor",
    "possible_engineer":   "Possible Engineer",
    "address":             "Address",
    "territory":           "Territory",
    "groundbreaking_year": "Groundbreaking Year",
    "completion_year":     "Completion Year",
    "article_title":       "Article Title",
    "article_date":        "Article Date",
    "scraped_date":        "Scraped Date",
    "article_link":        "Article Link",
    "article_summary":     "Article Summary",
    "milestone_mentions":  "Milestone Mentions",
    "planned_mentions":    "Planned Mentions",
    "lead_score":          "Lead Score",
    "qualified":           "Qualified",
    "justification":       "Justification",
    "use_type":            "Use Type",
    # v2 new fields
    "city":                "City",
    "total_units":         "Total Units",
    "square_footage":      "Square Footage",
    "building_height":     "Building Height",
    "source":              "Source",
    "case_number":         "Case Number",
    "case_type":           "Case Type",
    "structural_engineer": "Structural Engineer",
    "civil_engineer":      "Civil Engineer",
    "canonical_project_name": "Canonical Project Name",
    "confidence_score":    "Confidence Score",
}

# All Title Case column names in insert order
DB_COLUMNS = list(COLUMN_MAP.values())


def normalize_record(record: dict) -> dict:
    """Convert a snake_case record dict to Title Case column names for the database."""
    normalized = {}
    for snake_key, title_key in COLUMN_MAP.items():
        if snake_key in record and record[snake_key] not in (None, ""):
            normalized[title_key] = record[snake_key]
    return normalized
