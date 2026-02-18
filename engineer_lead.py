import os
import json
import pandas as pd
from sqlalchemy import create_engine, text
from rapidfuzz import process, fuzz
from datetime import datetime
import re

# ----------------------------------------------------------
# DB Connection
# ----------------------------------------------------------

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://neondb_owner:npg_s8CycEkWUDP5@ep-lively-bonus-af0wprvc-pooler."
    "c-2.us-west-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require"
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

# ----------------------------------------------------------
# Engineer Mapping (canonical mapping)
# ----------------------------------------------------------

_ENGINEER_RAW_TO_CANON = {
    # your giant mapping — unchanged
}

def _norm_name_key(s: str) -> str:
    if not s:
        return ""
    cleaned = re.sub(r"[^A-Za-z0-9&/+\s]", " ", s)
    cleaned = re.sub(r"\s+", " ", cleaned).strip().lower()
    return cleaned

_ENGINEER_NORM_MAP = {_norm_name_key(k): v for k, v in _ENGINEER_RAW_TO_CANON.items()}

def map_possible_engineer_name(name: str) -> str:
    if not name:
        return ""
    mapped = _ENGINEER_NORM_MAP.get(_norm_name_key(name))
    return mapped if mapped else name.strip()

def map_possible_engineers_joined(pe_str: str) -> str:
    if not pe_str:
        return ""
    parts = [p.strip() for p in pe_str.split("+") if p.strip()]
    out, seen = [], set()
    for p in parts:
        canon = map_possible_engineer_name(p)
        if canon.lower() not in seen:
            seen.add(canon.lower())
            out.append(canon)
    return " + ".join(out)

# ----------------------------------------------------------
# Architect → Engineer mapping table
# ----------------------------------------------------------

def load_arch_map():
    try:
        df = pd.read_sql("SELECT architect, engineers FROM architect_engineers_map", engine)
    except Exception:
        return [], {}

    names = df["architect"].dropna().astype(str).tolist()
    eng_map = {}

    for _, r in df.iterrows():
        raw = r["engineers"]
        try:
            lst = json.loads(raw)
            if not isinstance(lst, list):
                lst = []
        except Exception:
            lst = []
        eng_map[str(r["architect"])] = lst

    return names, eng_map

# ----------------------------------------------------------
# Architect input cleanup
# ----------------------------------------------------------

ARCH_REMOVE_RE = re.compile(
    r"\b(architects?|architecture|architectural|arch\.?)\b",
    re.IGNORECASE
)

def _clean_architect_input(name: str) -> str:
    if not name:
        return ""
    cleaned = ARCH_REMOVE_RE.sub(" ", name)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned

# ----------------------------------------------------------
# Fuzzy match logic
# ----------------------------------------------------------

def suggest_possible_engineers(arch_name, names_list, eng_map,
                               min_score=90, top_matches=10, max_engineers=10):

    if not arch_name:
        return []

    clean_input = _clean_architect_input(arch_name)

    if not clean_input:
        return []

    matches = process.extract(
        clean_input,
        names_list,
        scorer=fuzz.token_set_ratio,
        limit=top_matches
    )

    filtered = [(name, score) for (name, score, _) in matches if score >= min_score]
    if not filtered:
        return []

    filtered.sort(key=lambda x: x[1], reverse=True)

    out, seen = [], set()
    for (name, score) in filtered:
        for eng in eng_map.get(name, []):
            if eng not in seen:
                seen.add(eng)
                out.append(eng)
                if len(out) >= max_engineers:
                    return out
    return out

# ----------------------------------------------------------
# Lead Score Logic (NEW)
# ----------------------------------------------------------

def compute_lead_score(row) -> int:
    score = 1  # everyone starts at 1
    if str(row.get("Architect", "")).strip():
        score += 1
    if str(row.get("Possible Engineer", "")).strip():
        score += 1
    if str(row.get("Developer", "")).strip():
        score += 1
    return score  # always between 1–4

# ----------------------------------------------------------
# Disqualify leads with current-year-or-earlier dates
# ----------------------------------------------------------

YEAR_RE = re.compile(r"\b(20\d{2})\b")

def _extract_min_year(val) -> int | None:
    """Extract the smallest 4-digit year from a string like 'Early 2026' or 'Q1 2027'."""
    if pd.isna(val) or not str(val).strip():
        return None
    years = [int(y) for y in YEAR_RE.findall(str(val))]
    return min(years) if years else None

def disqualify_current_year_or_earlier():
    """Set Qualified='No' for rows where groundbreaking or completion year <= current year."""
    current_year = datetime.now().year
    print(f"Checking for qualified leads with groundbreaking/completion year <= {current_year}...")

    df = pd.read_sql(
        'SELECT "Article Link", "Project Name", "Groundbreaking Year", "Completion Year" '
        'FROM general_internal_scored WHERE "Qualified" = \'Yes\'',
        engine
    )

    to_disqualify = []
    for _, row in df.iterrows():
        gb_year = _extract_min_year(row["Groundbreaking Year"])
        comp_year = _extract_min_year(row["Completion Year"])

        if (gb_year and gb_year <= current_year) or (comp_year and comp_year <= current_year):
            to_disqualify.append((row["Article Link"], row["Project Name"]))

    if not to_disqualify:
        print("No leads to disqualify.")
        return

    with engine.begin() as conn:
        for url, project in to_disqualify:
            conn.execute(
                text("""
                    UPDATE general_internal_scored
                    SET "Qualified" = 'No'
                    WHERE "Article Link" = :url
                    AND "Project Name" = :project
                """),
                {"url": url, "project": project}
            )

    print(f"Disqualified {len(to_disqualify)} leads with groundbreaking/completion year <= {current_year}.")

# ----------------------------------------------------------
# MAIN
# ----------------------------------------------------------

def main():

    # Step 1: Disqualify leads that are too far along
    disqualify_current_year_or_earlier()

    # Step 2: Fill in engineer correlations for remaining qualified leads
    print("\nLoading table general_internal_scored...")
    df = pd.read_sql("SELECT * FROM general_internal_scored", engine)

    if "Architect" not in df.columns:
        raise RuntimeError("Table general_internal_scored does not have an 'Architect' column.")

    # Only process qualified rows where Possible Engineer is blank/null
    blank_mask = (
        (df["Possible Engineer"].fillna("").str.strip() == "") &
        (df["Qualified"].fillna("") == "Yes")
    )
    blank_df = df[blank_mask].copy()
    print(f"Found {len(blank_df)} qualified rows with blank Possible Engineer (out of {len(df)} total).")

    if blank_df.empty:
        print("Nothing to update — all rows already have a Possible Engineer.")
        return

    names_list, eng_index = load_arch_map()
    print(f"Loaded {len(names_list)} architects from mapping table.")

    print("Computing Possible Engineer for blank rows...")

    possible_list = []
    for _, row in blank_df.iterrows():
        arch = str(row["Architect"]) if pd.notna(row["Architect"]) else ""

        pe_list = suggest_possible_engineers(
            arch,
            names_list,
            eng_index
        )
        joined_pe = " + ".join(pe_list) if pe_list else ""
        joined_pe = map_possible_engineers_joined(joined_pe)

        possible_list.append(joined_pe)

    blank_df["Possible Engineer"] = possible_list

    print("Computing Lead Scores for updated rows...")
    blank_df["Lead Score"] = blank_df.apply(compute_lead_score, axis=1)

    print("Writing results back to Neon...")

    updated = 0
    with engine.begin() as conn:
        for idx, row in blank_df.iterrows():
            conn.execute(
                text("""
                    UPDATE general_internal_scored
                    SET "Possible Engineer" = :pe,
                        "Lead Score" = :ls
                    WHERE "Article Link" = :url
                    AND "Project Name" = :project
                """),
                {
                    "pe": row["Possible Engineer"],
                    "ls": int(row["Lead Score"]),
                    "url": row["Article Link"],
                    "project": row["Project Name"]
                }
            )
            updated += 1

    print(f"Done! Updated Possible Engineer and Lead Score for {updated} blank rows.")


if __name__ == "__main__":
    main()
