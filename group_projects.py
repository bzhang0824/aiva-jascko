#!/usr/bin/env python3
"""
group_projects.py
=================
Assigns a "Canonical Project Name" to every record in the database so the
frontend can group records that refer to the same physical project.

SANDBOX FIRST — all writes go to test_grouping.<table>.
Nothing in public schema is touched until you explicitly pass --apply-live.

Usage:
  python3 src/group_projects.py                                          # Dry-run on nola_scored_final
  python3 src/group_projects.py --table la_internal_scored               # Dry-run on a different table
  python3 src/group_projects.py --table la_internal_scored --max-llm 50  # Cap LLM calls (faster validation)
  python3 src/group_projects.py --confirm                                 # Write to sandbox
  python3 src/group_projects.py --apply-live                              # Copy to public.nola_scored_final

How it works (4-phase algorithm):
  Phase 1: Address matching  — same/similar street address = same project (most reliable)
  Phase 2: Name matching     — guarded fuzzy match with phase/type/territory checks
  Phase 3: LLM verification  — Claude haiku settles borderline cases
  Phase 4: Canonical naming  — pick the best project name for each group
"""

import os
import re
import sys
import json
from pathlib import Path

import psycopg2
import psycopg2.extras
from rapidfuzz import fuzz
import anthropic

# ─── Config ────────────────────────────────────────────────────────────────────

TEST_SCHEMA  = "test_grouping"
LIVE_SCHEMA  = "public"
LIVE_TABLE   = "nola_scored_final"  # --apply-live only works on this table

# Per-table column name overrides (different tables use different column names)
TABLE_PROFILES = {
    "nola_scored_final":           {"architect_col": "Architect (Sales Contact)"},
    "la_internal_scored":          {"architect_col": "Architect"},
    "test_la_internal_scored":     {"architect_col": "Architect"},
    "general_internal_scored":     {"architect_col": "Architect"},
    "nola_scored":                 {"architect_col": "Architect"},
    "general_internal_nola":       {"architect_col": "Architect"},
    # JASCKO South Florida v2
    "jascko_internal_scored_v2":   {"architect_col": "Architect"},
}

# Fuzzy thresholds
ADDR_HIGH    = 85   # >= this → same group via address
ADDR_LOW     = 65   # 65-84  → send to LLM
NAME_HIGH    = 88   # >= this → same group via name
NAME_LOW     = 68   # 68-87  → send to LLM

# Building type words — if two names explicitly name DIFFERENT types, they can't be same project
BUILDING_TYPES = {
    "school", "church", "hospital", "hotel", "apartment", "apartments",
    "complex", "center", "facility", "warehouse", "stadium", "arena",
    "park", "library", "clinic", "dormitory", "dorm", "office",
    "courthouse", "jail", "prison", "theater", "theatre",
}

# Noise words to strip when normalizing project names
NOISE_WORDS = {
    "the", "a", "an", "and", "of", "in", "at", "for", "to", "by", "on",
    "new", "planned", "proposed", "future", "project", "development",
    "construction", "renovation", "expansion", "improvements",
}

# Names so generic that they REQUIRE a strong address match (>= ADDR_HIGH) to group.
# When scrapers can't find a real project name they fall back to descriptors like
# "Affordable Housing Development" — these must NEVER be grouped by name alone,
# even if both records have addresses (the addresses could be completely different sites).
REQUIRES_ADDRESS_TO_GROUP = {
    # Admin / zoning
    "zoning text amendment", "zoning amendment", "rezoning",
    "variance", "conditional use permit", "special exception", "subdivision",
    # Generic construction descriptors (scraper LLM fallbacks)
    "new construction", "mixed use development", "mixed-use development",
    "commercial development", "residential development",
    "affordable housing", "mixed use", "mixed-use",
    "residential project", "apartment complex", "senior housing",
    "multi-family", "multifamily", "downtown residential",
    "new residential", "new commercial", "retail development",
    "hotel development", "office development", "industrial development",
    # Null / empty project names
    "unknown", "",
}

# Territory label aliases — different scrapers use different names for the same region.
# Normalized before comparing territories in Phase 2.
TERRITORY_ALIASES = {
    # LA
    "la":                       "Los Angeles County",
    "city of los angeles":      "Los Angeles County",
    # Tampa
    "greater tampa":            "Greater Tampa / Fort Myers",
    "tampa":                    "Greater Tampa / Fort Myers",
    # NOLA
    "shreveport-bossier region": "Shreveport-Bossier",
}

# Placeholder addresses that should be treated as "no address"
NON_ADDRESSES = {
    "see pdf", "see document", "see attachment", "tbd", "n/a",
    "to be determined", "various", "statewide", "multiple locations",
}

# Street suffix expansions for address normalization
STREET_SUFFIXES = {
    r"\bdr\b":   "drive",
    r"\bave\b":  "avenue",
    r"\bblvd\b": "boulevard",
    r"\bst\b":   "street",
    r"\bhwy\b":  "highway",
    r"\brd\b":   "road",
    r"\bln\b":   "lane",
    r"\bct\b":   "court",
    r"\bpl\b":   "place",
    r"\bpkwy\b": "parkway",
    r"\bsq\b":   "square",
    r"\bfwy\b":  "freeway",
    r"\bus-":    "us route ",
    # r"\bla-":    "louisiana route ",  # removed — conflicts with LA street names (La Brea, La Cienega)
    r"\bi-":     "interstate ",
}

# ─── .env loader ────────────────────────────────────────────────────────────────

def load_env():
    # Search for .env in script dir, then doc_checker/, then parent dirs
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir / ".env",
        script_dir / "doc_checker" / ".env",
        script_dir.parent / ".env",
    ]
    for env_path in candidates:
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    if k.strip() not in os.environ:
                        os.environ[k.strip()] = v.strip()
            break

# ─── DB helpers ──────────────────────────────────────────────────────────────────

def connect():
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        print("ERROR: DATABASE_URL not found")
        sys.exit(1)
    return psycopg2.connect(url)


def fetch_records(conn, schema, table):
    """Fetch all records as list of dicts."""
    cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(f'SELECT * FROM "{schema}"."{table}"')
    return [dict(r) for r in cur.fetchall()]

# ─── Normalization helpers ────────────────────────────────────────────────────────

def normalize_address(addr: str) -> str:
    """
    Strips city/state/zip, expands abbreviations, lowercases.
    Returns the street-level portion only (e.g., "6800 burbank drive").
    Returns empty string for placeholder/non-addresses and campus/city-only addresses.
    """
    if not addr or not addr.strip():
        return ""

    a = addr.lower().strip()

    # Reject known placeholder values
    if a in NON_ADDRESSES or any(p in a for p in NON_ADDRESSES):
        return ""

    # Remove zip codes (5 or 9 digit)
    a = re.sub(r"\b\d{5}(-\d{4})?\b", "", a)

    # Remove US state abbreviations at end (all 50 states + DC)
    a = re.sub(
        r",?\s*\b(AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS"
        r"|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b\s*$",
        "", a, flags=re.IGNORECASE,
    )

    # Remove full US state names at end
    a = re.sub(
        r",?\s*(alabama|alaska|arizona|arkansas|california|colorado|connecticut|delaware|florida"
        r"|georgia|hawaii|idaho|illinois|indiana|iowa|kansas|kentucky|louisiana|maine|maryland"
        r"|massachusetts|michigan|minnesota|mississippi|missouri|montana|nebraska|nevada"
        r"|new hampshire|new jersey|new mexico|new york|north carolina|north dakota|ohio"
        r"|oklahoma|oregon|pennsylvania|rhode island|south carolina|south dakota|tennessee"
        r"|texas|utah|vermont|virginia|washington|west virginia|wisconsin|wyoming"
        r"|district of columbia)\s*$",
        "", a, flags=re.IGNORECASE,
    )

    # Strip remaining city name (everything after last comma)
    a = re.sub(r",\s*[a-z\s]+$", "", a)

    # Expand street abbreviations (only at word boundary, to avoid "la-" in place names)
    for pattern, replacement in STREET_SUFFIXES.items():
        a = re.sub(pattern, replacement, a)

    # Strip punctuation except hyphens in addresses (e.g., "US-61")
    a = re.sub(r"[^\w\s-]", "", a)

    # Collapse whitespace
    a = re.sub(r"\s+", " ", a).strip()

    # Require a street number — reject city-only and campus-only addresses
    # Valid: "6800 burbank drive"  Invalid: "grambling state university" or "new roads"
    has_street_number = bool(re.search(r"^\d+", a))
    if not has_street_number:
        return ""

    return a


def extract_street_number(normalized_addr: str) -> int | None:
    """Extract the leading street number from a normalized address, or None."""
    match = re.match(r"^(\d+)", normalized_addr)
    if match:
        return int(match.group(1))
    return None


def normalize_name(name: str) -> str:
    """
    Lowercase, strip noise words and punctuation.
    Keeps phase numbers and building type words (they matter for disambiguation).
    """
    if not name or not name.strip():
        return ""

    n = name.lower().strip()

    # Normalize phase references: "phase i" → "phase 1", "phase ii" → "phase 2"
    roman = {"i": "1", "ii": "2", "iii": "3", "iv": "4", "v": "5"}
    for roman_num, arabic in roman.items():
        n = re.sub(rf"\bphase\s+{roman_num}\b", f"phase {arabic}", n)

    # Strip punctuation (keep spaces and hyphens)
    n = re.sub(r"[^\w\s-]", " ", n)

    # Remove noise words
    words = [w for w in n.split() if w not in NOISE_WORDS]
    n = " ".join(words)

    # Collapse whitespace
    n = re.sub(r"\s+", " ", n).strip()

    return n


def normalize_territory(t: str) -> str:
    """
    Normalize territory label using TERRITORY_ALIASES.
    "LA" → "Los Angeles County", "Greater Tampa" → "Greater Tampa / Fort Myers", etc.
    Called before comparing territories in Phase 2 so inconsistent labels don't block matches.
    """
    if not t:
        return ""
    return TERRITORY_ALIASES.get(t.lower().strip(), t.strip())


def extract_phase(normalized_name: str):
    """
    Extract phase number from a normalized name.
    Returns "1", "2", etc. or None if no phase mentioned.
    """
    match = re.search(r"\bphase\s+(\d+)\b", normalized_name)
    if match:
        return match.group(1)
    return None


def extract_building_type(normalized_name: str):
    """Return set of building type words found in the name."""
    words = set(normalized_name.split())
    return words & BUILDING_TYPES


def count_populated_fields(record: dict, architect_col: str = "Architect (Sales Contact)") -> int:
    """Count non-empty fields — used to pick the 'best' record in a group."""
    important = [
        "Project Name", "Address", architect_col,
        "Developer", "Contractor", "Location",
        "Groundbreaking Year", "Completion Year",
    ]
    return sum(1 for f in important if record.get(f) and str(record[f]).strip())

# ─── LLM verification ────────────────────────────────────────────────────────────

def llm_verify_same_project(rec_a: dict, rec_b: dict, client: anthropic.Anthropic) -> bool:
    """
    Ask Claude haiku whether two records describe the same physical project.
    Returns True if same, False if different.
    """
    def summarize(r):
        parts = []
        if r.get("Project Name"):
            parts.append(f"Name: {r['Project Name']}")
        if r.get("Address"):
            parts.append(f"Address: {r['Address']}")
        if r.get("Location"):
            parts.append(f"Location: {r['Location']}")
        if r.get("Territory"):
            parts.append(f"Territory: {r['Territory']}")
        if r.get("Developer"):
            parts.append(f"Developer: {r['Developer']}")
        desc = r.get("Activity Description") or r.get("Summary") or ""
        if desc:
            parts.append(f"Summary: {desc[:250]}")
        return "\n  ".join(parts)

    prompt = f"""Are these two construction project records describing the SAME physical construction project?

Record A:
  {summarize(rec_a)}

Record B:
  {summarize(rec_b)}

Reply in JSON only — no other text:
{{"same_project": true, "reason": "one sentence"}}
or
{{"same_project": false, "reason": "one sentence"}}"""

    try:
        response = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=100,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text.strip()
        # Strip markdown code fences if present
        raw = re.sub(r"```json\s*", "", raw)
        raw = re.sub(r"```\s*", "", raw)
        result = json.loads(raw)
        return bool(result.get("same_project"))
    except Exception as e:
        print(f"    [LLM error] {e} — defaulting to NO match")
        return False

# ─── Core grouping logic ──────────────────────────────────────────────────────────

def build_groups(records: list, dry_run: bool = True, max_llm: int = 0) -> list:
    """
    Runs 4-phase grouping. Returns list of groups (each group is a list of records).
    Each record gets a 'match_reason' annotation for the preview output.

    max_llm: if > 0, stop making LLM calls once this many have been used.
             Borderline pairs that exceed the cap become singletons (conservative).
             Useful for validation runs on large tables.
    """
    client = anthropic.Anthropic()
    llm_calls = 0

    # Work with copies so we can annotate without changing original dicts
    records = [dict(r) for r in records]
    for r in records:
        r["_matched"] = False
        r["_match_reason"] = "singleton"

    groups = []  # list of lists of records

    for i, rec in enumerate(records):
        if rec["_matched"]:
            continue

        my_group = [rec]
        rec["_matched"] = True

        addr_a = normalize_address(rec.get("Address") or "")
        name_a = normalize_name(rec.get("Project Name") or "")
        phase_a = extract_phase(name_a)
        types_a = extract_building_type(name_a)
        territory_a = normalize_territory(rec.get("Territory") or "")
        dev_a = normalize_name(rec.get("Developer") or "")

        for j, other in enumerate(records):
            if i == j or other["_matched"]:
                continue

            addr_b = normalize_address(other.get("Address") or "")
            name_b = normalize_name(other.get("Project Name") or "")
            phase_b = extract_phase(name_b)
            types_b = extract_building_type(name_b)
            territory_b = normalize_territory(other.get("Territory") or "")
            dev_b = normalize_name(other.get("Developer") or "")

            matched = False
            reason = ""

            # ── Phase 1: Address ───────────────────────────────────────────────
            if addr_a and addr_b:
                addr_score = fuzz.token_sort_ratio(addr_a, addr_b)

                # Street number mismatch guard:
                # If both addresses have street numbers and they differ,
                # drop score to force LLM verification or rejection.
                # E.g. "3308 washington ave" vs "2701 washington ave" = same
                # street name but different buildings → must check carefully.
                num_a = extract_street_number(addr_a)
                num_b = extract_street_number(addr_b)
                number_mismatch = (
                    num_a is not None and num_b is not None and num_a != num_b
                )
                if number_mismatch:
                    # Don't auto-match on address if numbers differ — always LLM
                    addr_score = min(addr_score, ADDR_LOW + 1)  # caps at 66, forces LLM

                if addr_score >= ADDR_HIGH:
                    matched = True
                    reason = f"address ({addr_score:.0f}%)"

                elif addr_score >= ADDR_LOW:
                    # Borderline — LLM check (skip if cap reached)
                    if max_llm > 0 and llm_calls >= max_llm:
                        pass  # Cap reached → conservative singleton
                    else:
                        llm_calls += 1
                        same = llm_verify_same_project(rec, other, client)
                        note = " ⚠️ STREET NUMBERS DIFFER — review" if number_mismatch else ""
                        if same:
                            matched = True
                            reason = f"address ({addr_score:.0f}%) + LLM ✓{note}"
                        else:
                            reason = f"address borderline ({addr_score:.0f}%) — LLM said NO"

            # ── Phase 2: Name (only if address didn't match) ────────────────────
            if not matched:
                # Hard disqualifier: generic/scraper-fallback names require a strong
                # address match regardless of whether addresses are present.
                # "Affordable Housing Project" at 6901 Woodman ≠ 511 N. Hoover — different projects.
                # Empty/null project names (canonical → "unknown" or "") also blocked here.
                norm_a_lower = name_a.lower()
                if any(t in norm_a_lower for t in REQUIRES_ADDRESS_TO_GROUP) or not name_a:
                    addr_sim = fuzz.token_sort_ratio(addr_a, addr_b) if addr_a and addr_b else 0
                    if addr_sim < ADDR_HIGH:
                        continue  # Generic name without strong address match → singleton

                # Hard disqualifiers
                if phase_a and phase_b and phase_a != phase_b:
                    # Different phases → definitely different project
                    continue

                if types_a and types_b and not types_a.intersection(types_b):
                    # Both have explicit building types but they differ → skip
                    continue

                # Territory guard — if no address, require same territory
                if not addr_a or not addr_b:
                    if territory_a and territory_b and territory_a != territory_b:
                        continue

                # Developer guard — if both have developer, they must be similar
                if dev_a and dev_b:
                    dev_score = fuzz.token_sort_ratio(dev_a, dev_b)
                    if dev_score < 75:
                        continue  # Different developers → different projects

                name_score = fuzz.token_sort_ratio(name_a, name_b)

                if name_score >= NAME_HIGH:
                    matched = True
                    reason = f"name ({name_score:.0f}%)"

                elif name_score >= NAME_LOW:
                    # Borderline — LLM check (skip if cap reached)
                    if max_llm > 0 and llm_calls >= max_llm:
                        pass  # Cap reached → conservative singleton
                    else:
                        llm_calls += 1
                        same = llm_verify_same_project(rec, other, client)
                        if same:
                            matched = True
                            reason = f"name ({name_score:.0f}%) + LLM ✓"

            if matched:
                other["_matched"] = True
                other["_match_reason"] = reason
                my_group.append(other)

        groups.append(my_group)

    # Collect true singletons separately
    singletons = [g for g in groups if len(g) == 1]
    multi_groups = [g for g in groups if len(g) > 1]

    print(f"\n[LLM calls used: {llm_calls}]")

    return multi_groups, singletons


def assign_canonical_names(groups: list, singletons: list, architect_col: str = "Architect (Sales Contact)") -> dict:
    """
    For each group, pick the best canonical name.
    Returns: dict of record_id → canonical_name
    """
    id_to_canonical = {}

    for group in groups:
        # Pick the record with the most populated fields
        best = max(group, key=lambda r: count_populated_fields(r, architect_col))
        canonical = (best.get("Project Name") or "").strip()

        for rec in group:
            rec_id = rec.get("id")
            if rec_id:
                id_to_canonical[rec_id] = canonical

    for group in singletons:
        rec = group[0]
        rec_id = rec.get("id")
        if rec_id:
            id_to_canonical[rec_id] = (rec.get("Project Name") or "").strip()

    return id_to_canonical

# ─── Output / preview ────────────────────────────────────────────────────────────

def _flag_edge_cases(group: list) -> list[str]:
    """
    Inspect a group for potential problems. Returns list of warning strings.
    Flags are printed in the preview so Brian can spot-check.
    """
    warnings = []
    names = [r.get("Project Name", "") for r in group]
    addrs = [r.get("Address", "") for r in group]

    # Flag: all records have the same generic/ambiguous name
    generic_names = {
        "zoning text amendment", "zoning amendment", "rezoning",
        "campus development", "new construction", "commercial development",
        "mixed use development", "residential development",
    }
    first_norm = normalize_name(names[0]).lower() if names else ""
    if first_norm in generic_names:
        warnings.append("⚠️  GENERIC NAME — verify these are actually the same project")

    # Flag: records matched by name but have conflicting addresses
    has_addr = [a for a in addrs if a and a.lower() not in ("no address", "see pdf", "")]
    if len(has_addr) >= 2:
        # Check if any two addresses differ significantly
        norm_addrs = [normalize_address(a) for a in has_addr]
        norm_addrs = [a for a in norm_addrs if a]
        if len(norm_addrs) >= 2:
            pairs_ok = all(
                fuzz.token_sort_ratio(norm_addrs[0], b) >= 80
                for b in norm_addrs[1:]
            )
            if not pairs_ok:
                warnings.append("⚠️  CONFLICTING ADDRESSES — records may be different projects")

    # Flag: LLM was used and confirmed — mark for human spot-check
    llm_confirmed = [r for r in group if "LLM ✓" in (r.get("_match_reason") or "")]
    if llm_confirmed:
        warnings.append(f"ℹ️  {len(llm_confirmed)} record(s) confirmed by LLM — spot-check recommended")

    # Flag: large group (5+ records merged) — more likely to have false positives
    if len(group) >= 5:
        warnings.append("⚠️  LARGE GROUP (5+ records) — review carefully for false positives")

    return warnings


def print_preview(groups, singletons, id_to_canonical):
    total_grouped = sum(len(g) for g in groups)
    print("\n" + "=" * 70)
    print("GROUPED PROJECTS")
    print("=" * 70)

    for group in groups:
        canonical = id_to_canonical.get(group[0].get("id"), "???")
        edge_flags = _flag_edge_cases(group)
        print(f"\nGROUP ({len(group)} records) → Canonical: \"{canonical}\"")
        for flag in edge_flags:
            print(f"  {flag}")
        for rec in group:
            reason = rec.get("_match_reason", "seed")
            pname = rec.get("Project Name", "")
            addr = rec.get("Address", "") or "no address"
            terr = rec.get("Territory", "") or "?"
            print(f"  • [{rec.get('id','')}] \"{pname}\"")
            print(f"    Address: {addr} | {terr}")
            print(f"    Matched via: {reason}")

    print(f"\n{'=' * 70}")
    print(f"SINGLETONS (no match found): {len(singletons)} records")
    for g in singletons[:20]:
        rec = g[0]
        print(f"  • \"{rec.get('Project Name','')}\" [{rec.get('Territory','')}]")
    if len(singletons) > 20:
        print(f"  ... and {len(singletons) - 20} more")

    print(f"\n{'=' * 70}")
    print(f"SUMMARY")
    print(f"  Total records : {total_grouped + len(singletons)}")
    print(f"  Groups formed : {len(groups)}  ({total_grouped} records merged)")
    print(f"  Singletons    : {len(singletons)}")
    print("=" * 70)

# ─── DB write ────────────────────────────────────────────────────────────────────

def write_to_db(conn, schema, table, id_to_canonical: dict):
    """Write canonical names to the specified schema.table."""
    cur = conn.cursor()
    updated = 0
    for rec_id, canonical in id_to_canonical.items():
        cur.execute(
            f'UPDATE "{schema}"."{table}" SET "Canonical Project Name" = %s WHERE id = %s',
            (canonical, rec_id)
        )
        updated += cur.rowcount
    conn.commit()
    print(f"\nWrote {updated} rows → {schema}.{table}")


def apply_live(conn):
    """
    Copy Canonical Project Name from test_grouping into public.
    Adds the column if it doesn't exist yet.
    """
    cur = conn.cursor()

    # Add column to live table if not present
    cur.execute("""
        ALTER TABLE public.nola_scored_final
        ADD COLUMN IF NOT EXISTS "Canonical Project Name" TEXT
    """)

    # Copy values over using id as join key
    cur.execute("""
        UPDATE public.nola_scored_final live
        SET "Canonical Project Name" = test."Canonical Project Name"
        FROM test_grouping.nola_scored_final test
        WHERE live.id = test.id
          AND test."Canonical Project Name" IS NOT NULL
    """)
    count = cur.rowcount
    conn.commit()
    print(f"Applied to live: updated {count} rows in public.nola_scored_final")

# ─── Sandbox setup ───────────────────────────────────────────────────────────────

def setup_sandbox(conn, table: str):
    """
    Drop and recreate test_grouping.<table> as a fresh copy of public.<table>.
    Called on every --confirm run so new records from the daily scraper are always included.
    """
    cur = conn.cursor()
    cur.execute(f'DROP TABLE IF EXISTS test_grouping."{table}"')
    cur.execute(f'CREATE TABLE test_grouping."{table}" AS SELECT * FROM public."{table}"')
    cur.execute(f'ALTER TABLE test_grouping."{table}" ADD COLUMN "Canonical Project Name" TEXT')
    conn.commit()
    print(f"Sandbox refreshed: test_grouping.{table} (fresh copy of public.{table})")

# ─── Main ────────────────────────────────────────────────────────────────────────

def main():
    load_env()

    confirm         = "--confirm"    in sys.argv
    apply_live_flag = "--apply-live" in sys.argv
    dry_run         = not confirm and not apply_live_flag

    # --table TABLE_NAME (default: nola_scored_final)
    table = "nola_scored_final"
    if "--table" in sys.argv:
        idx = sys.argv.index("--table")
        if idx + 1 < len(sys.argv):
            table = sys.argv[idx + 1]

    if table not in TABLE_PROFILES:
        print(f"ERROR: Unknown table '{table}'. Known tables: {list(TABLE_PROFILES.keys())}")
        sys.exit(1)

    architect_col = TABLE_PROFILES[table]["architect_col"]

    # --max-llm N  (0 = unlimited; >0 caps LLM calls for faster validation runs)
    max_llm = 0
    if "--max-llm" in sys.argv:
        idx = sys.argv.index("--max-llm")
        if idx + 1 < len(sys.argv):
            try:
                max_llm = int(sys.argv[idx + 1])
            except ValueError:
                pass

    print("=" * 70)
    print(f"AIVA Project Grouping Script  |  table: {table}")
    if dry_run:
        print("MODE: DRY-RUN — no DB writes (add --confirm to write to sandbox)")
    elif confirm:
        print(f"MODE: CONFIRM — will write to test_grouping.{table}")
    elif apply_live_flag:
        print("MODE: APPLY-LIVE — will copy results to public.nola_scored_final")
    if max_llm:
        print(f"LLM cap: {max_llm} calls max (borderline pairs beyond cap → singleton)")
    print("=" * 70)

    conn = connect()

    if apply_live_flag:
        if table != "nola_scored_final":
            print(f"ERROR: --apply-live only works on nola_scored_final (got '{table}')")
            print("  These tables are validation-only. Only nola_scored_final goes to live dashboard.")
            conn.close()
            sys.exit(1)
        print("\nCopying Canonical Project Name from sandbox → live...")
        apply_live(conn)
        conn.close()
        return

    # LA tables (test_la_internal_scored, la_internal_scored) write directly to public schema —
    # they already live there and don't need the NOLA test_grouping sandbox pattern.
    LA_DIRECT_TABLES = {"test_la_internal_scored", "la_internal_scored"}
    is_la_direct = table in LA_DIRECT_TABLES

    if is_la_direct:
        # LA mode: always read from public, write directly to public on --confirm
        src_schema = LIVE_SCHEMA
        print(f"\nLoading records from {src_schema}.{table}...")
        records = fetch_records(conn, src_schema, table)
        print(f"Loaded {len(records)} records")

        print("\nRunning grouping algorithm...")
        multi_groups, singletons = build_groups(records, dry_run=dry_run, max_llm=max_llm)
        id_to_canonical = assign_canonical_names(multi_groups, singletons, architect_col)
        print_preview(multi_groups, singletons, id_to_canonical)

        if confirm:
            print(f"\nWriting Canonical Project Name directly to public.{table}...")
            write_to_db(conn, LIVE_SCHEMA, table, id_to_canonical)
            print(f"\nDone. Verify with:")
            print(f'  SELECT "Project Name", "Canonical Project Name" FROM {table} WHERE "Canonical Project Name" IS NOT NULL LIMIT 20;')
        else:
            print(f"\nDry-run complete. Run with --confirm to write canonical names to public.{table}.")
    else:
        # NOLA mode: use test_grouping sandbox, require --confirm to write
        if confirm:
            setup_sandbox(conn, table)

        src_schema = TEST_SCHEMA if confirm else LIVE_SCHEMA
        print(f"\nLoading records from {src_schema}.{table}...")
        records = fetch_records(conn, src_schema, table)
        print(f"Loaded {len(records)} records")

        print("\nRunning grouping algorithm...")
        multi_groups, singletons = build_groups(records, dry_run=dry_run, max_llm=max_llm)
        id_to_canonical = assign_canonical_names(multi_groups, singletons, architect_col)
        print_preview(multi_groups, singletons, id_to_canonical)

        if confirm:
            print(f"\nWriting to sandbox (test_grouping.{table})...")
            write_to_db(conn, TEST_SCHEMA, table, id_to_canonical)
            print(f"\nDone. Preview with: python3 src/preview_groups.py --table {table} --merged-only")
        else:
            print(f"\nDry-run complete. Run with --confirm to write to sandbox.")

    conn.close()


if __name__ == "__main__":
    main()
