#!/bin/bash
# JASCKO South Florida Lead Sourcing Pipeline
# Runs daily via GitHub Actions at 8 PM PDT
#
# Usage:
#   bash run_pipeline.sh           # dry-run (no DB writes)
#   bash run_pipeline.sh --confirm # actually insert into DB + run grouping

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CONFIRM="${1:-}"
echo "=================================================="
echo "JASCKO South Florida Lead Sourcing Pipeline"
echo "Started: $(date)"
echo "Mode: ${CONFIRM:-dry-run}"
echo "=================================================="

# ── Stage 1: Scrape all sources ──────────────────────────────────────────────
# Each scraper is independent — || true ensures one failure doesn't kill pipeline
echo ""
echo "[STAGE 1] Scraping sources..."

python3 -m src.scrape_urbanize_miami      || true
python3 -m src.scrape_florida_yimby       || true
python3 -m src.scrape_therealdeal_miami   || true
python3 -m src.scrape_bisnow_miami        || true
python3 -m src.scrape_sfbj               || true
python3 -m src.scrape_globest            || true
python3 -m src.scrape_rebusiness         || true
python3 -m src.scrape_condo_black_book   || true
python3 -m src.search_tavily             || true

# ── Stage 2: Pre-qualify ─────────────────────────────────────────────────────
echo ""
echo "[STAGE 2] Pre-qualifying articles..."
python3 -m src.prequalify

# ── Stage 3: SOP extraction ──────────────────────────────────────────────────
echo ""
echo "[STAGE 3] Running SOP extraction..."
python3 -m src.extract_articles

# ── Stage 4: Upload to DB ────────────────────────────────────────────────────
echo ""
echo "[STAGE 4] Uploading to jascko_internal_scored_v2..."
if [ "$CONFIRM" = "--confirm" ]; then
    python3 -m src.upload_to_db --confirm
else
    python3 -m src.upload_to_db
fi

# ── Stage 5: Assign Canonical Project Names ───────────────────────────────────
if [ "$CONFIRM" = "--confirm" ]; then
    echo ""
    echo "[STAGE 5] Running group_projects.py (Canonical Project Name)..."
    cd "$SCRIPT_DIR/.."
    python3 group_projects.py --table jascko_internal_scored_v2 --apply-live
    cd "$SCRIPT_DIR"
fi

echo ""
echo "=================================================="
echo "Pipeline complete: $(date)"
echo "=================================================="
