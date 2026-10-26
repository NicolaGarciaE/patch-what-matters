"""Download the CISA Known Exploited Vulnerabilities (KEV) catalog as CSV.

The file is saved byte-for-byte in data/raw/ with the UTC download date in its
name. If a KEV snapshot already exists, the download is skipped and that
snapshot is reused, so the whole analysis relies on a single KEV photo.

Usage: uv run python src/download_kev.py
"""

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import requests

# Official link from https://www.cisa.gov/known-exploited-vulnerabilities-catalog
KEV_CSV_URL = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"
FILE_PREFIX = "known_exploited_vulnerabilities_"

KEY_COLUMNS = ["cveID", "vendorProject", "product", "dateAdded", "knownRansomwareCampaignUse"]
CVE_ID_PATTERN = r"CVE-\d{4}-\d+"
REQUEST_TIMEOUT_SECONDS = 60


def find_existing_snapshots() -> list[Path]:
    return sorted(RAW_DIR.glob(f"{FILE_PREFIX}*.csv"))


def download_snapshot() -> Path:
    download_date = datetime.now(timezone.utc).date().isoformat()
    destination = RAW_DIR / f"{FILE_PREFIX}{download_date}.csv"
    partial = destination.with_name(destination.name + ".part")

    response = requests.get(KEV_CSV_URL, timeout=REQUEST_TIMEOUT_SECONDS)
    response.raise_for_status()

    # Write to a temporary file first so an interrupted download never looks complete.
    partial.write_bytes(response.content)
    partial.replace(destination)
    return destination


def validate_snapshot(path: Path) -> pd.DataFrame:
    # utf-8-sig strips a byte-order mark if present, so the first column name stays clean.
    kev = pd.read_csv(path, dtype=str, keep_default_na=False, encoding="utf-8-sig")

    missing = [column for column in KEY_COLUMNS if column not in kev.columns]
    assert not missing, f"Missing expected columns: {missing}"
    assert len(kev) > 0, "KEV CSV has no rows"

    duplicated = kev.loc[kev["cveID"].duplicated(), "cveID"]
    assert duplicated.empty, f"{len(duplicated)} duplicated cveID values, e.g. {duplicated.head(5).tolist()}"

    bad_ids = kev.loc[~kev["cveID"].str.fullmatch(CVE_ID_PATTERN), "cveID"]
    assert bad_ids.empty, f"{len(bad_ids)} cveID values with unexpected format, e.g. {bad_ids.head(5).tolist()}"

    date_added = pd.to_datetime(kev["dateAdded"], format="%Y-%m-%d", errors="coerce")
    bad_dates = kev.loc[date_added.isna(), "dateAdded"]
    assert bad_dates.empty, f"{len(bad_dates)} dateAdded values not in YYYY-MM-DD format, e.g. {bad_dates.head(5).tolist()}"

    return kev


def main() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    existing = find_existing_snapshots()
    assert len(existing) <= 1, (
        f"Found {len(existing)} KEV snapshots in {RAW_DIR}; expected at most one: "
        f"{[p.name for p in existing]}"
    )

    if existing:
        snapshot = existing[0]
        print(f"Skipping download: KEV snapshot already exists ({snapshot.name})")
    else:
        print(f"Downloading KEV catalog from {KEV_CSV_URL}")
        snapshot = download_snapshot()
        print(f"Saved {snapshot.relative_to(PROJECT_ROOT)}")

    kev = validate_snapshot(snapshot)

    print("\nSummary")
    print(f"  File:            {snapshot.relative_to(PROJECT_ROOT)}")
    print(f"  Size (bytes):    {snapshot.stat().st_size:,}")
    print(f"  Rows:            {len(kev):,}")
    print(f"  Columns:         {len(kev.columns)}")
    print(f"  Unique cveID:    {kev['cveID'].nunique():,}")
    print(f"  dateAdded range: {kev['dateAdded'].min()} to {kev['dateAdded'].max()}")
    print("All checks passed.")


if __name__ == "__main__":
    main()
