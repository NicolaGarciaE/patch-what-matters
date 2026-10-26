"""Validate the raw NVD and KEV files in data/raw/ (read-only: nothing is written).

For the NVD windows in data/raw/nvd/ it checks that
- each window saved as many CVEs as the API's totalResults;
- no CVE ID appears more than once across all windows;
- every CVE's published day (UTC) falls within the days of its window;
- no CVE is published less than 1 s from any window boundary, including the
  start of the first window and the end of the last. Both pubStartDate and
  pubEndDate are inclusive and consecutive windows share their boundary
  (D 23:59:59.999Z). If NVD rounded .999 to SQL Server datetime precision
  (1/300 s), the boundary would move to the next second, so a CVE within 1 s
  of it could be counted twice or in the wrong window;
- the windows cover 2022-01-01 to 2024-12-31 with no gaps or overlaps.
It also counts the rows of the KEV CSV.

Usage: uv run python src/validate_raw.py
"""

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"
NVD_DIR = RAW_DIR / "nvd"

UNIVERSE_FIRST_DAY = date(2022, 1, 1)
UNIVERSE_LAST_DAY = date(2024, 12, 31)
MAX_WINDOW_DAYS = 120
BOUNDARY_TOLERANCE = timedelta(seconds=1)

NVD_FILE_NAME = re.compile(r"nvd_(\d{4}-\d{2}-\d{2})_to_(\d{4}-\d{2}-\d{2})_downloaded_(\d{4}-\d{2}-\d{2})\.json")
KEV_FILE_PREFIX = "known_exploited_vulnerabilities_"


@dataclass(frozen=True)
class WindowFile:
    path: Path
    first_day: date
    last_day: date
    pub_start: datetime
    pub_end: datetime
    download_date: str
    results_per_page: int
    total_results: int
    cves: list[tuple[str, datetime]]  # (cve.id, cve.published in UTC)

    @property
    def n_days(self) -> int:
        return (self.last_day - self.first_day).days + 1

    @property
    def label(self) -> str:
        return f"{self.first_day}_to_{self.last_day}"


def to_utc(raw: str) -> datetime:
    # NVD returns UTC datetimes: 'published' has no offset (e.g. 2022-01-01T00:15:08.057)
    # and the query parameters stored in the metadata end in 'Z'.
    timestamp = datetime.fromisoformat(raw)
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def day_boundary(day: date) -> datetime:
    """Window boundary used in the API queries: D 23:59:59.999Z."""
    return datetime(day.year, day.month, day.day, 23, 59, 59, 999_000, tzinfo=timezone.utc)


def read_window(path: Path) -> WindowFile:
    name = NVD_FILE_NAME.fullmatch(path.name)
    assert name, f"unexpected file name: {path.name}"
    with path.open(encoding="utf-8") as file:
        payload = json.load(file)
    metadata = payload["metadata"]
    expected = (metadata["window_first_day"], metadata["window_last_day"], metadata["download_date_utc"])
    assert name.groups() == expected, f"{path.name}: file name does not match its metadata {expected}"
    return WindowFile(
        path=path,
        first_day=date.fromisoformat(metadata["window_first_day"]),
        last_day=date.fromisoformat(metadata["window_last_day"]),
        pub_start=to_utc(metadata["pub_start_date_param"]),
        pub_end=to_utc(metadata["pub_end_date_param"]),
        download_date=metadata["download_date_utc"],
        results_per_page=metadata["results_per_page"],
        total_results=metadata["total_results"],
        cves=[(item["cve"]["id"], to_utc(item["cve"]["published"])) for item in payload["vulnerabilities"]],
    )


def check_coverage(windows: list[WindowFile]) -> list[str]:
    """Return the coverage problems found; an empty list means full coverage."""
    problems = []
    if windows[0].first_day != UNIVERSE_FIRST_DAY:
        problems.append(f"first window starts on {windows[0].first_day}, not {UNIVERSE_FIRST_DAY}")
    if windows[-1].last_day != UNIVERSE_LAST_DAY:
        problems.append(f"last window ends on {windows[-1].last_day}, not {UNIVERSE_LAST_DAY}")
    for window in windows:
        if not 1 <= window.n_days <= MAX_WINDOW_DAYS:
            problems.append(f"{window.label} has {window.n_days} days")
        # Each window was queried from the boundary of the day before its first day to that of its last day.
        expected = (day_boundary(window.first_day - timedelta(days=1)), day_boundary(window.last_day))
        if (window.pub_start, window.pub_end) != expected:
            problems.append(f"{window.label}: pubStartDate/pubEndDate do not match its days")
    for previous, current in zip(windows, windows[1:]):
        step = (current.first_day - previous.last_day).days
        if step > 1:
            problems.append(f"gap of {step - 1} days between {previous.label} and {current.label}")
        elif step < 1:
            problems.append(f"overlap of {1 - step} days between {previous.label} and {current.label}")
    return problems


def main() -> None:
    paths = sorted(NVD_DIR.glob("nvd_*.json"))
    assert paths, f"no NVD files in {NVD_DIR}"
    windows = sorted((read_window(path) for path in paths), key=lambda window: window.first_day)

    mismatched = [window.label for window in windows if window.total_results != len(window.cves)]
    id_counts = Counter(cve_id for window in windows for cve_id, _ in window.cves)
    duplicated = [cve_id for cve_id, count in id_counts.items() if count > 1]
    outside = [
        cve_id for window in windows for cve_id, published in window.cves
        if not window.first_day <= published.date() <= window.last_day
    ]
    boundaries = sorted({window.pub_start for window in windows} | {window.pub_end for window in windows})
    near_boundary = [
        f"{cve_id} ({published.isoformat()})" for window in windows for cve_id, published in window.cves
        if any(abs(published - boundary) < BOUNDARY_TOLERANCE for boundary in boundaries)
    ]
    coverage_problems = check_coverage(windows)

    kev_snapshots = sorted(RAW_DIR.glob(f"{KEV_FILE_PREFIX}*.csv"))
    assert len(kev_snapshots) == 1, f"expected one KEV snapshot, found {[p.name for p in kev_snapshots]}"
    # Same reading options as download_kev.py.
    kev = pd.read_csv(kev_snapshots[0], dtype=str, keep_default_na=False, encoding="utf-8-sig")

    print(f"NVD windows ({NVD_DIR.relative_to(PROJECT_ROOT)})")
    print(f"  {'window':<26} {'days':>5} {'totalResults':>12} {'saved':>8} {'match':>5} {'per_page':>8}  downloaded")
    for window in windows:
        match = "yes" if window.total_results == len(window.cves) else "NO"
        print(
            f"  {window.label:<26} {window.n_days:>5} {window.total_results:>12,} {len(window.cves):>8,}"
            f" {match:>5} {window.results_per_page:>8}  {window.download_date}"
        )
    total_days = sum(window.n_days for window in windows)
    total_api = sum(window.total_results for window in windows)
    total_saved = sum(len(window.cves) for window in windows)
    print(f"  {'TOTAL':<26} {total_days:>5,} {total_api:>12,} {total_saved:>8,}")

    print("\nChecks across windows (all must be 0)")
    checks = [
        ("Windows where saved != totalResults", len(mismatched)),
        ("CVE IDs that appear more than once", len(duplicated)),
        ("CVEs whose published day is outside their window", len(outside)),
        (f"CVEs within 1 s of a window boundary ({len(boundaries)} boundaries)", len(near_boundary)),
        ("Coverage problems (gaps, overlaps, wrong bounds)", len(coverage_problems)),
    ]
    for label, value in checks:
        print(f"  {label:<62} {value:>6,}")
    for problem in coverage_problems:
        print(f"    - {problem}")
    print(f"  Boundaries: {boundaries[0].isoformat()} to {boundaries[-1].isoformat()}")
    print(f"  Coverage: {len(windows)} windows, {windows[0].first_day} to {windows[-1].last_day}, {total_days:,} days")

    print(f"\nKEV ({kev_snapshots[0].relative_to(PROJECT_ROOT)})")
    print(f"  Rows: {len(kev):,}")

    assert not mismatched, f"saved != totalResults in {mismatched}"
    assert not duplicated, f"{len(duplicated)} CVE IDs appear more than once, e.g. {duplicated[:5]}"
    assert not outside, f"{len(outside)} CVEs published outside their window, e.g. {outside[:5]}"
    assert not near_boundary, f"{len(near_boundary)} CVEs within 1 s of a boundary, e.g. {near_boundary[:5]}"
    assert not coverage_problems, f"coverage problems: {coverage_problems}"
    assert len(kev) > 0, "KEV CSV has no rows"
    print("All checks passed.")


if __name__ == "__main__":
    main()
