"""Download NVD CVE records published between 2022-01-01 and 2024-12-31 (CVE API 2.0).

The period is split into consecutive windows of at most 120 days (API limit).
Each window is paged with startIndex until totalResults and saved as one JSON
file in data/raw/nvd/, with the UTC download date in its name. The API records
are stored unchanged. Windows that already have a file are skipped.

Usage:
    uv run python src/download_nvd.py                  # all windows
    uv run python src/download_nvd.py --max-windows 1  # first window only (test)

Date-boundary probe (2026-10-22). The NVD docs do not say whether
pubStartDate/pubEndDate are inclusive, so it was tested directly:
- 'published' milliseconds always end in 0, 3 or 7: values look stored in
  1/300 s steps and rounded for display ('.057' is really about '.0567').
- CVE-2021-45929 (published 2022-01-01T00:15:08.057): missing with
  start = end = .057 and with a range starting at .057; present in a range
  ending at .057.
- CVE-2021-45947 (published 2022-01-01T00:15:08.320, an exact 1/300 s step):
  present with start = end = .320.
Result: both bounds are inclusive. Every window boundary is D 23:59:59.999Z and
each window starts exactly where the previous one ends; no stored value can be
.999, so each CVE falls in exactly one window. validate_raw.py re-checks this
(duplicates across windows, CVEs within 1 s of a boundary).
"""

import argparse
import json
import os
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NVD_DIR = PROJECT_ROOT / "data" / "raw" / "nvd"

UNIVERSE_FIRST_DAY = date(2022, 1, 1)
UNIVERSE_LAST_DAY = date(2024, 12, 31)
MAX_WINDOW_DAYS = 120
BOUNDARY_TIME = "T23:59:59.999Z"

# The API maximum is 2000, but on 2026-10-23 pages of 2000 and 1000 records were
# cut mid-transfer on every attempt (ChunkedEncodingError). A diagnostic that day:
# 100 records arrived complete in 6 s; 500 records took 56 s to respond and the
# connection broke after 12.6 KB. Window 1 was downloaded with 2000; each file
# records its value in metadata.
RESULTS_PER_PAGE = 100
SECONDS_BETWEEN_REQUESTS = 6  # NVD best practice: sleep six seconds between requests
MAX_RETRIES = 5  # waits 6, 12, 24, 48, 96 s
REQUEST_TIMEOUT_SECONDS = (30, 180)  # (connect, read)


@dataclass(frozen=True)
class Window:
    first_day: date
    last_day: date

    @property
    def pub_start(self) -> str:
        return (self.first_day - timedelta(days=1)).isoformat() + BOUNDARY_TIME

    @property
    def pub_end(self) -> str:
        return self.last_day.isoformat() + BOUNDARY_TIME

    @property
    def n_days(self) -> int:
        return (self.last_day - self.first_day).days + 1

    @property
    def label(self) -> str:
        return f"{self.first_day}_to_{self.last_day}"


def build_windows() -> list[Window]:
    windows = []
    first_day = UNIVERSE_FIRST_DAY
    while first_day <= UNIVERSE_LAST_DAY:
        last_day = min(first_day + timedelta(days=MAX_WINDOW_DAYS - 1), UNIVERSE_LAST_DAY)
        windows.append(Window(first_day, last_day))
        first_day = last_day + timedelta(days=1)

    assert windows[0].first_day == UNIVERSE_FIRST_DAY, "first window does not start on the first day"
    assert windows[-1].last_day == UNIVERSE_LAST_DAY, "last window does not end on the last day"
    assert all(w.n_days <= MAX_WINDOW_DAYS for w in windows), "a window exceeds 120 days"
    for previous, current in zip(windows, windows[1:]):
        assert current.first_day == previous.last_day + timedelta(days=1), "gap or overlap between windows"
        assert current.pub_start == previous.pub_end, "consecutive windows do not share their boundary"
    assert sum(w.n_days for w in windows) == (UNIVERSE_LAST_DAY - UNIVERSE_FIRST_DAY).days + 1
    return windows


def is_retryable(status_code: int) -> bool:
    return status_code in (403, 429) or 500 <= status_code < 600


class NvdClient:
    """GET requests with the apiKey header, a fixed pause between requests and retries."""

    def __init__(self, api_key: str) -> None:
        self._session = requests.Session()
        self._session.headers["apiKey"] = api_key
        self._last_request_at: float | None = None

    def _respect_pause(self) -> None:
        if self._last_request_at is not None:
            remaining = SECONDS_BETWEEN_REQUESTS - (time.monotonic() - self._last_request_at)
            if remaining > 0:
                time.sleep(remaining)
        self._last_request_at = time.monotonic()

    def get(self, params: dict) -> dict:
        for attempt in range(MAX_RETRIES + 1):
            self._respect_pause()
            try:
                response = self._session.get(API_URL, params=params, timeout=REQUEST_TIMEOUT_SECONDS)
                if response.status_code == 200:
                    return response.json()
                # NVD explains client errors in a 'message' response header.
                problem = f"HTTP {response.status_code}, NVD message: {response.headers.get('message')}"
                if not is_retryable(response.status_code):
                    raise RuntimeError(f"Request failed (not retryable): {problem}")
            except (
                requests.ConnectionError,
                requests.Timeout,
                requests.exceptions.ChunkedEncodingError,
                requests.JSONDecodeError,
            ) as error:
                # The detail (e.g. bytes read before a cut) helps diagnose; the key is in a header, not here.
                problem = f"{type(error).__name__}: {str(error)[:300]}"

            if attempt == MAX_RETRIES:
                raise RuntimeError(f"Request failed after {MAX_RETRIES} retries: {problem}")
            wait = SECONDS_BETWEEN_REQUESTS * 2**attempt
            print(f"    {problem}; retry {attempt + 1}/{MAX_RETRIES} in {wait} s")
            time.sleep(wait)
        raise AssertionError("unreachable")


def published_day(raw: str) -> date:
    # NVD returns UTC datetimes without an offset, e.g. 2022-01-01T00:15:08.057.
    timestamp = datetime.fromisoformat(raw)
    if timestamp.tzinfo is not None:
        timestamp = timestamp.astimezone(timezone.utc)
    return timestamp.date()


def download_window(client: NvdClient, window: Window) -> dict:
    started_at = datetime.now(timezone.utc)
    vulnerabilities: list[dict] = []
    page_timestamps: list[str] = []
    total_results: int | None = None
    start_index = 0

    while total_results is None or start_index < total_results:
        page = client.get({
            "pubStartDate": window.pub_start,
            "pubEndDate": window.pub_end,
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
        })
        if total_results is None:
            total_results = page["totalResults"]
            api_format, api_version = page["format"], page["version"]
        assert page["totalResults"] == total_results, (
            f"totalResults changed during paging: {total_results} -> {page['totalResults']}"
        )
        assert page["startIndex"] == start_index, f"asked startIndex={start_index}, got {page['startIndex']}"
        received = page["vulnerabilities"]
        assert received or total_results == 0, f"empty page at startIndex={start_index} of {total_results}"

        vulnerabilities.extend(received)
        page_timestamps.append(page["timestamp"])
        start_index += len(received)
        print(f"    page {len(page_timestamps)}: {len(vulnerabilities):,} / {total_results:,}")

    ids = [item["cve"]["id"] for item in vulnerabilities]
    assert len(vulnerabilities) == total_results, f"saved {len(vulnerabilities)} but totalResults is {total_results}"
    assert len(set(ids)) == len(ids), f"{len(ids) - len(set(ids))} duplicated CVE IDs within the window"
    outside = [
        item["cve"]["id"] for item in vulnerabilities
        if not window.first_day <= published_day(item["cve"]["published"]) <= window.last_day
    ]
    assert not outside, f"{len(outside)} CVEs published outside the window, e.g. {outside[:5]}"

    metadata = {
        "source": API_URL,
        "window_first_day": window.first_day.isoformat(),
        "window_last_day": window.last_day.isoformat(),
        "pub_start_date_param": window.pub_start,
        "pub_end_date_param": window.pub_end,
        "download_date_utc": started_at.date().isoformat(),
        "download_started_at_utc": started_at.isoformat(timespec="seconds"),
        "download_finished_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_results": total_results,
        "n_vulnerabilities": len(vulnerabilities),
        "n_pages": len(page_timestamps),
        "results_per_page": RESULTS_PER_PAGE,
        "api_format": api_format,
        "api_version": api_version,
        "api_page_timestamps": page_timestamps,
    }
    return {"metadata": metadata, "vulnerabilities": vulnerabilities}


def find_existing(window: Window) -> Path | None:
    matches = sorted(NVD_DIR.glob(f"nvd_{window.label}_downloaded_*.json"))
    assert len(matches) <= 1, f"more than one file for window {window.label}: {[p.name for p in matches]}"
    return matches[0] if matches else None


def save_window(window: Window, payload: dict) -> Path:
    download_date = payload["metadata"]["download_date_utc"]
    destination = NVD_DIR / f"nvd_{window.label}_downloaded_{download_date}.json"
    partial = destination.with_name(destination.name + ".part")
    # Write to a temporary file first so an interrupted download never looks complete.
    with partial.open("w", encoding="utf-8") as file:
        json.dump(payload, file, ensure_ascii=False, separators=(",", ":"))
    partial.replace(destination)
    return destination


def read_saved(path: Path) -> dict:
    with path.open(encoding="utf-8") as file:
        payload = json.load(file)
    metadata = payload["metadata"]
    assert len(payload["vulnerabilities"]) == metadata["total_results"], f"{path.name}: count mismatch"
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Download NVD CVEs published 2022-2024 in 120-day windows.")
    parser.add_argument("--max-windows", type=int, help="process only the first N windows (for testing)")
    args = parser.parse_args()

    # override=True: the project's .env wins over any NVD_API_KEY set elsewhere.
    load_dotenv(PROJECT_ROOT / ".env", override=True)
    api_key = os.environ.get("NVD_API_KEY")
    if not api_key:
        raise SystemExit("NVD_API_KEY is not set in .env")

    NVD_DIR.mkdir(parents=True, exist_ok=True)
    windows = build_windows()
    selected = windows if args.max_windows is None else windows[: args.max_windows]
    assert selected, "--max-windows must be at least 1"
    print(f"{len(windows)} windows cover {UNIVERSE_FIRST_DAY} to {UNIVERSE_LAST_DAY}; processing {len(selected)}")

    client = NvdClient(api_key)
    rows = []
    for number, window in enumerate(selected, start=1):
        print(f"\n[{number}/{len(selected)}] {window.first_day} to {window.last_day} ({window.n_days} days)")
        existing = find_existing(window)
        if existing:
            print(f"    skipping: {existing.name} already exists")
            metadata, status = read_saved(existing), "skipped"
        else:
            started = time.monotonic()
            payload = download_window(client, window)
            existing = save_window(window, payload)
            metadata, status = payload["metadata"], f"downloaded ({time.monotonic() - started:.0f} s)"
            print(f"    saved {existing.relative_to(PROJECT_ROOT)}")
        rows.append((window, metadata, status))

    print("\nSummary")
    print(f"  {'window':<26} {'totalResults':>12} {'saved':>8} {'pages':>5}  status")
    for window, metadata, status in rows:
        print(
            f"  {window.label:<26} {metadata['total_results']:>12,} {metadata['n_vulnerabilities']:>8,}"
            f" {metadata['n_pages']:>5}  {status}"
        )
    total_api = sum(m["total_results"] for _, m, _ in rows)
    total_saved = sum(m["n_vulnerabilities"] for _, m, _ in rows)
    print(f"  {'TOTAL':<26} {total_api:>12,} {total_saved:>8,}")

    assert all(m["total_results"] == m["n_vulnerabilities"] for _, m, _ in rows), "some window does not match"
    print("All checks passed.")


if __name__ == "__main__":
    main()
