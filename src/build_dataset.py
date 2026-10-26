"""Build the CVE analysis table from the raw NVD files (CLAUDE.md section 5).

Universe: CVEs whose NVD 'published' day (UTC) is between 2022-01-01 and
2024-12-31, excluding vulnStatus "Rejected". One row per CVE with the CVSS v3
base score chosen as follows:
- the cvssMetricV31 list if it has entries, otherwise cvssMetricV30;
- inside it, the entry with type "Primary"; otherwise the only "Secondary";
  otherwise the Secondary whose source equals the CVE's sourceIdentifier, and if
  none matches, the first Secondary (flagged in cvss_multi_secondary_no_match).
The 'type' field is taken literally (decision of 2026-10-26): in a few CVEs the
Primary entry comes from the vendor, not from nvd@nist.gov, and it is still used.
When NVD scored the CVE in the same version but its entry was not chosen, its
score is kept in cvss_nvd_alt_score so the effect can be measured.
CVEs without a v3.1/v3.0 score are kept with severity "Unscored".

Then it joins the KEV snapshot on the CVE ID and adds in_kev, kev_date_added,
exploited_365d (in KEV with dateAdded <= published day + 365 days), days_to_kev
(dateAdded - published day; 0 and negative values are kept), ransomware
(knownRansomwareCampaignUse == "Known") and KEV's vendorProject and product,
unnormalized, as vendor and product. For CVEs not in KEV, in_kev and
exploited_365d are False and the other KEV columns are NULL.

The result is saved in data/processed/cves.duckdb: table 'cves' (one row per
CVE) and table 'sources' (each raw file with its download date and counts). If
the database already exists the build is skipped (delete it to rebuild). The
summary and checks always run on what the database holds.

Usage: uv run python src/build_dataset.py
"""

import json
import re
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path

import duckdb
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"
NVD_DIR = RAW_DIR / "nvd"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
DATABASE = PROCESSED_DIR / "cves.duckdb"

UNIVERSE_FIRST_DAY = date(2022, 1, 1)
UNIVERSE_LAST_DAY = date(2024, 12, 31)
REJECTED_STATUS = "Rejected"
NVD_SOURCE = "nvd@nist.gov"
# cve.metrics lists in order of preference, with the cvssData.version each one holds.
CVSS_LISTS = (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"))
SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Unscored"]
EXPLOITED_WINDOW = pd.Timedelta(days=365)
KEV_COLUMNS = ["cveID", "vendorProject", "product", "dateAdded", "knownRansomwareCampaignUse"]
KEV_RANSOMWARE_VALUES = {"Known": True, "Unknown": False}

# Column name -> DuckDB type, in table order.
CVES_COLUMNS = {
    "cve_id": "VARCHAR",
    "published_date": "DATE",
    "vuln_status": "VARCHAR",
    "cvss_score": "DOUBLE",
    "cvss_version": "VARCHAR",
    "cvss_type": "VARCHAR",
    "cvss_source": "VARCHAR",
    "severity": "VARCHAR",
    "cvss_multi_secondary_no_match": "BOOLEAN",
    "cvss_nvd_alt_score": "DOUBLE",
    "in_kev": "BOOLEAN",
    "kev_date_added": "DATE",
    "exploited_365d": "BOOLEAN",
    "days_to_kev": "INTEGER",
    "ransomware": "BOOLEAN",
    "vendor": "VARCHAR",
    "product": "VARCHAR",
}
SOURCES_COLUMNS = {
    "source": "VARCHAR",
    "file_name": "VARCHAR",
    "download_date": "DATE",
    "n_records": "INTEGER",
    "n_rejected": "INTEGER",
}

NVD_FILE_NAME = re.compile(r"nvd_(\d{4}-\d{2}-\d{2})_to_(\d{4}-\d{2}-\d{2})_downloaded_(\d{4}-\d{2}-\d{2})\.json")
KEV_FILE_NAME = re.compile(r"known_exploited_vulnerabilities_(\d{4}-\d{2}-\d{2})\.csv")


@dataclass(frozen=True)
class NvdFile:
    name: str
    download_date: str
    n_records: int
    n_rejected: int
    rows: list[dict]  # one per non-Rejected CVE


@dataclass(frozen=True)
class KevFile:
    name: str
    download_date: str
    table: pd.DataFrame


def to_utc(raw: str) -> datetime:
    # NVD returns UTC datetimes without an offset, e.g. 2022-01-01T00:15:08.057.
    timestamp = datetime.fromisoformat(raw)
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def severity(score: float | None) -> str:
    """Severity bands of CLAUDE.md section 5; no score means Unscored."""
    if score is None:
        return "Unscored"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def choose_cvss(cve: dict) -> dict:
    """Return the CVSS columns of one CVE, following CLAUDE.md section 5."""
    cve_id = cve["id"]
    for list_name, version in CVSS_LISTS:
        entries = cve["metrics"].get(list_name, [])
        if not entries:
            continue
        assert all(e["cvssData"]["version"] == version for e in entries), f"{cve_id}: {list_name} holds another version"
        assert all(e["type"] in ("Primary", "Secondary") for e in entries), f"{cve_id}: unexpected type in {list_name}"
        primary = [e for e in entries if e["type"] == "Primary"]
        secondary = [e for e in entries if e["type"] == "Secondary"]
        from_nvd = [e for e in entries if e["source"] == NVD_SOURCE]
        assert len(primary) <= 1, f"{cve_id}: more than one Primary in {list_name}"
        assert len(from_nvd) <= 1, f"{cve_id}: more than one {NVD_SOURCE} entry in {list_name}"

        no_match = False
        if primary:
            chosen = primary[0]
        elif len(secondary) == 1:
            chosen = secondary[0]
        else:
            matching = [e for e in secondary if e["source"] == cve["sourceIdentifier"]]
            assert len(matching) <= 1, f"{cve_id}: several Secondary entries match sourceIdentifier in {list_name}"
            no_match = not matching
            chosen = matching[0] if matching else secondary[0]

        score = chosen["cvssData"]["baseScore"]
        assert 0.0 <= score <= 10.0, f"{cve_id}: baseScore {score} out of range"
        nvd_alt = from_nvd[0] if from_nvd and from_nvd[0] is not chosen else None
        return {
            "cvss_score": score,
            "cvss_version": version,
            "cvss_type": chosen["type"],
            "cvss_source": chosen["source"],
            "severity": severity(score),
            "cvss_multi_secondary_no_match": no_match,
            "cvss_nvd_alt_score": nvd_alt["cvssData"]["baseScore"] if nvd_alt else None,
        }
    return {
        "cvss_score": None,
        "cvss_version": None,
        "cvss_type": None,
        "cvss_source": None,
        "severity": "Unscored",
        "cvss_multi_secondary_no_match": False,
        "cvss_nvd_alt_score": None,
    }


def read_nvd_file(path: Path) -> NvdFile:
    file_name = NVD_FILE_NAME.fullmatch(path.name)
    assert file_name, f"unexpected file name: {path.name}"
    with path.open(encoding="utf-8") as file:
        payload = json.load(file)
    metadata = payload["metadata"]
    records = payload["vulnerabilities"]
    assert len(records) == metadata["total_results"], f"{path.name}: saved != totalResults"
    assert file_name.group(3) == metadata["download_date_utc"], f"{path.name}: download date differs from metadata"

    rows = []
    n_rejected = 0
    for record in records:
        cve = record["cve"]
        if cve["vulnStatus"] == REJECTED_STATUS:
            n_rejected += 1
            continue
        rows.append({
            "cve_id": cve["id"],
            "published_date": to_utc(cve["published"]).date(),
            "vuln_status": cve["vulnStatus"],
            **choose_cvss(cve),
        })
    return NvdFile(path.name, metadata["download_date_utc"], len(records), n_rejected, rows)


def read_kev() -> KevFile:
    snapshots = sorted(RAW_DIR.glob("known_exploited_vulnerabilities_*.csv"))
    assert len(snapshots) == 1, f"expected one KEV snapshot, found {[p.name for p in snapshots]}"
    file_name = KEV_FILE_NAME.fullmatch(snapshots[0].name)
    assert file_name, f"unexpected file name: {snapshots[0].name}"
    # Same reading options as download_kev.py.
    kev = pd.read_csv(snapshots[0], dtype=str, keep_default_na=False, encoding="utf-8-sig")

    missing = [column for column in KEV_COLUMNS if column not in kev.columns]
    assert not missing, f"KEV is missing columns {missing}"
    repeated = kev.loc[kev["cveID"].duplicated(keep=False), "cveID"].drop_duplicates()
    assert repeated.empty, f"{len(repeated)} cveID values repeated in KEV, e.g. {repeated.head(5).tolist()}"
    unexpected = set(kev["knownRansomwareCampaignUse"]) - set(KEV_RANSOMWARE_VALUES)
    assert not unexpected, f"unexpected knownRansomwareCampaignUse values: {unexpected}"
    return KevFile(snapshots[0].name, file_name.group(1), kev)


def add_kev_columns(nvd: pd.DataFrame, kev: pd.DataFrame) -> pd.DataFrame:
    """Left join the NVD rows with KEV on the CVE ID and add the exploitation columns."""
    kev_columns = kev[KEV_COLUMNS].rename(columns={
        "cveID": "cve_id",
        "dateAdded": "kev_date_added",
        "vendorProject": "vendor",
    })
    kev_columns["kev_date_added"] = pd.to_datetime(kev_columns["kev_date_added"], format="%Y-%m-%d")
    joined = nvd.merge(kev_columns, on="cve_id", how="left", validate="one_to_one", indicator=True)

    joined["in_kev"] = joined["_merge"] == "both"
    joined["exploited_365d"] = joined["in_kev"] & (
        joined["kev_date_added"] <= joined["published_date"] + EXPLOITED_WINDOW
    )
    joined["days_to_kev"] = (joined["kev_date_added"] - joined["published_date"]).dt.days.astype("Int64")
    joined["ransomware"] = joined["knownRansomwareCampaignUse"].map(KEV_RANSOMWARE_VALUES).astype("boolean")
    kev_output = ["in_kev", "kev_date_added", "exploited_365d", "days_to_kev", "ransomware", "vendor", "product"]
    return joined[[*nvd.columns, *kev_output]]


def pct(part: int, whole: int) -> str:
    return f"{part / whole:.1%} = {part:,} / {whole:,}"


def build_tables() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Read the raw files and return the 'cves' and 'sources' tables."""
    paths = sorted(NVD_DIR.glob("nvd_*.json"))
    assert paths, f"no NVD files in {NVD_DIR}"
    nvd_files = [read_nvd_file(path) for path in paths]
    nvd = pd.DataFrame([row for nvd_file in nvd_files for row in nvd_file.rows])
    nvd["published_date"] = pd.to_datetime(nvd["published_date"])
    kev = read_kev()  # asserts that KEV has no repeated cveID before the join
    cves = add_kev_columns(nvd, kev.table)

    # Checks that need the raw files; the rest run on the saved database.
    n_in_kev = int(cves["in_kev"].sum())
    n_kev_ids_in_universe = int(kev.table["cveID"].isin(nvd["cve_id"]).sum())
    assert len(cves) == len(nvd), "the KEV join changed the number of rows"
    assert n_in_kev == n_kev_ids_in_universe, f"in_kev = {n_in_kev} but {n_kev_ids_in_universe} KEV IDs are in the universe"

    sources = pd.DataFrame([
        *(
            {"source": "NVD", "file_name": nvd_file.name, "download_date": nvd_file.download_date,
             "n_records": nvd_file.n_records, "n_rejected": nvd_file.n_rejected}
            for nvd_file in nvd_files
        ),
        {"source": "KEV", "file_name": kev.name, "download_date": kev.download_date,
         "n_records": len(kev.table), "n_rejected": None},
    ])
    sources["download_date"] = pd.to_datetime(sources["download_date"], format="%Y-%m-%d")
    sources["n_rejected"] = sources["n_rejected"].astype("Int64")
    return cves, sources


def write_database(cves: pd.DataFrame, sources: pd.DataFrame) -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    partial = DATABASE.with_name(DATABASE.name + ".part")
    # A leftover .part file comes from an interrupted build: start again from scratch.
    for leftover in (partial, partial.with_name(partial.name + ".wal")):
        leftover.unlink(missing_ok=True)

    # Write to a temporary file first so an interrupted build never looks complete.
    with duckdb.connect(str(partial)) as connection:
        for table, columns, key, frame in (
            ("cves", CVES_COLUMNS, "cve_id", cves),
            ("sources", SOURCES_COLUMNS, "file_name", sources),
        ):
            definition = ", ".join(f"{column} {column_type}" for column, column_type in columns.items())
            connection.execute(f"CREATE TABLE {table} ({definition}, PRIMARY KEY ({key}))")
            connection.register("frame", frame)
            connection.execute(f"INSERT INTO {table} BY NAME SELECT * FROM frame")
            connection.unregister("frame")
    partial.replace(DATABASE)


def read_database() -> tuple[pd.DataFrame, pd.DataFrame]:
    with duckdb.connect(str(DATABASE), read_only=True) as connection:
        for table, columns in (("cves", CVES_COLUMNS), ("sources", SOURCES_COLUMNS)):
            stored = [(name, column_type) for name, column_type, *_ in connection.execute(f"DESCRIBE {table}").fetchall()]
            assert stored == list(columns.items()), f"{table}: stored columns and types differ from the schema: {stored}"
        cves = connection.execute("SELECT * FROM cves").df()
        sources = connection.execute("SELECT * FROM sources ORDER BY source DESC, file_name").df()
    return cves, sources


def main() -> None:
    if DATABASE.exists():
        print("=" * 72)
        print(f"SKIPPED: using existing {DATABASE.name} (delete it to rebuild)")
        print("=" * 72)
    else:
        cves, sources = build_tables()
        write_database(cves, sources)
        print(f"Saved {DATABASE.relative_to(PROJECT_ROOT)}")

    # Summary and checks always run on what the database holds.
    cves, sources = read_database()
    nvd_sources = sources[sources["source"] == "NVD"]
    kev_sources = sources[sources["source"] == "KEV"]
    kev_source = kev_sources.iloc[0]

    n_records = int(nvd_sources["n_records"].sum())
    n_rejected = int(nvd_sources["n_rejected"].sum())
    total = len(cves)
    nvd_download_dates = sorted({day.date().isoformat() for day in nvd_sources["download_date"]})
    in_universe = cves["published_date"].between(pd.Timestamp(UNIVERSE_FIRST_DAY), pd.Timestamp(UNIVERSE_LAST_DAY))
    unscored = cves["severity"] == "Unscored"

    n_in_kev = int(cves["in_kev"].sum())
    n_exploited = int(cves["exploited_365d"].sum())
    days_to_kev = cves["days_to_kev"].dropna()
    n_ransomware_known = int(cves["ransomware"].eq(True).sum())
    n_ransomware_unknown = int(cves["ransomware"].eq(False).sum())
    # The 365-day window must have ended for every CVE before any source was downloaded.
    earliest_download = sources["download_date"].min()
    window_end = cves["published_date"].max() + EXPLOITED_WINDOW

    print(f"\nSummary of {DATABASE.relative_to(PROJECT_ROOT)}")
    print(f"NVD files ({NVD_DIR.relative_to(PROJECT_ROOT)}): {len(nvd_sources)}, downloaded {', '.join(nvd_download_dates)}")
    print(f"  Records:              {n_records:>8,}")
    print(f"  Rejected (excluded):  {n_rejected:>8,}")
    print(f"  CVEs kept:            {total:>8,}")
    print(f"  Published days:       {cves['published_date'].min().date()} to {cves['published_date'].max().date()}")

    print("\nvulnStatus")
    for status, count in cves["vuln_status"].value_counts().items():
        print(f"  {status:<24} {pct(int(count), total)}")

    print("\nCVSS used (version, type)")
    used = cves.groupby(["cvss_version", "cvss_type"], dropna=False).size().sort_values(ascending=False)
    for (version, cvss_type), count in used.items():
        label = f"v{version} {cvss_type}" if pd.notna(version) else "no CVSS v3"
        print(f"  {label:<24} {pct(int(count), total)}")

    print("\nSeverity")
    for name in SEVERITY_ORDER:
        print(f"  {name:<24} {pct(int((cves['severity'] == name).sum()), total)}")

    print("\nSelection cases")
    print(f"  Several Secondary, none matching sourceIdentifier (first used): {int(cves['cvss_multi_secondary_no_match'].sum()):,}")
    print(f"  NVD score in the same version but not used (cvss_nvd_alt_score): {int(cves['cvss_nvd_alt_score'].notna().sum()):,}")

    print(
        f"\nKEV ({kev_source['file_name']}): {kev_source['n_records']:,} rows,"
        f" downloaded {kev_source['download_date'].date()}"
    )
    print(f"  KEV entries in the universe (in_kev): {pct(n_in_kev, int(kev_source['n_records']))}")
    print(f"  exploited_365d:                       {n_exploited:>6,}")
    print(f"  In KEV after more than 365 days:      {n_in_kev - n_exploited:>6,}")
    print(f"  days_to_kev = 0:                      {int((days_to_kev == 0).sum()):>6,}")
    print(f"  days_to_kev < 0:                      {int((days_to_kev < 0).sum()):>6,}")
    print(f"  ransomware Known / Unknown:           {n_ransomware_known:,} / {n_ransomware_unknown:,}")
    print(
        f"  365-day window: last published day {cves['published_date'].max().date()} + 365 days ="
        f" {window_end.date()}; earliest download {earliest_download.date()}"
    )

    assert total == n_records - n_rejected, f"{total} rows but {n_records} records - {n_rejected} Rejected"
    assert cves["cve_id"].is_unique, f"{cves['cve_id'].duplicated().sum()} duplicated cve_id values"
    assert in_universe.all(), f"{(~in_universe).sum()} CVEs published outside the universe"
    assert (cves["vuln_status"] != REJECTED_STATUS).all(), "Rejected CVEs left in the table"
    assert (unscored == cves["cvss_score"].isna()).all(), "Unscored must be exactly the CVEs without a score"
    assert cves["severity"].isin(SEVERITY_ORDER).all(), "unexpected severity value"
    assert len(kev_sources) == 1, f"expected one KEV source, found {len(kev_sources)}"
    assert (~cves["exploited_365d"] | cves["in_kev"]).all(), "exploited_365d is True for a CVE not in KEV"
    assert (cves["days_to_kev"].isna() == ~cves["in_kev"]).all(), "days_to_kev must be NULL exactly when not in KEV"
    assert n_ransomware_known + n_ransomware_unknown == n_in_kev, "ransomware must be set exactly for the CVEs in KEV"
    assert window_end <= earliest_download, (
        f"the 365-day window ends {window_end.date()}, after the earliest download {earliest_download.date()}"
    )
    print("All checks passed.")


if __name__ == "__main__":
    main()
