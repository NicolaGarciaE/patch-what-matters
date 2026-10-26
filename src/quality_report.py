"""Print the data-quality report of data/processed/cves.duckdb (read-only).

Sections:
1. CVEs and % Unscored per published year (UTC).
2. CVSS version, type and source used.
3. Selection cases of CLAUDE.md section 5: several Secondary with no source
   match, Primary entries not from nvd@nist.gov, and NVD scores that were not
   used (how many of those CVEs are in KEV, and in how many the severity would
   change with NVD's score).
4. Duplicated CVE IDs (must be 0).
5. KEV entries in the universe.
6. days_to_kev <= 0.
7. The 365-day window has ended for every CVE before the earliest download.

Usage: uv run python src/quality_report.py   (after src/build_dataset.py)
"""

import duckdb
import pandas as pd

# Same definitions as the build, so the report cannot drift from them.
from build_dataset import DATABASE, EXPLOITED_WINDOW, NVD_SOURCE, PROJECT_ROOT, severity

TOP_SOURCES = 10


def pct(part: int, whole: int) -> str:
    return f"{part / whole:.1%} = {part:,} / {whole:,}"


def main() -> None:
    assert DATABASE.exists(), f"{DATABASE.relative_to(PROJECT_ROOT)} not found: run src/build_dataset.py first"
    with duckdb.connect(str(DATABASE), read_only=True) as connection:
        sources = connection.execute("SELECT * FROM sources ORDER BY source DESC, file_name").df()
        per_year = connection.execute("""
            SELECT year(published_date) AS year,
                   count(*) AS cves,
                   count(*) FILTER (WHERE severity = 'Unscored') AS unscored
            FROM cves
            GROUP BY year
            ORDER BY year
        """).df()
        cvss_used = connection.execute("""
            SELECT cvss_version, cvss_type, count(*) AS cves
            FROM cves
            GROUP BY cvss_version, cvss_type
            ORDER BY cves DESC
        """).df()
        top_sources = connection.execute(f"""
            SELECT cvss_source, count(*) AS cves
            FROM cves
            WHERE cvss_source IS NOT NULL
            GROUP BY cvss_source
            ORDER BY cves DESC, cvss_source
            LIMIT {TOP_SOURCES}
        """).df()
        nvd_alt = connection.execute("""
            SELECT cve_id, cvss_type, cvss_source, cvss_score, severity, cvss_nvd_alt_score, in_kev
            FROM cves
            WHERE cvss_nvd_alt_score IS NOT NULL
            ORDER BY cve_id
        """).df()
        counts = connection.execute("""
            SELECT count(*) AS total,
                   count(*) - count(DISTINCT cve_id) AS duplicated_ids,
                   count(*) FILTER (WHERE cvss_version IS NOT NULL) AS scored,
                   count(*) FILTER (WHERE cvss_multi_secondary_no_match) AS multi_secondary_no_match,
                   count(*) FILTER (WHERE cvss_type = 'Primary' AND cvss_source <> $nvd_source) AS primary_not_nvd,
                   count(*) FILTER (WHERE in_kev) AS in_kev,
                   count(*) FILTER (WHERE days_to_kev = 0) AS days_to_kev_zero,
                   count(*) FILTER (WHERE days_to_kev < 0) AS days_to_kev_negative,
                   max(published_date) AS last_published
            FROM cves
        """, {"nvd_source": NVD_SOURCE}).df().iloc[0]

    total = int(counts["total"])
    scored = int(counts["scored"])
    n_in_kev = int(counts["in_kev"])
    n_days_zero = int(counts["days_to_kev_zero"])
    n_days_negative = int(counts["days_to_kev_negative"])
    kev_rows = int(sources.loc[sources["source"] == "KEV", "n_records"].iloc[0])
    # The 365-day window must have ended for every CVE before any source was downloaded.
    earliest_download = sources["download_date"].min()
    window_end = pd.Timestamp(counts["last_published"]) + EXPLOITED_WINDOW

    nvd_alt["nvd_alt_severity"] = nvd_alt["cvss_nvd_alt_score"].map(severity)
    nvd_alt["in_kev_severity_changes"] = nvd_alt["in_kev"] & (nvd_alt["nvd_alt_severity"] != nvd_alt["severity"])
    alt_by_type = nvd_alt.groupby("cvss_type").agg(
        cves=("cve_id", "size"),
        in_kev=("in_kev", "sum"),
        in_kev_severity_changes=("in_kev_severity_changes", "sum"),
    )

    print(f"Quality report of {DATABASE.relative_to(PROJECT_ROOT)}")
    for source, group in sources.groupby("source", sort=False):
        days = sorted({day.date().isoformat() for day in group["download_date"]})
        print(f"  {source}: {len(group)} file(s), downloaded {', '.join(days)}")

    print("\n1. CVEs and Unscored per published year (UTC)")
    print(f"  {'year':<6} {'CVEs':>8}  Unscored")
    for row in per_year.itertuples():
        print(f"  {row.year:<6} {row.cves:>8,}  {pct(int(row.unscored), int(row.cves))}")
    print(f"  {'Total':<6} {total:>8,}  {pct(int(per_year['unscored'].sum()), total)}")

    print("\n2. CVSS used")
    print("  Version and type (of all CVEs)")
    for row in cvss_used.itertuples():
        label = f"v{row.cvss_version} {row.cvss_type}" if pd.notna(row.cvss_version) else "no CVSS v3 (Unscored)"
        print(f"    {label:<40} {pct(int(row.cves), total)}")
    print(f"  Top {TOP_SOURCES} cvss_source (of scored CVEs)")
    for row in top_sources.itertuples():
        print(f"    {row.cvss_source:<40} {pct(int(row.cves), scored)}")

    print("\n3. Selection cases (CLAUDE.md section 5)")
    print(f"  Several Secondary, none matching sourceIdentifier (first used): {int(counts['multi_secondary_no_match']):,}")
    print(f"  Primary entry not from {NVD_SOURCE} (used, type taken literally): {int(counts['primary_not_nvd']):,}")
    print(f"  NVD score in the same version but not used (cvss_nvd_alt_score): {len(nvd_alt):,}")
    print(f"    {'cvss_type used':<16} {'CVEs':>6} {'in_kev':>7}  in_kev and severity would change with NVD's score")
    for cvss_type, row in alt_by_type.iterrows():
        print(f"    {cvss_type:<16} {row['cves']:>6,} {row['in_kev']:>7,}  {row['in_kev_severity_changes']:,}")
    n_alt_in_kev = int(alt_by_type["in_kev"].sum())
    n_alt_changes = int(alt_by_type["in_kev_severity_changes"].sum())
    print(f"    {'Total':<16} {len(nvd_alt):>6,} {n_alt_in_kev:>7,}  {n_alt_changes:,}")
    print(f"    in_kev: {pct(n_alt_in_kev, len(nvd_alt))}; severity would change: {pct(n_alt_changes, n_alt_in_kev)}")
    for row in nvd_alt[nvd_alt["in_kev_severity_changes"]].itertuples():
        print(
            f"      {row.cve_id}: used {row.cvss_score} {row.severity} ({row.cvss_source})"
            f" -> NVD {row.cvss_nvd_alt_score} {row.nvd_alt_severity}"
        )

    print(f"\n4. Duplicated cve_id: {int(counts['duplicated_ids']):,}")
    print(f"\n5. KEV entries in the universe (in_kev): {pct(n_in_kev, kev_rows)}")
    print(f"\n6. days_to_kev <= 0 (of in_kev): {pct(n_days_zero + n_days_negative, n_in_kev)}")
    print(f"  = 0: {n_days_zero:,}")
    print(f"  < 0: {n_days_negative:,}")
    print(
        f"\n7. 365-day window: last published day {pd.Timestamp(counts['last_published']).date()} + 365 days ="
        f" {window_end.date()}; earliest download {earliest_download.date()}"
    )

    assert int(counts["duplicated_ids"]) == 0, f"{int(counts['duplicated_ids'])} duplicated cve_id values"
    assert window_end <= earliest_download, (
        f"the 365-day window ends {window_end.date()}, after the earliest download {earliest_download.date()}"
    )
    assert int(per_year["cves"].sum()) == total, "CVEs per year do not add up to the total"
    assert int(cvss_used["cves"].sum()) == total, "CVSS version/type counts do not add up to the total"
    print("All checks passed.")


if __name__ == "__main__":
    main()
