"""Tests the Excel importer against a small synthetic workbook built with the
same header shape as the real telecom_vpn_cve_zero_click.xlsx (Step 11) - so
this suite never depends on the actual research workbook's row content
staying stable. A separate smoke test at the bottom does exercise the real
file, since it is already checked into the repository.
"""

from pathlib import Path

import pytest

from zeroshield.intelligence.excel_importer import (
    ExcelImportError,
    import_and_merge,
    import_workbook,
)
from zeroshield.models.enums import ZeroClickRelevance
from zeroshield.models.vulnerability import VulnerabilitySourceName

REPO_ROOT = Path(__file__).resolve().parents[3]
REAL_WORKBOOK = REPO_ROOT / "telecom_vpn_cve_zero_click.xlsx"

_HEADER = [
    "CVE ID", "Year", "Domain", "Vendor", "Product / Component", "Trust Boundary Affected",
    "CVSS Score", "CWE", "Zero-Click Relevance", "CISA KEV?", "EPSS Score",
    "Source URL 1", "Source URL 2", "Source URL 3",
]


def _write_workbook(path: Path, rows: list[list[object]], sheet_name: str = " CVE Intelligence") -> None:
    from openpyxl import Workbook

    wb = Workbook()
    ws = wb.active
    ws.title = sheet_name
    ws.append(_HEADER)
    for row in rows:
        ws.append(row)
    wb.save(path)


def _row(
    cve_id="CVE-2024-21762", vendor="Fortinet", product="FortiOS", trust="boundary text",
    cvss=9.6, cwe="CWE-787 / improper access control", zero_click="High", kev="Yes", epss="94.50%",
    url1="https://example.com/a",
) -> list[object]:
    return [cve_id, 2024, "VPN", vendor, product, trust, cvss, cwe, zero_click, kev, epss, url1, None, None]


def test_import_workbook_parses_valid_row(tmp_path: Path) -> None:
    path = tmp_path / "wb.xlsx"
    _write_workbook(path, [_row()])
    result = import_workbook(path)
    assert len(result.contributions) == 1
    assert result.skipped == []

    c = result.contributions[0]
    assert c.cve_id == "CVE-2024-21762"
    assert c.source is VulnerabilitySourceName.MANUAL_IMPORT
    assert c.vendor == "Fortinet"
    assert c.products == [("Fortinet", "FortiOS", None)]
    assert c.cvss_score == 9.6
    assert c.cwe_ids == ["CWE-787"]
    assert c.zero_click_relevance is ZeroClickRelevance.HIGH
    assert c.kev_listed is True
    assert c.epss_score == pytest.approx(0.945)
    assert c.references == ["https://example.com/a"]


def test_import_workbook_skips_row_with_malformed_cve_id(tmp_path: Path) -> None:
    path = tmp_path / "wb.xlsx"
    _write_workbook(path, [_row(cve_id="not-a-cve"), _row(cve_id="CVE-2024-00001")])
    result = import_workbook(path)
    assert len(result.contributions) == 1
    assert len(result.skipped) == 1
    assert "malformed" in result.skipped[0].reason


def test_import_workbook_skips_blank_rows(tmp_path: Path) -> None:
    path = tmp_path / "wb.xlsx"
    _write_workbook(path, [[None] * len(_HEADER), _row()])
    result = import_workbook(path)
    assert len(result.contributions) == 1
    assert result.skipped == []


def test_import_workbook_missing_file_raises() -> None:
    with pytest.raises(ExcelImportError, match="not found"):
        import_workbook(Path("does_not_exist.xlsx"))


def test_import_workbook_missing_sheet_raises(tmp_path: Path) -> None:
    path = tmp_path / "wb.xlsx"
    _write_workbook(path, [_row()], sheet_name="Some Other Sheet")
    with pytest.raises(ExcelImportError, match="not found in"):
        import_workbook(path, sheet_name=" CVE Intelligence")


def test_import_workbook_missing_required_column_raises(tmp_path: Path) -> None:
    from openpyxl import Workbook

    path = tmp_path / "wb.xlsx"
    wb = Workbook()
    ws = wb.active
    ws.title = " CVE Intelligence"
    ws.append(["Not CVE ID", "Vendor"])
    ws.append(["x", "y"])
    wb.save(path)
    with pytest.raises(ExcelImportError, match="CVE ID"):
        import_workbook(path)


def test_import_workbook_handles_numeric_and_percentage_epss(tmp_path: Path) -> None:
    path = tmp_path / "wb.xlsx"
    _write_workbook(path, [_row(epss=0.5), _row(cve_id="CVE-2024-00002", epss="50.0%")])
    result = import_workbook(path)
    assert result.contributions[0].epss_score == pytest.approx(0.5)
    assert result.contributions[1].epss_score == pytest.approx(0.5)


def test_import_and_merge_persists_into_repository(tmp_path: Path, vuln_repo) -> None:
    path = tmp_path / "wb.xlsx"
    _write_workbook(path, [_row(), _row(cve_id="not-a-cve")])
    summary = import_and_merge(path, repository=vuln_repo)
    assert summary.fetched_count == 1
    assert summary.created_count == 1
    assert summary.failed_count == 1

    stored = vuln_repo.get_vulnerability("CVE-2024-21762")
    assert stored is not None
    assert stored.zero_click_relevance is ZeroClickRelevance.HIGH
    assert VulnerabilitySourceName.MANUAL_IMPORT in stored.sources


@pytest.mark.skipif(not REAL_WORKBOOK.is_file(), reason="real research workbook not present in this checkout")
def test_import_workbook_real_research_file_parses_without_error() -> None:
    result = import_workbook(REAL_WORKBOOK)
    assert len(result.contributions) > 0
    assert all(c.source is VulnerabilitySourceName.MANUAL_IMPORT for c in result.contributions)
