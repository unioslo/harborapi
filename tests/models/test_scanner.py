from __future__ import annotations

import pytest
from hypothesis import HealthCheck
from hypothesis import given
from hypothesis import settings
from hypothesis import strategies as st
from pytest_mock import MockerFixture

from harborapi.models.scanner import CVSSDetails
from harborapi.models.scanner import HarborVulnerabilityReport
from harborapi.models.scanner import Scanner
from harborapi.models.scanner import Severity
from harborapi.models.scanner import VulnerabilityItem

from ..strategies.artifact import get_hbv_strategy


def test_vulnerabilityitem_get_severity_highest():
    vuln = VulnerabilityItem(
        vendor_attributes={
            "CVSS": {
                "nvd": {"V3Score": 7.5},  # 7.5: high
                "redhat": {"V3Score": 9.1},  # 9.1: critical
            }
        },
    )
    assert vuln.get_severity_highest("Trivy", ("redhat", "nvd")) == Severity.critical


def test_vulnerabilityitem_get_severity():
    vuln = VulnerabilityItem(
        vendor_attributes={
            "CVSS": {
                "nvd": {"V3Score": 7.5},  # 7.5: high
                "redhat": {"V3Score": 9.1},  # 9.1: critical
            }
        },
    )
    assert vuln.get_severity("Trivy", ("nvd", "redhat")) == Severity.high
    assert vuln.get_severity("Trivy", ("redhat", "nvd")) == Severity.critical


def test_severity_enum():
    # Defined in order from least to most severe
    severities = [
        "Unknown",
        "None",
        "Negligible",
        "Low",
        "Medium",
        "High",
        "Critical",
    ]
    for severity in severities:
        assert getattr(Severity, severity.lower()) == Severity(severity)

    # Test that the enum is ordered
    # TODO: fix code generation to place the `none` value before others
    # assert list(iter(Severity)) == [Severity(s) for s in severities]

    # Test enum comparison
    assert Severity.low < Severity.medium
    assert Severity.medium > Severity.low
    assert Severity.medium <= Severity.medium
    assert Severity.medium >= Severity.medium
    assert Severity.medium == Severity.medium
    assert Severity.medium <= Severity.high
    assert Severity.medium < Severity.high
    assert Severity.high == Severity.high
    assert Severity.high <= Severity.critical
    assert Severity.high < Severity.critical
    assert Severity.critical == Severity.critical

    # TODO: see TODO above
    # Ensure that the enum values are ordered from least to most severe
    # severities = list(Severity)
    # for i, severity in enumerate(severities):
    #     if i == 0:
    #         assert severity < severities[i + 1]
    #     elif i == len(severities) - 1:
    #         assert severity > severities[i - 1]
    #     else:
    #         assert severity > severities[i - 1]
    #         assert severity < severities[i + 1]
    #     # TODO: Assert that the cache is not modified.
    #     # We use an lru_cache(maxsize=1) decorator instead of computed_property
    #     # because computed_property doesn't play well with classmethods.
    #     # Since we have a maxsize of 1, we want to make sure this cache is
    #     # never modified.


@given(get_hbv_strategy())
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_harborvulnerabilityreport(report: HarborVulnerabilityReport) -> None:
    test_vuln = VulnerabilityItem(
        id="CVE-2022-1337-test",
        description="test-cve",
        package="test-package",
        severity=Severity.high,
    )
    test_vuln2 = VulnerabilityItem(
        id="CVE-2022-1337-test-2",
        description="test-cve-2",
        package="test-package-2",
        severity=Severity.critical,
    )
    report.vulnerabilities = [test_vuln, test_vuln2]

    # Test `has_` methods
    assert report.has_cve("CVE-2022-1337-test")
    assert not report.has_cve("CVE-2022-1337-test2")
    assert report.has_description("test-cve")
    assert report.has_package("test-package")

    # Test `vuln(s)_with_` methods
    assert report.vuln_with_cve("CVE-2022-1337-test") == test_vuln
    assert list(report.vulns_with_description("test-cve"))[0] == test_vuln
    assert list(report.vulns_with_package("test-package"))[0] == test_vuln

    # Test sorting
    assert report.vulnerabilities[0] == test_vuln
    assert report.vulnerabilities[1] == test_vuln2
    report.sort()
    assert report.vulnerabilities[0] == test_vuln2
    assert report.vulnerabilities[1] == test_vuln
    # We can only compare using cvss scores if we have a scanner
    # (which we should probably always have)
    if report.scanner is not None:
        # vuln3 has identical severity to vuln2, but should be sorted before
        # vuln 2, because it has a CVSS score, while vuln2 does not.
        test_vuln3 = VulnerabilityItem(
            id="CVE-2022-1337-test-3",
            description="test-cve-3",
            package="test-package-3",
            severity=Severity.critical,
            vendor_attributes={
                "CVSS": {
                    "nvd": {"V3Score": 7.5},  # 7.5: high
                    "redhat": {"V3Score": 9.1},  # 9.1: critical
                }
            },
        )
        report.vulnerabilities.append(test_vuln3)
        report.sort(use_cvss=True)
        assert report.vulnerabilities[0] == test_vuln3


def test_vulnerability_item_severity_none() -> None:
    """Passing None to VulnerabilityItem.severity should assign it Severity.unknown"""
    v = VulnerabilityItem(
        id="CVE-2022-1337-test",
        description="test-cve",
        package="test-package",
        severity=None,
    )
    assert v.severity is not None
    assert v.severity == Severity.unknown

def test_harborvulnerabilityreport_severity_none() -> None:
    """Passing None to HarborVulnerabilityReport.severity should assign it Severity.unknown"""
    v = HarborVulnerabilityReport(
        severity=None,
    )
    assert v.severity is not None
    assert v.severity == Severity.unknown

def test_harborvulnerabilityreport_severity_empty_str() -> None:
    """Passing empty string to HarborVulnerabilityReport.severity should assign it Severity.unknown"""
    v = HarborVulnerabilityReport(
        severity="",
    )
    assert v.severity is not None
    assert v.severity == Severity.unknown

@pytest.mark.parametrize("scanner_name", ["Trivy", "Clair"])
def test_vulnerability_item_get_cvss_score(scanner_name: str) -> None:
    """Test that the CVSS score is correctly computed when no preferred CVSS is present."""
    v = VulnerabilityItem(preferred_cvss=None)
    assert v.preferred_cvss is None
    v.vendor_attributes = {
        "CVSS": {
            "nvd": {"V2Score": 1.0, "V3Score": 2.0},
            "redhat": {"V2Score": 3.0, "V3Score": 4.0},
        },
    }
    scanner = Scanner(name=scanner_name)

    if scanner.name == "Trivy":
        # NVD vendor (default)
        assert v.get_cvss_score(scanner, version=2) == 1.0
        assert v.get_cvss_score(scanner, version=3) == 2.0
        assert v.get_cvss_score(scanner, vendor_priority=["nvd"], version=3) == 2.0
        assert v.get_cvss_score(scanner, vendor_priority=["nvd"], version=3) == 2.0
        # RedHat vendor
        assert v.get_cvss_score(scanner, vendor_priority=["redhat"], version=2) == 3.0
        assert v.get_cvss_score(scanner, vendor_priority=["redhat"], version=3) == 4.0
    else:
        assert v.get_cvss_score(scanner) == 0.0
        # other args are ignored because of unknown scanner
        assert v.get_cvss_score(scanner, version=2) == 0.0
        assert v.get_cvss_score(scanner, version=3) == 0.0
        assert v.get_cvss_score(scanner, vendor_priority=["nvd"], version=3) == 0.0
        assert v.get_cvss_score(scanner, vendor_priority=["redhat"], version=2) == 0.0


@pytest.mark.parametrize("scanner_name", ["Trivy", "Clair"])
def test_vulnerability_item_get_cvss_score_no_cvss_data(scanner_name: str) -> None:
    """Tests that the default score is returned if vendor data is empty."""
    v = VulnerabilityItem()
    v.vendor_attributes = {}
    scanner = Scanner(name=scanner_name)

    # Regardless of which scanner we pass in, we should get the default score
    assert v.get_cvss_score(scanner) == 0.0

    # Vendor attributes contains empty CVSS dict
    v.vendor_attributes = {"CVSS": {}}
    assert v.get_cvss_score(scanner) == 0.0


def test_vulnerability_item_get_cvss_score_malformed_trivy_cvss_data(
    caplog: pytest.LogCaptureFixture, mocker: MockerFixture
) -> None:
    """Tests that the default score is returned if vendor data is empty."""
    v = VulnerabilityItem()
    v.vendor_attributes = {"CVSS": {"nvd": ["malformed", "data"]}}
    scanner = Scanner(name="Trivy")
    trivy_method = mocker.spy(v, "_get_trivy_cvss_score")

    # Call the method and check that the underlying Trivy method was called
    version = 3
    vendor_priority = ["nvd", "redhat"]
    default = 0.0
    assert (
        v.get_cvss_score(
            scanner, version=version, vendor_priority=vendor_priority, default=default
        )
        == default
    )

    assert "malformed vendor cvss data" in caplog.text.lower()
    trivy_method.assert_called_once_with(
        version=version, vendor_priority=vendor_priority, default=default
    )


@given(
    st.builds(
        VulnerabilityItem,
        preferred_cvss=st.builds(CVSSDetails),
    ),
    st.floats(0.0, 10.0),
    st.floats(0.0, 10.0),
)
def test_vulnerability_item_get_cvss_score_preferred_cvss(
    v: VulnerabilityItem,
    score_v2: float,
    score_v3: float,
) -> None:
    """Test that preferred CVSS takes precedence if it exists.

    NOTE
    ----
    As of 2023-10-16, preferred CVSS has always been observed to be None in practice,
    and the CVSS scores are always computed from the vendor attributes,
    but we have to make sure this works in case Harbor starts using it.
    """
    assert v.preferred_cvss is not None
    v.preferred_cvss.score_v2 = score_v2
    v.preferred_cvss.score_v3 = score_v3
    assert v.preferred_cvss.score_v3 == score_v3
    assert v.preferred_cvss.score_v2 == score_v2

    # Test the method
    assert v.get_cvss_score(version=2) == score_v2
    assert v.get_cvss_score(version=3) == score_v3
    assert v.get_cvss_score() == score_v3  # default

    # Scanner and priority arguments are ignored
    assert v.get_cvss_score(scanner=Scanner(name="Clair")) == score_v3  # default
    assert v.get_cvss_score(scanner=Scanner(name="Trivy"), version=2) == score_v2
    assert v.get_cvss_score(scanner=Scanner(name="Clair"), version=3) == score_v3
    assert (
        v.get_cvss_score(scanner=Scanner(name="Trivy"), vendor_priority=["nvd"])
        == score_v3
    )


# TODO: Add tests:
# - VulnerabilityItem:
#   - low
#   - medium
#   - high
#   - critical
#   - vulnerabilities_by_severity
#   - top_vulns
#   - get_severity with all severities
# - sort_distribution
