from hypothesis import HealthCheck, given, settings

from harborapi.models.scanner import (
    HarborVulnerabilityReport,
    Severity,
    VulnerabilityItem,
)

from ..strategies.artifact import get_hbv_strategy


def test_vulnerabilityitem_get_severity_highest():
    vuln = VulnerabilityItem(
        vendor_attributes={
            "CVSS": {
                "nvd": {"V3Score": 7.5},
                "redhat": {"V3Score": 9.1},
            }
        },
    )
    assert vuln.get_severity_highest("Trivy", ("redhat", "nvd")) == Severity.critical


def test_vulnerabilityitem_get_severity():
    vuln = VulnerabilityItem(
        vendor_attributes={
            "CVSS": {
                "nvd": {"V3Score": 7.5},
                "redhat": {"V3Score": 9.1},
            }
        },
    )
    assert vuln.get_severity("Trivy", ("nvd", "redhat")) == Severity.high
    assert vuln.get_severity("Trivy", ("redhat", "nvd")) == Severity.critical


def test_severity_enum():
    # Defined in order from least to most severe
    severities = [
        "Unknown",
        "Negligible",
        "Low",
        "Medium",
        "High",
        "Critical",
    ]
    for severity in severities:
        assert getattr(Severity, severity.lower()) == Severity(severity)

    # Test that the enum is ordered
    assert list(iter(Severity)) == [Severity(s) for s in severities]


@given(get_hbv_strategy())
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_harborvulnerabilityreport(report: HarborVulnerabilityReport) -> None:
    test_vuln = VulnerabilityItem(
        id="CVE-2022-1337-test",
        description="test-cve",
        package="test-package",
    )
    report.vulnerabilities.append(test_vuln)

    # Test `has_` methods
    assert report.has_cve("CVE-2022-1337-test")
    assert not report.has_cve("CVE-2022-1337-test2")
    assert report.has_description("test-cve")
    assert report.has_package("test-package")

    # Test `vuln(s)_with_` methods
    assert report.vuln_with_cve("CVE-2022-1337-test") is test_vuln
    assert list(report.vulns_with_description("test-cve"))[0] is test_vuln
    assert list(report.vulns_with_package("test-package"))[0] is test_vuln
