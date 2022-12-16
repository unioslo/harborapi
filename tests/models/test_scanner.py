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

    # Test enum comparison
    assert Severity.low < Severity.medium
    assert Severity.medium > Severity.low
    assert Severity.medium <= Severity.medium
    assert Severity.medium >= Severity.medium
    assert Severity.medium == Severity.medium
    assert Severity.medium != Severity.high

    # Ensure that the enum values are ordered from least to most severe
    severities = list(Severity)
    for i, severity in enumerate(severities):
        if i == 0:
            assert severity < severities[i + 1]
        elif i == len(severities) - 1:
            assert severity > severities[i - 1]
        else:
            assert severity > severities[i - 1]
            assert severity < severities[i + 1]
        # TODO: Assert that the cache is not modified.
        # We use an lru_cache(maxsize=1) decorator instead of computed_property
        # because computed_property doesn't play well with classmethods.
        # Since we have a maxsize of 1, we want to make sure this cache is
        # never modified.


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
    assert report.vuln_with_cve("CVE-2022-1337-test") is test_vuln
    assert list(report.vulns_with_description("test-cve"))[0] is test_vuln
    assert list(report.vulns_with_package("test-package"))[0] is test_vuln

    # Test sorting
    assert report.vulnerabilities[0] is test_vuln
    assert report.vulnerabilities[1] is test_vuln2
    report.sort()
    assert report.vulnerabilities[0] is test_vuln2
    assert report.vulnerabilities[1] is test_vuln
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
        assert report.vulnerabilities[0] is test_vuln3
