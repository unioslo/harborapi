from harborapi.models.scanner import Severity, VulnerabilityItem


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
