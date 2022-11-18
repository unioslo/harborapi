from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from harborapi.ext.report import ArtifactReport
from harborapi.models.scanner import Severity, VulnerabilityItem

from ..strategies.ext import artifact_report_strategy


@given(artifact_report_strategy)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_artifactreport(
    report: ArtifactReport,
) -> None:
    # make sure test is deterministic
    assume(len(report.artifacts) > 0)
    vuln = VulnerabilityItem(
        id="CVE-2022-test-1",
        package="test-package",
        version="1.0.0",
        fix_version="1.0.1",
        severity=Severity.high,
        description="test description",
        links=[
            "https://www.test.com",
            "https://www.test2.com",
        ],
    )
    for artifact in report.artifacts:
        artifact.report.vulnerabilities = [vuln]

    assert report.has_cve("CVE-2022-test-1")
    assert report.has_description("test description")
    assert report.has_package("test-package")
    assert report.has_package("test-package", min_version=(1, 0, 0))
    assert report.has_package("test-package", max_version=(1, 0, 0))
    assert report.has_package("test-package", max_version=(1, 0, 1))

    # Filtering by package
    assert len(report.with_package("test-package").artifacts) == len(report.artifacts)

    # test chaining
    assert len(
        report.with_cve("CVE-2022-test-1")
        .with_package("test-package")
        .with_description("test description")
        .artifacts
    ) == len(report.artifacts)

    # test filtering by severity
