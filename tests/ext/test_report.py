import copy

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from harborapi.ext.report import ArtifactReport
from harborapi.models.scanner import Severity, VulnerabilityItem

from ..strategies.ext import artifact_report_strategy

# TODO: add fixture that initializes the report with the data we do in the test below
#       Afterwards, we can split up the tests and use the fixture to initialize the report
#       so that we can test each method separately, instead of in one massive function.


@given(artifact_report_strategy)
@settings(
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow]
)
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
        assert len(artifact.artifact.tags) > 0  # our strategy should ensure this
        artifact.artifact.tags[0].name = "latest-test"

    assert report.has_tag("latest-test")
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
        .with_tag("latest-test")
        .artifacts
    ) == len(report.artifacts)

    # Make sure we have more than 1 artifact
    # Use deep copy to ensure the artifacts are different objects
    report.artifacts.extend(copy.deepcopy(report.artifacts))
    assert report.is_aggregate
    assert len(report.artifacts) > 1

    # Test CVSS (with trivy vendor attributes)
    # TODO: add other scanners
    for artifact in report.artifacts:
        artifact.report.scanner = "Trivy"
        for vulnerability in artifact.report.vulnerabilities:
            vulnerability.vendor_attributes = {
                "CVSS": {
                    "nvd": {"V3Score": 5.0, "V2Score": 5.0},
                    "redhat": {"V3Score": 5.0, "V2Score": 5.0},
                }
            }
    assert report.cvss.max == 5.0
    assert report.cvss.min == 5.0
    assert report.cvss.median == 5.0
    assert report.cvss.mean == 5.0
    assert report.cvss.stdev == 0.0

    # Get fixable/unfixable vulnerabilities
    for is_fixable in [True, False]:
        for artifact in report.artifacts:
            for vulnerability in artifact.report.vulnerabilities:
                if is_fixable:
                    vulnerability.fix_version = "1.0.1"
                else:
                    vulnerability.fix_version = None
                fixable = [v.vulnerability for v in report.fixable]
                unfixable = [v.vulnerability for v in report.unfixable]
                if is_fixable:
                    assert vulnerability in fixable
                    assert vulnerability not in unfixable
                else:
                    assert vulnerability not in fixable
                    assert vulnerability in unfixable

    # Test filtering by severity (+ show distribution)
    n_vulnerabilities = sum(len(a.report.vulnerabilities) for a in report.artifacts)
    for severity in Severity:
        if not report.artifacts:
            break
        for i, artifact in enumerate(report.artifacts):
            # Set the report and its vulnerabilities to the given severity
            artifact.report.severity = severity
            for vulnerability in artifact.report.vulnerabilities:
                vulnerability.severity = severity
            artifact.artifact.digest = f"{artifact.artifact.digest}-{i}-{severity}"
        assert len(report.with_severity(severity).artifacts) == len(report.artifacts)
        assert report.has_severity(severity)
        # Test that the distribution is correct
        # NOTE: report.distribution operates on vulnerabilities, not ArtifactInfo objects,
        # which is inconsistent with the other methods. This should be renamed, and
        # the method should be changed to operate on ArtifactInfo objects.
        assert report.distribution[severity] == n_vulnerabilities

    # Iteration
    for i, artifact in enumerate(report):
        assert artifact == report.artifacts[i]
    assert len(report) == len(report.artifacts)

    # Test constructing from a list of ArtifactInfo objects
    report2 = ArtifactReport.from_artifacts(report.artifacts)
    assert report2.artifacts == report.artifacts


@given(artifact_report_strategy)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_artifactreport_with_repository(
    report: ArtifactReport,
) -> None:
    assume(len(report.artifacts) > 0)
    # It's unlikely hypothesis will generate the name "Test-Repo-1", but to ensure our test
    # isn't flaky because of an assumption, we should set the names of _all_
    # repositories every time.

    N_ARTIFACTS = 10
    report.artifacts = [copy.deepcopy(report.artifacts[0]) for i in range(N_ARTIFACTS)]
    for i, artifact in enumerate(report.artifacts):
        artifact.repository.name = "Test-Repo-1"
        artifact.artifact.digest = f"{artifact.artifact.digest}-{i}"

    assert report.has_repository("Test-Repo-1", case_sensitive=True)
    assert report.has_repository("Test-Repo-1", case_sensitive=False)
    assert report.has_repository("test-repo-1", case_sensitive=False)
    assert not report.has_repository("test-repo-1", case_sensitive=True)

    assert len(
        report.with_repository("Test-Repo-1", case_sensitive=True).artifacts
    ) == len(report.artifacts)
    assert len(
        report.with_repository("Test-Repo-1", case_sensitive=False).artifacts
    ) == len(report.artifacts)
    assert len(
        report.with_repository("test-repo-1", case_sensitive=False).artifacts
    ) == len(report.artifacts)
    assert (
        len(report.with_repository("test-repo-1", case_sensitive=True).artifacts) == 0
    )

    # Artifacts with different repos
    report.artifacts[0].repository.name = "Test-Repo-2"
    assert report.has_repository("Test-Repo-2", case_sensitive=True)
    assert report.has_repository("Test-Repo-2", case_sensitive=False)
    assert report.has_repository("test-repo-2", case_sensitive=False)
    assert not report.has_repository("test-repo-2", case_sensitive=True)

    assert (
        len(report.with_repository("Test-Repo-1", case_sensitive=True).artifacts)
        == len(report.artifacts) - 1
    )
    assert (
        len(report.with_repository("Test-Repo-1", case_sensitive=False).artifacts)
        == len(report.artifacts) - 1
    )
    assert (
        len(report.with_repository("Test-Repo-2", case_sensitive=True).artifacts) == 1
    )
    assert (
        len(report.with_repository("Test-Repo-2", case_sensitive=False).artifacts) == 1
    )

    # Match multiple repos
    assert len(
        report.with_repository(
            ["Test-Repo-1", "Test-Repo-2"], case_sensitive=True
        ).artifacts
    ) == len(report.artifacts)
    assert len(
        report.with_repository(
            ["Test-Repo-1", "Test-Repo-2"], case_sensitive=False
        ).artifacts
    ) == len(report.artifacts)
    assert (
        len(
            report.with_repository(
                ["test-repo-1", "test-repo-2"], case_sensitive=True
            ).artifacts
        )
        == 0
    )
    assert len(
        report.with_repository(
            ["test-repo-1", "test-repo-2"], case_sensitive=False
        ).artifacts
    ) == len(report.artifacts)

    # regex
    assert len(
        report.with_repository("test-repo-.*", case_sensitive=False).artifacts
    ) == len(report.artifacts)
    assert (
        len(report.with_repository("test-repo-.*", case_sensitive=True).artifacts) == 0
    )
    # TODO: more extensive regex tests
