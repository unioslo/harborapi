from typing import List

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from harborapi.ext.artifact import ArtifactInfo
from harborapi.models.models import Artifact, Repository
from harborapi.models.scanner import (
    HarborVulnerabilityReport,
    Severity,
    VulnerabilityItem,
)

from ..strategies.artifact import artifact_strategy, get_hbv_strategy


@given(artifact_strategy, st.builds(Repository, name=st.text()), get_hbv_strategy())
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_artifactinfo(
    art: Artifact,
    repository: Repository,
    report: HarborVulnerabilityReport,
) -> None:
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
    report.vulnerabilities = [vuln]

    artifact = ArtifactInfo(artifact=art, repository=repository, report=report)

    assert artifact.has_cve("CVE-2022-test-1")
    assert artifact.has_description("test description")
    assert artifact.has_package("test-package")
    assert not artifact.has_cve("CVE-2022-test-2")
    assert not artifact.has_description("test description 2")
    assert not artifact.has_package("test-package-2")

    vuln2 = vuln.copy(deep=True)
    vuln2.id = "CVE-2022-test-2"
    vuln2.description = None
    artifact.report.vulnerabilities.append(vuln2)

    assert artifact.vuln_by_cve("CVE-2022-test-1") == vuln
    assert list(artifact.vulns_with_package("test-package")) == [vuln, vuln2]
    assert list(artifact.vulns_with_description("test description")) == [vuln]
