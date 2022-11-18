from typing import List

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from harborapi.ext.artifact import ArtifactInfo
from harborapi.models.scanner import Severity, VulnerabilityItem
from harborapi.version import SemVer

from ..strategies.ext import artifact_info_strategy


@given(artifact_info_strategy)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_artifactinfo(
    artifact: ArtifactInfo,
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
    artifact.report.vulnerabilities = [vuln]

    assert artifact.has_cve("CVE-2022-test-1")
    assert artifact.has_description("test description")

    # Affected package (with and without version constraints)
    assert artifact.has_package("test-package")
    assert artifact.has_package("test-package", min_version=(1, 0, 0))
    assert artifact.has_package("test-package", max_version=(1, 0, 0))
    assert artifact.has_package("test-package", max_version=(1, 0, 1))
    assert not artifact.has_package("test-package", min_version=(1, 0, 1))
    assert not artifact.has_package("test-package", max_version=(0, 9, 1))

    # Different types of version constraints
    for version in [(1, 0, 0), "1.0.0", 1, SemVer(1, 0, 0)]:
        assert artifact.has_package("test-package", min_version=version)
        assert artifact.has_package(
            "test-package", min_version=version, max_version=version
        )

    # Invalid version constraint (min > max)
    with pytest.raises(ValueError):
        assert artifact.has_package(
            "test-package", max_version=(1, 0, 0), min_version=(1, 0, 1)
        )

    # CVE that doesn't exist
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
