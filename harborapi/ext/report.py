import re
from collections import Counter
from dataclasses import dataclass
from functools import cached_property
from typing import Iterable, List, Optional, Union

from harborapi.models.scanner import Severity, VulnerabilityItem

from ..models.base import BaseModel
from ..version import VersionType
from .api import ArtifactInfo
from .cve import CVSSData


@dataclass
class Vulnerability:
    vulnerability: VulnerabilityItem
    artifact: ArtifactInfo


@dataclass
class ArtifactCVSS:
    cvss: CVSSData
    artifact: ArtifactInfo

    @classmethod
    def from_artifactinfo_cvss(cls, artifact: ArtifactInfo):
        """Create a CVSSData instance from an ArtifactInfo."""
        return cls(
            cvss=artifact.cvss,
            artifact=artifact,
        )


def _remove_duplicate_artifacts(
    artifacts: List[ArtifactInfo],
) -> Iterable[ArtifactInfo]:
    """Remove duplicate artifacts from the list of artifacts, based on SHA256 digest."""
    seen = set()
    for a in artifacts:
        if a.artifact.digest not in seen:
            seen.add(a.artifact.digest)
            yield a


class ArtifactReport(BaseModel):
    """Aggregation of artifacts and their vulnerabilities."""

    artifacts: List[ArtifactInfo] = []

    def __init__(
        self,
        artifacts: Optional[List[ArtifactInfo]] = None,
        **kwargs,
    ) -> None:
        if artifacts is None:
            artifacts = []
        super().__init__(artifacts=artifacts, **kwargs)

    class Config:
        keep_untouched = (cached_property,)

    @classmethod
    def from_artifacts(cls, artifacts: Iterable[ArtifactInfo]) -> "ArtifactReport":
        """Create an ArtifactReport from an iterable of ArtifactInfo instances.
        Does not validate the artifacts for faster construction.

        !!! warning
            Only use this with artifacts that have already been validated,
            (e.g. from an existing ArtifactReport).

        Parameters
        ----------
        artifacts : Iterable[ArtifactInfo]
            The artifacts to include in the report.

        Returns
        -------
        ArtifactReport
            A report with the given artifacts.
        """
        return cls.construct(artifacts=artifacts)

    def __bool__(self) -> bool:
        return bool(self.artifacts)

    def __iter__(self) -> Iterable[ArtifactInfo]:
        return iter(self.artifacts)

    def __len__(self) -> int:
        return len(self.artifacts)

    @property
    def is_aggregate(self) -> bool:
        return len(self.artifacts) > 1

    @cached_property
    def cvss(self) -> CVSSData:
        """Get an aggregate of CVSS data for the artifacts in this report."""
        return CVSSData.from_report(self)

    # TODO: The methods that return Iterable[Vulnerability] are inconsistent
    # with the other methods that return ArtifactReport. We should probably
    # change them to return ArtifactReport or Iterable[ArtifactInfo],
    # or change their names to reflect that they return invididual vulnerabilities.

    @property
    def fixable(self) -> Iterable[Vulnerability]:
        """Get all fixable vulnerabilities."""
        for a in self.artifacts:
            for v in a.report.fixable:
                yield Vulnerability(v, a)

    @property
    def unfixable(self) -> Iterable[Vulnerability]:
        """Get all fixable vulnerabilities."""
        for a in self.artifacts:
            for v in a.report.unfixable:
                yield Vulnerability(v, a)

    @property
    def critical(self) -> Iterable[Vulnerability]:
        """Get all critical vulnerabilities.

        Yields
        ------
        Vulnerability
            A vulnerability with its artifact.
        """
        yield from self.vulnerabilities_by_severity(Severity.critical)

    @property
    def high(self) -> Iterable[Vulnerability]:
        """Get all high vulnerabilities.

        Yields
        ------
        Vulnerability
            A vulnerability with its artifact.
        """
        yield from self.vulnerabilities_by_severity(Severity.high)

    @property
    def medium(self) -> Iterable[Vulnerability]:
        """Get all medium vulnerabilities.

        Yields
        ------
        Vulnerability
            A vulnerability with its artifact.
        """
        yield from self.vulnerabilities_by_severity(Severity.medium)

    @property
    def low(self) -> Iterable[Vulnerability]:
        """Get all low vulnerabilities.

        Yields
        ------
        Vulnerability
            A vulnerability with its artifact.
        """
        yield from self.vulnerabilities_by_severity(Severity.low)

    @property
    def distribution(self) -> "Counter[Severity]":
        """Get the distribution of severities from the vulnerabilities of all artifacts.

        Example
        -------
        ```py
        >>> report.distribution
        Counter({Severity.high: 2, Severity.medium: 1})
        ```

        Returns
        -------
        Counter[Severity]
            A counter of the severities.
        """
        dist = Counter()  # type: Counter[Severity]
        for artifact in self.artifacts:
            a_dist = artifact.report.distribution
            dist.update(a_dist)
        return dist

    def vulnerabilities_by_severity(
        self, severity: Severity
    ) -> Iterable[Vulnerability]:
        for a in self.artifacts:
            for v in a.report.vulnerabilities_by_severity(severity):
                yield Vulnerability(v, a)

    def has_cve(self, cve_id: str) -> bool:
        """Check if any of the artifacts has the given CVE.

        Parameters
        ----------
        cve_id : str
            The CVE ID, e.g. CVE-2019-1234.

        Returns
        -------
        bool
            True if any of the artifacts has the given CVE, False otherwise.
        """
        return any(a.has_cve(cve_id) for a in self.artifacts)

    def with_cve(self, cve_id: str) -> "ArtifactReport":
        """Get all artifacts that have the given CVE.

        Parameters
        ----------
        cve_id : str
            The CVE ID, e.g. CVE-2019-1234.

        Returns
        -------
        ArtifactReport
            A report with all artifacts that are affected by the given CVE.
        """
        return ArtifactReport.from_artifacts(
            [a for a in self.artifacts if a.has_cve(cve_id)]
        )

    def has_description(self, description: str, case_sensitive: bool = False) -> bool:
        """Check if any of the artifacts have a vulnerability with a description
        that contains the given string.

        Parameters
        ----------
        description : str
            The description to search for.
        case_sensitive : bool
            Whether the search should be case sensitive, by default False.

        Returns
        -------
        bool
            True if any of the artifacts has the given description, False otherwise.
        """
        return any(
            a.has_description(description, case_sensitive=case_sensitive)
            for a in self.artifacts
        )

    def with_description(
        self, description: str, case_sensitive: bool = False
    ) -> "ArtifactReport":
        """Get all artifacts that have a vulnerability containing the given string.

        Parameters
        ----------
        description : str
            The string to search for in vulnerability descriptions.
        case_sensitive : bool
            Case sensitive matching

        Returns
        -------
        ArtifactReport
            A report with all artifacts that have a vulnerability containing the given
            string.
        """
        return ArtifactReport.from_artifacts(
            [
                a
                for a in self.artifacts
                if a.has_description(description, case_sensitive)
            ]
        )

    def has_package(
        self,
        package: str,
        case_sensitive: bool = False,
        min_version: Optional[VersionType] = None,
        max_version: Optional[VersionType] = None,
    ) -> bool:
        """Check if any of the artifacts has the given package.

        Parameters
        ----------
        package : str
            The package name to search for.
        case_sensitive : bool
            Whether the search should be case sensitive, by default False.
        min_version : Optional[VersionType]
            The minimum version of the package to search for, by default None.
        max_version : Optional[VersionType]
            The maximum version of the package to search for, by default None.

        Returns
        -------
        bool
            True if any of the artifacts has the given package, False otherwise.
        """
        return any(
            a.has_package(
                package,
                case_sensitive=case_sensitive,
                min_version=min_version,
                max_version=max_version,
            )
            for a in self.artifacts
        )

    def with_package(
        self,
        package: str,
        case_sensitive: bool = False,
        min_version: Optional[VersionType] = None,
        max_version: Optional[VersionType] = None,
    ) -> "ArtifactReport":
        """Get all artifacts that have a vulnerability affecting the given package.

        Parameters
        ----------
        package : str
            The name of the package to search for.
            Supports regular expressions.
        case_sensitive : bool
            Case sensitive matching
        min_version : Optional[VersionType]
            The minimum version of the package to search for, by default None.
        max_version : Optional[VersionType]
            The maximum version of the package to search for, by default None.

        Returns
        -------
        ArtifactReport
            An artifact report with all artifacts that have a vulnerability affecting
            the given package.
        """
        return ArtifactReport.from_artifacts(
            [
                a
                for a in self.artifacts
                if a.has_package(
                    package,
                    case_sensitive,
                    min_version=min_version,
                    max_version=max_version,
                )
            ],
        )

    def has_severity(self, severity: Severity) -> bool:
        """Check if any of the artifacts has a vulnerability with the given severity.

        Parameters
        ----------
        severity : Severity
            The severity to search for.

        Returns
        -------
        bool
            True if any of the artifacts has the given severity, False otherwise.
        """
        return bool(self.with_severity(severity).artifacts)

    def with_severity(self, severity: Severity) -> "ArtifactReport":
        """Get all artifacts that have a report with the given severity.

        Parameters
        ----------
        severity : Severity
            The severity to search for.

        Returns
        -------
        ArtifactReport
            An artifact report with all artifacts that have a vulnerability with the
            given severity.
        """
        return ArtifactReport.from_artifacts(
            [a for a in self.artifacts if a.report.severity == severity]
        )

    def has_repository(self, repository: str, case_sensitive: bool = False) -> bool:
        """Check if any of the artifacts belong to the given repository.

        Parameters
        ----------
        repository : str
            The repository name to search for.
            Supports regular expressons.
        case_sensitive : bool, optional
            Case sensitive search, by default False

        Returns
        -------
        bool
            Whether any of the artifacts belong to the given repository.
        """
        return bool(self.with_repository(repository, case_sensitive).artifacts)

    def with_repository(
        self, repositories: Union[str, List[str]], case_sensitive: bool = False
    ) -> "ArtifactReport":
        """Return a new report with all artifacts belonging to one or more repositories.

        Parameters
        ----------
        repositories : Union[str, List[str]]
            A repository or a list of repositories to filter for.
            Supports regular expressions.
        case_sensitive : bool
            Case sensitive repository name matching, by default False

        Returns
        -------
        ArtifactReport
            A new ArtifactReport where all artifacts belong to one of the given
            repositories.
        """
        # Docker doesn't allow upper-case letters in repository names, but
        # I could not find any documentation on whether Harbor allows it.
        # So we'll just assume that it does. Worst case scenario, the `case_sensitive`
        # parameter will be redundant, but that's fine just to ensure compatibility.

        if isinstance(repositories, str):
            repositories = [repositories]
        elif not isinstance(repositories, list) or not all(
            isinstance(r, str) for r in repositories
        ):
            raise TypeError(
                "repositories must be either a string or a list of strings"
            )  # pragma: no cover

        # Make regex pattern for each repository
        # Our cache function only accepts string arguments, but it's fine to not
        # use it here, since this method is not called nearly as often as the underlying
        # `has_*` methods on the ArtifactInfo objects.
        pattern = re.compile(
            "|".join(repositories), flags=re.IGNORECASE if not case_sensitive else 0
        )
        return ArtifactReport.from_artifacts(
            [a for a in self.artifacts if pattern.match(a.repository.name)]
        )

    def has_tag(self, tag: str) -> bool:
        """Check if any of the artifacts has the given tag.

        Parameters
        ----------
        tag : str
            The tag to search for.

        Returns
        -------
        bool
            True if any of the artifacts has the given tag, False otherwise.
        """
        return any(a.has_tag(tag) for a in self.artifacts)

    def with_tag(self, tag: str) -> "ArtifactReport":
        """Return a new report with all artifacts having the given tag.

        Parameters
        ----------
        tag : str
            The tag to filter for.

        Returns
        -------
        ArtifactReport
            A new ArtifactReport where all artifacts have the given tag.
        """
        return ArtifactReport.from_artifacts(
            [a for a in self.artifacts if a.has_tag(tag)]
        )


# TODO: add test to ensure parity with HarborVulnerabilityReport
