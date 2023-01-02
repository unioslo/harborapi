import re
from functools import cached_property
from typing import TYPE_CHECKING, Callable, Iterable, List, Optional

from ..version import VersionType, get_semver

if TYPE_CHECKING:
    from typing import Dict

from ..models import Artifact, Repository
from ..models.base import BaseModel
from ..models.scanner import HarborVulnerabilityReport, VulnerabilityItem
from .cve import CVSSData
from .regex import get_pattern, match


class ArtifactInfo(BaseModel):
    """Class composed of models returned by the Harbor API
    that gives information about an artifact."""

    artifact: Artifact
    repository: Repository
    report: HarborVulnerabilityReport = HarborVulnerabilityReport()  # type: ignore # why complain?
    # NOTE: add Project?

    class Config:
        keep_untouched = (cached_property,)

    @property
    def __rich_panel_title__(self) -> str:
        return self.name_with_digest

    @cached_property
    def cvss(self) -> CVSSData:
        """Key CVSS metrics for the artifact.

        Returns
        -------
        CVSSData
            Key CVSS metrics for the artifact.
        """
        return CVSSData.from_artifactinfo(self)

    @cached_property
    def cvss_max(self) -> float:
        """Maximum CVSS score of all vulnerabilities affecting the artifact.

        Returns
        -------
        float
            Maximum CVSS score of all vulnerabilities affecting the artifact.
        """
        return max(self.report.cvss_scores, default=0.0)

    @property
    def name_with_digest(self) -> str:

        """The name of the artifact as denoted by its digest.

        Returns
        -------
        str
            The artifact's name in the form of `repository@digest`.
        """
        # The digest should always exist, but just in case:
        digest = self.artifact.digest
        if digest:
            digest = digest[:15]  # mimic harbor digest notation
        return f"{self.repository.name}@{digest}"

    @property
    def name_with_tag(self) -> str:
        """The name of the artifact as denoted by its primary tag.

        Returns
        -------
        str
            The artifact's name in the form of `repository:tag`.
        """
        tag = None
        if self.artifact.tags:
            tag = self.artifact.tags[0].name
        if not tag:
            tag = "untagged"
        return f"{self.repository.name}:{tag}"

    @property
    def project_name(self) -> str:
        """The name of the project that the artifact belongs to.

        Returns
        -------
        str
            The name of the project that the artifact belongs to.
        """
        return self.repository.project_name

    @property
    def repository_name(self) -> str:
        """The name of the repository that the artifact belongs to.

        Returns
        -------
        str
            The name of the repository that the artifact belongs to.
        """
        return self.repository.base_name

    @property
    def tags(self) -> str:
        """The tags of the artifact.

        Returns
        -------
        str
            The tags of the artifact.
        """
        if not self.artifact.tags:
            return ""
        return ", ".join(filter(None, (t.name for t in self.artifact.tags)))

    def has_cve(self, cve_id: str) -> bool:
        """Returns whether the artifact is affected by the given CVE ID.

        Parameters
        ----------
        cve_id : str
            The CVE ID, e.g. CVE-2019-1234.

        Returns
        -------
        bool
            Whether the artifact is affected by the given CVE ID.
        """
        return self.vuln_with_cve(cve_id) is not None

    def has_description(self, description: str, case_sensitive: bool = False) -> bool:
        """Returns whether the artifact is affected by a vulnerability whose description
        contains the given string.

        Parameters
        ----------
        description : str
            The string to search for in vulnerability descriptions.
        case_sensitive : bool
            Case sensitive matching

        Returns
        -------
        bool
            Whether the artifact is affected by a vulnerability whose description
            contains the given string.
        """
        for vuln in self.vulns_with_description(description, case_sensitive):
            return True
        return False

    def has_package(
        self,
        package: str,
        case_sensitive: bool = False,
        min_version: Optional[VersionType] = None,
        max_version: Optional[VersionType] = None,
    ) -> bool:
        """Returns whether the artifact is affected by a vulnerability whose affected
        package matches the given string.

        Parameters
        ----------
        package : str
            The name of the package to search for.
        case_sensitive : bool
            Case sensitive matching
        min_version : Optional[VersionType]
            Minimum version of the package to match
        max_version : Optional[VersionType]
            Maximum version of the package to match

        Returns
        -------
        bool
            Whether the artifact is affected by a vulnerability whose affected
            package matches the given string.
        """
        minv = get_semver(min_version)
        maxv = get_semver(max_version)
        if maxv and minv:
            if maxv < minv:
                raise ValueError(
                    "max_version must be greater than or equal to min_version"
                )

        for vuln in self.vulns_with_package(package, case_sensitive):
            if not vuln.semver:
                continue
            if min_version is not None and vuln.semver < minv:
                continue
            if max_version is not None and vuln.semver > maxv:
                continue
            return True
        return False

    def has_tag(self, tag: str) -> bool:
        """Returns whether the artifact has the given tag.

        Parameters
        ----------
        tag : str
            The tag to search for.

        Returns
        -------
        bool
            Whether the artifact has the given tag.
        """
        if not self.artifact.tags:
            return False
        pattern = get_pattern(tag)
        for t in self.artifact.tags:
            if t.name is None:
                continue
            if match(pattern, t.name):
                return True
        return False

    def vuln_with_cve(self, cve: str) -> Optional[VulnerabilityItem]:
        """Returns the vulnerability with the specified CVE ID if the artifact is
        affected by it.

        To just check if the artifact is affected by a given CVE, use [`has_cve()`][harborapi.ext.artifact.ArtifactInfo.has_cve].

        Parameters
        ----------
        cve : str
            The CVE ID of the vulnerability to return.
            Supports regular expressions.

        Returns
        -------
        Optional[VulnerabilityItem]
            The vulnerability with the specified CVE ID if it exists, otherwise `None`.
        """
        pattern = get_pattern(cve, case_sensitive=False)
        for vuln in self.report.vulnerabilities:
            if vuln.id is None:
                continue
            # Prioritize exact matches (inefficient? Add regex param?)
            if vuln.id == cve or match(pattern, vuln.id):
                return vuln
        return None

    def vulns_with_package(
        self, package: str, case_sensitive: bool = False
    ) -> Iterable[VulnerabilityItem]:
        """Generator of all vulnerabilities whose affected package name contains the given string.

        Parameters
        ----------
        package : str
            The name of the affected package to search for.
            Supports regular expressions.
        case_sensitive : bool, optional
            Case sensitive search, by default False

        Yields
        ------
        VulnerabilityItem
            Vulnerability that affects the given package.
        """
        pattern = get_pattern(package, case_sensitive=case_sensitive)
        for vuln in self.report.vulnerabilities:
            # Can't compare with None
            if vuln.package is None:
                continue
            if pattern.match(vuln.package):
                yield vuln

    def vulns_with_description(
        self, description: str, case_sensitive: bool = False
    ) -> Iterable[VulnerabilityItem]:
        """Generator of all vulnerabilities whose description contains the given string.
        Optionally, the comparison can be case sensitive.

        Parameters
        ----------
        description : str
            The string to search for in the vulnerability descriptions.
            Supports regular expressions.
        case_sensitive : Optional[bool]
            Case sensitive comparison, by default False

        Yields
        ------
        VulnerabilityItem
            A vulnerability whose description contains the given string.
        """
        pattern = get_pattern(description, case_sensitive=case_sensitive)
        for vuln in self.report.vulnerabilities:
            # Can't compare with None
            if vuln.description is None:
                continue
            if match(pattern, vuln.description):
                yield vuln


async def filter_artifacts_latest(
    artifacts: List[ArtifactInfo],
    fallback: Optional[Callable[[ArtifactInfo, ArtifactInfo], ArtifactInfo]] = None,
) -> List[ArtifactInfo]:
    """Get the latest version of all artifacts from a list of ArtifactInfo objects.

    Optionally takes a comparison function to fall back on if the push time of two artifacts
    are the same, or if one of the artifacts being compared doesn't have a push time.

    Example
    -------
    ```py
    # Our comparison function used to determine which artifact is the latest
    # (don't actually compare digests, use a better heuristic for your use case)
    def compare_artifacts(latest_artifact, other_artifact):
        # we know they have no push_time, so we compare digests
        if latest_artifact.artifact.digest and other_artifact.artifact.digest:
            return latest_artifact if latest_artifact.artifact.digest > other_artifact.artifact.digest else other_artifact
        return latest_artifact # fallback if no digest

    artifacts = await get_artifacts(client)
    latest_artifacts = filter_artifacts_latest(artifacts, compare_artifacts)
    ```

    Parameters
    ----------
    artifacts : List[ArtifactInfo]
        The list of artifacts to filter.
    fallback : Optional[Callable[[ArtifactInfo, ArtifactInfo], ArtifactInfo]]
        Optional comparison function to use if one of the artifacts has no `push_time`.
        The function should take two ArtifactInfo objects `(latest_artifact, other_artifact)`
        and return the one deemed to be the latest.
        If not specified, artifacts without `push_time` are ignored.

    Returns
    -------
    List[ArtifactInfo]
        A list of ArtifactInfo objects, with the latest artifact for each repository.
    """

    art = {}  # type: Dict[str, ArtifactInfo]
    for a in artifacts:
        # should never happen, but spec says this can be None
        if not a.repository.name:
            continue

        newest = art.get(a.repository.name)

        # if no newest, set first as newest
        if not newest:
            art[a.repository.name] = a
            continue

        # if one of the artifacts does not have a push time or the two artifacts
        # have the same push time, fall back on comparison function or skip it
        #
        # FIXME: problematic if art[a.repository.name] has no push time (????)
        if (
            not a.artifact.push_time
            or not newest.artifact.push_time
            or a.artifact.push_time == newest.artifact.push_time
        ):
            # use fallback comparison function if provided, otherwise skip
            if fallback is not None:
                art[a.repository.name] = fallback(newest, a)
            continue

        # compare push times, pick most recent
        if a.artifact.push_time > newest.artifact.push_time:
            art[a.repository.name] = a
            continue

    return list(art.values())
