from typing import TYPE_CHECKING, Callable, Generator, Iterable, List, Optional

if TYPE_CHECKING:
    from typing import Dict

from pydantic import BaseModel

from ..models import Artifact, Repository
from ..models.scanner import HarborVulnerabilityReport, VulnerabilityItem


class ArtifactInfo(BaseModel):
    """Class composed of models returned by the Harbor API
    that gives information about an artifact."""

    artifact: Artifact
    repository: Repository
    report: HarborVulnerabilityReport = HarborVulnerabilityReport()  # type: ignore # why complain?
    # NOTE: add Project?

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
        return f"{self.repository.name}@{self.artifact.digest}"

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

    def has_cve(self, cve_id: str) -> bool:
        return self.vuln_by_cve(cve_id) is not None

    def has_description(self, description: str, case_sensitive: bool = False) -> bool:
        for vuln in self.vulns_with_description(description, case_sensitive):
            return True
        return False

    def has_package(self, package: str, case_sensitive: bool = False) -> bool:
        for vuln in self.vulns_with_package(package, case_sensitive):
            return True
        return False

    def vuln_by_cve(self, cve: str) -> Optional[VulnerabilityItem]:
        """Returns the vulnerability with the specified CVE ID if it exists.

        Parameters
        ----------
        cve : str
            The CVE ID of the vulnerability to return.

        Returns
        -------
        Optional[VulnerabilityItem]
            The vulnerability with the specified CVE ID if it exists, otherwise `None`.
        """
        for vuln in self.report.vulnerabilities:
            if vuln.id == cve:
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
        case_sensitive : bool, optional
            Case sensitive search, by default False

        Yields
        ------
        VulnerabilityItem
            Vulnerability that affects the given package.
        """
        for vuln in self.report.vulnerabilities:
            # Can't compare with None
            if vuln.package is None:
                continue

            # Case insensitive comparison
            vuln_package = vuln.package
            if not case_sensitive:
                package = package.lower()
                vuln_package = vuln_package.lower()

            if vuln_package == package:
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
        case_sensitive : Optional[bool]
            Case sensitive comparison, by default False

        Yields
        ------
        VulnerabilityItem
            A vulnerability whose description contains the given string.
        """
        for vuln in self.report.vulnerabilities:
            # Can't compare with None
            if vuln.description is None:
                continue

            # Case insensitive comparison
            vuln_description = vuln.description
            if not case_sensitive:
                description = description.lower()
                vuln_description = vuln_description.lower()

            if description in vuln_description:
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
