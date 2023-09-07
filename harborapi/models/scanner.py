from __future__ import annotations

import functools
from collections import Counter
from datetime import datetime
from enum import Enum
from functools import cached_property
from typing import Any
from typing import Dict
from typing import Final
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union

from pydantic import AnyUrl
from pydantic import ConfigDict
from pydantic import Field
from pydantic import field_validator
from pydantic import FieldValidationInfo
from pydantic import RootModel

from ..log import logger
from ..version import get_semver
from ..version import SemVer
from .base import BaseModel


class Scanner(BaseModel):
    """
    Basic scanner properties such as name, vendor, and version.

    """

    name: Optional[str] = Field(
        None, description="The name of the scanner.", example="Trivy"
    )
    vendor: Optional[str] = Field(
        None, description="The name of the scanner's provider.", example="Aqua Security"
    )
    version: Optional[str] = Field(
        None, description="The version of the scanner.", example="0.4.0"
    )

    @property
    def semver(self) -> SemVer:
        return get_semver(self.version)


class ScannerProperties(RootModel[Optional[Dict[str, str]]]):
    """
    A set of custom properties that can further describe capabilities of a given scanner.

    """

    root: Optional[Dict[str, str]] = None


class ScannerCapability(BaseModel):
    """
    Capability consists of the set of recognized artifact MIME types and the set of scanner report MIME types.
    For example, a scanner capable of analyzing Docker images and producing a vulnerabilities report recognizable
    by Harbor web console might be represented with the following capability:
    - consumes MIME types:
      - `application/vnd.oci.image.manifest.v1+json`
      - `application/vnd.docker.distribution.manifest.v2+json`
    - produces MIME types:
      - `application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0`

    """

    consumes_mime_types: List[str] = Field(
        ...,
        description='The set of MIME types of the artifacts supported by the scanner to produce the reports specified in the "produces_mime_types". A given\nmime type should only be present in one capability item.\n',
        example=[
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ],
    )
    produces_mime_types: List[str] = Field(
        ...,
        description="The set of MIME types of reports generated by the scanner for the consumes_mime_types of the same capability record.\n",
        example=[
            "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
        ],
    )


class ScanRequestId(RootModel[str]):
    root: str = Field(
        ...,
        description="A unique identifier returned by the [/scan](#/operation/AcceptScanRequest] operations. The format of the\nidentifier is not imposed but it should be unique enough to prevent collisons when polling for scan reports.\n",
        example="3fa85f64-5717-4562-b3fc-2c963f66afa6",
    )


class Registry(BaseModel):
    url: Optional[str] = Field(
        None,
        description="A base URL or the Docker Registry v2 API.",
        example="https://core.harbor.domain",
    )
    authorization: Optional[str] = Field(
        None,
        description="An optional value of the HTTP Authorization header sent with each request to the Docker Registry v2 API.\nIt's used to exchange Base64 encoded robot account credentials to a short lived JWT access token which\nallows the underlying scanner to pull the artifact from the Docker Registry.\n",
        example="Basic BASE64_ENCODED_CREDENTIALS",
    )


class Artifact(BaseModel):
    repository: Optional[str] = Field(
        None,
        description="The name of the Docker Registry repository containing the artifact.",
        example="library/mongo",
    )
    digest: Optional[str] = Field(
        None,
        description="The artifact's digest, consisting of an algorithm and hex portion.",
        example="sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b",
    )
    tag: Optional[str] = Field(
        None, description="The artifact's tag", example="3.14-xenial"
    )
    mime_type: Optional[str] = Field(
        None,
        description="The MIME type of the artifact.",
        example="application/vnd.docker.distribution.manifest.v2+json",
    )


class Severity(Enum):
    """
    A standard scale for measuring the severity of a vulnerability.

    * `Unknown` - either a security problem that has not been assigned to a priority yet or a priority that the
      scanner did not recognize.
    * `Negligible` - technically a security problem, but is only theoretical in nature, requires a very special
      situation, has almost no install base, or does no real damage.
    * `Low` - a security problem, but is hard to exploit due to environment, requires a user-assisted attack,
      a small install base, or does very little damage.
    * `Medium` - a real security problem, and is exploitable for many people. Includes network daemon denial of
      service attacks, cross-site scripting, and gaining user privileges.
    * `High` - a real problem, exploitable for many people in a default installation. Includes serious remote denial
      of service, local root privilege escalations, or data loss.
    * `Critical` - a world-burning problem, exploitable for nearly all people in a default installation. Includes
      remote root privilege escalations, or massive data loss.

    """

    unknown = "Unknown"
    negligible = "Negligible"
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"
    none = "None"

    def __gt__(self, other: Severity) -> bool:
        return SEVERITY_PRIORITY[self] > SEVERITY_PRIORITY[other]

    def __ge__(self, other: Severity) -> bool:
        return SEVERITY_PRIORITY[self] >= SEVERITY_PRIORITY[other]

    def __lt__(self, other: Severity) -> bool:
        return SEVERITY_PRIORITY[self] < SEVERITY_PRIORITY[other]

    def __le__(self, other: Severity) -> bool:
        return SEVERITY_PRIORITY[self] <= SEVERITY_PRIORITY[other]


class Error(BaseModel):
    message: Optional[str] = Field(None, example="Some unexpected error")


class CVSSDetails(BaseModel):
    score_v3: Optional[float] = Field(
        None, description="The CVSS 3.0 score for the vulnerability.\n", example=3.2
    )
    score_v2: Optional[float] = Field(
        None, description="The CVSS 2.0 score for the vulnerability.\n"
    )
    vector_v3: Optional[str] = Field(
        None,
        description="The CVSS 3.0 vector for the vulnerability. \n",
        example="CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    )
    vector_v2: Optional[str] = Field(
        None,
        description="The CVSS 2.0 vector for the vulnerability. The string is of the form AV:L/AC:M/Au:N/C:P/I:N/A:N\n",
        example="AV:N/AC:L/Au:N/C:N/I:N/A:P",
    )


class ScannerAdapterMetadata(BaseModel):
    """
    Represents metadata of a Scanner Adapter which allows Harbor to lookup a scanner capable
    of scanning a given Artifact stored in its registry and making sure that it
    can interpret a returned result.

    """

    scanner: Scanner
    capabilities: List[ScannerCapability]
    properties: Optional[ScannerProperties] = None


class ScanRequest(BaseModel):
    registry: Registry
    artifact: Artifact


class ScanResponse(BaseModel):
    id: ScanRequestId


class VulnerabilityItem(BaseModel):
    id: Optional[str] = Field(
        None,
        description="The unique identifier of the vulnerability.",
        example="CVE-2017-8283",
    )
    package: Optional[str] = Field(
        None,
        description="An operating system package containing the vulnerability.\n",
        example="dpkg",
    )
    version: Optional[str] = Field(
        None,
        description="The version of the package containing the vulnerability.\n",
        example="1.17.27",
    )
    fix_version: Optional[str] = Field(
        None,
        description="The version of the package containing the fix if available.\n",
        example="1.18.0",
    )
    severity: Severity = Field(
        Severity.unknown,
        description="The severity of the vulnerability.",
        example=Severity.high.value,
    )
    description: Optional[str] = Field(
        None,
        description="The detailed description of the vulnerability.\n",
        example="dpkg-source in dpkg 1.3.0 through 1.18.23 is able to use a non-GNU patch program\nand does not offer a protection mechanism for blank-indented diff hunks, which\nallows remote attackers to conduct directory traversal attacks via a crafted\nDebian source package, as demonstrated by using of dpkg-source on NetBSD.\n",
    )
    links: Optional[List[AnyUrl]] = Field(
        None,
        description="The list of links to the upstream databases with the full description of the vulnerability.\n",
        example=["https://security-tracker.debian.org/tracker/CVE-2017-8283"],
    )
    preferred_cvss: Optional[CVSSDetails] = None
    cwe_ids: Optional[List[str]] = Field(
        None,
        description="The Common Weakness Enumeration Identifiers associated with this vulnerability.\n",
        example=["CWE-476"],
    )
    vendor_attributes: Optional[Dict[str, Any]] = None

    @field_validator("severity", mode="before")
    @classmethod
    def _severity_none_is_default(
        cls, v: Optional[Severity], info: FieldValidationInfo
    ) -> Severity:
        return v or cls.model_fields[info.field_name].default

    @property
    def semver(self) -> SemVer:
        return get_semver(self.version)

    @property
    def fixable(self) -> bool:
        return bool(self.fix_version)

    def get_cvss_score(
        self,
        scanner: Union[Optional[Scanner], str] = "Trivy",
        version: int = 3,
        vendor_priority: Optional[Iterable[str]] = None,
        default: float = 0.0,
    ) -> float:
        """The default scanner Trivy, as of version 0.29.1, does not use the
        preferred_cvss field.

        In order to not tightly couple this method with a specific scanner,
        we use the scanner name to determinehow to retrieve the CVSS score.

        Forward compatibility is in place in the event that Trivy starts
        conforming to the spec.
        """
        if vendor_priority is None:
            vendor_priority = DEFAULT_VENDORS
        if self.preferred_cvss is not None:
            if version == 3 and self.preferred_cvss.score_v3 is not None:
                return self.preferred_cvss.score_v3
            elif version == 2 and self.preferred_cvss.score_v2 is not None:
                return self.preferred_cvss.score_v2
        if not scanner:
            return default
        if isinstance(scanner, str):
            scanner_name = scanner
        elif isinstance(scanner, Scanner):
            scanner_name = scanner.name or ""
        if scanner_name.lower() == "trivy":
            return self._get_trivy_cvss_score(
                version=version, vendor_priority=vendor_priority, default=default
            )
        return default

    def _get_trivy_cvss_score(
        self, version: int, vendor_priority: Iterable[str], default: float = 0.0
    ) -> float:
        if self.vendor_attributes is None:
            return default
        cvss_data = self.vendor_attributes.get("CVSS", {})
        if not cvss_data:
            return default
        for prio in vendor_priority:
            vendor_cvss = cvss_data.get(prio, {})
            if not vendor_cvss:
                continue
            elif not isinstance(vendor_cvss, dict):
                logger.warning(
                    "Received non-dict value for vendor CVSS data: %s", vendor_cvss
                )
                continue
            if version == 3:
                return vendor_cvss.get("V3Score", default)
            elif version == 2:
                return vendor_cvss.get("V2Score", default)
        return default

    def get_severity(
        self,
        scanner: Union[Optional[Scanner], str] = "Trivy",
        vendor_priority: Optional[Iterable[str]] = None,
    ) -> Severity:
        """Returns the CVSS V3 severity of the vulnerability based on a specific vendor.
        If no vendor is specified, the default vendor priority is used (NVD over RedHat).

        With Trivy 0.29.1, the `severity` field is based on the Red Hat vulnerability rating.
        This attempts to return the severity based on a user-provided vendor priority.

        TODO: improve documentation for the what and why of this method
        """
        cvss_score = self.get_cvss_score(
            scanner=scanner, vendor_priority=vendor_priority
        )
        if cvss_score >= 9.0:
            return Severity.critical
        elif cvss_score >= 7.0:
            return Severity.high
        elif cvss_score >= 4.0:
            return Severity.medium
        elif cvss_score >= 0.1:
            return Severity.low
        else:
            return Severity.negligible

    def get_severity_highest(
        self,
        scanner: Union[Optional[Scanner], str] = "Trivy",
        vendors: Optional[Iterable[str]] = None,
    ) -> Severity:
        """Attempts to find the highest severity of the vulnerability based on a specific vendor."""
        if vendors is None:
            vendors = DEFAULT_VENDORS
        severities = [
            self.get_severity(scanner=scanner, vendor_priority=[v]) for v in vendors
        ]
        if self.severity is not None:
            severities.append(self.severity)
        return most_severe(severities)


class ErrorResponse(BaseModel):
    error: Optional[Error] = None


class HarborVulnerabilityReport(BaseModel):
    generated_at: Optional[datetime] = Field(
        None, description="The time the report was generated."
    )
    artifact: Optional[Artifact] = Field(None, description="The scanned artifact.")
    scanner: Optional[Scanner] = Field(
        None, description="The scanner used to generate the report."
    )
    severity: Optional[Severity] = Field(
        None, description="The overall severity of the vulnerabilities."
    )
    vulnerabilities: List[VulnerabilityItem] = Field(
        default_factory=list, description="The list of vulnerabilities found."
    )
    model_config = ConfigDict(ignored_types=(cached_property,))

    def __repr__(self) -> str:
        return f"HarborVulnerabilityReport(generated_at={self.generated_at}, artifact={self.artifact}, scanner={self.scanner}, severity={self.severity}, vulnerabilities=list(len={len(self.vulnerabilities)}))"

    @property
    def fixable(self) -> List[VulnerabilityItem]:
        return [v for v in self.vulnerabilities if v.fixable]

    @property
    def unfixable(self) -> List[VulnerabilityItem]:
        return [v for v in self.vulnerabilities if not v.fixable]

    @property
    def critical(self) -> List[VulnerabilityItem]:
        return self.vulnerabilities_by_severity(Severity.critical)

    @property
    def high(self) -> List[VulnerabilityItem]:
        return self.vulnerabilities_by_severity(Severity.high)

    @property
    def medium(self) -> List[VulnerabilityItem]:
        return self.vulnerabilities_by_severity(Severity.medium)

    @property
    def low(self) -> List[VulnerabilityItem]:
        return self.vulnerabilities_by_severity(Severity.low)

    @property
    def distribution(self) -> Counter[Severity]:
        dist = Counter()
        for vulnerability in self.vulnerabilities:
            if vulnerability.severity:
                dist[vulnerability.severity] += 1
        return dist

    def vulnerabilities_by_severity(
        self, severity: Severity
    ) -> List[VulnerabilityItem]:
        return [v for v in self.vulnerabilities if v.severity == severity]

    def sort(self, descending: bool = True, use_cvss: bool = False) -> None:
        """Sorts the vulnerabilities by severity in place.

        A wrapper around `vulnerabilities.sort` that sorts by severity,
        then optionally by CVSS score to break ties.

        Parameters
        ----------
        descending : bool, optional
            Whether to sort in descending order, by default True
            Equivalent to `reverse=True` in `sorted()`.
        use_cvss : bool, optional
            Whether to use CVSS score to determine sorting order
            when items have identical severity, by default False
            This is somewhat experimental and may be removed in the future.
        """

        def cmp(v1: VulnerabilityItem, v2: VulnerabilityItem) -> int:
            if v1.severity > v2.severity:
                return 1
            elif v1.severity < v2.severity:
                return -1
            if not use_cvss:
                return 0
            diff = v1.get_cvss_score(self.scanner) - v2.get_cvss_score(self.scanner)
            if diff > 0:
                return 1
            elif diff < 0:
                return -1
            return 0

        self.vulnerabilities.sort(key=functools.cmp_to_key(cmp), reverse=descending)

    @cached_property
    def cvss_scores(self) -> List[float]:
        """Returns a list of CVSS scores for each vulnerability.
        Vulnerabilities with a score of `None` are omitted.

        Returns
        ----
        List[Optional[float]]
            A list of CVSS scores for each vulnerability.
        """
        return list(
            filter(
                None.__ne__,
                [v.get_cvss_score(self.scanner) for v in self.vulnerabilities],
            )
        )

    def top_vulns(self, n: int = 5, fixable: bool = False) -> List[VulnerabilityItem]:
        """Returns the n most severe vulnerabilities.


        Parameters
        ----------
        n : int
            The maximum number of vulnerabilities to return.
        fixable : bool
            If `True`, only vulnerabilities with a fix version are returned.

        Returns
        -------
        List[VulnerabilityItem]
            The n most severe vulnerabilities.

        """
        vulns: Iterable[VulnerabilityItem] = []
        if fixable:
            vulns = self.fixable
        else:
            vulns = self.vulnerabilities
        vulns = filter(lambda v: v.get_cvss_score(self.scanner) is not None, vulns)
        return sorted(
            vulns, key=lambda v: v.get_cvss_score(self.scanner), reverse=True
        )[:n]

    def has_cve(self, cve_id: str, case_sensitive: bool = False) -> bool:
        """Whether or not the report contains a vulnerability with the given CVE ID.

        Parameters
        ----------
        cve_id : str
            The CVE ID to search for.

        Returns
        -------
        bool
            Report contains the a vulnerability with the given CVE ID.
        """
        return self.vuln_with_cve(cve_id, case_sensitive) is not None

    def has_description(self, description: str, case_sensitive: bool = False) -> bool:
        """Whether or not the report contains a vulnerability whose description contains the given string.

        Parameters
        ----------
        description : str
            The string to search for in the descriptions.
        case_sensitive : bool
            Case sensitive search, by default False

        Returns
        -------
        bool
            The report contains a vulnerability whose description contains the given string.
        """
        for _ in self.vulns_with_description(description, case_sensitive):
            return True
        return False

    def has_package(self, package: str, case_sensitive: bool = False) -> bool:
        """Whether or not the report contains a vulnerability affecting the given package.

        Parameters
        ----------
        package : str
            Name of the package to search for.
        case_sensitive : bool
            Case sensitive search, by default False

        Returns
        -------
        bool
            The given package is affected by a vulnerability in the report.
        """
        for _ in self.vulns_with_package(package, case_sensitive):
            return True
        return False

    def vuln_with_cve(
        self, cve: str, case_sensitive: bool = False
    ) -> Optional[VulnerabilityItem]:
        """Returns a vulnerability with the specified CVE ID if it exists in the report.

        Parameters
        ----------
        cve : str
            The CVE ID of the vulnerability to return.
        case_sensitive : bool
            Case sensitive search, by default False

        Returns
        -------
        Optional[VulnerabilityItem]
            A vulnerability with the specified CVE ID if it exists, otherwise `None`.
        """
        for vuln in self.vulnerabilities:
            if vuln.id is None:
                continue
            vuln_id = vuln.id
            if not case_sensitive:
                vuln_id = vuln.id.lower()
                cve = cve.lower()
            if vuln_id == cve:
                return vuln
        return None

    def vulns_with_package(
        self, package: str, case_sensitive: bool = False
    ) -> Iterable[VulnerabilityItem]:
        """Generator that yields all vulnerabilities that affect the given package.

        Parameters
        ----------
        package : str
            The package name to search for.
        case_sensitive : bool
            Case sensitive search, by default False

        Yields
        ------
        VulnerabilityItem
            Vulnerability that affects the given package.
        """
        for vuln in self.vulnerabilities:
            if vuln.package is None:
                continue
            vuln_package = vuln.package
            if not case_sensitive:
                vuln_package = vuln.package.lower()
                package = package.lower()
            if vuln_package == package:
                yield vuln

    def vulns_with_description(
        self, description: str, case_sensitive: bool = False
    ) -> Iterable[VulnerabilityItem]:
        """Generator that yields all vulnerabilities whose description contains the given string.

        Parameters
        ----------
        description : str
            The string to search for in vulnerability descriptions.
        case_sensitive : bool
            Case sensitive search, by default False

        Yields
        ------
        VulnerabilityItem
            Vulnerability whose description contains the given string.
        """
        for vuln in self.vulnerabilities:
            if vuln.description is None:
                continue
            vuln_description = vuln.description
            if not case_sensitive:
                description = description.lower()
                vuln_description = vuln_description.lower()
            if description in vuln_description:
                yield vuln


DEFAULT_VENDORS = ("nvd", "redhat")
SEVERITY_PRIORITY: Final[Dict[Severity, int]] = {
    Severity.none: 0,
    Severity.unknown: 1,
    Severity.negligible: 2,
    Severity.low: 3,
    Severity.medium: 4,
    Severity.high: 5,
    Severity.critical: 6,
}


def most_severe(severities: Iterable[Severity]) -> Severity:
    """Returns the highest severity in a list of severities."""
    return max(severities, key=lambda x: SEVERITY_PRIORITY[x], default=Severity.unknown)


def sort_distribution(distribution: "Counter[Severity]") -> List[Tuple[Severity, int]]:
    """Turn a counter of Severities into a sorted list of (severity, count) tuples."""
    return [
        (k, v)
        for (k, v) in sorted(
            distribution.items(), key=lambda x: SEVERITY_PRIORITY[x[0]]
        )
    ]
