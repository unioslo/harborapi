from __future__ import annotations

import functools
from collections import Counter
from datetime import datetime
from enum import Enum
from functools import cached_property
from typing import Dict, Final, Iterable, List, Optional, Tuple, Union

from loguru import logger
from pydantic import Field

from ..version import SemVer, get_semver
from ._scanner import Artifact as ScanArtifact
from ._scanner import CVSSDetails, Error, ErrorResponse
from ._scanner import HarborVulnerabilityReport as _HarborVulnerabilityReport
from ._scanner import Registry
from ._scanner import Scanner as _Scanner  # Severity not imported (see below)
from ._scanner import ScannerAdapterMetadata as _ScannerAdapterMetadata
from ._scanner import (
    ScannerCapability,
    ScannerProperties,
    ScanRequest,
    ScanRequestId,
    ScanResponse,
)
from ._scanner import VulnerabilityItem as _VulnerabilityItem
from ._utils import optional_field, override_field

__all__ = [
    "Scanner",
    "ScannerProperties",
    "ScannerCapability",
    "ScanRequestId",
    "Registry",
    "ScanArtifact",
    "Severity",
    "Error",
    "Severity",
    "CVSSDetails",
    "ScannerAdapterMetadata",
    "ScanRequest",
    "ScanResponse",
    "VulnerabilityItem",
    "ErrorResponse",
    "HarborVulnerabilityReport",
]

DEFAULT_VENDORS = ("nvd", "redhat")

# START Scanner


class Scanner(_Scanner):
    @property
    def semver(self) -> SemVer:
        return get_semver(self.version)


class ScannerAdapterMetadata(_ScannerAdapterMetadata):
    scanner: Scanner


# NOTE: HarborVulnerabilityReport is defined below

# END Scanner

# We can't extend enums, so we redefine it here.
# Since the enum is based on CVSS v3.x, it shouldn't change

# START Severity


class Severity(Enum):
    unknown = "Unknown"
    negligible = "Negligible"
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"

    def __gt__(self, other: Severity) -> bool:
        return SEVERITY_PRIORITY[self] > SEVERITY_PRIORITY[other]

    def __ge__(self, other: Severity) -> bool:
        return SEVERITY_PRIORITY[self] >= SEVERITY_PRIORITY[other]

    def __lt__(self, other: Severity) -> bool:
        return SEVERITY_PRIORITY[self] < SEVERITY_PRIORITY[other]

    def __le__(self, other: Severity) -> bool:
        return SEVERITY_PRIORITY[self] <= SEVERITY_PRIORITY[other]


SEVERITY_PRIORITY = {
    s: i for i, s in enumerate(Severity)
}  # type: Final[Dict[Severity, int]]
"""The priority of severity levels, from lowest to highest. Used for sorting."""

# END Severity

# START VulnerabilityItem


class VulnerabilityItem(_VulnerabilityItem):
    # Changed from spec: Severity.unknown as default instead of None
    #                    Add description and example
    severity: Severity = override_field(
        _VulnerabilityItem,
        "severity",
        default=Severity.unknown,
        description="The severity of the vulnerability.",
        example=Severity.high.value,
    )  # type: ignore
    # AnyUrl has been known to fail on some URLs, so we use str instead
    links: Optional[List[str]] = optional_field(_VulnerabilityItem, "links")  # type: ignore

    @property
    def semver(self) -> SemVer:
        return get_semver(self.version)

    @property
    def fixable(self) -> bool:
        return bool(self.fix_version)  # None and empty string are False

    def get_cvss_score(
        self,
        scanner: Union[Optional[Scanner], str] = "Trivy",
        version: int = 3,
        vendor_priority: Iterable[str] = DEFAULT_VENDORS,
        default: float = 0.0,
    ) -> float:
        """The default scanner Trivy, as of version 0.29.1, does not use the
        preferred_cvss field.

        In order to not tightly couple this method with a specific scanner,
        we use the scanner name to determinehow to retrieve the CVSS score.

        Forward compatibility is in place in the event that Trivy starts
        conforming to the spec.
        """
        # Forward compatibility for Trivy (and others):
        # try to use the preferred_cvss field first in case it is implemented in the future
        if self.preferred_cvss is not None:
            if version == 3 and self.preferred_cvss.score_v3 is not None:
                return self.preferred_cvss.score_v3
            elif version == 2 and self.preferred_cvss.score_v2 is not None:
                return self.preferred_cvss.score_v2

        # fallback to the scanner-specific CVSS score

        # Scanner is an optional field in the spec,
        # but it's likely that it will always be present,
        # since there is no vulnerability without a scanner.
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

        # Other scanners here
        # ...

        return default

    def _get_trivy_cvss_score(
        self,
        version: int = 3,
        vendor_priority: Iterable[str] = DEFAULT_VENDORS,
        default: float = 0.0,
    ) -> float:
        # TODO: add logging when we hit defaults
        if self.vendor_attributes is None:
            return default

        cvss_data = self.vendor_attributes.get("CVSS", {})
        if not cvss_data:
            return default

        for prio in vendor_priority:
            # Trivy uses the vendor name as the key for the CVSS data
            vendor_cvss = cvss_data.get(prio, {})  # type: Dict[str, float]
            if not vendor_cvss:
                continue
            elif not isinstance(vendor_cvss, dict):
                logger.warning(
                    f"Received non-dict value for vendor CVSS data: {vendor_cvss}"
                )
                continue
            # NOTE: we can't guarantee these values are floats (dangerous)
            if version == 3:
                return vendor_cvss.get("V3Score", default)
            elif version == 2:
                return vendor_cvss.get("V2Score", default)
        return default

    def get_severity(
        self,
        scanner: Union[Optional[Scanner], str] = "Trivy",
        vendor_priority: Iterable[str] = DEFAULT_VENDORS,
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
            return Severity.negligible  # this is called "None" in the CVSSv3 spec
        # can never return Severity.unknown

    def get_severity_highest(
        self,
        scanner: Union[Optional[Scanner], str] = "Trivy",
        vendors: Iterable[str] = DEFAULT_VENDORS,
    ) -> Severity:
        """Attempts to find the highest severity of the vulnerability based on a specific vendor."""
        severities = [
            self.get_severity(scanner=scanner, vendor_priority=[v]) for v in vendors
        ]
        if self.severity is not None:
            severities.append(self.severity)
        return most_severe(severities)


# TODO: find a more suitable place for this
def most_severe(severities: Iterable[Severity]) -> Severity:
    """Returns the highest severity in a list of severities."""
    return max(severities, key=lambda x: SEVERITY_PRIORITY[x], default=Severity.unknown)


def sort_distribution(distribution: "Counter[Severity]") -> List[Tuple[Severity, int]]:
    """Turn a counter of Severities into a sorted list of (severity, count) tuples."""
    return [
        (k, v)
        for k, v in sorted(distribution.items(), key=lambda x: SEVERITY_PRIORITY[x[0]])
    ]


# NOTE: HarborVulnerabilityReport (which references this model) is defined below

# END VulnerabilityItem

# START HarborVulnerabilityReport


class HarborVulnerabilityReport(_HarborVulnerabilityReport):
    # Changes: added descriptions
    generated_at: Optional[datetime] = Field(
        None, description="The time the report was generated."
    )
    artifact: Optional[ScanArtifact] = Field(None, description="The artifact scanned.")

    # Changes: references the overridden Scanner class
    scanner: Optional[Scanner] = Field(
        None, description="The scanner used to generate the report."
    )

    # Changes from spec: these two fields have been given defaults
    severity: Severity = Field(
        Severity.unknown, description="The overall severity of the vulnerabilities."
    )  # type: ignore
    vulnerabilities: List[VulnerabilityItem] = Field(
        default_factory=list, description="The list of vulnerabilities found."
    )  # type: ignore

    class Config:
        keep_untouched = (cached_property,)

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
        dist = Counter()  # type: Counter[Severity]
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
        # TODO: implement this comparison in the VulnerabilityItem class
        def cmp(v1: VulnerabilityItem, v2: VulnerabilityItem) -> int:
            # First try to compare severities
            if v1.severity > v2.severity:
                return 1
            elif v1.severity < v2.severity:
                return -1
            if not use_cvss:
                return 0
            # Only proceeed if severities are identical
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
        # TODO: implement UNfixable
        vulns: Iterable[VulnerabilityItem] = []  # declare type for mypy

        if fixable:
            vulns = self.fixable
        else:
            vulns = self.vulnerabilities

        # Remove vulnerabilities with no CVSS score
        vulns = filter(lambda v: v.get_cvss_score(self.scanner) is not None, vulns)

        # Sort by CVSS score
        return sorted(
            vulns, key=lambda v: v.get_cvss_score(self.scanner), reverse=True
        )[:n]

    # DEPRECATED:
    # The with_ and has_ methods are deprecated in favor of similar methods
    # on the `ext.artifact.ArtifactInfo` class.

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
                return vuln  # should only be one match
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


# END HarborVulnerabilityReport
