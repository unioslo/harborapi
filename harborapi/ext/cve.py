from collections import Counter
from typing import TYPE_CHECKING, Iterable, List, Tuple

from pydantic import BaseModel

from ..models.scanner import Severity
from . import stats

if TYPE_CHECKING:
    from .artifact import ArtifactInfo
    from .report import ArtifactReport

CVE_PRIO = [  # low -> high
    Severity.unknown,
    Severity.negligible,
    Severity.low,
    Severity.medium,
    Severity.high,
    Severity.critical,
]


class CVSSData(BaseModel):
    """Key CVSS metrics for a scanned container."""

    mean: float
    median: float
    stdev: float
    min: float
    max: float

    @classmethod
    def from_artifactinfo(cls, artifact: "ArtifactInfo") -> "CVSSData":
        """Create a CVSSData instance from an ArtifactInfo object.

        See Also
        --------
        [ArtifactInfo.cvss][harborapi.ext.artifact.ArtifactInfo.cvss]
        """
        scores = artifact.report.cvss_scores
        return cls(
            mean=stats.median(scores),
            median=stats.mean(scores),
            stdev=stats.stdev(scores),
            min=stats.min(scores),
            max=stats.max(scores),
        )

    @classmethod
    def from_report(cls, report: "ArtifactReport") -> "CVSSData":
        """Create a CVSSData instance from an ArtifactReport object."""
        data = [artifact.cvss for artifact in report.artifacts]
        return cls(
            mean=stats.median([d.mean for d in data]),
            median=stats.mean([d.median for d in data]),
            stdev=stats.stdev([d.stdev for d in data]),
            min=stats.min([d.min for d in data]),
            max=stats.max([d.max for d in data]),
        )


def most_severe(severities: Iterable[Severity]) -> Severity:
    """Returns the highest severity in a list of severities."""

    # TODO: add test to ensure we test every possible Severity value
    highest_idx = 0
    for s in severities:
        i = CVE_PRIO.index(s)
        if i > highest_idx:
            highest_idx = i
    return CVE_PRIO[highest_idx]


def sort_distribution(distribution: "Counter[Severity]") -> List[Tuple[Severity, int]]:
    """Sort the distribution of severities by severity."""
    return [
        (k, v)
        for k, v in sorted(distribution.items(), key=lambda x: CVE_PRIO.index(x[0]))
    ]
