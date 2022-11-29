from collections import Counter
from typing import TYPE_CHECKING, Iterable, List, Optional, Tuple

from pydantic import BaseModel

from ..models.scanner import SEVERITY_PRIORITY, Severity
from . import stats

if TYPE_CHECKING:
    from .artifact import ArtifactInfo
    from .report import ArtifactReport


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

        Parameters
        ----------
        artifact : ArtifactInfo
            The artifact to extract CVSS data from.

        Returns
        -------
        CVSSData
            The CVSS data for the artifact.

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
        """Create a CVSSData instance from an ArtifactReport object.

        Parameters
        ----------
        report : ArtifactReport
            The report to extract CVSS data from.

        Returns
        -------
        CVSSData
            The CVSS data for the report.
        """
        data = [artifact.cvss for artifact in report.artifacts]
        return cls(
            mean=stats.median([d.mean for d in data]),
            median=stats.mean([d.median for d in data]),
            stdev=stats.stdev([d.stdev for d in data]),
            min=stats.min([d.min for d in data]),
            max=stats.max([d.max for d in data]),
        )
