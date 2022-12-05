from itertools import chain
from typing import TYPE_CHECKING

from pydantic import BaseModel

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
            mean=stats.mean(scores),
            median=stats.median(scores),
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
        # Wrap generator in list to allow for re-use
        scores = list(
            chain.from_iterable([a.report.cvss_scores for a in report.artifacts])
        )
        return cls(
            mean=stats.mean(scores),
            median=stats.median(scores),
            stdev=stats.stdev(scores),
            min=stats.min(scores),
            max=stats.max(scores),
        )
