from collections import Counter
from typing import Iterable, List, Tuple

from pydantic import BaseModel

from ..models.scanner import Severity

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
