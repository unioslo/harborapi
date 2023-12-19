from __future__ import annotations

from typing import Dict
from typing import Final
from typing import List
from typing import Tuple


class Severity(Enum):
    # adds `none` to the enum. Unknown what it signifies, but it has been observed
    # in responses from the API.
    none = "None"

    def __gt__(self, other: Severity) -> bool:
        return SEVERITY_PRIORITY[self] > SEVERITY_PRIORITY[other]

    def __ge__(self, other: Severity) -> bool:
        return SEVERITY_PRIORITY[self] >= SEVERITY_PRIORITY[other]

    def __lt__(self, other: Severity) -> bool:
        return SEVERITY_PRIORITY[self] < SEVERITY_PRIORITY[other]

    def __le__(self, other: Severity) -> bool:
        return SEVERITY_PRIORITY[self] <= SEVERITY_PRIORITY[other]


SEVERITY_PRIORITY: Final[Dict[Severity, int]] = {
    Severity.none: 0,  # added by fragment
    Severity.unknown: 1,
    Severity.negligible: 2,
    Severity.low: 3,
    Severity.medium: 4,
    Severity.high: 5,
    Severity.critical: 6,
}
"""The priority of severity levels, from lowest to highest. Used for sorting."""


def most_severe(severities: Iterable[Severity]) -> Severity:
    """Returns the highest severity in a list of severities."""
    return max(severities, key=lambda x: SEVERITY_PRIORITY[x], default=Severity.unknown)


def sort_distribution(distribution: "Counter[Severity]") -> List[Tuple[Severity, int]]:
    """Turn a counter of Severities into a sorted list of (severity, count) tuples."""
    return [
        (k, v)
        for k, v in sorted(distribution.items(), key=lambda x: SEVERITY_PRIORITY[x[0]])
    ]
