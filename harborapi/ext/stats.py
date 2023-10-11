from __future__ import annotations

import statistics
from typing import Any
from typing import Callable
from typing import Iterable

from ..log import logger

__all__ = [
    "mean",
    "median",
    "stdev",
    "min",
    "max",
]

_min = min
_max = max
DEFAULT_VALUE = 0.0


def mean(a: Iterable[float]) -> float:
    return _do_stats_math(statistics.mean, a)


def median(a: Iterable[float]) -> float:
    return _do_stats_math(statistics.median, a)


def stdev(a: Iterable[float]) -> float:
    return _do_stats_math(statistics.stdev, a)


def min(a: Iterable[float]) -> float:
    return _min(a, default=DEFAULT_VALUE)


def max(a: Iterable[float]) -> float:
    return _max(a, default=DEFAULT_VALUE)


def _do_stats_math(
    func: Callable[[Any], float],
    a: Iterable[float],
    default: float = DEFAULT_VALUE,
    filter_none: bool = False,
) -> float:
    """Wrapper function around stats functions that handles exceptions."""
    if filter_none:
        a = filter(None, a)

    # Try to run the statistics function, but if it fails, return the default value
    # Functions like stdev, median and mean will fail if there is only one data point
    # or no data points. In these cases, we want to return the default value.
    try:
        res = func(a)
    except statistics.StatisticsError:
        logger.error("%s(%s) failed. Defaulting to %s", func.__name__, repr(a), default)
        return float(default)
    return float(res)
