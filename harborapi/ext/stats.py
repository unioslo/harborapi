import statistics
from numbers import Number
from typing import Any, Callable, Iterable, Union

from loguru import logger

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


def mean(a: Iterable[Number]) -> float:
    return _do_stats_math(statistics.mean, a)


def median(a: Iterable[Number]) -> float:
    return _do_stats_math(statistics.median, a)


def stdev(a: Iterable[Number]) -> float:
    return _do_stats_math(statistics.stdev, a)


def min(a: Iterable[Number]) -> float:  # todo : fix type
    return _min(a, default=DEFAULT_VALUE)


def max(a: Iterable[Number]) -> float:  # todo : fix type
    return _max(a, default=DEFAULT_VALUE)


def _do_stats_math(
    func: Callable[[Any], float],
    a: Iterable[Number],
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
    except statistics.StatisticsError as e:
        logger.error(f"{func.__name__}({repr(a)}) failed. Defaulting to {default}")
        return float(default)
    return float(res)
