"""Caching functions for the ext module."""
import re
from functools import lru_cache
from typing import Dict, Tuple

from loguru import logger

# NOTE: Regex type generics require >=3.9. Have to wrap in a string.

# Unbounded cache (should be fine since we're only caching regex patterns)
_pattern_cache: Dict[Tuple[str, bool], "re.Pattern[str]"] = {}

# TODO: bake get_pattern() into match(), so we only have to call match() in the codebase.

# NOTE: could we just do away with _pattern_cache and add lru_cache to the
# get_pattern function?  I think we could, but we should test the performance of both approaches.
def get_pattern(pattern: str, case_sensitive: bool = False) -> "re.Pattern[str]":
    """Simple cache function for getting/setting compiled regex patterns.

    Parameters
    ----------
    pattern : str
        The regex pattern to compile.
    case_sensitive : bool, optional
        Whether the pattern should be case sensitive, by default False

    Returns
    -------
    re.Pattern[str]
        The compiled regex pattern.
    """
    cache_key = (pattern, case_sensitive)
    if cache_key not in _pattern_cache:
        flags = re.IGNORECASE if not case_sensitive else 0
        _pattern_cache[cache_key] = re.compile(pattern, flags=flags)
    return _pattern_cache[cache_key]


@lru_cache(maxsize=128)
def match(pattern: "re.Pattern[str]", s: str) -> "re.Match[str]":
    try:
        return pattern.match(s)
    except Exception as e:
        logger.error(f"Error matching pattern {pattern} to string {s}: {e}")
        return None
