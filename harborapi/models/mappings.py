from __future__ import annotations

import sys
from typing import Optional
from typing import TypeVar

if sys.version_info >= (3, 9):
    from collections import OrderedDict
else:
    from typing import OrderedDict


_KT = TypeVar("_KT")  #  key type
_VT = TypeVar("_VT")  #  value type


# NOTE: How to parametrize a normal dict in 3.8? In >=3.9 we can do `dict[_KT, _VT]`
class FirstDict(OrderedDict[_KT, _VT]):
    """Dict with method to get its first value."""

    def first(self) -> Optional[_VT]:
        """Return the first value in the dict or None if dict is empty."""
        return next(iter(self.values()), None)
