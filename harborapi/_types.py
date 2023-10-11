from __future__ import annotations

from typing import Any
from typing import Dict
from typing import List
from typing import MutableMapping
from typing import Sequence
from typing import TypeVar
from typing import Union

from httpx._types import PrimitiveData
from pydantic import BaseModel

JSONType = Union[Dict[str, Any], List[Any]]  # TODO: Use PrimitiveData

T = TypeVar("T", bound=BaseModel)
ModelOrDict = Union[T, Dict[str, Any]]
"""A type that can be either a model or a dict."""


# HTTP(X)
QueryParamValue = Union[PrimitiveData, Sequence[PrimitiveData]]
QueryParamMapping = MutableMapping[str, QueryParamValue]
