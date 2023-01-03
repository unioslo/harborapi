from typing import Any, Dict, List, Mapping, Sequence, TypeVar, Union

from pydantic import BaseModel

JSONType = Union[Dict[str, Any], List[Any]]

# This is more correct, but leads to a whole lot of typing bloat wrt. handling iterables.
# We assume that the API will always return a list or dict.
# JSONType = Union[None, int, float, str, Dict[str, Any], List[Any]]

T = TypeVar("T", bound=BaseModel)
ModelOrDict = Union[T, Dict[str, Any]]
"""A type that can be either a model or a dict."""


# HTTP(X)
ParamValue = Union[str, int, float, bool, None]
ParamType = Union[ParamValue, Sequence[ParamValue], Mapping[str, ParamValue]]
