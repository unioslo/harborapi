from __future__ import annotations

from typing import Any
from typing import Dict
from typing import List
from typing import MutableMapping
from typing import Sequence
from typing import Union

from httpx._types import PrimitiveData

JSONType = Union[Dict[str, Any], List[Any]]  # TODO: Use PrimitiveData


# HTTP(X)
QueryParamValue = Union[PrimitiveData, Sequence[PrimitiveData]]
QueryParamMapping = MutableMapping[str, QueryParamValue]
