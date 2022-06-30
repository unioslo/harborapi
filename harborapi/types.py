from typing import Any, Dict, List, Union

JSONType = Union[Dict[str, Any], List[Any]]

# This is more correct, but leads to a whole lot of typing bloat wrt. handling iterables.
# We assume that the API will always return a list or dict.
# JSONType = Union[None, int, float, str, Dict[str, Any], List[Any]]
