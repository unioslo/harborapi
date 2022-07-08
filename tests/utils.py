from typing import Sequence

from pydantic import BaseModel


def json_from_list(models: Sequence[BaseModel]) -> str:
    """Creates a JSON string from a list of BaseModel objects.
    We use this to deal with missing support for datetime serialization
    in pytest-httpserver.
    """
    return "[" + ",".join(m.json() for m in models) + "]"
