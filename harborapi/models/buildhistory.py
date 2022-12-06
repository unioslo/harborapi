"""Models defined here are part of the Harbor API, but not documented in the official schema.

The models in this module are _NOT_ automatically generated.
"""

from datetime import datetime
from typing import Optional

from .base import BaseModel


# Unclear what is optional and what isn't
class BuildHistoryEntry(BaseModel):
    created: datetime
    created_by: str
    author: Optional[str] = None
    empty_layer: bool = False
