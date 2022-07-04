"""Models defined here are part of the Harbor API, but not documented of the official schema.
The models in this module are _NOT_ automatically generated."""

from datetime import datetime
from typing import List

from pydantic import BaseModel, Field


class BuildHistoryEntry(BaseModel):
    created: datetime
    created_by: str
    empty_layer: bool


class BuildHistory(BaseModel):
    """Returned by GET /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/additions/build_history"""

    __root__: List[BuildHistoryEntry] = Field(default_factory=list)
