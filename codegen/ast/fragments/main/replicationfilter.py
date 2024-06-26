from __future__ import annotations

from typing import Any
from typing import Dict
from typing import Union

from pydantic import Field


class ReplicationFilter(BaseModel):
    value: Union[str, Dict[str, Any], None] = Field(
        default=None, description="The value of replication policy filter."
    )
