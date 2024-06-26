from __future__ import annotations

from typing import Optional

from pydantic import Field


class GeneralInfo(BaseModel):
    with_chartmuseum: Optional[bool] = Field(
        default=None,
        description="DEPRECATED: Harbor instance is deployed with nested chartmuseum.",
    )
