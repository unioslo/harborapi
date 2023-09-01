from typing import Optional

from pydantic import BaseModel, Field


class GeneralInfo(BaseModel):
    with_chartmuseum: Optional[bool] = Field(
        None,
        description="DEPRECATED: Harbor instance is deployed with nested chartmuseum.",
    )
