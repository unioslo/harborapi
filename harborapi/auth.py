import json
from datetime import datetime
from pathlib import Path
from typing import List, Union

from pydantic import BaseModel, Field


def load_harbor_auth_file(path: Union[str, Path]) -> "HarborAuthFile":
    with open(path, "r") as f:
        # parse without any guards against exceptions
        # pass the exception to the caller
        j = json.load(f)
    return HarborAuthFile.parse_obj(j)


class HarborAction(BaseModel):
    action: str
    resource: str


class HarborPermission(BaseModel):
    access: List[HarborAction] = Field(default_factory=list)
    kind: str
    namespace: str


class HarborPermissionScope(BaseModel):
    # NOTE: unclear if this model is different from HarborPermission,
    # or if we should bake it into HarborPermission with default values
    # for the fields
    access: List[HarborAction] = Field(default_factory=list)
    cover_all: bool = Field(..., alias="coverAll")

    class Config:
        allow_population_by_field_name = True


class HarborAuthFile(BaseModel):
    creation_time: datetime
    description: str
    disable: bool
    duration: int  # in days
    editable: bool
    expires_at: datetime  # unix timestamp in source file
    id: int
    level: str
    name: str
    permissions: List[HarborPermission] = Field(default_factory=list)
    update_time: datetime
    permission_scope: HarborPermissionScope = Field(..., alias="permissionScope")
    secret: str

    class Config:
        allow_population_by_field_name = True
