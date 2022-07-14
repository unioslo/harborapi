import json
from pathlib import Path
from typing import List, Union

from pydantic import BaseModel, Field

from harborapi.models.models import Robot, RobotCreate, RobotCreated


def load_harbor_auth_file(path: Union[str, Path]) -> "HarborAuthFile":
    with open(path, "r") as f:
        # parse without any guards against exceptions
        # pass the exception to the caller
        j = json.load(f)
    return HarborAuthFile.parse_obj(j)


def save_authfile(path: Union[str, Path], authfile: "HarborAuthFile") -> None:
    with open(path, "w") as f:
        json.dump(authfile.dict(), f)


def new_authfile_from_robotcreate(
    path: Union[str, Path], robotcreate: RobotCreate, robotcreated: RobotCreated
) -> None:
    authfile = HarborAuthFile.parse_obj(
        {**(robotcreated.dict()), **(robotcreate.dict())}
    )
    save_authfile(path, authfile)


def new_authfile_from_robot(path: Union[str, Path], robot: Robot, secret: str) -> None:
    authfile = HarborAuthFile.parse_obj(robot.dict())
    authfile.secret = secret
    save_authfile(path, authfile)


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


class HarborAuthFile(Robot):
    class Config:
        allow_population_by_field_name = True
        extra = "allow"
