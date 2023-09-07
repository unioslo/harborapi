from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from pydantic import ConfigDict
from pydantic import Field

from harborapi.models.models import Robot
from harborapi.models.models import RobotCreate
from harborapi.models.models import RobotCreated


def _load_harbor_auth_file(path: Union[str, Path]) -> "HarborAuthFile":
    """Load a HarborAuthFile from a file path. Performs no validation beyond
    the built-in Pydantic validation."""
    with open(path, "r") as f:
        # parse without any guards against exceptions
        # pass the exception to the caller
        j = json.load(f)
    return HarborAuthFile.model_validate(j)


def load_harbor_auth_file(path: Union[str, Path]) -> "HarborAuthFile":
    """Load a HarborAuthFile from a file path. Ensure that the file contains
    a name and secret.

    Parameters
    ----------
    path : Union[str, Path]
        The path to the file to load.

    Returns
    -------
    HarborAuthFile
        The HarborAuthFile loaded from the file.

    Raises
    ------
    ValueError
        The auth file does not contain a username and/or secret.
    """
    authfile = _load_harbor_auth_file(path)
    if not authfile.name:
        raise ValueError("Field 'name' is required")
    if not authfile.secret:
        raise ValueError("Field 'secret' is required")
    return authfile


def save_authfile(
    path: Union[str, Path], authfile: "HarborAuthFile", overwrite: bool
) -> None:
    """Save the authfile to the given path.

    Parameters
    ----------
    path : Union[str, Path]
        Path to save the file to.
    authfile : HarborAuthFile
        Auth file definition to save.
    overwrite : bool
        Overwrite file if it exists.

    Raises
    ------
    FileExistsError
        A file with the given path already exists, and `overwrite` is `False`.
    """
    p = Path(path)
    if p.exists() and not overwrite:
        raise FileExistsError(f"File {p} already exists")
    with open(path, "w") as f:
        f.write(authfile.model_dump_json(indent=4))


def new_authfile_from_robotcreate(
    path: Union[str, Path],
    robotcreate: RobotCreate,
    robotcreated: RobotCreated,
    overwrite: bool = False,
) -> None:
    """Create a new authfile from the result of a create robot call.

    Parameters
    ----------
    path : Union[str, Path]
        Path to save the file to.
    robotcreate : RobotCreate
        The arguments used to create the robot.
    robotcreated : RobotCreated
        The result of the create robot call.
    overwrite : bool, optional
        Overwrite file if it exists.

    See Also
    --------
    [harborapi.auth.save_authfile][]
    """
    # Specify robotcreated last, since that is the object that should
    # contain the secret (which we definitely don't want to overwrite)
    authfile = HarborAuthFile.model_validate(
        {**(robotcreate.model_dump()), **(robotcreated.model_dump())}
    )
    save_authfile(path, authfile, overwrite=overwrite)


def new_authfile_from_robot(
    path: Union[str, Path],
    robot: Robot,
    secret: str,
    overwrite: bool = False,
) -> None:
    """Create a new authfile from a Robot definition and a secret.

    Parameters
    ----------
    path : Union[str, Path]
        Path to save the file to.
    robot : Robot
        Robot definition.
    secret : str
        Secret to use for the robot.
    overwrite : bool
        Overwrite file if it exists.

    See Also
    --------
    [harborapi.auth.save_authfile][]
    """
    authfile = HarborAuthFile.model_validate(robot.model_dump())
    authfile.secret = secret
    save_authfile(path, authfile, overwrite=overwrite)


class HarborAuthFile(Robot):
    """Represents a Harbor robot account auth file.

    Supports arbitrary extra fields to allow for future compatibility.
    """

    name: str = Field(None, description="The name of the robot account")
    secret: str = Field(None, description="The secret for the robot account")
    model_config = ConfigDict(populate_by_name=True, extra="allow")
