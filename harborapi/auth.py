import json
from pathlib import Path
from typing import Union

from harborapi.models.models import Robot, RobotCreate, RobotCreated


def load_harbor_auth_file(path: Union[str, Path]) -> "HarborAuthFile":
    """Load a HarborAuthFile from a file path. Fails if the auth file
    does not contain a username and secret.

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
    with open(path, "r") as f:
        # parse without any guards against exceptions
        # pass the exception to the caller
        j = json.load(f)
    authfile = HarborAuthFile.parse_obj(j)
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
        f.write(authfile.json(indent=4))


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
    authfile = HarborAuthFile.parse_obj(
        {**(robotcreated.dict()), **(robotcreate.dict())}
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
    authfile = HarborAuthFile.parse_obj(robot.dict())
    authfile.secret = secret
    save_authfile(path, authfile, overwrite=overwrite)


class HarborAuthFile(Robot):
    """Represents a Harbor robot account auth file.

    Supports arbitrary extra fields to allow for future compatibility.
    """

    class Config:
        allow_population_by_field_name = True  # why? do we have any aliases?
        extra = "allow"
