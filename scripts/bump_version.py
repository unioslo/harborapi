from __future__ import annotations

import subprocess
from enum import Enum

import typer


class VersionType(Enum):
    major: str = "major"
    minor: str = "minor"
    patch: str = "patch"


class StatusType(Enum):
    # Release
    release: str = "release"

    # Alpha
    a: str = "a"
    alpha: str = "alpha"

    # Beta
    b: str = "b"
    beta: str = "beta"

    # Release Candidate
    c: str = "c"
    rc: str = "rc"
    pre: str = "pre"
    preview: str = "preview"

    # Revision / Post
    r: str = "r"
    rev: str = "rev"
    post: str = "post"

    # Dev
    dev: str = "dev"


# TODO: some sort of check to ensure we don't tag twice (??)
# but we also need to allow for the case where we want to create
# a status tag for a version that already exists.

versions = [v.value for v in VersionType]
statuses = [s.value for s in StatusType]


def main(
    version: str = typer.Argument(
        ...,
        help="Version bump to perform or new version to set.",
        metavar="[" + "|".join(versions) + "|x.y.z],[" + "|".join(statuses) + "]",
    ),
) -> None:
    """Bump the version of the project and create a new git tag.

    Examples:

    $ python bump_version.py minor

    $ python bump_version.py major,rc

    $ python bump_version.py 1.2.3 # generally don't use this
    """
    # We don't verify that the arguments are valid, we just pass them
    # to hatch and let it handle it.
    # Worst case scenario, we get a non-zero exit code and the script exits
    p_version = subprocess.run(["hatch", "version", version])
    if p_version.returncode != 0:
        typer.echo(f"Failed to bump version: {p_version.stderr.decode()}")
        raise typer.Exit(1)

    # If this fails, something is very wrong.
    new_version = subprocess.check_output(["hatch", "version"]).decode().strip()
    typer.echo(f"New version: {new_version}")

    tag = f"harborapi-v{new_version}"
    p_git_tag = subprocess.run(["git", "tag", tag])
    if p_git_tag.returncode != 0:
        typer.echo(f"Failed to tag version: {p_git_tag.stderr.decode()}")
        raise typer.Exit(1)


if __name__ == "__main__":
    typer.run(main)
