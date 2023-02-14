from __future__ import annotations

import subprocess
import sys
from enum import Enum
from subprocess import CompletedProcess
from typing import Any, Iterator, NamedTuple, Sequence

import typer
from rich.console import Console

console = Console()
err_console = Console(stderr=True, style="red")


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


class State(Enum):
    OLD_VERSION = 0  # before bumping version
    NEW_VERSION = 1  # after bumping version
    GIT_ADD = 2  # after git adding version file
    GIT_COMMIT = 3  # after git commit
    GIT_TAG = 4  # after git tag
    GIT_PUSH = 5  # after git push

    @classmethod
    def __missing__(cls, value: Any) -> State:
        return State.OLD_VERSION


class StateMachine:
    old_version: str | None = None
    new_version: str | None = None

    def __init__(self) -> None:
        self.state = State.OLD_VERSION

    def advance(self) -> None:
        self.state = State(self.state.value + 1)

    def revert(self) -> State:
        self.state = State(self.state.value - 1)
        return self.state

    def rewind(self) -> Iterator[State]:
        while self.state != State.OLD_VERSION:
            yield self.revert()


def set_version(version: str) -> str:
    # We don't verify that the version arg is valid, we just pass it
    # to hatch and let it handle it.
    # Worst case scenario, we get a non-zero exit code and the script exits
    p_version = subprocess.run(["hatch", "version", version], capture_output=True)
    if p_version.returncode != 0:
        err_console.print(f"Failed to set version: {p_version.stderr.decode()}")
        raise typer.Exit(1)
    return p_version.stdout.decode().strip()  # the new version


def cleanup(state: StateMachine) -> None:
    for st in state.rewind():
        # from last to first
        # Best-effort cleanup
        try:
            if st == State.GIT_PUSH:
                # probably nothing to clean up here
                # we could do a git push --delete, but if it failed,
                # it probably isn't in the upstream repo anyway
                pass
            elif st == State.GIT_TAG:
                if not state.new_version:
                    raise ValueError("No new version to untag.")
                subprocess.run(["git", "tag", "-d", state.new_version])
            elif st == State.GIT_COMMIT:
                subprocess.run(["git", "revert", "HEAD"])
            elif st == State.GIT_ADD:
                subprocess.run(["git", "reset", "HEAD"])
            elif st == State.NEW_VERSION:
                # just revert change to __about__.py instead?
                if not state.old_version:
                    raise ValueError("No old version to revert to.")
                # Revert the version bump
                set_version(state.old_version)
        except Exception as e:
            print(f"Failed to revert state {state.state}: {e}", file=sys.stderr)


def main(
    version: str = typer.Argument(
        ...,
        help="Version bump to perform or new version to set.",
        metavar="[" + "|".join(versions) + "|x.y.z],[" + "|".join(statuses) + "]",
    ),
    push: bool = typer.Option(
        False,
        help="Push the created tag and commmit to the remote repository automatically.",
    ),
) -> None:
    """Bump the version of the project and create a new git tag.

    Examples:

    $ python bump_version.py minor

    $ python bump_version.py major,rc

    $ python bump_version.py 1.2.3 # generally don't use this
    """
    state = StateMachine()
    try:
        _main(state, version=version, push=push)
    except Exception as e:
        cleanup(state)
        raise e


class CommandCheck(NamedTuple):
    program: str
    command: Sequence[str]
    message: str


REQUIRED_COMMANDS = [
    CommandCheck(
        program="Hatch",
        command=["hatch", "--version"],
        message="Hatch is not installed. Please install it with `pip install hatch`.",
    ),
    CommandCheck(
        program="Git",
        command=["git", "--version"],
        message="Git is not installed. Please install it.",
    ),
]


def _check_commands() -> None:
    """Checks that we have the necessary programs installed and available"""
    for command in REQUIRED_COMMANDS:
        try:
            subprocess.check_output(command.command)
        except FileNotFoundError:
            err_console.print(f"{command.message} :x:", style="bold red")
            raise typer.Exit(1)
        else:
            console.print(f"{command.program} :white_check_mark:")


def _do_get_new_version() -> str:
    # If this fails, something is very wrong.
    new_version = subprocess.check_output(["hatch", "version"]).decode().strip()
    err_console.print(f"New version: {new_version}")
    return new_version


def _do_add() -> CompletedProcess[bytes]:
    p_git_add = subprocess.run(
        ["git", "add", "harborapi/__about__.py"], capture_output=True
    )
    if p_git_add.returncode != 0:
        err_console.print(f"Failed to add version file: {p_git_add.stderr.decode()}")
        raise typer.Exit(1)
    return p_git_add


def _do_commit(new_version: str) -> CompletedProcess[bytes]:
    p_git_commit = subprocess.run(
        ["git", "commit", "-m", f"Bump version to {new_version}"],
        capture_output=True,
    )
    if p_git_commit.returncode != 0:
        err_console.print(
            f"Failed to commit version bump: {p_git_commit.stderr.decode()}"
        )
        raise typer.Exit(1)
    return p_git_commit


def _do_tag(new_version: str) -> CompletedProcess[bytes]:
    tag = f"harborapi-v{new_version}"
    p_git_tag = subprocess.run(["git", "tag", tag], capture_output=True)
    if p_git_tag.returncode != 0:
        err_console.print(f"Failed to tag version: {p_git_tag.stderr.decode()}")
        raise typer.Exit(1)
    return p_git_tag


def _do_push() -> CompletedProcess[bytes]:
    p_git_push = subprocess.run(
        ["git", "push", "--tags", "origin", "main"], capture_output=True
    )
    if p_git_push.returncode != 0:
        err_console.print(f"Failed to push new version: {p_git_push.stderr.decode()}")
        raise typer.Exit(1)
    return p_git_push


def _main(state: StateMachine, version: str, push: bool) -> None:
    _check_commands()

    old_version = subprocess.check_output(["hatch", "version"])
    state.old_version = old_version.decode().strip()

    set_version(version)
    state.advance()
    assert state.state == State.NEW_VERSION

    new_version = _do_get_new_version()
    state.new_version = new_version

    # Add the updated version file to staged changes
    _do_add()
    state.advance()
    assert state.state == State.GIT_ADD

    _do_commit(new_version)
    state.advance()
    assert state.state == State.GIT_COMMIT

    _do_tag(new_version)
    state.advance()
    assert state.state == State.GIT_TAG

    if push:
        _do_push()
        state.advance()
        assert state.state == State.GIT_PUSH


if __name__ == "__main__":
    typer.run(main)
