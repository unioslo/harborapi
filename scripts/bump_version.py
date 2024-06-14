from __future__ import annotations

import subprocess
import sys
from datetime import datetime
from enum import Enum
from enum import IntEnum
from enum import auto
from pathlib import Path
from subprocess import CompletedProcess
from typing import Any
from typing import Iterator
from typing import NamedTuple
from typing import Sequence

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


class State(IntEnum):
    OLD_VERSION = auto()  # before bumping version
    NEW_VERSION = auto()  # after bumping version
    MODIFY_CHANGELOG = auto()  # after modifying changelog
    GIT_ADD = auto()  # after git adding version file
    GIT_COMMIT = auto()  # after git commit
    GIT_TAG = auto()  # after git tag
    GIT_PUSH = auto()  # after git push

    @classmethod
    def __missing__(cls, value: Any) -> State:
        return State.OLD_VERSION

    @classmethod
    def ensure_contiguous(cls) -> None:
        """Ensure that enum values are contiguous and increment by 1"""
        # NOTE: this is just a sanity check that ensures we increment and
        # decrement the state machine correctly.
        if len(cls) != max(cls):  # starts at 1
            raise ValueError("Enum values must be contiguous")
        prev = None
        for st in cls:
            if prev is not None and st != prev + 1:
                raise ValueError("Enum values must increment by 1")
            prev = st


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
                subprocess.run(["git", "reset", "HEAD"])
            elif st == State.GIT_ADD:
                subprocess.run(["git", "reset", "HEAD"])
            elif st == State.NEW_VERSION:
                # Nothing to do; when resetting git, we lose the new version.
                pass
        except Exception as e:
            print(f"Failed to revert state {state.state}: {e}", file=sys.stderr)


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


def git_add() -> CompletedProcess[bytes]:
    p_git_add = subprocess.run(
        ["git", "add", "harborapi/__about__.py", "CHANGELOG.md"], capture_output=True
    )
    if p_git_add.returncode != 0:
        err_console.print(f"Failed to add version file: {p_git_add.stderr.decode()}")
        raise typer.Exit(1)
    return p_git_add


def git_commit(new_version: str, rerun: bool = False) -> CompletedProcess[bytes]:
    p_git_commit = subprocess.run(
        ["git", "commit", "-m", f"Bump version to {new_version}"],
        capture_output=True,
    )
    if p_git_commit.returncode != 0:
        # pre-commit might have modified our files
        msg = p_git_commit.stderr.decode()
        if "- hook id" in msg and not rerun:
            # re-run git-add and git-commit
            git_add()
            git_commit(new_version, rerun=True)
        else:
            err_console.print(f"Failed to commit version bump:\n{msg}")
            raise typer.Exit(1)
    return p_git_commit


def git_tag(new_version: str) -> CompletedProcess[bytes]:
    tag = f"harborapi-v{new_version}"
    p_git_tag = subprocess.run(["git", "tag", tag], capture_output=True)
    if p_git_tag.returncode != 0:
        err_console.print(f"Failed to tag version: {p_git_tag.stderr.decode()}")
        raise typer.Exit(1)
    return p_git_tag


def git_push() -> CompletedProcess[bytes]:
    p_git_push = subprocess.run(
        ["git", "push", "--tags", "upstream", "main"], capture_output=True
    )
    if p_git_push.returncode != 0:
        err_console.print(f"Failed to push new version: {p_git_push.stderr.decode()}")
        raise typer.Exit(1)
    return p_git_push


def add_changelog_header(new_version: str) -> None:
    changelog_path = Path("CHANGELOG.md")
    changelog = changelog_path.read_text()

    # Find the line containing the unreleased header
    lines = changelog.splitlines()
    index = next(
        iter(
            [idx for idx, line in enumerate(lines) if line.startswith("## Unreleased")],
        ),
        None,
    )
    if index is None:
        err_console.print("Failed to find '## Unreleased' section in CHANGELOG.md")
        raise typer.Exit(1)

    header = f"## [{new_version}](https://github.com/unioslo/harborapi/tree/harborapi-v{new_version}) - {datetime.now().strftime('%Y-%m-%d')}"
    lines[index] = "<!-- ## Unreleased -->"  # comment out
    lines.insert(index + 1, f"\n{header}")  # insert after
    changelog_path.write_text("\n".join(lines))


def main(
    version: str = typer.Argument(
        ...,
        help="Version bump to perform or new version to set.",
        metavar="[" + "|".join(versions) + "|x.y.z],[" + "|".join(statuses) + "]",
    ),
    push: bool = typer.Option(
        True,
        "--push/--no-push",
        help="Push the created tag and commmit to the remote repository automatically.",
    ),
) -> None:
    """Bump the version of the project and create a new git tag.

    If using --no-push, remember to also push the tag manually:
    `git push --tags upstream main`.

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


def _main(state: StateMachine, version: str, push: bool) -> None:
    _check_commands()
    State.ensure_contiguous()  # sanity check

    # TODO: * ensure we are on the correct branch
    #           `git rev-parse --abbrev-ref HEAD`
    #       * ensure we are up-to-date with the remote
    #           `git fetch upstream`

    old_version = subprocess.check_output(["hatch", "version"])
    state.old_version = old_version.decode().strip()

    set_version(version)
    state.advance()
    assert state.state == State.NEW_VERSION
    new_version = _do_get_new_version()
    state.new_version = new_version

    add_changelog_header(new_version)
    state.advance()
    assert state.state == State.MODIFY_CHANGELOG

    # Add the updated version file to staged changes
    git_add()
    state.advance()
    assert state.state == State.GIT_ADD

    git_commit(new_version)
    state.advance()
    assert state.state == State.GIT_COMMIT

    git_tag(new_version)
    state.advance()
    assert state.state == State.GIT_TAG

    if push:
        git_push()
        state.advance()
        assert state.state == State.GIT_PUSH


if __name__ == "__main__":
    typer.run(main)
