from typing import NamedTuple, Optional, Tuple, Union


class SemVer(NamedTuple):
    major: int
    minor: int = 0
    patch: int = 0
    prerelease: Optional[str] = None
    build: Optional[str] = None

    def __bool__(self):
        return bool(self.major or self.minor or self.patch)

    def __eq__(self, other: "VersionType"):
        other = get_semver(other)
        return (
            self.major == other.major
            and self.minor == other.minor
            and self.patch == other.patch
            and self.prerelease == other.prerelease
            and self.build == other.build
        )

    def __gt__(self, other: "VersionType"):
        other = get_semver(other)
        if self.major > other.major:
            return True
        elif self.major < other.major:
            return False
        else:
            if self.minor > other.minor:
                return True
            elif self.minor < other.minor:
                return False
            else:
                if self.patch > other.patch:
                    return True
                elif self.patch < other.patch:
                    return False
                else:
                    if self.prerelease is None and other.prerelease is not None:
                        return True
                    return False

    def __ge__(self, other: "VersionType"):
        other = get_semver(other)
        return self > other or self == other

    def __le__(self, other: "VersionType"):
        other = get_semver(other)
        return (not self > other) or self == other

    def __lt__(self, other: "VersionType"):
        other = get_semver(other)
        if (
            self.build != other.build
        ):  # we don't care about build equality for less than
            other = SemVer(other.major, other.minor, other.patch, other.prerelease)
        return not self >= other


# Anything that can be passed in as a version
VersionType = Union[str, int, SemVer, Tuple[int, int, int]]


def get_semver(version: Optional[VersionType]) -> SemVer:
    if isinstance(version, SemVer):
        return version
    elif isinstance(version, tuple):
        return SemVer(*version)
    elif isinstance(version, int):
        # Return SemVer with major version only if version is an integer
        return SemVer(version)
    elif version is None:
        # Return empty SemVer if version is None or empty string
        return SemVer(0, 0, 0)

    # Otherwise, parse the version string
    parts = version.split(".", 2)
    major, minor, patch = 0, 0, 0
    prerelease = None
    build = None
    if len(parts) > 0:
        major = int(parts[0])
    if len(parts) > 1:
        minor = int(parts[1])
    # Patch + prerelease + build
    if len(parts) > 2:
        patch = parts[2]
        # Get prerelease (if exists)
        try:
            patch, prerelease = patch.split("-", 1)
        except:
            pass
        # Get build info (if exists)
        try:
            if prerelease:
                prerelease, build = prerelease.split("+", 1)
            else:
                patch, build = patch.split("+", 1)
        except:
            pass
        patch = int(patch)
    return SemVer(major, minor, patch, prerelease, build)
