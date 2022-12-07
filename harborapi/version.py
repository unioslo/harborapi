from typing import NamedTuple, Optional, Tuple, Union


class SemVer(NamedTuple):
    major: int
    minor: int = 0
    patch: int = 0
    prerelease: Optional[str] = None
    build: Optional[str] = None

    def __bool__(self) -> bool:
        return bool(self.major or self.minor or self.patch)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            raise TypeError(f"Cannot compare {type(self)} with {type(other)}")
        other = get_semver(other)
        return (
            self.major == other.major
            and self.minor == other.minor
            and self.patch == other.patch
            and self.prerelease == other.prerelease
            and self.build == other.build
        )

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            raise TypeError(f"Cannot compare {type(self)} with {type(other)}")
        other = get_semver(other)
        if self.major > other.major:
            return True
        if self.major < other.major:
            return False
        if self.minor > other.minor:
            return True
        if self.minor < other.minor:
            return False
        if self.patch > other.patch:
            return True
        if self.patch < other.patch:
            return False
        # A non-prerelease version is always greater than a prerelease version
        if self.prerelease is None and other.prerelease is not None:
            return True
        return False

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            raise TypeError(f"Cannot compare {type(self)} with {type(other)}")
        other = get_semver(other)
        return self > other or self == other

    def __le__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            raise TypeError(f"Cannot compare {type(self)} with {type(other)}")
        other = get_semver(other)
        return (not self > other) or self == other

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, SemVer):
            raise TypeError(f"Cannot compare {type(self)} with {type(other)}")
        other = get_semver(other)
        if (
            self.build != other.build
        ):  # we don't care about build equality for less than
            other = SemVer(other.major, other.minor, other.patch, other.prerelease)
        return not self >= other


# Anything that can be passed in as a version
VersionType = Union[str, int, SemVer, Tuple[int, int, int]]


def clean_version_number(version: str, default: int = 0) -> int:
    """Ignore characters after non-numeric chars in patch (e.g. 3a4 -> 3)

    These characters are completely discarded, and as such, this function
    is not appropriate if full version info from version schemes other than
    SemVer are needed.

    Parameters
    ----------
    version : str
        The version string to clean.
    default : int
        The default value to return if the version string is empty or
        contains only non-numeric characters, by default 0

    Returns
    -------
    int
        The version number as an integer
    """

    v = []
    for c in version:
        if c.isnumeric():
            v.append(c)
        else:
            break
    try:
        return int("".join(v))
    except:  # noqa: E722
        return default


def get_semver(version: Optional[VersionType]) -> SemVer:
    if isinstance(version, SemVer):
        return version
    elif isinstance(version, tuple):
        for i, v in enumerate(version):
            # first 3 values are major, minor, patch
            if i <= 2:
                if not isinstance(v, int):
                    raise ValueError(
                        f"Version tuple must contain integers, got {version}"
                    )
                elif v < 0:
                    raise ValueError(
                        f"Version tuple must contain positive integers, got {version}"
                    )
            try:
                return SemVer(*version)
            except Exception as e:
                raise ValueError(f"Invalid version {version}: {e}")
        else:
            raise ValueError(f"Invalid semver tuple: {version}")
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
        major = clean_version_number(parts[0])
    if len(parts) > 1:
        minor = clean_version_number(parts[1])
    # Patch + prerelease + build
    if len(parts) > 2:
        patch = parts[2]
        # Get prerelease (if exists)
        try:
            patch, prerelease = patch.split("-", 1)
        except:  # noqa: E722
            pass
        # Get build info (if exists)
        try:
            if prerelease:
                prerelease, build = prerelease.split("+", 1)
            else:
                patch, build = patch.split("+", 1)
        except:  # noqa: E722
            pass
        patch = clean_version_number(patch)

    return SemVer(major, minor, patch, prerelease, build)
