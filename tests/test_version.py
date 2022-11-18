import pytest

from harborapi.version import SemVer, get_semver


@pytest.mark.parametrize(
    "version,expected",
    [
        ("1.2.3", SemVer(1, 2, 3)),
        ("1.2.3+build", SemVer(1, 2, 3, build="build")),
        ("1.2.3-alpha", SemVer(1, 2, 3, prerelease="alpha")),
        ("1.2.3-alpha+build", SemVer(1, 2, 3, prerelease="alpha", build="build")),
        ("1.2.3-alpha.1", SemVer(1, 2, 3, prerelease="alpha.1")),
        ("1.2.3-alpha.1+build", SemVer(1, 2, 3, prerelease="alpha.1", build="build")),
    ],
)
def test_get_semver(version: str, expected: SemVer):
    assert get_semver(version) == expected


@pytest.mark.parametrize(
    "version1, version2, expected",
    [
        (SemVer(1, 2, 3), SemVer(1, 2, 3), True),
        (SemVer(1, 2, 3), SemVer(1, 2, 4), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 3, prerelease="alpha"), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 3, build="build"), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 3, prerelease="alpha", build="build"), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 4, prerelease="alpha"), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 4, build="build"), False),
    ],
)
def test_semver_eq(version1: SemVer, version2: SemVer, expected: bool):
    assert (version1 == version2) == expected


@pytest.mark.parametrize(
    "version1, version2,expected",
    [
        (SemVer(1, 2, 3), SemVer(1, 2, 3), True),
        (SemVer(1, 2, 3), SemVer(1, 2, 4), False),
        # no pre-release, greater than pre-release
        (SemVer(1, 2, 3), SemVer(1, 2, 3, prerelease="alpha"), True),
        (SemVer(1, 2, 3), SemVer(1, 2, 3, build="build"), False),
        # no pre-release, greater than pre-release
        (SemVer(1, 2, 3), SemVer(1, 2, 3, prerelease="alpha", build="build"), True),
        (SemVer(1, 2, 3), SemVer(1, 2, 4, prerelease="alpha"), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 4, build="build"), False),
    ],
)
def test_semver_ge(version1: SemVer, version2: SemVer, expected: bool):
    assert (version1 >= version2) == expected


@pytest.mark.parametrize(
    "version1, version2 ,expected",
    [
        (SemVer(1, 2, 3), SemVer(1, 2, 3), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 4), False),
        (SemVer(1, 2, 4), SemVer(1, 2, 3), True),
        (SemVer(1, 2, 3), SemVer(1, 2, 3, prerelease="alpha"), True),
        (SemVer(1, 2, 3), SemVer(1, 2, 3, build="build"), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 3, prerelease="alpha", build="build"), True),
        (SemVer(1, 2, 3, prerelease="alpha"), SemVer(1, 2, 3, build="build"), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 4, prerelease="alpha"), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 4, build="build"), False),
    ],
)
def test_semver_gt(version1: SemVer, version2: SemVer, expected: bool):
    assert (version1 > version2) == expected


@pytest.mark.parametrize(
    "version1, version2,expected",
    [
        (SemVer(1, 2, 3), SemVer(1, 2, 3), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 4), True),
        (SemVer(1, 2, 4), SemVer(1, 2, 3), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 3, prerelease="alpha"), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 3, build="build"), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 3, prerelease="alpha", build="build"), False),
        (SemVer(1, 2, 3, prerelease="alpha"), SemVer(1, 2, 3, build="build"), True),
        (SemVer(1, 2, 3), SemVer(1, 2, 4, prerelease="alpha"), True),
        (SemVer(1, 2, 3), SemVer(1, 2, 4, build="build"), True),
    ],
)
def test_semver_lt(version1: SemVer, version2: SemVer, expected: bool):
    assert (version1 < version2) == expected


@pytest.mark.parametrize(
    "version1, version2,expected",
    [
        (SemVer(1, 2, 3), SemVer(1, 2, 3), True),
        (SemVer(1, 2, 3), SemVer(1, 2, 4), True),
        (SemVer(1, 2, 4), SemVer(1, 2, 3), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 3, prerelease="alpha"), False),
        (SemVer(1, 2, 3), SemVer(1, 2, 3, build="build"), True),
        (SemVer(1, 2, 3), SemVer(1, 2, 3, prerelease="alpha", build="build"), False),
        (SemVer(1, 2, 3, prerelease="alpha"), SemVer(1, 2, 3, build="build"), True),
        (SemVer(1, 2, 3), SemVer(1, 2, 4, prerelease="alpha"), True),
        (SemVer(1, 2, 3), SemVer(1, 2, 4, build="build"), True),
    ],
)
def test_semver_le(version1: SemVer, version2: SemVer, expected: bool):
    assert (version1 <= version2) == expected
