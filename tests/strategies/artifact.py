from hypothesis import strategies as st

from harborapi.models.models import (
    Accessory,
    AdditionLinks,
    Annotations,
    Artifact,
    ExtraAttrs,
    Label,
    ScanOverview,
    Tag,
)
from harborapi.models.scanner import (
    HarborVulnerabilityReport,
    ScanArtifact,
    Scanner,
    Severity,
    VulnerabilityItem,
)

tag_strategy = st.builds(
    Tag,
    id=st.integers(),
    repository_id=st.integers(),
    artifact_id=st.integers(),
    name=st.text(),
    push_time=st.datetimes(),
    pull_time=st.datetimes(),
    immutable=st.booleans(),
    signed=st.booleans(),
)

artifact_strategy = st.builds(
    Artifact,
    id=st.integers(),
    type=st.one_of(st.sampled_from(["image", "chart"]), st.text()),
    # TODO: investiate proper values for this field
    manifest_media_type=st.sampled_from(
        ["application/vnd.docker.distribution.manifest.v2+json"]
    ),
    # TODO: add other possible mime types
    media_type=st.sampled_from(
        ["application/vnd.docker.distribution.manifest.v2+json"]
    ),
    project_id=st.integers(),
    repository_id=st.integers(),
    digest=st.text(),
    size=st.integers(),
    icon=st.one_of(st.text(), st.none()),
    push_time=st.datetimes(),
    pull_time=st.datetimes(),
    annotations=st.builds(Annotations),
    extra_attrs=st.builds(ExtraAttrs),
    tags=st.lists(tag_strategy, min_size=1),
    addition_links=st.builds(AdditionLinks),
    labels=st.lists(st.builds(Label)),
    scan_overview=st.builds(ScanOverview),
    accessories=st.lists(st.builds(Accessory)),
)
artifact_or_none_strategy = st.one_of(st.none(), artifact_strategy)

scanner_trivy_strategy = st.builds(
    Scanner,
    name=st.just("Trivy"),
    vendor=st.just("Aqua Security"),
    version=st.text(),
)

# TODO: test with other scanners + random values
#       We rely on using "Trivy" as the scanner name in certain tests
#       Especially in tests/models/test_scanner.py
#       This is because the scanner name is used to retrieve the CVSS score
#       from the vulnerability item.
scanner_strategy = st.one_of(
    st.none(),
    scanner_trivy_strategy,
)


def get_vulnerability_item_strategy() -> st.SearchStrategy[VulnerabilityItem]:
    return st.builds(
        VulnerabilityItem,
        id=st.integers(),
        package=st.text(),
        version=st.text(),  # should major.minor.patch
        fix_version=st.text(),
        severity=st.sampled_from(Severity),
    )


def get_hbv_strategy() -> st.SearchStrategy[HarborVulnerabilityReport]:
    # TODO: add other possible mime types
    # TODO: add parameter for CVSS type to pass to get_vulnerability_item_strategy
    return st.builds(
        HarborVulnerabilityReport,
        generated_at=st.datetimes(),
        artifact=st.builds(ScanArtifact),
        scanner=scanner_strategy,
        vulnerabilities=st.lists(get_vulnerability_item_strategy()),
    )
