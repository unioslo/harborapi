from hypothesis import strategies as st

from harborapi.models.scanner import (
    Artifact,
    HarborVulnerabilityReport,
    Scanner,
    Severity,
    VulnerabilityItem,
)

artifact_strategy = st.one_of(
    st.none(),
    st.builds(
        Artifact,
        repository=st.text(),
        digest=st.text(),
        tag=st.text(),
        # TODO: add other possible mime types
        mime_type=st.sampled_from(
            ["application/vnd.docker.distribution.manifest.v2+json"]
        ),
    ),
)

scanner_strategy = st.one_of(
    st.none(),
    st.builds(
        Scanner,
        name=st.text(),
        vendor=st.text(),
        version=st.text(),  # should major.minor.patch
    ),
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
        artifact=artifact_strategy,
        scanner=scanner_strategy,
        vulnerabilities=st.lists(get_vulnerability_item_strategy()),
    )
