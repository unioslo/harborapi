from contextlib import nullcontext
from typing import List

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.exceptions import StatusError
from harborapi.models import HarborVulnerabilityReport
from harborapi.models.buildhistory import BuildHistoryEntry
from harborapi.models.models import Accessory, Artifact, Label, Tag

from ..strategies.artifact import artifact_strategy, get_hbv_strategy
from ..utils import json_from_list


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [200, 201])
@given(st.builds(Tag))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_artifact_tag_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    caplog: pytest.LogCaptureFixture,
    status_code: int,
    tag: Tag,
):
    async_client.url = httpserver.url_for("/api/v2.0")
    expect_location = (
        async_client.url
        + "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/tags/123"
    )
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/tags",
        method="POST",
        json=tag.dict(exclude_unset=True),
    ).respond_with_data(
        headers={"Location": expect_location},
        status=status_code,
    )
    location = await async_client.create_artifact_tag(
        "testproj", "testrepo", "latest", tag
    )
    assert location == expect_location
    if status_code == 200:
        assert "expected 201" in caplog.text


@pytest.mark.asyncio
@given(get_hbv_strategy())
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_artifact_vulnerabilities_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    report: HarborVulnerabilityReport,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/additions/vulnerabilities",
        method="GET",
    ).respond_with_data(
        # use report.json() to avoid datetime serialization issues
        '{{"application/vnd.security.vulnerability.report; version=1.1": {r}}}'.format(
            r=report.json()
        ),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    r = await async_client.get_artifact_vulnerabilities(
        "testproj", "testrepo", "latest"
    )
    # TODO: specify MIME type when testing?
    assert r == report


@pytest.mark.asyncio
@given(st.lists(st.builds(BuildHistoryEntry)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_artifact_build_history_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    build_history: List[BuildHistoryEntry],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/additions/build_history",
        method="GET",
    ).respond_with_data(
        json_from_list(build_history),
        content_type="application/json",
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_artifact_build_history(
        "testproj", "testrepo", "latest"
    )
    assert build_history == resp


@pytest.mark.asyncio
async def test_get_artifact_vulnerabilities_empty_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    """Tests that an empty response is handled correctly.

    Empty responses can occur when the server does not have a report for
    the given MIME type.
    """
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/additions/vulnerabilities",
        method="GET",
    ).respond_with_json({})

    async_client.url = httpserver.url_for("/api/v2.0")
    r = await async_client.get_artifact_vulnerabilities(
        "testproj", "testrepo", "latest"
    )
    assert r == None


@pytest.mark.asyncio
@given(st.lists(st.builds(Tag)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_artifact_tags_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    tags: List[Tag],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/tags",
        method="GET",
    ).respond_with_data(
        json_from_list(tags),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    tags_resp = await async_client.get_artifact_tags("testproj", "testrepo", "latest")
    # TODO: test params
    assert tags_resp == tags
    for tag in tags_resp:
        assert isinstance(tag, Tag)


@pytest.mark.asyncio
@given(st.lists(st.builds(Accessory)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_artifact_accessories_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    accessories: List[Accessory],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/accessories",
        method="GET",
    ).respond_with_data(
        json_from_list(accessories),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    accessories_resp = await async_client.get_artifact_accessories(
        "testproj", "testrepo", "latest"
    )
    assert accessories_resp == accessories
    for accessory in accessories_resp:
        assert isinstance(accessory, Accessory)


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [200, 404])
@pytest.mark.parametrize("missing_ok", [True, False])
async def test_delete_artifact_tag(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    status_code: int,
    missing_ok: bool,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/tags/123",
        method="DELETE",
    ).respond_with_data(status=status_code)
    async_client.url = httpserver.url_for("/api/v2.0")
    if status_code == 404 and not missing_ok:
        ctx = pytest.raises(StatusError)
    else:
        ctx = nullcontext()  # type: ignore
    with ctx:
        await async_client.delete_artifact_tag(
            "testproj", "testrepo", "latest", "123", missing_ok=missing_ok
        )


@pytest.mark.asyncio
async def test_copy_artifact(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts",
        query_string={"from": "oldproj/oldrepo:oldtag"},
        method="POST",
    ).respond_with_data(status=201, headers={"Location": "/api/v2.0/artifacts/123"})
    async_client.url = httpserver.url_for("/api/v2.0")

    location = await async_client.copy_artifact(
        "testproj",
        "testrepo",
        "oldproj/oldrepo:oldtag",
    )
    assert location == "/api/v2.0/artifacts/123"


@pytest.mark.asyncio
@given(st.lists(artifact_strategy))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_artifacts_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    artifacts: List[Artifact],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts",
        method="GET",
    ).respond_with_data(
        json_from_list(artifacts),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    accessories_resp = await async_client.get_artifacts(
        "testproj",
        "testrepo",
    )
    # TODO: add params tests
    assert accessories_resp == artifacts
    for accessory in accessories_resp:
        assert isinstance(accessory, Artifact)


@pytest.mark.asyncio
@given(st.builds(Label))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_add_artifact_label_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    label: Label,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/labels",
        method="POST",
        json=label.dict(exclude_unset=True),
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.add_artifact_label(
        "testproj",
        "testrepo",
        "latest",
        label,
    )


@pytest.mark.asyncio
@given(artifact_strategy)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_artifact_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    artifact: Artifact,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest",
        method="GET",
    ).respond_with_data(
        artifact.json(),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    # TODO: test params
    resp = await async_client.get_artifact(
        "testproj",
        "testrepo",
        "latest",
    )
    assert resp == artifact


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_ok", [True, False])
@pytest.mark.parametrize("status_code", [200, 404])
async def test_delete_artifact_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    missing_ok: bool,
    status_code: int,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest",
        method="DELETE",
    ).respond_with_data(
        status=status_code,
    )

    async_client.url = httpserver.url_for("/api/v2.0")
    if status_code == 404 and not missing_ok:
        ctx = pytest.raises(StatusError)
    else:
        ctx = nullcontext()  # type: ignore
    with ctx:
        await async_client.delete_artifact(
            "testproj", "testrepo", "latest", missing_ok=missing_ok
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("missing_ok", [True, False])
@pytest.mark.parametrize("status_code", [200, 404])
async def test_delete_artifact_label_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    missing_ok: bool,
    status_code: int,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/labels/123",
        method="DELETE",
    ).respond_with_data(
        status=status_code,
    )

    async_client.url = httpserver.url_for("/api/v2.0")
    if status_code == 404 and not missing_ok:
        ctx = pytest.raises(StatusError)
    else:
        ctx = nullcontext()  # type: ignore
    with ctx:
        await async_client.delete_artifact_label(
            "testproj", "testrepo", "latest", 123, missing_ok=missing_ok
        )
