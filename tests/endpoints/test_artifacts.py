from __future__ import annotations

from contextlib import nullcontext
from typing import List

import pytest
from hypothesis import given
from hypothesis import HealthCheck
from hypothesis import settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from ..strategies.artifact import artifact_strategy
from ..strategies.artifact import get_hbv_strategy
from ..utils import json_from_list
from harborapi.client import HarborAsyncClient
from harborapi.exceptions import NotFound
from harborapi.exceptions import StatusError
from harborapi.exceptions import UnprocessableEntity
from harborapi.models import HarborVulnerabilityReport
from harborapi.models.buildhistory import BuildHistoryEntry
from harborapi.models.models import Accessory
from harborapi.models.models import Artifact
from harborapi.models.models import Label
from harborapi.models.models import Tag


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
        json=tag.model_dump(exclude_unset=True),
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
        # use report.model_dump_json() to avoid datetime serialization issues
        '{{"application/vnd.security.vulnerability.report; version=1.1": {r}}}'.format(
            r=report.model_dump_json()
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

    with pytest.raises(NotFound):
        await async_client.get_artifact_vulnerabilities(
            "testproj", "testrepo", "latest"
        )


@pytest.mark.asyncio
async def test_get_artifact_vulnerabilities_nondict_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    """Tests that requesting a report and receiving a non-dict response
    is handled correctly. In the method, we manually get the report for
    the given MIME type, so the response should always be a dict.

    This is different from most other endpoints, since we don't wholly
    rely on construct_model to do all the work for us.
    """
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/additions/vulnerabilities",
        method="GET",
    ).respond_with_json([{"MIME_TYPE_HERE": {"foo": "bar"}}])
    async_client.url = httpserver.url_for("/api/v2.0")

    with pytest.raises(UnprocessableEntity):
        await async_client.get_artifact_vulnerabilities(
            "testproj", "testrepo", "latest"
        )


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
async def test_delete_artifact_tag(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    status_code: int,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/tags/123",
        method="DELETE",
    ).respond_with_data(status=status_code)
    async_client.url = httpserver.url_for("/api/v2.0")
    if status_code == 404:
        ctx = pytest.raises(StatusError)
    else:
        ctx = nullcontext()  # type: ignore
    with ctx:
        await async_client.delete_artifact_tag("testproj", "testrepo", "latest", "123")


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [200, 201])
async def test_copy_artifact(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    caplog: pytest.LogCaptureFixture,
    status_code: int,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts",
        query_string={"from": "oldproj/oldrepo:oldtag"},
        method="POST",
    ).respond_with_data(
        status=status_code, headers={"Location": "/api/v2.0/artifacts/123"}
    )
    async_client.url = httpserver.url_for("/api/v2.0")

    location = await async_client.copy_artifact(
        "testproj",
        "testrepo",
        "oldproj/oldrepo:oldtag",
    )
    assert location == "/api/v2.0/artifacts/123"
    if status_code == 200:
        assert "expected 201" in caplog.text


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
    resp = await async_client.get_artifacts(
        "testproj",
        "testrepo",
    )
    # FIXME: when we dump a model with a ScanOverview that has an empty
    # root value, the resulting JSON is "scan_overview": null
    # And when that is parsed with Pydantic again, we get an object with
    # scan_overview = None, which can't be comapred with the original.
    # To that end, we have to dump both the original and the response
    # and compare the dicts instead. This is very clunky, and was
    # not a problem in Pydantic V1
    assert [a.model_dump() for a in resp] == [a.model_dump() for a in artifacts]


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
        json=label.model_dump(exclude_unset=True),
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
        artifact.model_dump_json(),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    # TODO: test params
    resp = await async_client.get_artifact(
        "testproj",
        "testrepo",
        "latest",
    )
    # See FIXME in test_get_artifacts_mock
    assert resp.model_dump() == artifact.model_dump()


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [200, 404])
async def test_delete_artifact_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    status_code: int,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest",
        method="DELETE",
    ).respond_with_data(
        status=status_code,
    )

    async_client.url = httpserver.url_for("/api/v2.0")
    if status_code == 404:
        ctx = pytest.raises(StatusError)
    else:
        ctx = nullcontext()  # type: ignore
    with ctx:
        await async_client.delete_artifact("testproj", "testrepo", "latest")


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [200, 404])
async def test_delete_artifact_label_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    status_code: int,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/labels/123",
        method="DELETE",
    ).respond_with_data(
        status=status_code,
    )

    async_client.url = httpserver.url_for("/api/v2.0")
    if status_code == 404:
        ctx = pytest.raises(StatusError)
    else:
        ctx = nullcontext()  # type: ignore
    with ctx:
        await async_client.delete_artifact_label("testproj", "testrepo", "latest", 123)
