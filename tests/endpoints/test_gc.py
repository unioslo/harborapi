from contextlib import nullcontext
from typing import List

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.exceptions import StatusError
from harborapi.models.models import GCHistory, Schedule

from ..strategies.artifact import get_hbv_strategy
from ..utils import json_from_list


@pytest.mark.asyncio
@given(st.builds(Schedule))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_gc_schedule_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    schedule: Schedule,
):
    async_client.url = httpserver.url_for("/api/v2.0")
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/gc/schedule",
        method="GET",
    ).respond_with_data(schedule.json(), content_type="application/json")
    resp = await async_client.get_gc_schedule()
    assert resp == schedule


@pytest.mark.asyncio
@given(st.builds(Schedule))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_gc_schedule_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    schedule: Schedule,
):
    expect_location = "/api/v2.0/system/gc/schedule"  # idk?
    async_client.url = httpserver.url_for("/api/v2.0")
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/gc/schedule",
        method="POST",
        json=schedule.dict(),
    ).respond_with_data(
        headers={"Location": expect_location},
        status=201,
    )
    location = await async_client.create_gc_schedule(schedule)
    assert location == expect_location


@pytest.mark.asyncio
@given(st.builds(Schedule))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_gc_schedule_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    schedule: Schedule,
):
    async_client.url = httpserver.url_for("/api/v2.0")
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/gc/schedule",
        method="PUT",
        json=schedule.dict(),
    ).respond_with_data()
    await async_client.update_gc_schedule(schedule)


@pytest.mark.asyncio
@given(st.lists(st.builds(GCHistory)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_gc_jobs_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    jobs: List[GCHistory],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/gc",
        method="GET",
    ).respond_with_data(
        json_from_list(jobs),
        content_type="application/json",
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_gc_jobs()
    assert resp == jobs


@pytest.mark.asyncio
@given(st.builds(GCHistory))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_gc_job_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    job: GCHistory,
):
    job.id = 123
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/gc/123",
        method="GET",
    ).respond_with_data(
        job.json(),
        content_type="application/json",
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_gc_job(123)
    assert resp == job


@pytest.mark.asyncio
@pytest.mark.parametrize("as_list", [True, False])
@given(st.text())
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_gc_log_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    as_list: bool,
    log: str,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/system/gc/123/log",
        method="GET",
    ).respond_with_data(
        log,
        content_type="text/plain",
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_gc_log(123, as_list=as_list)
    if as_list:
        assert isinstance(resp, list)
        assert resp == log.splitlines()
        assert len(resp) == len(log.splitlines())
        # any other reasonable assertions?
    else:
        assert resp == log


# @pytest.mark.asyncio
# async def test_get_artifact_vulnerabilities_empty_mock(
#     async_client: HarborAsyncClient,
#     httpserver: HTTPServer,
# ):
#     """Tests that an empty response is handled correctly.

#     Empty responses can occur when the server does not have a report for
#     the given MIME type.
#     """
#     httpserver.expect_oneshot_request(
#         "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/additions/vulnerabilities",
#         method="GET",
#     ).respond_with_json({})

#     async_client.url = httpserver.url_for("/api/v2.0")
#     r = await async_client.get_artifact_vulnerabilities(
#         "testproj", "testrepo", "latest"
#     )
#     assert r == None


# @pytest.mark.asyncio
# @given(st.lists(st.builds(Tag)))
# @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
# async def test_get_artifact_tags_mock(
#     async_client: HarborAsyncClient,
#     httpserver: HTTPServer,
#     tags: List[Tag],
# ):
#     httpserver.expect_oneshot_request(
#         "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/tags",
#         method="GET",
#     ).respond_with_data(
#         json_from_list(tags),
#         headers={"Content-Type": "application/json"},
#     )
#     async_client.url = httpserver.url_for("/api/v2.0")
#     tags_resp = await async_client.get_artifact_tags("testproj", "testrepo", "latest")
#     # TODO: test params
#     assert tags_resp == tags
#     for tag in tags_resp:
#         assert isinstance(tag, Tag)


# @pytest.mark.asyncio
# @given(st.lists(st.builds(Accessory)))
# @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
# async def test_get_artifact_accessories_mock(
#     async_client: HarborAsyncClient,
#     httpserver: HTTPServer,
#     accessories: List[Accessory],
# ):
#     httpserver.expect_oneshot_request(
#         "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/accessories",
#         method="GET",
#     ).respond_with_data(
#         json_from_list(accessories),
#         headers={"Content-Type": "application/json"},
#     )
#     async_client.url = httpserver.url_for("/api/v2.0")
#     accessories_resp = await async_client.get_artifact_accessories(
#         "testproj", "testrepo", "latest"
#     )
#     assert accessories_resp == accessories
#     for accessory in accessories_resp:
#         assert isinstance(accessory, Accessory)


# @pytest.mark.asyncio
# @pytest.mark.parametrize("status_code", [200, 404])
# @pytest.mark.parametrize("missing_ok", [True, False])
# async def test_delete_artifact_tag(
#     async_client: HarborAsyncClient,
#     httpserver: HTTPServer,
#     status_code: int,
#     missing_ok: bool,
# ):
#     httpserver.expect_oneshot_request(
#         "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/tags/123",
#         method="DELETE",
#     ).respond_with_data(status=status_code)
#     async_client.url = httpserver.url_for("/api/v2.0")
#     if status_code == 404 and not missing_ok:
#         ctx = pytest.raises(StatusError)
#     else:
#         ctx = nullcontext()  # type: ignore
#     with ctx:
#         await async_client.delete_artifact_tag(
#             "testproj", "testrepo", "latest", "123", missing_ok=missing_ok
#         )


# @pytest.mark.asyncio
# async def test_copy_artifact(
#     async_client: HarborAsyncClient,
#     httpserver: HTTPServer,
# ):
#     httpserver.expect_oneshot_request(
#         "/api/v2.0/projects/testproj/repositories/testrepo/artifacts",
#         query_string={"from": "oldproj/oldrepo:oldtag"},
#         method="POST",
#     ).respond_with_data(status=201, headers={"Location": "/api/v2.0/artifacts/123"})
#     async_client.url = httpserver.url_for("/api/v2.0")

#     location = await async_client.copy_artifact(
#         "testproj",
#         "testrepo",
#         "oldproj/oldrepo:oldtag",
#     )
#     assert location == "/api/v2.0/artifacts/123"


# @pytest.mark.asyncio
# @given(st.lists(st.builds(Artifact)))
# @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
# async def test_get_artifacts_mock(
#     async_client: HarborAsyncClient,
#     httpserver: HTTPServer,
#     artifacts: List[Artifact],
# ):
#     httpserver.expect_oneshot_request(
#         "/api/v2.0/projects/testproj/repositories/testrepo/artifacts",
#         method="GET",
#     ).respond_with_data(
#         json_from_list(artifacts),
#         headers={"Content-Type": "application/json"},
#     )
#     async_client.url = httpserver.url_for("/api/v2.0")
#     accessories_resp = await async_client.get_artifacts(
#         "testproj",
#         "testrepo",
#     )
#     # TODO: add params tests
#     assert accessories_resp == artifacts
#     for accessory in accessories_resp:
#         assert isinstance(accessory, Artifact)


# @pytest.mark.asyncio
# @given(st.builds(Label))
# @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
# async def test_add_artifact_label_mock(
#     async_client: HarborAsyncClient,
#     httpserver: HTTPServer,
#     label: Label,
# ):
#     httpserver.expect_oneshot_request(
#         "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/labels",
#         method="POST",
#         json=label.dict(),
#     ).respond_with_data()
#     async_client.url = httpserver.url_for("/api/v2.0")
#     await async_client.add_artifact_label(
#         "testproj",
#         "testrepo",
#         "latest",
#         label,
#     )


# @pytest.mark.asyncio
# @given(st.builds(Artifact))
# @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
# async def test_get_artifact_mock(
#     async_client: HarborAsyncClient,
#     httpserver: HTTPServer,
#     artifact: Artifact,
# ):
#     httpserver.expect_oneshot_request(
#         "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest",
#         method="GET",
#     ).respond_with_data(
#         artifact.json(),
#         headers={"Content-Type": "application/json"},
#     )
#     async_client.url = httpserver.url_for("/api/v2.0")
#     # TODO: test params
#     resp = await async_client.get_artifact(
#         "testproj",
#         "testrepo",
#         "latest",
#     )
#     assert resp == artifact


# @pytest.mark.asyncio
# @pytest.mark.parametrize("missing_ok", [True, False])
# @pytest.mark.parametrize("status_code", [200, 404])
# async def test_delete_artifact_mock(
#     async_client: HarborAsyncClient,
#     httpserver: HTTPServer,
#     missing_ok: bool,
#     status_code: int,
# ):
#     httpserver.expect_oneshot_request(
#         "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest",
#         method="DELETE",
#     ).respond_with_data(
#         status=status_code,
#     )

#     async_client.url = httpserver.url_for("/api/v2.0")
#     if status_code == 404 and not missing_ok:
#         ctx = pytest.raises(StatusError)
#     else:
#         ctx = nullcontext()  # type: ignore
#     with ctx:
#         await async_client.delete_artifact(
#             "testproj", "testrepo", "latest", missing_ok=missing_ok
#         )


# @pytest.mark.asyncio
# @pytest.mark.parametrize("missing_ok", [True, False])
# @pytest.mark.parametrize("status_code", [200, 404])
# async def test_delete_artifact_label_mock(
#     async_client: HarborAsyncClient,
#     httpserver: HTTPServer,
#     missing_ok: bool,
#     status_code: int,
# ):
#     httpserver.expect_oneshot_request(
#         "/api/v2.0/projects/testproj/repositories/testrepo/artifacts/latest/labels/123",
#         method="DELETE",
#     ).respond_with_data(
#         status=status_code,
#     )

#     async_client.url = httpserver.url_for("/api/v2.0")
#     if status_code == 404 and not missing_ok:
#         ctx = pytest.raises(StatusError)
#     else:
#         ctx = nullcontext()  # type: ignore
#     with ctx:
#         await async_client.delete_artifact_label(
#             "testproj", "testrepo", "latest", 123, missing_ok=missing_ok
#         )
