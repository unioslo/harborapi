from typing import List, Optional

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import ReplicationExecution, ReplicationPolicy, ReplicationTask

from ..utils import json_from_list


@pytest.mark.asyncio
@given(st.builds(ReplicationExecution))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_replication_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    replication: ReplicationExecution,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/replication/executions/1234", method="GET"
    ).respond_with_data(replication.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_replication(1234)
    assert resp == replication


@pytest.mark.asyncio
async def test_start_replication_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    ex = {"policy_id": 1234}
    httpserver.expect_oneshot_request(
        "/api/v2.0/replication/executions",
        method="POST",
        json=ex,
    ).respond_with_data(
        headers={"Location": "http://localhost/api/v2.0/replication/executions/1234"}
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.start_replication(1234)
    assert resp == "http://localhost/api/v2.0/replication/executions/1234"


@pytest.mark.asyncio
async def test_stop_replication(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/replication/executions/1234", method="PUT"
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.stop_replication(1234)


@pytest.mark.asyncio
@given(st.lists(st.builds(ReplicationExecution)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_replications_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    replications: List[ReplicationExecution],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/replication/executions", method="GET"
    ).respond_with_data(
        json_from_list(replications),
        content_type="application/json",
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_replications()
    assert resp == replications


@pytest.mark.asyncio
@given(st.lists(st.builds(ReplicationTask)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_replication_tasks_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    replications: List[ReplicationTask],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/replication/executions/1234/tasks", method="GET"
    ).respond_with_data(
        json_from_list(replications),
        content_type="application/json",
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_replication_tasks(1234)
    assert resp == replications


@pytest.mark.asyncio
async def test_get_replication_task_log(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/replication/executions/1234/tasks/567/log", method="GET"
    ).respond_with_data(
        "logline1\nlogline2",
        content_type="text/plain",
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_replication_task_log(1234, 567)
    assert resp == "logline1\nlogline2"


@pytest.mark.asyncio
@given(st.builds(ReplicationPolicy))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_replication_policy(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    policy: ReplicationPolicy,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/replication/policies/1234", method="GET"
    ).respond_with_data(
        policy.json(),
        content_type="application/json",
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_replication_policy(1234)
    assert resp == policy


@pytest.mark.asyncio
@given(st.builds(ReplicationPolicy))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_replication_policy(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    policy: ReplicationPolicy,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/replication/policies",
        method="POST",
        json=policy.dict(exclude_unset=True),
    ).respond_with_data(
        headers={
            "Location": "http://localhost:8080/api/v2.0/replication/policies/1234"
        },
        status=201,
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.create_replication_policy(policy)
    assert resp == "http://localhost:8080/api/v2.0/replication/policies/1234"


@pytest.mark.asyncio
@given(st.builds(ReplicationPolicy))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_replication_policy(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    policy: ReplicationPolicy,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/replication/policies/1234",
        method="PUT",
        json=policy.dict(exclude_unset=True),
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_replication_policy(1234, policy)


@pytest.mark.asyncio
async def test_delete_replication_policy(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/replication/policies/1234",
        method="DELETE",
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.delete_replication_policy(1234)


@pytest.mark.asyncio
@given(st.lists(st.builds(ReplicationPolicy)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_replication_policies(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    policies: List[ReplicationPolicy],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/replication/policies", method="GET"
    ).respond_with_data(
        json_from_list(policies),
        content_type="application/json",
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_replication_policies()
    assert resp == policies
