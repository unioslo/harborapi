from typing import List

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import (
    Project,
    ProjectMetadata,
    RetentionExecution,
    RetentionExecutionTask,
    RetentionMetadata,
    RetentionPolicy,
)

from ..utils import json_from_list


@pytest.mark.asyncio
@pytest.mark.parametrize("is_id", [True, False])
@given(st.builds(Project, metadata=st.builds(ProjectMetadata)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_retention_id_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    is_id: bool,
    project: Project,
) -> None:
    expect_id = 456
    project.metadata.retention_id = expect_id

    project_name_or_id = 123 if is_id else "library"
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_name_or_id}",
        method="GET",
        headers={"X-Is-Resource-Name": "false" if is_id else "true"},
    ).respond_with_data(project.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_retention_id(project_name_or_id)
    assert resp == expect_id


@pytest.mark.asyncio
@given(st.builds(RetentionPolicy))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_retention_policy_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    policy: RetentionPolicy,
):
    retention_id = 123
    httpserver.expect_oneshot_request(
        f"/api/v2.0/retentions/{retention_id}",
        method="GET",
    ).respond_with_data(policy.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_retention_policy(retention_id)
    assert resp == policy


@pytest.mark.asyncio
@given(st.builds(RetentionPolicy))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_retention_policy_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    policy: RetentionPolicy,
) -> None:
    expect_location = "/api/v2.0/retentions/123"
    httpserver.expect_oneshot_request(
        f"/api/v2.0/retentions",
        method="POST",
    ).respond_with_data(
        headers={"Location": expect_location},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.create_retention_policy(policy)
    assert resp == expect_location


@pytest.mark.asyncio
@given(st.builds(RetentionPolicy))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_retention_policy_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    policy: RetentionPolicy,
) -> None:
    policy_id = 123
    httpserver.expect_oneshot_request(
        f"/api/v2.0/retentions/{policy_id}",
        method="PUT",
        json=policy.dict(exclude_unset=True),
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_retention_policy(policy_id, policy)


@pytest.mark.asyncio
async def test_delete_retention_policy_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
) -> None:
    policy_id = 123
    httpserver.expect_oneshot_request(
        f"/api/v2.0/retentions/{policy_id}",
        method="DELETE",
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.delete_retention_policy(policy_id)


@pytest.mark.asyncio
@given(st.lists(st.builds(RetentionExecutionTask)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_retention_tasks_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    tasks: List[RetentionExecutionTask],
) -> None:
    policy_id = 123
    execution_id = 456
    httpserver.expect_oneshot_request(
        f"/api/v2.0/retentions/{policy_id}/executions/{execution_id}/tasks",
        method="GET",
        query_string=f"page=1&page_size=10",
    ).respond_with_data(
        json_from_list(tasks),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_retention_tasks(
        policy_id, execution_id, page=1, page_size=10
    )
    assert resp == tasks


@pytest.mark.asyncio
@given(st.builds(RetentionMetadata))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_retention_metadata_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    metadata: RetentionMetadata,
) -> None:
    httpserver.expect_oneshot_request(
        f"/api/v2.0/retentions/metadatas",
        method="GET",
    ).respond_with_data(
        metadata.json(),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_retention_metadata()
    assert resp == metadata


@pytest.mark.asyncio
@given(st.text())
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_retention_execution_task_log_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    log: str,
) -> None:
    retention_id = 123
    execution_id = 456
    task_id = 789
    httpserver.expect_oneshot_request(
        f"/api/v2.0/retentions/{retention_id}/executions/{execution_id}/tasks/{task_id}",
        method="GET",
    ).respond_with_data(log, content_type="text/plain")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_retention_execution_task_log(
        retention_id, execution_id, task_id
    )
    assert resp == log


@pytest.mark.asyncio
@given(st.lists(st.builds(RetentionExecution)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_retention_executions_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    executions: List[RetentionExecution],
) -> None:
    retention_id = 123
    httpserver.expect_oneshot_request(
        f"/api/v2.0/retentions/{retention_id}/executions",
        method="GET",
        query_string=f"page=1&page_size=10",
    ).respond_with_data(
        json_from_list(executions),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_retention_executions(
        retention_id, page=1, page_size=10
    )
    assert resp == executions


@pytest.mark.asyncio
@pytest.mark.parametrize("dry_run", [True, False])
async def test_start_retention_execution_mock(
    async_client: HarborAsyncClient, httpserver: HTTPServer, dry_run: bool
) -> None:
    retention_id = 123
    expect_location = "/api/v2.0/retentions/123/executions/456"
    httpserver.expect_oneshot_request(
        f"/api/v2.0/retentions/{retention_id}/executions",
        method="POST",
        json={"dry_run": dry_run},
    ).respond_with_data(
        headers={"Location": expect_location},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.start_retention_execution(retention_id, dry_run=dry_run)
    assert resp == expect_location


@pytest.mark.asyncio
async def test_stop_retention_execution_mock(
    async_client: HarborAsyncClient, httpserver: HTTPServer
) -> None:
    retention_id = 123
    execution_id = 456
    httpserver.expect_oneshot_request(
        f"/api/v2.0/retentions/{retention_id}/executions/{execution_id}",
        method="PATCH",
        json={"action": "stop"},
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.stop_retention_execution(retention_id, execution_id)
