from typing import List

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import (
    SupportedWebhookEventTypes,
    WebhookJob,
    WebhookLastTrigger,
    WebhookPolicy,
)

from ..utils import json_from_list


@pytest.mark.asyncio
@given(st.lists(st.builds(WebhookJob)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_webhook_jobs_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    jobs: List[WebhookJob],
):
    project_id = 123
    policy_id = 456
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_id}/webhook/jobs",
        method="GET",
        query_string=f"policy_id={policy_id}&page=1&page_size=10",
        headers={"X-Is-Resource-Name": "false"},
    ).respond_with_data(
        json_from_list(jobs),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_webhook_jobs(project_id, policy_id)
    assert resp == jobs


@pytest.mark.asyncio
@given(st.builds(WebhookPolicy))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_webhook_policy_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    policy: WebhookPolicy,
):
    project_id = 123
    expect_location = "/api/v2.0/projects/123/webhook/policies/456"
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_id}/webhook/policies",
        method="POST",
        headers={"X-Is-Resource-Name": "false"},
    ).respond_with_data(
        headers={"Location": "/api/v2.0/projects/123/webhook/policies/456"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.create_webhook_policy(project_id, policy)
    assert resp == expect_location


@pytest.mark.asyncio
@given(st.lists(st.builds(WebhookPolicy)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_webhook_policies_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    policies: List[WebhookPolicy],
):
    project_id = 123
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_id}/webhook/policies",
        method="GET",
        headers={"X-Is-Resource-Name": "false"},
    ).respond_with_data(
        json_from_list(policies),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_webhook_policies(project_id)
    assert resp == policies


@pytest.mark.asyncio
@given(st.builds(SupportedWebhookEventTypes))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_webhook_supported_events_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    events: SupportedWebhookEventTypes,
):
    project_id = 123
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_id}/webhook/events",
        method="GET",
        headers={"X-Is-Resource-Name": "false"},
    ).respond_with_data(events.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_webhook_supported_events(project_id)
    assert resp == events


@pytest.mark.asyncio
@given(st.lists(st.builds(WebhookLastTrigger)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_webhook_policy_last_trigger_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    triggers: List[WebhookLastTrigger],
):
    project_id = 123
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_id}/webhook/lasttrigger",
        method="GET",
        headers={"X-Is-Resource-Name": "false"},
    ).respond_with_data(
        json_from_list(triggers),
        headers={"Content-Type": "application/json"},
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_webhook_policy_last_trigger(project_id)
    assert resp == triggers


@pytest.mark.asyncio
@given(st.builds(WebhookPolicy))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_webhook_policy_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    policy: WebhookPolicy,
):
    project_id = 123
    policy_id = 456
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_id}/webhook/policies/{policy_id}",
        method="PUT",
        headers={"X-Is-Resource-Name": "false"},
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_webhook_policy(project_id, policy_id, policy)


@pytest.mark.asyncio
@given(st.builds(WebhookPolicy))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_webhook_policy_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    policy: WebhookPolicy,
):
    project_id = 123
    policy_id = 456
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_id}/webhook/policies/{policy_id}",
        method="GET",
        headers={"X-Is-Resource-Name": "false"},
    ).respond_with_data(policy.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_webhook_policy(project_id, policy_id)
    assert resp == policy


@pytest.mark.asyncio
@given(st.builds(WebhookPolicy))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_delete_webhook_policy_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    policy: WebhookPolicy,
):
    project_id = 123
    policy_id = 456
    httpserver.expect_oneshot_request(
        f"/api/v2.0/projects/{project_id}/webhook/policies/{policy_id}",
        method="DELETE",
        headers={"X-Is-Resource-Name": "false"},
    ).respond_with_data(policy.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.delete_webhook_policy(project_id, policy_id)
