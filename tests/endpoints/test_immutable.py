from __future__ import annotations

from typing import List

import pytest
from hypothesis import HealthCheck
from hypothesis import given
from hypothesis import settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import ImmutableRule

from ..utils import json_from_list


@pytest.mark.asyncio
@given(st.lists(st.builds(ImmutableRule)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_immutable_tag_rules_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    rules: List[ImmutableRule],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/immutabletagrules", method="GET"
    ).respond_with_data(
        json_from_list(rules), headers={"Content-Type": "application/json"}
    )
    resp = await async_client.get_project_immutable_tag_rules(1234)
    assert resp == rules


@pytest.mark.asyncio
@given(st.builds(ImmutableRule))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_project_immutable_tag_rule_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    rule: ImmutableRule,
):
    expect_location = "/api/v2.0/projects/1234/immutabletagrules/1"
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/immutabletagrules",
        method="POST",
        json=rule.model_dump(mode="json", exclude_unset=True),
    ).respond_with_data(headers={"Location": expect_location})
    resp = await async_client.create_project_immutable_tag_rule(1234, rule)
    assert resp == expect_location


@pytest.mark.asyncio
@given(st.builds(ImmutableRule))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_project_immutable_tag_rule_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    rule: ImmutableRule,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/immutabletagrules/1",
        method="PUT",
        json=rule.model_dump(mode="json", exclude_unset=True),
        headers={"X-Is-Resource-Name": "false"},
    ).respond_with_data()

    await async_client.update_project_immutable_tag_rule(1234, 1, rule)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "enable",
    [True, False],
)
async def test_enable_project_immutable_tagrule(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    enable: bool,
):
    """Test updating a rule with only the disabled field set."""
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/immutabletagrules/1",
        method="PUT",
        json={"disabled": not enable},
        headers={"X-Is-Resource-Name": "false"},
    ).respond_with_data()

    await async_client.enable_project_immutable_tagrule(1234, 1, enable)


@pytest.mark.asyncio
async def test_delete_project_immutable_tag_rule_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/immutabletagrules/1",
        method="DELETE",
        headers={"X-Is-Resource-Name": "false"},
    ).respond_with_data()

    await async_client.delete_project_immutable_tag_rule(1234, 1)
