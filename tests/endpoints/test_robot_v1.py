from __future__ import annotations

from typing import List

import pytest
from hypothesis import HealthCheck
from hypothesis import given
from hypothesis import settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models.models import Robot
from harborapi.models.models import RobotCreated
from harborapi.models.models import RobotCreateV1

from ..utils import json_from_list


@pytest.mark.asyncio
@given(st.builds(RobotCreateV1), st.builds(RobotCreated))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_robot_v1_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    robot: RobotCreateV1,
    robot_created: RobotCreated,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/robots",
        method="POST",
        json=robot.model_dump(mode="json", exclude_unset=True),
    ).respond_with_data(
        robot_created.model_dump_json(), content_type="application/json"
    )
    resp = await async_client.create_robot_v1(1234, robot)
    assert resp == robot_created


@pytest.mark.asyncio
@given(st.lists(st.builds(Robot)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_robots_v1_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    robots: List[Robot],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/robots", method="GET"
    ).respond_with_data(json_from_list(robots), content_type="application/json")

    resp = await async_client.get_robots_v1(1234)
    assert resp == robots


@pytest.mark.asyncio
@given(st.builds(Robot))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_robot_v1_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    robot: Robot,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/robots/1", method="GET"
    ).respond_with_data(robot.model_dump_json(), content_type="application/json")

    resp = await async_client.get_robot_v1(1234, 1)
    assert resp == robot


@pytest.mark.asyncio
@given(st.builds(Robot))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_robot_v1_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    robot: Robot,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/robots/1",
        method="PUT",
        json=robot.model_dump(mode="json", exclude_unset=True),
    ).respond_with_data()

    await async_client.update_robot_v1(1234, 1, robot)


@pytest.mark.asyncio
async def test_delete_robot_v1_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/robots/1", method="DELETE"
    ).respond_with_data()

    await async_client.delete_robot_v1(1234, 1)
