from typing import List, Optional, Union

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import Quota
from harborapi.models.models import (
    AuditLog,
    Project,
    ProjectDeletable,
    ProjectMember,
    ProjectMemberEntity,
    ProjectReq,
    ProjectSummary,
    RoleRequest,
    ScannerRegistration,
    UserEntity,
    UserGroup,
)
from tests.utils import json_from_list


@pytest.mark.asyncio
async def test_set_project_scanner_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/scanner", method="PUT"
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.set_project_scanner("1234", "myscanner")


@pytest.mark.asyncio
@given(st.builds(ScannerRegistration))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_scanner_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    scanner: ScannerRegistration,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/scanner",
        method="GET",
    ).respond_with_data(scanner.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_scanner("1234")
    assert resp == scanner


@pytest.mark.asyncio
@given(st.lists(st.builds(AuditLog)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_logs_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    logs: List[AuditLog],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/logs", method="GET"
    ).respond_with_data(json_from_list(logs), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_logs("1234")
    assert resp == logs


@pytest.mark.anyio
@pytest.mark.parametrize(
    "status,expected",
    [(200, True), (404, False), (400, False), (500, False)],
)
async def test_project_exists_mock(
    async_client: HarborAsyncClient, httpserver: HTTPServer, status: int, expected: bool
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects", method="HEAD", query_string="project_name=1234"
    ).respond_with_data(status=status)
    async_client.url = httpserver.url_for("/api/v2.0")
    try:
        assert await async_client.project_exists("1234") == expected
    except Exception as e:
        if expected:
            raise e


@pytest.mark.asyncio
@given(st.builds(ProjectReq))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_project_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project: ProjectReq,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects",
        method="POST",
        json=project.dict(exclude_unset=True),
    ).respond_with_data(headers={"Location": "%2Fapi%2Fv2.0%2Fprojects%2F1234"})
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.create_project(project)
    assert resp == "/api/v2.0/projects/1234"


@pytest.mark.asyncio
@given(st.lists(st.builds(Project)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_projects_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    projects: List[Project],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects",
        method="GET",
    ).respond_with_data(json_from_list(projects), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_projects("1234")
    assert resp == projects


@pytest.mark.asyncio
@given(st.builds(ProjectReq))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_update_project_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project: ProjectReq,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234",
        method="PUT",
    ).respond_with_data(project.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_project("1234", project)


@pytest.mark.asyncio
@given(st.builds(Project))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project: Project,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234",
        method="GET",
    ).respond_with_data(project.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project("1234")
    assert resp == project


@pytest.mark.asyncio
async def test_delete_project_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234",
        method="DELETE",
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.delete_project("1234")


@pytest.mark.asyncio
@given(st.lists(st.builds(ScannerRegistration)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_scanner_candidates_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    scanners: List[ScannerRegistration],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/scanner/candidates",
        method="GET",
    ).respond_with_data(json_from_list(scanners), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_scanner_candidates("1234")
    assert resp == scanners


@pytest.mark.asyncio
@given(st.builds(ProjectSummary))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_summary_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    project_summary: ProjectSummary,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/summary",
        method="GET",
    ).respond_with_data(project_summary.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_summary("1234")
    assert resp == project_summary


@pytest.mark.asyncio
@given(st.builds(ProjectDeletable))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_deletable_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    deletable: ProjectDeletable,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/_deletable",
        method="GET",
    ).respond_with_data(deletable.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_deletable("1234")
    assert resp == deletable


@pytest.mark.asyncio
@given(st.builds(ProjectMemberEntity))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_member_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    member: ProjectMemberEntity,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/members/567",
        method="GET",
    ).respond_with_data(member.json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_member("1234", 567)
    assert resp == member


@pytest.mark.asyncio
@given(st.builds(ProjectMember))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_add_project_member_mock_fuzz(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    member: ProjectMember,
):
    """Let Hypothesis generate random ProjectMemberEntity instances"""
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/members",
        method="POST",
    ).respond_with_data(
        status=201
    )  # TODO: header location
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.add_project_member("1234", member)


@pytest.mark.asyncio
async def test_add_project_member_with_user_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    """Tests add_project_member with a ProjectMemberEntity with a member_user"""
    member = ProjectMember(
        member_user=UserEntity(
            user_id=567,
        ),
        role_id=1,
    )
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/members",
        method="POST",
        data=member.json(exclude_unset=True),
    ).respond_with_data(
        status=201, headers={"Location": "/api/v2.0/projects/1234/members/567"}
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.add_project_member("1234", member)


@pytest.mark.asyncio
async def test_add_project_member_with_group_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
):
    """Tests add_project_member with a ProjectMemberEntity with a member_group"""
    member = ProjectMember(
        member_group=UserGroup(
            id=567,
        ),
        role_id=1,
    )
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/members",
        method="POST",
        data=member.json(exclude_unset=True),
    ).respond_with_data(
        status=201, headers={"Location": "/api/v2.0/projects/1234/members/567"}
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.add_project_member("1234", member)


@pytest.mark.asyncio
@pytest.mark.parametrize("username,user_id", [("user1", None), (None, 123)])
async def test_add_project_member_user_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    username: Optional[str],
    user_id: Optional[int],
):
    kwarg = {"username": username} if username else {"user_id": user_id}
    expect_member = ProjectMember(
        member_user=UserEntity(
            **kwarg,
        ),
        role_id=1,
    )
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/members",
        method="POST",
        data=expect_member.json(exclude_unset=True),
    ).respond_with_data(
        status=201, headers={"Location": "/api/v2.0/projects/1234/members/567"}
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.add_project_member_user(
        "1234",
        username_or_id=username or user_id,  # type: ignore
        role_id=1,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("ldap_group_dn,group_id", [("ou=Groups", None), (None, 123)])
async def test_add_project_member_group_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    ldap_group_dn: Optional[str],
    group_id: Optional[int],
):
    kwarg = {"ldap_group_dn": ldap_group_dn} if ldap_group_dn else {"id": group_id}
    expect_member = ProjectMember(
        member_group=UserGroup(
            **kwarg,
        ),
        role_id=1,
    )
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/members",
        method="POST",
        data=expect_member.json(exclude_unset=True),
    ).respond_with_data(
        status=201, headers={"Location": "/api/v2.0/projects/1234/members/567"}
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.add_project_member_group(
        "1234",
        ldap_group_dn_or_id=ldap_group_dn or group_id,  # type: ignore
        role_id=1,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("as_int", [True, False])
async def test_update_project_member_role_mock(
    async_client: HarborAsyncClient, httpserver: HTTPServer, as_int: bool
):
    role_id = 1234
    expect = RoleRequest(role_id=role_id)
    if as_int:
        role_arg = role_id
    else:
        role_arg = RoleRequest(role_id=role_id) if as_int else role_id

    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/members/567",
        method="PUT",
        data=expect.json(exclude_unset=True),
    ).respond_with_data(status=200)
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.update_project_member_role("1234", 567, role_arg)


@pytest.mark.asyncio
async def test_remove_project_member_mock(
    async_client: HarborAsyncClient, httpserver: HTTPServer
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/members/567",
        method="DELETE",
    ).respond_with_data(status=200)
    async_client.url = httpserver.url_for("/api/v2.0")
    await async_client.remove_project_member("1234", 567)


@pytest.mark.asyncio
@given(st.lists(st.builds(ProjectMemberEntity)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_project_members_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    members: List[ProjectMemberEntity],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/projects/1234/members",
        method="GET",
    ).respond_with_data(json_from_list(members), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.get_project_members("1234")
    assert resp == members
