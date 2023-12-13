from __future__ import annotations

from typing import List
from typing import Optional

import pytest
from hypothesis import given
from hypothesis import HealthCheck
from hypothesis import settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from ..utils import json_from_list
from harborapi.client import HarborAsyncClient
from harborapi.models.models import LdapConf
from harborapi.models.models import LdapPingResult
from harborapi.models.models import LdapUser
from harborapi.models.models import UserGroup


@pytest.mark.asyncio
@given(st.builds(LdapConf), st.builds(LdapPingResult))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_ping_ldap_with_config_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    config: LdapConf,
    result: LdapPingResult,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/ldap/ping",
        method="POST",
        json=config.model_dump(mode="json", exclude_unset=True),
    ).respond_with_data(result.model_dump_json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.ping_ldap(config)
    assert resp == result


@pytest.mark.asyncio
@given(st.builds(LdapPingResult))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_ping_ldap_no_config_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    result: LdapPingResult,
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/ldap/ping",
        method="POST",
    ).respond_with_data(result.model_dump_json(), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")
    resp = await async_client.ping_ldap()
    assert resp == result


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "group_name,group_dn", [("foo", "bar"), (None, "bar"), ("foo", None), (None, None)]
)
@given(st.lists(st.builds(UserGroup)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_search_ldap_groups_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    group_name: Optional[str],
    group_dn: Optional[str],
    results: List[UserGroup],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/ldap/groups/search",
        method="GET",
    ).respond_with_data(json_from_list(results), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")

    if not group_name and not group_dn:
        with pytest.raises(ValueError):
            await async_client.search_ldap_groups(group_name, group_dn)
    else:
        resp = await async_client.search_ldap_groups(group_name, group_dn)
        assert resp == results


@pytest.mark.asyncio
@pytest.mark.parametrize("username", ["test-user", ""])
@given(st.lists(st.builds(LdapUser)))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_search_ldap_users_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    username: str,
    results: List[LdapUser],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/ldap/users/search",
        method="GET",
    ).respond_with_data(json_from_list(results), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")

    resp = await async_client.search_ldap_users(username)
    assert resp == results


@pytest.mark.asyncio
@given(st.lists(st.text()))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_import_ldap_users_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    user_ids: List[str],
):
    httpserver.expect_oneshot_request(
        "/api/v2.0/ldap/users/import",
        method="POST",
        json={"ldap_uid_list": user_ids},
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")
    # The method constructs the request model,
    # we just pass in the list of user IDs.
    await async_client.import_ldap_users(user_ids)
