from typing import Dict, List, Optional, Union

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models.models import LdapConf, LdapPingResult, LdapUser, UserGroup

from ..utils import json_from_list


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
        f"/api/v2.0/ldap/ping",
        method="POST",
        json=config.dict(exclude_unset=True),
    ).respond_with_data(result.json(), content_type="application/json")
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
        f"/api/v2.0/ldap/ping",
        method="POST",
    ).respond_with_data(result.json(), content_type="application/json")
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
        f"/api/v2.0/ldap/groups/search",
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
        f"/api/v2.0/ldap/users/search",
        method="GET",
    ).respond_with_data(json_from_list(results), content_type="application/json")
    async_client.url = httpserver.url_for("/api/v2.0")

    resp = await async_client.search_ldap_users(username)
    assert resp == results


@pytest.mark.asyncio
@given(st.lists(st.one_of(st.text(), st.integers())))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_import_ldap_users_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    user_ids: List[Union[str, int]],
):
    # We pass in lists containing both strings and ints to check that the
    # pydantic model converts these to strings
    httpserver.expect_oneshot_request(
        f"/api/v2.0/ldap/users/import",
        method="POST",
        # make sure the user ids are converted to strings
        json={"ldap_uid_list": [str(uid) for uid in user_ids]},
    ).respond_with_data()
    async_client.url = httpserver.url_for("/api/v2.0")

    # The method constructs the request model,
    # we just pass in the list of user IDs.
    await async_client.import_ldap_users(user_ids)  # type: ignore
