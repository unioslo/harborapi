from __future__ import annotations

from json import JSONDecodeError
from typing import Dict
from typing import Optional
from typing import Union

import pytest
from httpx import Request
from httpx import Response

from harborapi._types import JSONType
from harborapi.exceptions import HarborAPIException
from harborapi.utils import get_artifact_path
from harborapi.utils import get_basicauth
from harborapi.utils import get_project_headers
from harborapi.utils import handle_optional_json_response
from harborapi.utils import is_json
from harborapi.utils import parse_pagination_url
from harborapi.utils import urldecode_header


@pytest.mark.parametrize(
    "headers, expected",
    [
        ({"content-type": "application/json"}, True),
        ({"content-type": "application/json; charset=utf-8"}, True),
        ({"content-type": "text/plain"}, False),
        ({"content-type": "text/plain; application/json"}, False),  # invalid format
    ],
)
def test_is_json(headers: Dict[str, str], expected: bool):
    resp = Response(200, headers=headers)
    assert is_json(resp) == expected


@pytest.mark.parametrize("project_name_or_id", ["project_name", "1234", 1234])
def test_get_project_headers(project_name_or_id: Union[str, int]):
    headers = get_project_headers(project_name_or_id)
    if isinstance(project_name_or_id, str):
        assert headers["X-Is-Resource-Name"] == "true"
    else:
        assert headers["X-Is-Resource-Name"] == "false"


def test_get_basicauth():
    assert (
        get_basicauth("username", "secret").get_secret_value() == "dXNlcm5hbWU6c2VjcmV0"
    )


@pytest.mark.parametrize(
    "response, expected",
    [
        (
            Response(
                200, text='{"foo": "bar"}', headers={"content-type": "application/json"}
            ),
            {"foo": "bar"},
        ),
        (
            Response(200, text="{}", headers={"content-type": "application/json"}),
            {},
        ),
        (
            Response(
                204,
                text="",
                headers={"content-type": "application/json"},
            ),
            None,
        ),
        (
            Response(
                200,
                text='{"foo": "bar"}',
                headers={"content-type": "text/plain"},
            ),
            None,
        ),
    ],
)
def test_handle_optional_json_response(
    response: Response,
    expected: Optional[JSONType],
):
    assert handle_optional_json_response(response) == expected


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(
            Response(
                200,
                text="",
                headers={"content-type": "application/json"},
                request=Request("GET", "http://example.com"),
            ),
            id="empty body",
        ),
        pytest.param(
            Response(
                200,
                text='{"a": "b",}',
                headers={"content-type": "application/json"},
                request=Request("GET", "http://example.com"),
            ),
            id="invalid json (trailing comma)",
        ),
    ],
)
def test_handle_optional_json_fail(
    response: Response,
):
    with pytest.raises(HarborAPIException) as exc_info:
        handle_optional_json_response(response)
    assert isinstance(exc_info.value.__cause__, JSONDecodeError)


@pytest.mark.parametrize(
    "project_name, repository_name, reference, expected",
    [
        (
            "project_name",
            "repository_name",
            "reference",
            "/projects/project_name/repositories/repository_name/artifacts/reference",
        ),
        (
            "project_name",
            "repo/name",
            "reference",
            "/projects/project_name/repositories/repo%252Fname/artifacts/reference",
        ),
    ],
)
def test_get_artifact_path(
    project_name: str,
    repository_name: str,
    reference: str,
    expected: str,
):
    assert get_artifact_path(project_name, repository_name, reference) == expected


@pytest.mark.parametrize(
    "header,key,expected",
    [
        (
            {"Location": "%2Fsome%2Fpath"},
            "Location",
            "/some/path",
        ),
        (
            {"Location": "%2Fsome%2Fpath"},
            "location",
            "/some/path",
        ),
        (
            {"Location": "/some/path"},
            "Location",
            "/some/path",
        ),
        (
            {"Location": "/some/path"},
            "location",
            "/some/path",
        ),
        (
            {"Location": "%2Fsome%2Fpath", "content-type": "application/json"},
            "location",
            "/some/path",
        ),
        (
            {"content-type": "application/json", "Location": "%2Fsome%2Fpath"},
            "location",
            "/some/path",
        ),
        (
            {"content-type": "application/json"},
            "location",
            "",
        ),
    ],
)
def test_urldecode_header(header: Dict[str, str], key: str, expected: str):
    resp = Response(200, headers=header)
    assert urldecode_header(resp, key) == expected


@pytest.mark.parametrize(
    "url, expected",
    [
        # Just next link
        (
            '</api/v2.0/projects?page=3&page_size=10&sort=resource_type&with_detail=true>; rel="next"',
            "/projects?page=3&page_size=10&sort=resource_type&with_detail=true",
        ),
        # No next link
        (
            '</api/v2.0/projects?page=1&page_size=10&sort=resource_type,op_time&with_detail=true>; rel="prev"',
            None,
        ),
        # Next link with comma in query string
        (
            '</api/v2.0/projects?page=2&page_size=10&sort=resource_type,op_time&with_detail=true>; rel="next"',
            "/projects?page=2&page_size=10&sort=resource_type,op_time&with_detail=true",
        ),
        # Next and prev links with comma in query string
        (
            '</api/v2.0/projects?page=1&page_size=10&sort=resource_type,op_time&with_detail=true>; rel="prev" , </api/v2.0/projects?page=3&page_size=10&sort=resource_type,op_time&with_detail=true>; rel="next"',
            "/projects?page=3&page_size=10&sort=resource_type,op_time&with_detail=true",
        ),
        # Next link with no /api/v2.0 prefix
        (
            '</projects?page=3&page_size=10&sort=resource_type,op_time&with_detail=true>; rel="next"',
            "/projects?page=3&page_size=10&sort=resource_type,op_time&with_detail=true",
        ),
        # Next link with advanced query string (union relationship)
        (
            '</api/v2.0/audit-logs?page=2&page_size=10&q=operation={push pull},resource_type=artifact>; rel="next"',
            "/audit-logs?page=2&page_size=10&q=operation={push pull},resource_type=artifact",
        ),
        # Next link with advanced query string (intersection relationship)
        (
            '</api/v2.0/audit-logs?page=2&page_size=10&q=operation=(push pull),resource_type=artifact>; rel="next"',
            "/audit-logs?page=2&page_size=10&q=operation=(push pull),resource_type=artifact",
        ),
    ],
)
def test_parse_pagination_url(url: str, expected: Optional[str]) -> None:
    assert parse_pagination_url(url, strip=True) == expected


@pytest.mark.parametrize(
    "url, expected",
    [
        # Just next link
        (
            '</api/v2.0/projects?page=3&page_size=10&sort=resource_type&with_detail=true>; rel="next"',
            "/api/v2.0/projects?page=3&page_size=10&sort=resource_type&with_detail=true",
        ),
        # No next link
        (
            '</api/v2.0/projects?page=1&page_size=10&sort=resource_type,op_time&with_detail=true>; rel="prev"',
            None,
        ),
        # Next link with comma in query string
        (
            '</api/v2.0/projects?page=2&page_size=10&sort=resource_type,op_time&with_detail=true>; rel="next"',
            "/api/v2.0/projects?page=2&page_size=10&sort=resource_type,op_time&with_detail=true",
        ),
        # Next and prev links with comma in query string
        (
            '</api/v2.0/projects?page=1&page_size=10&sort=resource_type,op_time&with_detail=true>; rel="prev" , </api/v2.0/projects?page=3&page_size=10&sort=resource_type,op_time&with_detail=true>; rel="next"',
            "/api/v2.0/projects?page=3&page_size=10&sort=resource_type,op_time&with_detail=true",
        ),
        # Next link with no /api/v2.0 prefix
        (
            '</projects?page=3&page_size=10&sort=resource_type,op_time&with_detail=true>; rel="next"',
            "/projects?page=3&page_size=10&sort=resource_type,op_time&with_detail=true",
        ),
        # Next link with advanced query string (union relationship)
        (
            '</api/v2.0/audit-logs?page=2&page_size=10&q=operation={push pull},resource_type=artifact>; rel="next"',
            "/api/v2.0/audit-logs?page=2&page_size=10&q=operation={push pull},resource_type=artifact",
        ),
        # Next link with advanced query string (intersection relationship)
        (
            '</api/v2.0/audit-logs?page=2&page_size=10&q=operation=(push pull),resource_type=artifact>; rel="next"',
            "/api/v2.0/audit-logs?page=2&page_size=10&q=operation=(push pull),resource_type=artifact",
        ),
    ],
)
def test_parse_pagination_url_nostrip(url: str, expected: Optional[str]) -> None:
    assert parse_pagination_url(url, strip=False) == expected
