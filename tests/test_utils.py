from typing import Dict, Optional, Type, Union

import pytest
from httpx import Request, Response

from harborapi._types import JSONType
from harborapi.exceptions import HarborAPIException
from harborapi.utils import (
    get_artifact_path,
    get_credentials,
    get_project_headers,
    handle_optional_json_response,
    is_json,
    urldecode_header,
)


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


def test_get_credentials():
    assert get_credentials("username", "secret") == "dXNlcm5hbWU6c2VjcmV0"


@pytest.mark.parametrize(
    "response, expected, exception",
    [
        (
            Response(
                200, text='{"foo": "bar"}', headers={"content-type": "application/json"}
            ),
            {"foo": "bar"},
            None,
        ),
        (
            Response(200, text="{}", headers={"content-type": "application/json"}),
            {},
            None,
        ),
        (
            Response(
                200,
                text="",
                headers={"content-type": "application/json"},
                # need to set request here for some reason (because empty body?)
                request=Request("GET", "http://example.com"),
            ),
            None,
            HarborAPIException,
        ),
        (
            Response(
                204,
                text="",
                headers={"content-type": "application/json"},
            ),
            None,
            None,
        ),
        (
            Response(
                200,
                text='{"foo": "bar"}',
                headers={"content-type": "text/plain"},
            ),
            None,
            None,
        ),
    ],
)
def test_handle_optional_json_response(
    response: Response,
    expected: Optional[JSONType],
    exception: Optional[Type[Exception]],
):
    if exception:
        with pytest.raises(exception):
            handle_optional_json_response(response)
    else:
        assert handle_optional_json_response(response) == expected


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
