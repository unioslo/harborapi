from typing import Dict

import pytest
from httpx import Response

from harborapi.utils import is_json


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
