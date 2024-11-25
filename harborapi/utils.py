from __future__ import annotations

import re
from base64 import b64encode
from json import JSONDecodeError
from typing import Dict
from typing import Optional
from typing import Sequence
from typing import Union
from typing import cast
from urllib.parse import quote_plus
from urllib.parse import unquote_plus

from httpx import Response
from pydantic import SecretStr

from ._types import JSONType
from ._types import QueryParamMapping
from ._types import QueryParamValue
from .exceptions import HarborAPIException  # avoid circular import
from .log import logger


def is_json(response: Response) -> bool:
    """Determines if a response body has a json content type.

    Parameters
    ----------
    response : Response
        The HTTPX response to check.

    Returns
    -------
    bool
        `True` if the response has a json content type, `False` otherwise.
    """
    return response.headers.get("content-type", "").startswith("application/json")


def handle_optional_json_response(resp: Response) -> Optional[JSONType]:
    """Attempt to parse response body as JSON, returning None if body is not JSON or is empty."""
    if not is_json(resp) or resp.status_code == 204:
        return None
    return handle_json_response(resp)


def handle_json_response(resp: Response) -> JSONType:
    """Takes in a response and attempts to parse the body as JSON.

    If the response cannot be parsed, an exception is raised.

    Parameters
    ----------
    resp : Response
        The HTTPX response to parse.

    Returns
    -------
    JSONType
        The parsed JSON response body.

    Raises
    ------
    HarborAPIException
        Raised if the response body cannot be parsed as JSON.
        The `__cause__` attribute of the exception will be the original
        JSONDecodeError.
    """
    try:
        # We assume Harbor API returns dict or list.
        # If not, they are breaking their own schema and that is not our fault
        return cast(JSONType, resp.json())
    except JSONDecodeError as e:
        logger.error("Failed to parse JSON from %s: %s", resp.url, e)
        msg = f"{resp.url} did not return valid JSON: {resp.text}"
        if "/api/v2.0" not in str(resp.url):
            msg += "\nDid you remember to include /api/v2.0 in the server URL?"
        raise HarborAPIException(msg) from e


def urlencode_repo(repository_name: str) -> str:
    """URL-encode a repository name.
    The Harbor API requires names to be double URL-encoded for some reason.
    So we have to manually encode it here, and then let HTTPX encode it again
    when we make the request.

    Parameters
    ----------
    repository_name : str
        The repository name to encode.

    Returns
    -------
    str
        The encoded repository name.
    """
    return quote_plus(quote_plus(repository_name))


def urldecode_header(response: Response, key: str) -> str:
    """URL decode a value of a specific key from a response's headers.

    Returns the decoded value, or an empty string if the header key is not present.

    Parameters
    ----------
    response : Response
        The HTTPX response to parse.
    key : str
        The header key to decode.

    Returns
    -------
    str
        The decoded header value, or an empty string if the header key is not present.
    """
    return unquote_plus(response.headers.get(key, ""))


def get_repo_path(project_name: str, repository_name: str) -> str:
    """Get a Harbor repository path given a project name and a repository name.

    Example
    -------
    ```pycon
    >>> get_repo_path("library", "hello-wØrld")
    '/projects/library/repositories/hello-w%25C3%2598rld'
    ```

    Parameters
    ----------
    project_name : str
        The project name
    repository_name : str
        The repository name

    Returns
    -------
    str
        The repository path
    """
    repo_name = urlencode_repo(repository_name)
    return f"/projects/{project_name}/repositories/{repo_name}"


def get_artifact_path(project_name: str, repository_name: str, reference: str) -> str:
    """Get artifact path given a project name, repo name and a reference (tag or digest)

    Example
    -------
    ```pycon
    >>> get_artifact_path("library", "hello-wØrld", "latest")
    '/projects/library/repositories/hello-w%25C3%2598rld/artifacts/latest'
    ```

    Parameters
    ----------
    project_name : str
        The project name
    repository_name : str
        The repository name
    reference : str
        The tag or digest of the artifact

    Returns
    -------
    str
        The artifact path
    """
    repo_path = get_repo_path(project_name, repository_name)
    return f"{repo_path}/artifacts/{reference}"


def get_basicauth(username: str, secret: str) -> SecretStr:
    """Get HTTP basic access authentication credentials given a username and a secret.

    Parameters
    ----------
    username : str
        The username to use for authentication.
    secret : str
        The secret (password) for the user.

    Returns
    -------
    SecretStr
        The credentials string used for HTTP basic access authentication,
        encoded in base64 as a Pydantic SecretStr, which prevents the
        credentials from leaking when printing locals.
        The string is a base64 encoded string of the form `username:secret`,
        and should not be considered secure, as it is not encrypted.
    """
    val = b64encode(f"{username}:{secret}".encode("utf-8")).decode("utf-8")
    return SecretStr(val)


# Finds the next url in a pagination header (e.g. Link: </api/v2.0/endpoint?page=X&page_size=Y>; rel="next")
# Ripped from: https://docs.github.com/en/rest/guides/using-pagination-in-the-rest-api?apiVersion=2022-11-28#example-creating-a-pagination-method
PAGINATION_NEXT_PATTERN = re.compile('<([^>]+)>; rel="next"')

# Finds the API path in a URL (e.g. /api/v2.0/)
API_PATH_PATTERN = re.compile(r"\/api\/v[0-9]\.[0-9]{1,2}")


def parse_pagination_url(url: str, strip: bool = True) -> Optional[str]:
    """Parse pagination URL and return the next URL

    Parameters
    ----------
    url : str
        The pagination URL to parse
    strip : bool, optional
        Whether to strip the /api/v2.x/ path from the URL

    Returns
    -------
    Optional[str]
        The next URL, or `None` if the URL relation is `prev` and `ignore_prev` is `True`
    """

    match = PAGINATION_NEXT_PATTERN.search(url)
    if not match:
        return None

    m = match.group(1)  # exclude rel="next" from the match
    if not strip:
        return m

    # Remove /api/v2.0/ from next link
    # Yeah, this is a result of not including /api/v2.0/ in the URLs we call
    # in the first place, but it's too late to change that now.
    return API_PATH_PATTERN.sub("", m)


def get_project_headers(project_name_or_id: Union[str, int]) -> Dict[str, str]:
    """Get HTTP header for identifying whether a Project Name or
    Project ID is used in an API call.

    If the value is an integer, it is assumed to be the Project ID.
    Otherwise, it is assumed to be the Project Name.
    This determines the value of the `X-Is-Resource-Name` header.

    `X-Is-Resource-Name: true` means the value is a project name,
    `X-Is-Resource-Name: false` means the value is a project ID.

    Parameters
    ----------
    project_name_or_id : Union[str, int]
        The project name or ID.

    Returns
    -------
    Dict[str, str]
        The headers to use for the request.
    """
    return {"X-Is-Resource-Name": str(isinstance(project_name_or_id, str)).lower()}


def get_mime_type_header(mime_type: Union[str, Sequence[str]]) -> Dict[str, str]:
    # NOTE: in the offical API spec, a comma AND space is used to separate:
    # https://github.com/goharbor/harbor/blob/df4ab856c7597e6fe28b466ba8419257de8a1af7/api/v2.0/swagger.yaml#L6256
    if not isinstance(mime_type, str):
        mime_type_param = ", ".join(mime_type)
    else:
        mime_type_param = mime_type
    return {"X-Accept-Vulnerabilities": mime_type_param}


def get_params(**kwargs: QueryParamValue) -> QueryParamMapping:
    """Get parameters for an API call as a dict, where `None` values are ignored.

    Parameters
    ----------
    **kwargs: ParamType
        The parameters to use for the request.
        Each keyword argument type must be a primitive, JSON-serializable type.

    Returns
    -------
    QueryParamMapping
        The dict representation of the parameters with `None` values removed.
    """
    params: QueryParamMapping = {k: v for k, v in kwargs.items() if v is not None}
    # Ensure that the "query" parameter is renamed to "q"
    # We use "query" as the parameter name in this library, but "q" is the
    # parameter name used by the Harbor API.
    if "query" in params and not params.get("q"):
        params["q"] = params.pop("query")
    return params
