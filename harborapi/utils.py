from base64 import b64encode
from json import JSONDecodeError
from typing import Dict, Optional, Union
from urllib.parse import quote_plus, unquote_plus

from httpx import Response
from loguru import logger

from .types import JSONType


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
    return response.headers.get("content-type", "").startswith("application/json")  # type: ignore # headers guaranteed to be a dict[str, str]


def handle_optional_json_response(resp: Response) -> Optional[JSONType]:
    """Takes in a response and attempts to parse the body as JSON.

    If the response cannot be parsed, an exception is raised.
    If the response has no body, `None` is returned.

    Parameters
    ----------
    resp : Response
        The HTTPX response to parse.

    Returns
    -------
    Optional[JSONType]
        The parsed JSON, or `None` if the response has no body.

    Raises
    ------
    HarborAPIException
        Raised if the response body cannot be parsed as JSON.
        The __cause__ attribute of the exception will be the original
        JSONDecodeError.

    """
    # import here to resolve circular import
    from .exceptions import HarborAPIException

    if not is_json(resp) or resp.status_code == 204:
        return None
    try:
        j = resp.json()
    except JSONDecodeError as e:
        logger.error("Failed to parse JSON from {}: {}", resp.url, e)
        raise HarborAPIException("Failed to parse JSON from {}".format(resp.url)) from e
    # we assume Harbor API returns dict or list,
    # if not, they are breaking their own schema and that is not our fault
    return j  # type: ignore


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


def get_credentials(username: str, secret: str) -> str:
    """Get HTTP basic access authentication credentials given a username and a secret.

    Parameters
    ----------
    username : str
        The username to use for authentication.
    secret : str
        The secret (password) for the user.

    Returns
    -------
    str
        The credentials string used for HTTP basic access authentication,
        encoded in base64. This is not a one-way hash, so it should be
        considered insecure!
    """
    return b64encode(f"{username}:{secret}".encode("utf-8")).decode("utf-8")


def parse_pagination_url(url: str) -> Optional[str]:
    """Parse pagination URL and return the next URL

    Parameters
    ----------
    url : str
        The pagination URL to parse

    Returns
    -------
    Optional[str]
        The next URL, or `None` if the URL relation is `prev` and `ignore_prev` is `True`
    """
    # Formatting: '</api/v2.0/endpoint?page=X&page_size=Y>; rel="next"'
    if 'rel="prev"' in url:
        return None
    elif 'rel="next"' not in url:
        # abnormal case, log warning and return None
        logger.debug("No next page found in pagination URL: {}", url)
        return None
    url = url.split(";")[0].strip("><")
    u = url.split("/", 3)  # remove /api/v2.0/
    return "/" + u[-1]  # last segment is the next URL


def get_project_headers(project_name_or_id: Union[str, int]) -> Dict[str, str]:
    """Get HTTP headers used to make a request given a project name or ID,
    which distinguishes whether the request uses the project name or ID.

    If the project name or ID is an integer, it is assumed to be the project ID.
    Otherwise, it is assumed to be the project name.
    This determines the value of the `X-Is-Resource-Name` header.

    `True` means the value is a project name, `False` means the value is a project ID.

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
