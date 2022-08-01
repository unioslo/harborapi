from base64 import b64encode
from json import JSONDecodeError
from typing import Dict, Optional, Union
from urllib.parse import quote_plus, unquote_plus

from httpx import Response
from loguru import logger

from .types import JSONType


def is_json(response: Response) -> bool:
    """Return True if the response body is JSON-encoded."""
    return response.headers.get("content-type", "").startswith("application/json")  # type: ignore # headers guaranteed to be a dict[str, str]


def handle_optional_json_response(resp: Response) -> Optional[JSONType]:
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
    """
    return quote_plus(quote_plus(repository_name))


def urldecode_header(response: Response, key: str) -> str:
    """URL decode the location header of a response.

    Returns the decoded value, or an empty string if the header is not present.
    """
    return unquote_plus(response.headers.get(key, ""))


def get_repo_path(project_name: str, repository_name: str) -> str:
    """Get repository path given a project name and a repository name"""
    repo_name = urlencode_repo(repository_name)
    return f"/projects/{project_name}/repositories/{repo_name}"


def get_artifact_path(project_name: str, repository_name: str, reference: str) -> str:
    """Get artifact path given a project name, repo name and a reference (tag or digest)"""
    repo_path = get_repo_path(project_name, repository_name)
    return f"{repo_path}/artifacts/{reference}"


def get_credentials(username: str, secret: str) -> str:
    """Get HTTP basic access authentication credentials given a username and a secret"""
    return b64encode(f"{username}:{secret}".encode("utf-8")).decode("utf-8")


def parse_pagination_url(url: str, ignore_prev: bool = True) -> Optional[str]:
    """Parse pagination URL and return the next URL

    Parameters
    ----------
    url : str
        The pagination URL to parse
    ignore_prev : bool
        Whether to return `None` if the URL relation is `prev`


    Returns
    -------
    Optional[str]
        The next URL, or `None` if the URL relation is `prev` and `ignore_prev` is `True`
    """
    # Formatting: '</api/v2.0/endpoint?page=X&page_size=Y>; rel="next"'
    if 'rel="next"' not in url:
        # abnormal case, log warning and return None
        logger.warning("No next page found in pagination URL: {}", url)
        return None
    if ignore_prev and 'rel="prev"' in url:
        return None  # this is normal, and should not be logged

    url = url.split(";")[0].strip("><")
    u = url.split("/", 3)  # remove /api/v2.0/
    return "/" + u[-1]  # last segment is the next URL


def get_project_headers(project_name_or_id: Union[str, int]) -> Dict[str, str]:
    """Get HTTP headers given a project name or ID.

    If the project name or ID is an integer, it is assumed to be the project ID.
    Otherwise, it is assumed to be the project name.
    This determines the value of the `X-Is-Resource-Name` header.

    `True` means the value is a project name, `False` means the value is a project ID.
    """
    return {"X-Is-Resource-Name": str(isinstance(project_name_or_id, str)).lower()}
