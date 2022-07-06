from base64 import b64encode
from json import JSONDecodeError
from typing import Optional
from urllib.parse import quote

from httpx import Response
from loguru import logger

from .types import JSONType


def is_json(response: Response) -> bool:
    """Return True if the response body is JSON-encoded."""
    return response.headers.get("content-type", "").startswith("application/json")


def handle_optional_json_response(resp: Response) -> Optional[JSONType]:
    # import here to resolve circular import
    from .exceptions import HarborAPIException

    if not is_json(resp) or resp.status_code == 204:
        return None
    try:
        j = resp.json()
    except JSONDecodeError as e:
        logger.error("Failed to parse JSON from {}: {}", resp.url, e)
        raise HarborAPIException(e)
    return j


def get_artifact_path(project_name: str, repository_name: str, reference: str) -> str:
    """Get artifact path given a project name, repo name and a reference (tag or digest)"""
    repo_name = quote(repository_name, safe="")  # URL-encode the repository name
    return f"/projects/{project_name}/repositories/{repo_name}/artifacts/{reference}"


def get_credentials(username: str, secret: str) -> str:
    """Get HTTP basic access authentication credentials given a username and a secret"""
    return b64encode(f"{username}:{secret}".encode("utf-8")).decode("utf-8")
