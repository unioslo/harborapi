from json import JSONDecodeError
from typing import Any, Optional, Union

import backoff
import httpx
from httpx import HTTPStatusError, RequestError, Response
from loguru import logger
from pydantic import BaseModel

from .exceptions import HarborAPIException, StatusError
from .types import JSONType


class _HarborClientBase:
    """Base class used by both the AsyncClient and the Client classes."""

    def __init__(self, token: str, url: str, config: Optional[Any] = None):
        self.token = token
        if url.endswith("/"):
            url = url[:-1]
        self.url = url
        self.config = config


class HarborClient(_HarborClientBase):
    def __init__(self, token: str, url: str):
        super().__init__(token, url)
        self.client = httpx.Client(base_url=self.url)

    @backoff.on_exception(backoff.expo, RequestError, max_tries=3)
    def _get(self, path: str, params: Optional[dict] = None) -> Response:
        try:
            with httpx.Client() as client:
                resp = client.get(path, params=params)
                resp.raise_for_status()
        except HTTPStatusError as e:
            raise StatusError(e)
        return resp

    def get(self, path: str, params: Optional[dict] = None) -> JSONType:
        res = self._get(path, params)
        try:
            j = res.json()
        except JSONDecodeError as e:
            logger.error("Failed to parse JSON from {}{}: {}", self.url, path, e)
        return j
