from json import JSONDecodeError
from typing import Any, Dict, List, Optional, Type, TypeVar, Union, cast

import backoff
import httpx
from httpx import HTTPStatusError, RequestError, Response
from loguru import logger
from pydantic import BaseModel, ValidationError

from .exceptions import HarborAPIException, StatusError
from .model import Permission, UserResp, UserSearchRespItem
from .types import JSONType

T = TypeVar("T", bound=BaseModel)


def create_model(cls: Type[T], data: JSONType) -> T:
    try:
        return cls.parse_obj(data)
    except ValidationError as e:
        logger.error(
            "Failed to validate {} given {}, error: {}", cls.__class__.__name__, data, e
        )
        raise e


class _HarborClientBase:
    """Base class used by both the AsyncClient and the Client classes."""

    def __init__(
        self,
        username: str,
        token: str,
        url: str,
        config: Optional[Any] = None,
        version: str = "v2.0",
    ) -> None:
        self.username = username
        self.token = token

        # TODO: add URL regex and improve parsing OR don't police this at all
        url = url.strip("/")  # remove trailing slash
        if version and not "/api/v" in url:
            if "/api" in url:
                url = url.strip("/") + "/" + version
            else:
                url = url + "/api/" + version
        self.url = url.strip("/")  # make sure we haven't added a trailing slash again

        self.config = config


class HarborAsyncClient(_HarborClientBase):
    def __init__(self, username: str, token: str, url: str, **kwargs: Any) -> None:
        super().__init__(username, token, url, **kwargs)
        self.client = httpx.AsyncClient()

    async def get_users_by_username(
        self, username: str, **kwargs: Any
    ) -> List[UserSearchRespItem]:
        users_resp = await self.get(
            "/users/search",
            params={"username": username, **kwargs},
        )
        users_resp = cast(List[dict], users_resp)
        return [create_model(UserSearchRespItem, u) for u in users_resp]

    async def get_users(self, sort: Optional[str] = None, **kwargs) -> List[UserResp]:
        params = {**kwargs}
        if sort:
            params["sort"] = sort
        users_resp = await self.get("/users", params=params)
        users_resp = cast(List[dict], users_resp)
        return [create_model(UserResp, u) for u in users_resp]

    async def get_current_user(self) -> UserResp:
        user_resp = await self.get("/users/current")
        return create_model(UserResp, user_resp)

    async def get_current_user_permissions(
        self, scope: Optional[str], relative: bool = False
    ) -> List[Permission]:
        """Get current user permissions.

        Parameters
        ----------
        scope : Optional[str]
            The scope for the permission
        relative : bool, optional
            Display resource paths relative to the scope, by default False
            Has no effect if `scope` is not specified

        Returns
        -------
        List[Permission]
            _description_
        """
        params = {}  # type: Dict[str, Any]
        if scope:
            params["scope"] = scope
            params["relative"] = relative
        resp = await self.get("/api/users/current/permissions", params=params)
        resp = cast(List[dict], resp)
        return [create_model(Permission, p) for p in resp]

    @backoff.on_exception(backoff.expo, RequestError, max_tries=3)
    async def get(self, path: str, params: Optional[dict] = None) -> JSONType:
        return await self._get(path, params)

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": "Basic " + self.token,
            "accept": "application/json",
        }

    async def _get(self, path: str, params: Optional[dict] = None) -> JSONType:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    self.url + path,
                    params=params,
                    headers=self._get_headers(),
                )
                resp.raise_for_status()
                j = resp.json()
        except HTTPStatusError as e:
            raise StatusError(e)  # TODO: add information to this exception
        except JSONDecodeError as e:
            logger.error("Failed to parse JSON from {}{}: {}", self.url, path, e)
            raise HarborAPIException(e)
        if link := resp.headers.get("link"):
            logger.debug("Handling paginated results. URL: {}", link)
            j = await self._handle_pagination(j, link)  # recursion (refactor?)
        return j

    async def _handle_pagination(self, data: JSONType, link: str) -> JSONType:
        if not isinstance(data, list):  # NOTE: use generic?
            logger.warning(
                "Unable to handle paginated results, data is not a list. URL: {}", link
            )
            return data
        j = await self._get(link)  # ignoring params
        data.append(j)
        return data

    # NOTE: POST is not idempotent, should we still retry?
    @backoff.on_exception(backoff.expo, RequestError, max_tries=1)
    async def post(self, path: str, body: Union[BaseModel, JSONType]) -> JSONType:
        if isinstance(body, BaseModel):
            body = body.dict()
        try:
            res = await self._post(path, body)
            j = res.json()
        except JSONDecodeError as e:
            logger.error("Failed to parse JSON from {}{}: {}", self.url, path, e)
            raise HarborAPIException(e)
        except Exception as e:
            logger.error(
                "Failed to post to {}{} with body {}, error: {}",
                self.url,
                path,
                body,
                e,
            )
            raise HarborAPIException(e)
        return j

    async def _post(self, path: str, body: JSONType) -> Response:
        try:
            async with self.client:
                resp = await self.client.post(self.url + path, json=body)
                resp.raise_for_status()
        except HTTPStatusError as e:
            raise StatusError(e)
        return resp

    @backoff.on_exception(backoff.expo, RequestError, max_tries=3)
    async def put(self, path: str, body: JSONType) -> Optional[JSONType]:
        return await self.put(path, body)

    async def _put(self, path: str, body: JSONType) -> Response:
        try:
            async with self.client:
                resp = await self.client.post(self.url + path, json=body)
                resp.raise_for_status()
        except HTTPStatusError as e:
            raise StatusError(e)
        return resp
