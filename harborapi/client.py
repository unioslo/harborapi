from json import JSONDecodeError
from typing import Any, Dict, List, Optional, Type, TypeVar, Union

import backoff
import httpx
from httpx import HTTPStatusError, RequestError, Response
from loguru import logger
from pydantic import BaseModel, ValidationError

from .exceptions import HarborAPIException, StatusError
from .model import (
    Permission,
    ScannerAdapterMetadata,
    ScannerRegistration,
    ScannerRegistrationReq,
    UserResp,
    UserSearchRespItem,
)
from .types import JSONType

T = TypeVar("T", bound=BaseModel)


def construct_model(cls: Type[T], data: Any) -> T:
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

    # CATEGORY: user

    # GET /users/search?username=<username>
    async def get_users_by_username(
        self, username: str, **kwargs: Any
    ) -> List[UserSearchRespItem]:
        users_resp = await self.get(
            "/users/search",
            params={"username": username, **kwargs},
        )
        return [construct_model(UserSearchRespItem, u) for u in users_resp]

    # GET /users
    async def get_users(self, sort: Optional[str] = None, **kwargs) -> List[UserResp]:
        params = {**kwargs}
        if sort:
            params["sort"] = sort
        users_resp = await self.get("/users", params=params)
        return [construct_model(UserResp, u) for u in users_resp]

    # GET /users/current
    async def get_current_user(self) -> UserResp:
        user_resp = await self.get("/users/current")
        return construct_model(UserResp, user_resp)

    # GET /users/current/permissions
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
            A list of Permission objects for the current user.
        """
        params = {}  # type: Dict[str, Any]
        if scope:
            params["scope"] = scope
            params["relative"] = relative
        resp = await self.get("/api/users/current/permissions", params=params)
        return [construct_model(Permission, p) for p in resp]

    # CATEGORY: gc
    # CATEGORY: scanAll
    # CATEGORY: configure
    # CATEGORY: usergroup
    # CATEGORY: preheat
    # CATEGORY: replication
    # CATEGORY: label
    # CATEGORY: robot
    # CATEGORY: webhookjob
    # CATEGORY: icon
    # CATEGORY: project
    # CATEGORY: webhook
    # CATEGORY: scan
    # CATEGORY: member
    # CATEGORY: ldap
    # CATEGORY: registry
    # CATEGORY: search
    # CATEGORY: artifact
    # CATEGORY: immutable
    # CATEGORY: retention

    # CATEGORY: scanner

    # POST /scanners
    async def create_scanner(self, scanner: ScannerRegistrationReq) -> str:
        """Creates a new scanner. Returns location of the created scanner."""
        resp = await self.post("/scanners", json=scanner)
        return resp.headers.get("Location")

    # GET /scanners
    async def get_scanners(self, *args, **kwargs) -> List[ScannerRegistration]:
        scanners = await self.get("/scanners", params=kwargs)
        return [construct_model(ScannerRegistration, s) for s in scanners]

    # PUT /scanners/{registration_id}
    async def update_scanner(
        self, registration_id: Union[int, str], scanner: ScannerRegistrationReq
    ) -> None:
        await self.put(f"/scanners/{registration_id}", json=scanner)

    # GET /scanners/{registration_id}
    async def get_scanner(
        self, registration_id: Union[int, str]
    ) -> ScannerRegistration:
        scanner = await self.get(f"/scanners/{registration_id}")
        return construct_model(ScannerRegistration, scanner)

    # DELETE /scanners/{registration_id}
    async def delete_scanner(self, registration_id: Union[int, str]) -> None:
        await self.delete(f"/scanners/{registration_id}")

    # PATCH /scanners/{registration_id}

    # POST /scanners/ping

    # GET /scanners/{registration_id}/metadata
    async def get_scanner_metadata(
        self, registration_id: int
    ) -> ScannerAdapterMetadata:
        scanner = await self.get(f"/scanners/{registration_id}/metadata")
        return construct_model(ScannerAdapterMetadata, scanner)

    # CATEGORY: systeminfo
    # CATEGORY: statistic
    # CATEGORY: quota
    # CATEGORY: repository
    # CATEGORY: ping
    # CATEGORY: oidc
    # CATEGORY: SystemCVEAllowlist
    # CATEGORY: health
    # CATEGORY: robotv1
    # CATEGORY: projectMetadata
    # CATEGORY: auditlog

    @backoff.on_exception(backoff.expo, RequestError, max_time=30)
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
        """Handles paginated results by recursing until all results are returned."""
        # NOTE: can this be done more elegantly?
        # TODO: re-use async client somehow
        j = await self._get(link)  # ignoring params and only using the link
        if not isinstance(j, list) or not isinstance(data, list):
            logger.warning(
                "Unable to handle paginated results, received non-list value. URL: {}",
                link,
            )
            # TODO: add more diagnostics info here
            return data
        data.extend(j)
        return data

    # NOTE: POST is not idempotent, should we still retry?
    # TODO: fix abstraction of post/_post. Put everything into _post?
    @backoff.on_exception(backoff.expo, RequestError, max_tries=1)
    async def post(self, path: str, json: Union[BaseModel, JSONType]) -> Response:
        if isinstance(json, BaseModel):
            body = json.dict()
        return await self._post(path, body)

    async def _post(self, path: str, json: JSONType) -> Response:
        try:
            async with self.client:
                resp = await self.client.post(self.url + path, json=json)
                resp.raise_for_status()
        except HTTPStatusError as e:
            logger.error(
                "ERROR: POST {}{} with body {}, error: {}",
                self.url,
                path,
                json,
                e,
            )
            raise HarborAPIException(e)
        return resp

    @backoff.on_exception(backoff.expo, RequestError, max_time=30)
    async def put(self, path: str, json: JSONType) -> Optional[JSONType]:
        return await self.put(path, json)

    async def _put(self, path: str, json: JSONType) -> Response:
        try:
            async with self.client:
                resp = await self.client.put(self.url + path, json=json)
                resp.raise_for_status()
        except HTTPStatusError as e:
            raise StatusError(e)
        return resp

    @backoff.on_exception(backoff.expo, RequestError, max_time=30)
    async def delete(self, path: str, **kwargs) -> Optional[JSONType]:
        return await self.put(path, **kwargs)

    async def _delete(self, path: str, **kwargs) -> Response:
        try:
            async with self.client:
                resp = await self.client.delete(self.url + path)
                resp.raise_for_status()
        except HTTPStatusError as e:
            raise StatusError(e)
        return resp

    # TODO: add on_giveup callback for all backoff methods
