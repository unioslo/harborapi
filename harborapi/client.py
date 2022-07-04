from typing import Any, Dict, List, Optional, Type, TypeVar, Union

import backoff
import httpx
from httpx import RequestError, Response
from loguru import logger
from pydantic import BaseModel, ValidationError

from .exceptions import HarborAPIException, StatusError, check_response_status
from .models import (
    CVEAllowlist,
    HarborVulnerabilityReport,
    IsDefault,
    OverallHealthStatus,
    Permission,
    ScannerAdapterMetadata,
    ScannerRegistration,
    ScannerRegistrationReq,
    ScannerRegistrationSettings,
    Schedule,
    Stats,
    UserResp,
    UserSearchRespItem,
)
from .types import JSONType
from .utils import get_artifact_path, get_token, handle_optional_json_response

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
        url: str,
        username: str = None,
        secret: str = None,
        token: str = None,
        config: Optional[Any] = None,
        version: str = "v2.0",
    ) -> None:
        self.username = username
        if username and secret:
            self.token = get_token(username, secret)
        elif token:
            self.token = token
        else:
            raise ValueError("Must provide either username and secret or token")

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
    def __init__(
        self,
        url: str,
        username: str = None,
        secret: str = None,
        token: str = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(url, username, secret, token, **kwargs)
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

    # GET /scans/all/metrics
    async def get_scan_all_metrics(self) -> Stats:
        resp = await self.get("/scans/all/metrics")
        return construct_model(Stats, resp)

    # PUT /system/scanAll/schedule
    async def update_scan_all_schedule(self, schedule: Schedule) -> None:
        """Update the scan all schedule."""
        await self.put("/system/scanAll/schedule", json=schedule)

    # POST /system/scanAll/schedule
    async def create_scan_all_schedule(self, schedule: Schedule) -> str:
        """Create a new scan all job schedule. Returns location of the created schedule."""
        resp = await self.post("/system/scanAll/schedule", json=schedule)
        return resp.headers.get("Location")

    # GET /system/scanAll/schedule
    async def get_scan_all_schedule(self) -> Schedule:
        resp = await self.get("/system/scanAll/schedule")
        return construct_model(Schedule, resp)

    # POST /system/scanAll/stop
    async def stop_scan_all_job(self) -> None:
        await self.post("/system/scanAll/stop")

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

    # POST /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/scan
    async def scan_artifact(
        self, project_name: str, repository_name: str, reference: str
    ) -> None:
        """Scan an artifact.

        Parameters
        ----------
        project_name : str
            The name of the project
        repository_name : str
            The name of the repository
        reference : str
            The reference of the artifact, can be digest or tag
        """
        path = get_artifact_path(project_name, repository_name, reference)
        resp = await self.post(f"{path}/scan")
        if resp.status_code != 202:
            logger.warning(
                "Scan request for {} returned status code {}, expected 202",
                path,
                resp.status_code,
            )

    async def get_scan_report_log(
        self, project_name: str, repository_name: str, reference: str, report_id: str
    ) -> str:
        """Get the log of a scan report."""
        # TODO: investigate what exactly this endpoint returns
        path = get_artifact_path(project_name, repository_name, reference)
        return await self.get_text(f"{path}/scan/{report_id}")

    async def stop_artifact_scan(
        self, project_name: str, repository_name: str, reference: str
    ) -> None:
        """Stop a scan for a particular artifact."""
        path = get_artifact_path(project_name, repository_name, reference)
        await self.post(f"{path}/scan/stop")

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
    async def delete_scanner(
        self, registration_id: Union[int, str]
    ) -> ScannerRegistration:
        scanner = await self.delete(f"/scanners/{registration_id}")
        if not scanner:
            raise HarborAPIException("Deletion request returned no data")
        return construct_model(ScannerRegistration, scanner)

    # PATCH /scanners/{registration_id}
    async def set_default_scanner(
        self, registration_id: Union[int, str], is_default: bool = True
    ) -> None:
        await self.patch(
            f"/scanners/{registration_id}", json=IsDefault(is_default=is_default)
        )

    # POST /scanners/ping
    async def ping_scanner_adapter(self, settings: ScannerRegistrationSettings) -> None:
        await self.post("/scanners/ping", json=settings)

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
    # GET /ping
    async def ping_harbor_api(self) -> str:
        """Pings the Harbor API to check if it is alive."""
        # TODO: add plaintext GET method so we don't have to do this here
        return await self.get_text("/ping")

    # CATEGORY: oidc

    # CATEGORY: SystemCVEAllowlist
    # PUT /system/CVEAllowlist
    async def update_cve_allowlist(self, allowlist: CVEAllowlist) -> None:
        """Overwrites the existing CVE allowlist with a new one."""
        await self.put("/system/CVEAllowlist", json=allowlist)

    # GET /system/CVEAllowlist
    async def get_cve_allowlist(self) -> CVEAllowlist:
        resp = await self.get("/system/CVEAllowlist")
        return construct_model(CVEAllowlist, resp)

    # CATEGORY: health
    # GET /health
    async def health_check(self) -> OverallHealthStatus:
        resp = await self.get("/health")
        return construct_model(OverallHealthStatus, resp)

    # CATEGORY: robotv1
    # CATEGORY: projectMetadata
    # CATEGORY: auditlog

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": "Basic " + self.token,
            "accept": "application/json",
        }

    @backoff.on_exception(backoff.expo, RequestError, max_time=30)
    async def get(
        self, path: str, params: Optional[dict] = None, headers: Optional[dict] = None
    ) -> JSONType:
        return await self._get(
            path,
            params=params,
            headers=headers,
        )

    @backoff.on_exception(backoff.expo, RequestError, max_time=30)
    async def get_text(
        self, path: str, params: Optional[dict] = None, headers: Optional[dict] = None
    ) -> str:
        """Bad workaround in order to have a cleaner API for text/plain responses."""
        resp = await self._get(
            path,
            params=params,
            headers=headers,
        )
        return resp  # type: ignore

    # TODO: refactor this method so it looks like the other methods, while still supporting pagination.
    async def _get(
        self, path: str, params: Optional[dict] = None, headers: Optional[dict] = None
    ) -> JSONType:
        headers = headers or {}
        headers.update(self._get_headers())

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                self.url + path,
                params=params,
                headers=headers,
            )
            check_response_status(resp)
        j = handle_optional_json_response(resp)
        if j is None:
            return resp.text  # type: ignore # FIXME: resolve this ASAP (use overload?)

        # If we have "Link" in headers, we need to handle paginated results
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
    async def post(
        self, path: str, json: Optional[Union[BaseModel, JSONType]] = None
    ) -> Response:
        """Sends a POST request to a path, optionally with a JSON body."""
        return await self._post(path, json)

    async def _post(
        self, path: str, json: Optional[Union[BaseModel, JSONType]] = None
    ) -> Response:
        if isinstance(json, BaseModel):
            json = json.dict()
        async with httpx.AsyncClient() as client:
            resp = await client.post(self.url + path, json=json)
            check_response_status(resp)
        return resp

    @backoff.on_exception(backoff.expo, RequestError, max_time=30)
    async def put(
        self, path: str, json: Union[BaseModel, JSONType]
    ) -> Optional[JSONType]:
        resp = await self._put(path, json)
        return handle_optional_json_response(resp)

    async def _put(self, path: str, json: Union[BaseModel, JSONType]) -> Response:
        if isinstance(json, BaseModel):
            json = json.dict()
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                self.url + path, json=json, headers=self._get_headers()
            )
            check_response_status(resp)
        return resp

    @backoff.on_exception(backoff.expo, RequestError, max_time=30)
    async def patch(
        self, path: str, json: Union[BaseModel, JSONType]
    ) -> Optional[JSONType]:
        resp = await self._patch(path, json)
        return handle_optional_json_response(resp)

    async def _patch(self, path: str, json: Union[BaseModel, JSONType]) -> Response:
        if isinstance(json, BaseModel):
            json = json.dict()

        async with httpx.AsyncClient() as client:
            resp = await client.patch(
                self.url + path, json=json, headers=self._get_headers()
            )
            check_response_status(resp)
        return resp

    @backoff.on_exception(backoff.expo, RequestError, max_time=30)
    async def delete(self, path: str, **kwargs) -> Optional[JSONType]:
        resp = await self._delete(path, **kwargs)
        return handle_optional_json_response(resp)

    async def _delete(self, path: str, **kwargs) -> Response:
        async with httpx.AsyncClient() as client:
            resp = await client.delete(self.url + path, headers=self._get_headers())
            check_response_status(resp)
        return resp

    # TODO: add on_giveup callback for all backoff methods
