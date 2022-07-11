import asyncio
from typing import Any, Dict, List, Optional, Type, TypeVar, Union

import backoff
import httpx
from httpx import RequestError, Response
from loguru import logger
from pydantic import BaseModel, ValidationError

from .exceptions import BadRequest, HarborAPIException, check_response_status
from .models import (
    Accessory,
    Artifact,
    AuditLog,
    CVEAllowlist,
    GeneralInfo,
    HarborVulnerabilityReport,
    IsDefault,
    Label,
    OIDCTestReq,
    OverallHealthStatus,
    PasswordReq,
    Permission,
    Quota,
    QuotaUpdateReq,
    Registry,
    RegistryInfo,
    RegistryPing,
    RegistryProviderInfo,
    RegistryUpdate,
    Repository,
    ScannerAdapterMetadata,
    ScannerRegistration,
    ScannerRegistrationReq,
    ScannerRegistrationSettings,
    Schedule,
    Search,
    Statistic,
    Stats,
    SystemInfo,
    Tag,
    UserCreationReq,
    UserProfile,
    UserResp,
    UserSearchRespItem,
    UserSysAdminFlag,
)
from .types import JSONType
from .utils import get_artifact_path, get_credentials, handle_optional_json_response

__all__ = ["HarborAsyncClient"]

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

    # NOTE: Async and sync clients were originally intended to be implemented
    #       as separate classes that both inherit from this class.
    #       However, given the way the sync client ended up being implemented,
    #       the functionality of this class should be baked into the async client.

    def __init__(
        self,
        url: str,
        username: str = None,
        secret: str = None,
        credentials: str = None,
        config: Optional[Any] = None,
        version: str = "v2.0",
    ) -> None:
        self.username = username
        if username and secret:
            self.credentials = get_credentials(username, secret)
        elif credentials:
            self.credentials = credentials
        else:
            raise ValueError("Must provide either username and secret or credentials")

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
        credentials: str = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(url, username, secret, credentials, **kwargs)
        self.client = httpx.AsyncClient()

    # NOTE: add destructor that closes client?

    # CATEGORY: user
    # PUT /users/{user_id}/cli_secret
    async def set_user_cli_secret(
        self,
        user_id: int,
        secret: str,
    ) -> None:
        """Set the CLI secret for a user.

        Parameters
        ----------
        user_id : int
            The ID of the user to set the secret for
        secret : str
            The secret to set for the user

        Raises
        ------
        BadRequest
            Invalid user ID.
            Or user is not onboarded via OIDC authentication.
            Or the secret does not meet the standard.
            (This is a Harbor API implementation detail.)
        """
        try:
            await self.put(f"/users/{user_id}/cli_secret", json={"secret": secret})
        except BadRequest as e:
            logger.error(e.__cause__.response.text if e.__cause__ else e.__str__())
            # TODO: do anything else here? Raise a more specific exception?
            raise

    # GET /users/search
    async def get_users_by_username(
        self,
        username: str,
        page: int = 1,
        page_size: int = 100,
        retrieve_all: bool = True,
    ) -> List[UserSearchRespItem]:
        """Search for users by username.

        Parameters
        ----------
        username : str
            The username to search for
        page : int
            The page of results to return
        page_size : int
            The number of results to return per page
        retrieve_all : bool
            If True, retrieve all results, otherwise, retrieve only the first page
        """
        params = {"username": username, "page": page, "page_size": page_size}
        users_resp = await self.get(
            "/users/search",
            params=params,
            follow_links=retrieve_all,
        )
        return [construct_model(UserSearchRespItem, u) for u in users_resp]

    # GET /users/current/permissions
    async def get_current_user_permissions(
        self, scope: Optional[str] = None, relative: bool = False
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
        resp = await self.get("/users/current/permissions", params=params)
        return [construct_model(Permission, p) for p in resp]

    # GET /users/current
    async def get_current_user(self) -> UserResp:
        user_resp = await self.get("/users/current")
        return construct_model(UserResp, user_resp)

    # PUT /users/{user_id}/sysadmin
    async def set_user_admin(self, user_id: int, is_admin: bool) -> None:
        """Set a user's admin status.

        Parameters
        ----------
        user_id : int
            The ID of the user to set the admin status for
        is_admin : bool
            Whether the user should be an admin or not
        """
        await self.put(
            f"/users/{user_id}/sysadmin", json=UserSysAdminFlag(sysadmin_flag=is_admin)
        )

    # PUT /users/{user_id}/password
    async def set_user_password(
        self,
        user_id: int,
        new_password: str,
        old_password: Optional[str] = None,
    ) -> None:
        """Set a user's password.
        Admin users can change any user's password.
        Non-admin users can only change their own password.

        Parameters
        ----------
        user_id : int
            The ID of the user to set the password for
        new_password : str
            The new password to set for the user
        old_password : str
            The old password for the user, not required if API user is admin.

        Raises
        ------
        BadRequest
            Raised for any of the following reasons:
            * Invalid user ID
            * Password does not meet requirement
            * Old password is incorrect
        """
        try:
            await self.put(
                f"/users/{user_id}/password",
                json=PasswordReq(old_password=old_password, new_password=new_password),
            )
        except BadRequest as e:
            logger.error(e.__cause__.response.text if e.__cause__ else e.__str__())
            raise

    # POST /users
    async def create_user(self, user: UserCreationReq) -> Optional[str]:
        """Create a new user.
        Can only be used when the authentication mode is for local DB,
        when self registration is disabled.

        Parameters
        ----------
        user : UserCreationReq
            The user to create

        Returns
        -------
        Optional[str]
            The location of the created user
        """
        resp = await self.post("/users", json=user)
        return resp.headers.get("Location")

    # GET /users
    async def get_users(self, sort: Optional[str] = None, **kwargs) -> List[UserResp]:
        params = {**kwargs}
        if sort:
            params["sort"] = sort
        users_resp = await self.get("/users", params=params)
        return [construct_model(UserResp, u) for u in users_resp]

    # PUT /users/{user_id}
    async def update_user_profile(self, user_id: int, user: UserProfile) -> None:
        """Update a user's profile.

        Parameters
        ----------
        user_id : int
            The ID of the user to update
        user : UserProfile
            The user profile to update
        """
        await self.put(f"/users/{user_id}", json=user)

    # GET /users/{user_id}
    async def get_user(self, user_id: int) -> UserResp:
        user_resp = await self.get(f"/users/{user_id}")
        return construct_model(UserResp, user_resp)

    # DELETE /users/{user_id}
    async def delete_user(self, user_id: int, missing_ok: bool = False) -> None:
        await self.delete(f"/users/{user_id}", missing_ok=missing_ok)

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

    # GET /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/scan/{report_id}/log
    async def get_artifact_scan_report_log(
        self, project_name: str, repository_name: str, reference: str, report_id: str
    ) -> str:
        """Get the log of a scan report."""
        # TODO: investigate what exactly this endpoint returns
        path = get_artifact_path(project_name, repository_name, reference)
        return await self.get_text(f"{path}/scan/{report_id}/log")

    # # POST /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/scan/stop
    async def stop_artifact_scan(
        self, project_name: str, repository_name: str, reference: str
    ) -> None:
        """Stop a scan for a particular artifact."""
        path = get_artifact_path(project_name, repository_name, reference)
        resp = await self.post(f"{path}/scan/stop")
        if resp.status_code != 202:
            logger.warning(
                "Stop scan request for {} returned status code {}, expected 202",
                path,
                resp.status_code,
            )

    # CATEGORY: member
    # CATEGORY: ldap

    # CATEGORY: registry
    # POST /registries/ping
    async def check_registry_status(self, ping: RegistryPing) -> None:
        """Check the status of the registry."""
        await self.post("/registries/ping", json=ping)

    # GET /replication/adapters
    async def get_registry_adapters(self) -> List[str]:
        """Get the list of available registry adapters."""
        resp = await self.get("/replication/adapters")
        return resp  # type: ignore # we know this is a list of strings

    # GET /registries/{id}/info
    async def get_registry_info(self, id: int) -> RegistryInfo:
        """Get the info of a registry."""
        resp = await self.get(f"/registries/{id}/info")
        return construct_model(RegistryInfo, resp)

    # GET /replication/adapterinfos
    async def get_registry_providers(self) -> List[RegistryProviderInfo]:
        """Get all registered registry provider information.

        Returns
        -------
        List[RegistryProviderInfo]
            A list of RegistryProviderInfo objects.
        """
        resp = await self.get("/replication/adapterinfos")
        return [construct_model(RegistryProviderInfo, p) for p in resp]

    # PUT /registries/{id}
    async def update_registry(self, id: int, registry: RegistryUpdate) -> None:
        """Update a registry.

        Parameters
        ----------
        id : int
            The ID of the registry
        registry : RegistryUpdate
            The updated registry values.
        """
        await self.put(f"/registries/{id}", json=registry)

    # GET /registries/{id}
    async def get_registry(self, id: int) -> Registry:
        """Get a registry.

        Parameters
        ----------
        id : int
            The ID of the registry
        """
        resp = await self.get(f"/registries/{id}")
        return construct_model(Registry, resp)

    # DELETE /registries/{id}
    async def delete_registry(self, id: int, missing_ok: bool = False) -> None:
        """Delete a registry.

        Parameters
        ----------
        id : int
            The ID of the registry
        missing_ok : bool
            If True, don't raise an exception if the registry doesn't exist.
        """
        await self.delete(f"/registries/{id}", missing_ok=missing_ok)

    # POST /registries
    async def create_registry(self, registry: Registry) -> Optional[str]:
        """Create a new registry.

        Parameters
        ----------
        registry : Registry
            The new registry values.

        Returns
        -------
        Optional[str]
            The ID of the new registry if it exists.
            This value should probably never be `None`.
        """
        resp = await self.post("/registries", json=registry)
        return resp.headers.get("Location")

    # GET /registries
    async def get_registries(
        self,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        name: Optional[str] = None,
        retrieve_all: bool = True,
    ) -> List[Registry]:
        """Get all registries.

        Parameters
        ----------
        query : Optional[str]
            A query string to filter the artifacts

            Except the basic properties, the other supported queries includes:
            * `"tags=*"` to list only tagged artifacts
            * `"tags=nil"` to list only untagged artifacts
            * `"tags=~v"` to list artifacts whose tag fuzzy matches "v"
            * `"tags=v"` to list artifact whose tag exactly matches "v"
            * `"labels=(id1, id2)"` to list artifacts that both labels with id1 and id2 are added to

        sort : Optional[str]
            The sort order of the artifacts.
        page : int
            The page of results to return, default 1
        page_size : int
            The number of results to return per page, default 10
        name: str: Optional[str]
            The name of the registry (deprecated, use `query` instead)
        retrieve_all: bool
            If true, retrieve all the resources,
            otherwise, retrieve only the number of resources specified by `page_size`.

        Returns
        -------
        List[Registry]
            A list of Registry objects.
        """
        params = {
            "query": query,
            "sort": sort,
            "page": page,
            "page_size": page_size,
            "name": name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        resp = await self.get("/registries", params=params, follow_links=retrieve_all)
        return [construct_model(Registry, r) for r in resp]

    # CATEGORY: search
    # GET /search
    async def search(self, query: str) -> Search:
        """Search for projects, repositories and helm charts that the user has access to.

        WARNING
        -------
        This method's API is highly likely to change in the future.
        Right now we just copy the API spec, which requires a query string.

        Parameters
        ----------
        query : str
            Search parameters for project and repository name.
            NOTE: API docs do not mention helm charts here. Oversight?
        """
        resp = await self.get("/search", params={"q": query})
        return construct_model(Search, resp)

    # CATEGORY: artifact

    # POST /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/tags
    async def create_artifact_tag(
        self, project_name: str, repository_name: str, reference: str, tag: Tag
    ) -> str:
        """Create a tag for an artifact.

        Parameters
        ----------
        project_name : str
            The name of the project
        repository_name : str
            The name of the repository
        reference : str
            The reference of the artifact, can be digest or tag
        tag : Tag
            The tag to create
        """
        path = get_artifact_path(project_name, repository_name, reference)
        resp = await self.post(f"{path}/tags", json=tag)
        if resp.status_code != 201:
            logger.warning(
                "Create tag request for {} returned status code {}, expected 201",
                path,
                resp.status_code,
            )
        return resp.headers.get("Location")

    # GET /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/tags
    async def get_artifact_tags(
        self,
        project_name: str,
        repository_name: str,
        reference: str,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        with_signature: bool = False,
        with_immutable_status: bool = False,
        retrieve_all: bool = True,
    ) -> List[Tag]:
        """Get the tags for an artifact.

        Parameters
        ----------
        project_name : str
            The name of the project
        repository_name : str
            The name of the repository
        reference : str
            The reference of the artifact, can be digest or tag
        query : Optional[str]
            A query string to filter the tags
        sort : Optional[str]
            The sort order of the tags. TODO: document this parameter
        page : int
            The page of results to return, default 1
        page_size : int
            The number of results to return per page, default 10
        with_signature : bool
            Whether to include the signature of the tag in the response
        with_immutable_status : bool
            Whether to include the immutable status of the tag in the response
        retrieve_all: bool
            If true, retrieve all the resources,
            otherwise, retrieve only the number of resources specified by `page_size`.

        Returns
        -------
        List[Tag]
            A list of Tag objects for the artifact.
        """
        path = get_artifact_path(project_name, repository_name, reference)
        params = {
            "page": page,
            "page_size": page_size,
            "with_signature": with_signature,
            "with_immutable_status": with_immutable_status,
        }  # type: Dict[str, Any]
        if query:
            params["q"] = query
        if sort:
            params["sort"] = sort
        resp = await self.get(f"{path}/tags", follow_links=retrieve_all)
        return [construct_model(Tag, t) for t in resp]

    # GET /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/tags
    async def get_artifact_accessories(
        self,
        project_name: str,
        repository_name: str,
        reference: str,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        retrieve_all: bool = True,
    ) -> List[Accessory]:
        """Get the tags for an artifact.

        Parameters
        ----------
        project_name : str
            The name of the project
        repository_name : str
            The name of the repository
        reference : str
            The reference of the artifact, can be digest or tag
        query : Optional[str]
            A query string to filter the tags
        sort : Optional[str]
            The sort order of the tags.
        page : int
            The page of results to return, default 1
        page_size : int
            The number of results to return per page, default 10
        retrieve_all: bool
            If true, retrieve all the resources,
            otherwise, retrieve only the number of resources specified by `page_size`.

        Returns
        -------
        List[Accessory]
            A list of Accessory objects for the artifact.
        """
        path = get_artifact_path(project_name, repository_name, reference)
        params = {
            "page": page,
            "page_size": page_size,
        }  # type: Dict[str, Any]
        if query:
            params["q"] = query
        if sort:
            params["sort"] = sort
        resp = await self.get(f"{path}/accessories", follow_links=retrieve_all)
        return [construct_model(Accessory, a) for a in resp]

    # DELETE /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/tags
    async def delete_artifact_tag(
        self,
        project_name: str,
        repository_name: str,
        reference: str,
        tag_name: str,
        missing_ok: bool = False,
    ) -> None:
        """Get the tags for an artifact.

        Parameters
        ----------
        project_name : str
            The name of the project
        repository_name : str
            The name of the repository
        reference : str
            The reference of the artifact, can be digest or tag
        tag_name : str
            The name of the tag to delete
        """
        path = get_artifact_path(project_name, repository_name, reference)
        # TODO: implement missing_ok for all delete methods
        await self.delete(f"{path}/tags/{tag_name}", missing_ok=missing_ok)

    # POST /projects/{project_name}/repositories/{repository_name}/artifacts
    async def copy_artifact(
        self, project_name: str, repository_name: str, source: str
    ) -> Optional[str]:
        """Copy an artifact.

        Parameters
        ----------
        project_name : str
            Name of new artifact's project
        repository_name : str
            Name of new artifact's repository
        source : str
            The source artifact to copy from in the form of
            `"project/repository:tag"` or `"project/repository@digest"`

        Returns
        -------
        Optional[str]
            The location of the new artifact
        """
        path = f"/projects/{project_name}/repositories/{repository_name}/artifacts"
        resp = await self.post(f"{path}", params={"from": source})
        if resp.status_code != 201:
            logger.warning(
                "Copy artifact request for {} returned status code {}, expected 201",
                path,
                resp.status_code,
            )
        return resp.headers.get("Location")

    # GET /projects/{project_name}/repositories/{repository_name}/artifacts
    async def get_artifacts(
        self,
        project_name: str,
        repository_name: str,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        with_tag: bool = True,
        with_label: bool = False,
        with_scan_overview: bool = False,
        with_signature: bool = False,
        with_immutable_status: bool = False,
        with_accessory: bool = False,
        mime_type: str = "application/vnd.security.vulnerability.report; version=1.1",
        retrieve_all: bool = True,
    ) -> List[Artifact]:
        """Get the artifacts for a repository.

        Parameters
        ----------
        project_name : str
            The name of the project
        repository_name : str
            The name of the repository
        query : Optional[str]
            A query string to filter the artifacts

            Except the basic properties, the other supported queries includes:
            * `"tags=*"` to list only tagged artifacts
            * `"tags=nil"` to list only untagged artifacts
            * `"tags=~v"` to list artifacts whose tag fuzzy matches "v"
            * `"tags=v"` to list artifact whose tag exactly matches "v"
            * `"labels=(id1, id2)"` to list artifacts that both labels with id1 and id2 are added to

        sort : Optional[str]
            The sort order of the artifacts.
        page : int
            The page of results to return, default 1
        page_size : int
            The number of results to return per page, default 10
        with_tag : bool
            Whether to include the tags of the artifact in the response
        with_label : bool
            Whether to include the labels of the artifact in the response
        with_scan_overview : bool
            Whether to include the scan overview of the artifact in the response
        with_signature : bool
            Whether the signature is included inside the tags of the returning artifacts.
            Only works when setting `with_tag==True`.
        with_immutable_status : bool
            Whether the immutable status is included inside the tags of the returning artifacts.
        with_accessory : bool
            Whether the accessories are included of the returning artifacts.
        mime_type : str
            A comma-separated lists of MIME types for the scan report or scan summary.
            The first mime type will be used when the report found for it.
            Currently the mime type supports:
            * `'application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0'`
            * `'application/vnd.security.vulnerability.report; version=1.1'`
        retrieve_all: bool
            If true, retrieve all the resources,
            otherwise, retrieve only the number of resources specified by `page_size`.
        """
        path = f"/projects/{project_name}/repositories/{repository_name}/artifacts"
        params = {
            "page": page,
            "page_size": page_size,
            "with_tag": with_tag,
            "with_label": with_label,
            "with_scan_overview": with_scan_overview,
            "with_signature": with_signature,
            "with_immutable_status": with_immutable_status,
            "with_accessory": with_accessory,
        }  # type: Dict[str, Union[str, int, bool]]
        if query:
            params["q"] = query
        if sort:
            params["sort"] = sort
        resp = await self.get(
            f"{path}",
            params=params,
            headers={"X-Accept-Vulnerabilities": mime_type},
            follow_links=retrieve_all,
        )
        return [construct_model(Artifact, a) for a in resp]

    # POST /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/labels
    async def add_artifact_label(
        self,
        project_name: str,
        repository_name: str,
        reference: str,
        label: Label,
    ) -> None:
        """Add a label to an artifact.

        Parameters
        ----------
        project_name : str
            The name of the project
        repository_name : str
            The name of the repository
        reference : str
            The reference of the artifact, can be digest or tag
        label : Label
            The label to add
        """
        path = get_artifact_path(project_name, repository_name, reference)
        await self.post(
            f"{path}/labels",
            json=label,
        )
        # response should have status code 201, but API spec says it's 200
        # so we don't check it

    async def get_artifact(
        self,
        project_name: str,
        repository_name: str,
        reference: str,
        page: int = 1,
        page_size: int = 10,
        with_tag: bool = True,
        with_label: bool = False,
        with_scan_overview: bool = False,
        with_signature: bool = False,
        with_immutable_status: bool = False,
        with_accessory: bool = False,
        mime_type: str = "application/vnd.security.vulnerability.report; version=1.1",
    ) -> Artifact:
        """Get an artifact.

        Parameters
        ----------
        project_name : str
            The name of the project
        repository_name : str
            The name of the repository
        reference : str
            The reference of the artifact, can be digest or tag
        page : int
            The page of results to return, default 1
            NOTE: unclear if this has an effect, even though it's in the API spec
        page_size : int
            The number of results to return per page, default 10
            NOTE: unclear if this has an effect, even though it's in the API spec
        with_tag : bool
            Whether to include the tags of the artifact in the response
        with_label : bool
            Whether to include the labels of the artifact in the response
        with_scan_overview : bool
            Whether to include the scan overview of the artifact in the response
        with_signature : bool
            Whether the signature is included inside the tags of the returning artifact.
            Only works when setting `with_tag==True`.
        with_immutable_status : bool
            Whether the immutable status is included inside the tags of the returning artifact.
        with_accessory : bool
            Whether the accessories are included of the returning artifact.
        mime_type : str
            A comma-separated lists of MIME types for the scan report or scan summary.
            The first mime type will be used when the report found for it.
            Currently the mime type supports:
            * `'application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0'`
            * `'application/vnd.security.vulnerability.report; version=1.1'`
        """
        path = get_artifact_path(project_name, repository_name, reference)
        resp = await self.get(
            f"{path}",
            params={
                "page": page,
                "page_size": page_size,
                "with_tag": with_tag,
                "with_label": with_label,
                "with_scan_overview": with_scan_overview,
                "with_signature": with_signature,
                "with_immutable_status": with_immutable_status,
                "with_accessory": with_accessory,
            },
            headers={"X-Accept-Vulnerabilities": mime_type},
        )
        return construct_model(Artifact, resp)

    async def delete_artifact(
        self,
        project_name: str,
        repository_name: str,
        reference: str,
        missing_ok: bool = False,
    ) -> None:
        """Delete an artifact.

        Parameters
        ----------
        project_name : str
            The name of the project
        repository_name : str
            The name of the repository
        reference : str
            The reference of the artifact, can be digest or tag
        missing_ok : bool
            Whether to ignore 404 error when deleting the artifact
        """
        path = get_artifact_path(project_name, repository_name, reference)
        await self.delete(path, missing_ok=missing_ok)

    async def delete_artifact_label(
        self,
        project_name: str,
        repository_name: str,
        reference: str,
        label_id: int,
        missing_ok: bool = False,
    ) -> None:
        """Delete an artifact.

        Parameters
        ----------
        project_name : str
            The name of the project
        repository_name : str
            The name of the repository
        reference : str
            The reference of the artifact, can be digest or tag
        label_id : int
            The id of the label to delete
        missing_ok : bool
            Whether to ignore 404 error when deleting the label
        """
        path = get_artifact_path(project_name, repository_name, reference)
        url = f"{path}/labels/{label_id}"
        await self.delete(url, missing_ok=missing_ok)

    # GET /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/additions/vulnerabilities
    async def get_artifact_vulnerabilities(
        self,
        project_name: str,
        repository_name: str,
        reference: str,  # Make this default to "latest"?
        # TODO: support multiple mime types?
        mime_type: str = "application/vnd.security.vulnerability.report; version=1.1",
    ) -> Optional[HarborVulnerabilityReport]:
        """Get the vulnerabilities for an artifact."""
        path = get_artifact_path(project_name, repository_name, reference)
        url = f"{path}/additions/vulnerabilities"
        resp = await self.get(url, headers={"X-Accept-Vulnerabilities": mime_type})

        if not isinstance(resp, dict):
            logger.bind(response=resp).warning("{} returned non-dict response", url)
            return None

        # Get the report, which is stored under the key of the mime type
        report = resp.get(mime_type)
        if not report:
            logger.warning("{} returned no report", url)  # Is this an error?
            return None

        return construct_model(HarborVulnerabilityReport, report)

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
        self,
        registration_id: Union[int, str],
        missing_ok: bool = False,
    ) -> Optional[ScannerRegistration]:
        scanner = await self.delete(
            f"/scanners/{registration_id}", missing_ok=missing_ok
        )
        # TODO: differentiate between 404 and no return value (how?)
        if not scanner:
            if missing_ok:
                return None
            raise HarborAPIException(
                "Deletion request returned no data. Is the scanner registered?"
            )
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

    # GET /systeminfo/volumes
    async def get_system_volume_info(self) -> SystemInfo:
        """Get info about the system's volumes."""
        resp = await self.get("/systeminfo/volumes")
        return construct_model(SystemInfo, resp)

    # GET /systeminfo/getcert
    # async def get_system_certificate(self) -> str:
    #     """Get the certificate for the system."""
    #     raise NotImplementedError("File download not yet implemented")

    # GET /systeminfo
    async def get_system_info(self) -> GeneralInfo:
        """Get info about the system."""
        resp = await self.get("/systeminfo")
        return construct_model(GeneralInfo, resp)

    # CATEGORY: statistic
    async def get_statistics(self) -> Statistic:
        """Get the statistics of the Harbor server."""
        stats = await self.get("/statistics")
        return construct_model(Statistic, stats)

    # CATEGORY: quota
    async def get_quotas(
        self,
        reference: Optional[str] = None,
        reference_id: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        retrieve_all: bool = True,
    ) -> List[Quota]:
        """Get quotas.

        Parameters
        ----------
        reference : str
            The reference type of the quota.
            TODO: document what these values can be.
        reference_id : str
            The reference id of the quota
        sort : str
            Sort method.
            Valid values include:
            - `"hard.resource_name"`
            - `"-hard.resource_name"`
            - `"used.resource_name"`
            - `"-used.resource_name"`

            `"-"` denotes descending order, resource_name should be the real
            resource name of the quota
        page: int
            The page number to retrieve resources from.
        page_size: int
            The number of resources to retrieve per page.
        retrieve_all: bool
            If true, retrieve all the resources,
            otherwise, retrieve only the number of resources specified by `page_size`.
        """
        params = {
            "reference": reference,
            "reference_id": reference_id,
            "sort": sort,
            "page": page,
            "page_size": page_size,
        }
        params = {k: v for k, v in params.items() if v is not None}
        quotas = await self.get("/quotas", params=params, follow_links=retrieve_all)
        return [construct_model(Quota, q) for q in quotas]

    async def update_quota(self, id: int, quota: QuotaUpdateReq) -> None:
        """Update a quota.

        Parameters
        ----------
        id : int
            The id of the quota to update.
        quota : QuotaUpdateReq
            The new quota values.
            `QuotaUpdateReq.hard` allows assignment of any attribute with
            an `int` value.

            Example:
            ```py
            QuotaUpdateReq(
                hard={"storage": 100000, "other_property": 1234}
            )
            ```
        """
        await self.put(f"/quotas/{id}", json=quota)

    async def get_quota(self, id: int) -> Quota:
        """Get a quota by id.

        Parameters
        ----------
        id : int
            The id of the quota to get.
        """
        quota = await self.get(f"/quotas/{id}")
        return construct_model(Quota, quota)

    # CATEGORY: repository

    # GET /projects/{project_name}/repositories/{repository_name}
    async def get_repository(
        self,
        project_id: str,
        repository_name: str,
    ) -> Repository:
        """Get a repository.

        Parameters
        ----------
        project_id : int
            The id of the project the repository belongs to.
        repository_name : str
            The name of the repository.

        Returns
        -------
        Repository
            The repository.
        """
        resp = await self.get(f"/projects/{project_id}/repositories/{repository_name}")
        return construct_model(Repository, resp)

    # PUT /projects/{project_name}/repositories/{repository_name}
    async def update_repository(
        self,
        project_name: str,
        repository_name: str,
        repository: Repository,
    ) -> None:
        """Get a repository.

        Parameters
        ----------
        project_id : int
            The name of the project the repository belongs to.
        repository_name : str
            The name of the repository.
        """
        url = f"/projects/{project_name}/repositories/{repository_name}"
        await self.put(url, json=repository)

    # DELETE /projects/{project_name}/repositories/{repository_name}
    async def delete_repository(
        self,
        project_id: str,
        repository_name: str,
        missing_ok: bool = False,
    ) -> None:
        """Get a repository.

        Parameters
        ----------
        project_id : int
            The id of the project the repository belongs to.
        repository_name : str
            The name of the repository.
        missing_ok : bool
            If true, do not raise an error if the repository does not exist.
        """
        await self.delete(
            f"/projects/{project_id}/repositories/{repository_name}",
            missing_ok=True,
        )

    # GET /projects/{project_name}/repositories
    # &
    # GET /repositories
    async def get_repositories(
        self,
        project_name: Optional[str] = None,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        retrieve_all: bool = True,
    ) -> List[Repository]:
        """Get a list of repositories

        Parameters
        ----------
        project_name : str
            The name of the project.
        query : str
            The query string.
            Supported query patterns are "exact match(k=v)", "fuzzy match(k=~v)", "range(k=[min~max])", "list with union releationship(k={v1 v2 v3})" and "list with intersetion relationship(k=(v1 v2 v3))". The value of range and list can be string(enclosed by " or '), integer or time(in format "2020-04-09 02:36:00"). All of these query patterns should be put in the query string "q=xxx" and splitted by ",". e.g. q=k1=v1,k2=~v2,k3=[min~max]

            TODO: format query documentation
        sort : str
            The sort method.
            TODO: add boilerplate sort documentation
        page : int
            The page number.
        page_size : int
            The page size.
        retrieve_all : bool
            If true, retrieve all the resources,
            otherwise, retrieve only the number of resources specified by `page_size`.
        """
        params = {
            "query": query,
            "sort": sort,
            "page": page,
            "page_size": page_size,
        }
        params = {k: v for k, v in params.items() if v is not None}
        if project_name:
            url = f"/projects/{project_name}/repositories"
        else:
            url = "/repositories"
        resp = await self.get(url, params=params, follow_links=retrieve_all)
        return [construct_model(Repository, r) for r in resp]

    # CATEGORY: ping
    # GET /ping
    async def ping_harbor_api(self) -> str:
        """Pings the Harbor API to check if it is alive."""
        return await self.get_text("/ping")

    # CATEGORY: oidc
    # POST /system/oidc/ping
    async def test_oidc(self, oidcreq: OIDCTestReq) -> None:
        """Tests an OIDC endpoint. Can only be called by system admin.

        Raises `StatusError` if endpoint is unreachable.

        Parameters
        ----------
        oidctest : OIDCTestReq
            The OIDC test request.
        """
        await self.post("/system/oidc/ping", json=oidcreq)

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
    # GET /audit-logs
    async def get_audit_logs(
        self,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        retrieve_all: bool = False,
    ) -> List[AuditLog]:
        """Get a list of audit logs for the projects the user is a member of.

        NOTE
        ----
        Set `retrieve_all` to `True` to retrieve the entire audit log for all projects.

        Parameters
        ----------
        query: Optional[str]
            Query string to query resources.

            Supported query patterns are
            * exact match(`"k=v"`)
            * fuzzy match(`"k=~v"`)
            * range(`"k=[min~max]"`)
            * list with union releationship(`"k={v1 v2 v3}"`)
            * list with intersection relationship(`"k=(v1 v2 v3)"`).

            The value of range and list can be
            * string(enclosed by `"` or `'`)
            * integer
            * time(in format `"2020-04-09 02:36:00"`)

            All of these query patterns should be put in the query string and separated by `","`.
            e.g. `"k1=v1,k2=~v2,k3=[min~max]"`
        sort: Optional[str]
            Sort the resource list in ascending or descending order.
            e.g. sort by field1 in ascending order and field2 in descending order with `"sort=field1,-field2"`
        page: int
            The page number to fetch resources from.
        page_size: int
            The number of resources to fetch per page.
        retrieve_all: bool
            If true, retrieve all the resources,
            otherwise, retrieve only the number of resources specified by `page_size`.

        Returns
        -------
        List[AuditLog]
            The list of audit logs.
        """
        params = {
            "query": query,
            "sort": sort,
            "page": page,
            "page_size": page_size,
        }
        params = {k: v for k, v in params.items() if v is not None}
        resp = await self.get("/audit-logs", params=params, follow_links=retrieve_all)
        return [construct_model(AuditLog, r) for r in resp]

    def _get_headers(self, headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = headers or {}
        base_headers = {
            "Authorization": "Basic " + self.credentials,
            "Accept": "application/json",
        }
        base_headers.update(headers)  # Override defaults with provided headers
        return base_headers

    @backoff.on_exception(backoff.expo, RequestError, max_time=30)
    async def get(
        self,
        path: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        follow_links: bool = True,
        **kwargs,
    ) -> JSONType:
        return await self._get(
            path,
            params=params,
            headers=headers,
            follow_links=follow_links,
            **kwargs,
        )

    @backoff.on_exception(backoff.expo, RequestError, max_time=30)
    async def get_text(
        self,
        path: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        **kwargs,
    ) -> str:
        """Bad workaround in order to have a cleaner API for text/plain responses."""
        resp = await self._get(path, params=params, headers=headers, **kwargs)
        return resp  # type: ignore

    # TODO: refactor this method so it looks like the other methods, while still supporting pagination.
    async def _get(
        self,
        path: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        follow_links: bool = True,
        **kwargs,
    ) -> JSONType:
        """Sends a GET request to the Harbor API.
        Returns JSON unless the response is text/plain.

        Parameters
        ----------
        path : str
            URL path to resource
        params : Optional[dict], optional
            Request parameters, by default None
        headers : Optional[dict], optional
            Request headers, by default None
        follow_links : bool, optional
            Enable pagination by following links in response header, by default True

        Returns
        -------
        JSONType
            JSON data returned by the API
        """
        # async with httpx.AsyncClient() as client:
        resp = await self.client.get(
            self.url + path,
            params=params,
            headers=self._get_headers(headers),
        )
        check_response_status(resp)
        j = handle_optional_json_response(resp)
        if j is None:
            return resp.text  # type: ignore # FIXME: resolve this ASAP (use overload?)

        # If we have "Link" in headers, we need to handle paginated results
        if (link := resp.headers.get("link")) and follow_links:
            logger.debug("Handling paginated results. URL: {}", link)
            j = await self._handle_pagination(j, link)  # recursion (refactor?)

        return j

    async def _handle_pagination(self, data: JSONType, link: str) -> JSONType:
        """Handles paginated results by recursing until all results are returned."""
        # NOTE: can this be done more elegantly?
        # TODO: re-use async client somehow
        j = await self.get(link)  # ignoring params and only using the link
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
        self,
        path: str,
        json: Optional[Union[BaseModel, JSONType]] = None,
        params: Optional[dict] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Response:
        """Sends a POST request to a path, optionally with a JSON body."""
        return await self._post(
            path,
            json=json,
            params=params,
            headers=headers,
        )

    async def _post(
        self,
        path: str,
        json: Optional[Union[BaseModel, JSONType]] = None,
        params: Optional[dict] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Response:
        if isinstance(json, BaseModel):
            json = json.dict()
        resp = await self.client.post(
            self.url + path,
            json=json,
            params=params,
            headers=self._get_headers(headers),
        )
        check_response_status(resp)
        return resp

    @backoff.on_exception(backoff.expo, RequestError, max_time=30)
    async def put(
        self,
        path: str,
        json: Union[BaseModel, JSONType],
        params: Optional[dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> Optional[JSONType]:
        resp = await self._put(
            path,
            json=json,
            params=params,
            headers=headers,
            **kwargs,
        )
        return handle_optional_json_response(resp)

    async def _put(
        self,
        path: str,
        json: Union[BaseModel, JSONType],
        params: Optional[dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> Response:
        if isinstance(json, BaseModel):
            json = json.dict()
        resp = await self.client.put(
            self.url + path,
            json=json,
            params=params,
            headers=self._get_headers(headers),
            **kwargs,
        )
        check_response_status(resp)
        return resp

    @backoff.on_exception(backoff.expo, RequestError, max_time=30)
    async def patch(
        self,
        path: str,
        json: Union[BaseModel, JSONType],
        params: Optional[dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> Optional[JSONType]:
        resp = await self._patch(
            path,
            json=json,
            headers=headers,
            params=params,
            **kwargs,
        )
        return handle_optional_json_response(resp)

    async def _patch(
        self,
        path: str,
        json: Union[BaseModel, JSONType],
        params: Optional[dict] = None,
        headers: Optional[Dict[str, str]] = None,
        **kwargs,
    ) -> Response:
        if isinstance(json, BaseModel):
            json = json.dict()

        resp = await self.client.patch(
            self.url + path,
            json=json,
            params=params,
            headers=self._get_headers(headers),
            **kwargs,
        )
        check_response_status(resp)
        return resp

    @backoff.on_exception(backoff.expo, RequestError, max_time=30)
    async def delete(
        self,
        path: str,
        params: Optional[dict] = None,
        headers: Optional[Dict[str, str]] = None,
        missing_ok: bool = False,
        **kwargs,
    ) -> Optional[JSONType]:
        resp = await self._delete(
            path,
            headers=headers,
            params=params,
            missing_ok=missing_ok,
            **kwargs,
        )
        return handle_optional_json_response(resp)

    async def _delete(
        self,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[dict] = None,
        missing_ok: bool = False,
        **kwargs,
    ) -> Response:
        resp = await self.client.delete(
            self.url + path,
            params=params,
            headers=self._get_headers(headers),
            **kwargs,
        )
        check_response_status(resp, missing_ok=missing_ok)
        return resp

    # TODO: add on_giveup callback for all backoff methods
