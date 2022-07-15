import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional, Type, TypeVar, Union

import backoff
import httpx
from httpx import RequestError, Response
from loguru import logger
from pydantic import BaseModel, ValidationError

from harborapi.auth import load_harbor_auth_file, new_authfile_from_robotcreate

from .exceptions import BadRequest, HarborAPIException, NotFound, check_response_status
from .models import (
    Accessory,
    Artifact,
    AuditLog,
    Configurations,
    ConfigurationsResponse,
    CVEAllowlist,
    GeneralInfo,
    HarborVulnerabilityReport,
    InternalConfigurationsResponse,
    IsDefault,
    Label,
    OIDCTestReq,
    OverallHealthStatus,
    PasswordReq,
    Permission,
    Project,
    ProjectDeletable,
    ProjectReq,
    ProjectScanner,
    ProjectSummary,
    Quota,
    QuotaUpdateReq,
    Registry,
    RegistryInfo,
    RegistryPing,
    RegistryProviderInfo,
    RegistryUpdate,
    Repository,
    Robot,
    RobotCreate,
    RobotCreated,
    RobotSec,
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
from .utils import (
    get_artifact_path,
    get_credentials,
    get_project_headers,
    get_repo_path,
    handle_optional_json_response,
    parse_pagination_url,
    urldecode_header,
)

__all__ = ["HarborAsyncClient"]

T = TypeVar("T", bound=BaseModel)


def construct_model(cls: Type[T], data: Any) -> T:
    try:
        return cls.parse_obj(data)
    except ValidationError as e:
        logger.error("Failed to construct {} with {}", cls, data)
        raise e


class HarborAsyncClient:
    def __init__(
        self,
        url: str,
        username: Optional[str] = None,
        secret: Optional[str] = None,
        credentials: Optional[str] = None,
        credentials_file: Optional[Union[str, Path]] = None,
        logging: bool = False,
        config: Optional[Any] = None,  # NYI
        version: str = "2.0",
        **kwargs: Any,
    ) -> None:
        """Initialize a new HarborAsyncClient with either a username and secret,
        an authentication token, or a credentials file.

        Parameters
        ----------
        url : str
            The URL of the Harbor server in the format `http://host:[port]/api/v<version>`

            Example: `http://localhost:8080/api/v2.0`
        username : Optional[str]
            Username to use for authentication.
            If not provided, the client attempts to use `credentials` to authenticate.
        secret : Optional[str]
            Secret to use for authentication along with `username`.
        credentials : Optional[str]
            base64-encoded Basic Access Authentication credentials to use for
            authentication in place of `username` and `secret`.
        credentials_file : Optional[Union[str, Path]]
            Path to a JSON-encoded credentials file from which to load credentials.
        logging : bool
            Enable client logging with `Loguru`.
        config : Optional[Any]
            (NYI) config
        version : str
            Used to construct URL if the specified URL does not contain the version.

        Raises
        ------
        ValueError
            Neither `username` and `secret`, `credentials` nor `credentials_file` are provided.
        """
        if username and secret:
            self.credentials = get_credentials(username, secret)
        elif credentials:
            self.credentials = credentials
        elif credentials_file:
            crfile = load_harbor_auth_file(credentials_file)
            self.credentials = get_credentials(crfile.name, crfile.secret)  # type: ignore # load_harbor_auth_file guarantees these are not None
        else:
            raise ValueError(
                "Must provide username and secret, credentials, or credentials_file"
            )

        # TODO: add URL regex and improve parsing OR don't police this at all
        url = url.strip("/")  # remove trailing slash
        if version and not "/api/v" in url:
            version = str(version)
            if "v" not in version:
                version = f"v{version}"
            if "/api" in url:
                url = url.strip("/") + "/" + version
            else:
                url = url + "/api/" + version

        self.url = url.strip("/")  # make sure we haven't added a trailing slash again
        self.config = config
        self.client = httpx.AsyncClient()

        # NOTE: make env var?
        if logging:
            # we explicitly enable the logger here, because previous instantiations
            # of the client may have disabled it.
            logger.enable("harborapi")
        else:
            logger.disable("harborapi")

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
        relative : bool
            Display resource paths relative to the scope.
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
        """Get information about the current user.

        Returns
        -------
        UserResp
            Information about the current user.
        """
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
    async def create_user(self, user: UserCreationReq) -> str:
        """Create a new user.
        Can only be used when the authentication mode is for local DB,
        when self registration is disabled.

        Parameters
        ----------
        user : UserCreationReq
            The user to create

        Returns
        -------
        str
            The location of the created user
        """
        resp = await self.post("/users", json=user)
        return urldecode_header(resp, "Location")

    # GET /users
    async def get_users(self, sort: Optional[str] = None, **kwargs) -> List[UserResp]:
        """Get all users.

        Parameters
        ----------
        sort : Optional[str]
            The sort order for the results.

        Returns
        -------
        List[UserResp]
            A list of users.
        """
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
        """Get information about a user.

        Parameters
        ----------
        user_id : int
            The ID of the user to get information about

        Returns
        -------
        UserResp
            Information about the user.
        """
        user_resp = await self.get(f"/users/{user_id}")
        return construct_model(UserResp, user_resp)

    # DELETE /users/{user_id}
    async def delete_user(self, user_id: int, missing_ok: bool = False) -> None:
        """Delete a user.

        Parameters
        ----------
        user_id : int
            The ID of the user to delete
        missing_ok : bool
            Do not raise an error if the user does not exist.
        """
        await self.delete(f"/users/{user_id}", missing_ok=missing_ok)

    # CATEGORY: gc

    # CATEGORY: scanAll

    # GET /scans/all/metrics
    async def get_scan_all_metrics(self) -> Stats:
        """Get metrics for a Scan All job.

        Returns
        -------
        Stats
            The metrics for the Scan All job.
        """
        resp = await self.get("/scans/all/metrics")
        return construct_model(Stats, resp)

    # PUT /system/scanAll/schedule
    async def update_scan_all_schedule(self, schedule: Schedule) -> None:
        """Update the schedule for a Scan All job.

        Parameters
        ----------
        schedule : Schedule
            The new schedule for the Scan All job
        """
        await self.put("/system/scanAll/schedule", json=schedule)

    # POST /system/scanAll/schedule
    async def create_scan_all_schedule(self, schedule: Schedule) -> str:
        """Create a new scan all job schedule. Returns location of the created schedule.

        Parameters
        ----------
        schedule : Schedule
            The schedule to create

        Returns
        -------
        str
            The location of the created schedule
        """
        resp = await self.post("/system/scanAll/schedule", json=schedule)
        return urldecode_header(resp, "Location")

    # GET /system/scanAll/schedule
    async def get_scan_all_schedule(self) -> Schedule:
        """Get the schedule for a Scan All job.

        Returns
        -------
        Schedule
            The schedule for the Scan All job.
        """
        resp = await self.get("/system/scanAll/schedule")
        return construct_model(Schedule, resp)

    # POST /system/scanAll/stop
    async def stop_scan_all_job(self) -> None:
        """Stop a Scan All job."""
        await self.post("/system/scanAll/stop")

    # CATEGORY: configure
    # GET /internalconfig
    async def get_internal_config(self) -> InternalConfigurationsResponse:
        """
        Get the internal configuration. Cannot be called by normal user accounts.

        !!! danger

            It is likely not possible to call this method due to its internal account
            requirement, but it is included for completeness and to allow for future use.

        Returns
        -------
        InternalConfigurationsResponse
            Internal system configuration.
        """
        resp = await self.get("/internalconfig")
        return construct_model(InternalConfigurationsResponse, resp)

    # PUT /internalconfig
    async def update_config(self, config: Configurations) -> None:
        """Fully or partially update the system configuration.

        !!! attention

            Requires admin privileges or a privileged Robot account.

        Parameters
        ----------
        config : Configurations
            The configuration map can contain a subset of the attributes
            of the schema, which are to be updated.
        """
        await self.put("/configurations", json=config)

    # GET /configurations
    async def get_config(self) -> ConfigurationsResponse:
        """Get the system configuration.

        !!! attention

            Requires admin privileges or a privileged Robot account.

        Returns
        -------
        ConfigurationsResponse
            The system configuration.
        """
        resp = await self.get("/configurations")
        return construct_model(ConfigurationsResponse, resp)

    # CATEGORY: usergroup
    # CATEGORY: preheat
    # CATEGORY: replication
    # CATEGORY: label
    # CATEGORY: robot

    # POST /robots
    async def create_robot(
        self,
        robot: RobotCreate,
        path: Optional[Union[str, Path]] = None,
        overwrite: bool = False,
    ) -> RobotCreated:
        """Create a new robot account.

        !!! attention

            This action requires a sysadmin account to perform.

        Parameters
        ----------
        robot : RobotCreate
            The definition for the robot account to create.
        path : Optional[Union[str, Path]]
            Optional path to save the robot credentials to.
        overwrite: bool
            If True, overwrite the existing credentials file.
            Has no effect if `path` is `None`.

        Returns
        -------
        RobotCreated
            Information about the created robot account.
        """
        resp = await self.post("/robots", json=robot)
        j = handle_optional_json_response(resp)
        if not j:
            raise HarborAPIException("Server did not return a JSON response.")
        robot_created = construct_model(RobotCreated, j)
        if path:
            new_authfile_from_robotcreate(
                path, robot, robot_created, overwrite=overwrite
            )
            logger.debug("Saved robot credentials to {path}", path=path)
        return robot_created

    # GET /robots
    async def get_robots(
        self,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
    ) -> List[Robot]:
        """Get all robot accounts, optionally filtered by query.

        Parameters
        ----------
        query : Optional[str]
            A query string to filter the resources.

            Except the basic properties, the other supported queries includes:

                * `"tags=*"` to list only tagged resources
                * `"tags=nil"` to list only untagged resources
                * `"tags=~v"` to list resources whose tag fuzzy matches "v"
                * `"tags=v"` to list artifact whose tag exactly matches "v"
                * `"labels=(id1, id2)"` to list resources that both labels with id1 and id2 are added to

            The value of range and list can be:

                * string(enclosed by `"` or `'`)
                * integer
                * time(in format `"2020-04-09 02:36:00"`)

            All of these query patterns should be put in the query string
            and separated by `","`. e.g. `"k1=v1,k2=~v2,k3=[min~max]"`
        sort : Optional[str]
            The sort order of the artifacts.
        page : int
            The page of results to return
        page_size : int
            The number of results to return per page

        Returns
        -------
        List[Robot]
            A list of registered robot accounts matching the query.
        """
        params = {
            "page": page,
            "page_size": page_size,
            "query": query,
            "sort": sort,
        }
        params = {k: v for k, v in params.items() if v is not None}
        resp = await self.get("/robots", params=params)
        return [construct_model(Robot, r) for r in resp]

    # GET /robots/{robot_id}
    async def get_robot(self, robot_id: int) -> Robot:
        """Fetch a robot account by its ID.

        Parameters
        ----------
        robot_id : int
            The ID of the robot account to get.

        Returns
        -------
        Robot
            Information about the robot account.
        """
        resp = await self.get(f"/robots/{robot_id}")
        return construct_model(Robot, resp)

    # PUT /robots/{robot_id}
    async def update_robot(self, robot_id: int, robot: Robot) -> None:
        """Update a robot account.

        Parameters
        ----------
        robot_id : int
            The ID of the robot account to update.
        robot : Robot
            The new definition for the robot account.
        """
        await self.put(f"/robots/{robot_id}", json=robot)

    # DELETE /robots/{robot_id}
    async def delete_robot(self, robot_id: int, missing_ok: bool = False) -> None:
        """Delete a robot account.

        Parameters
        ----------
        robot_id : int
            The ID of the robot account to delete.
        missing_ok : bool
            Do not raise an error if the robot account does not exist.
        """
        await self.delete(f"/robots/{robot_id}", missing_ok=missing_ok)

    # PATCH /robots/{robot_id}
    async def update_robot_secret(self, robot_id: int, secret: str) -> RobotSec:
        """Give the robot account a new secret.

        Parameters
        ----------
        robot_id : int
            The ID of the robot account to refresh.
        secret : str
            The new secret for the robot account.
        """
        resp = await self.patch(f"/robots/{robot_id}", json=RobotSec(secret=secret))
        return construct_model(RobotSec, resp)

    # CATEGORY: webhookjob
    # CATEGORY: icon

    # CATEGORY: project

    # PUT /projects/{project_name_or_id}/scanner
    async def set_project_scanner(
        self, project_name_or_id: str, scanner_uuid: str
    ) -> None:
        """Set one of the system configured scanner registration as the indepndent scanner of the specified project.

        Parameters
        ----------
        project_name_or_id: Union[str, int]
            The name or ID of the project

                * String arguments are treated as project names.
                * Integer arguments are treated as project IDs.

            Strings arguments set the `"X-Is-Resource-Name"` header to `true`.
        scanner_uuid: str
            The UUID of the scanner to set as the independent scanner of the project
        """
        headers = get_project_headers(project_name_or_id)
        await self.put(
            f"/projects/{project_name_or_id}/scanner",
            json=ProjectScanner(uuid=scanner_uuid),
            headers=headers,
        )

    # GET /projects/{project_name_or_id}/scanner
    async def get_project_scanner(self, project_name_or_id: str) -> ScannerRegistration:
        """Get the scanner registration of the specified project.
        If no scanner registration is configured for the specified project, the system default scanner registration will be returned.

        Parameters
        ----------
        project_name_or_id: Union[str, int]
            The name or ID of the project

                * String arguments are treated as project names.
                * Integer arguments are treated as project IDs.

            Strings arguments set the `"X-Is-Resource-Name"` header to `true`.

        Returns
        -------
        ScannerRegistration
            The scanner registration of the specified project
        """
        headers = get_project_headers(project_name_or_id)
        resp = await self.get(
            f"/projects/{project_name_or_id}/scanner", headers=headers
        )
        return construct_model(ScannerRegistration, resp)

    # GET /projects/{project_name}/logs
    async def get_project_logs(
        self,
        project_name: str,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        retrieve_all: bool = False,
    ) -> List[AuditLog]:
        """
        Get the audit logs of the specified project.

        Parameters
        ----------
        project_name: str
            The name of the project
        query : Optional[str]
            Query string to filter the logs.

            Supported query patterns are:

                * exact match(`"k=v"`)
                * fuzzy match(`"k=~v"`)
                * range(`"k=[min~max]"`)
                * list with union releationship(`"k={v1 v2 v3}"`)
                * list with intersection relationship(`"k=(v1 v2 v3)"`).

            The value of range and list can be:

                * string(enclosed by `"` or `'`)
                * integer
                * time(in format `"2020-04-09 02:36:00"`)

            All of these query patterns should be put in the query string
            and separated by `","`. e.g. `"k1=v1,k2=~v2,k3=[min~max]"`
        sort : Optional[str]
            The sort order of the artifacts.
        page : int
            The page of results to return
        page_size : int
            The number of results to return per page
        retrieve_all: bool
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
        logs = await self.get(
            f"/projects/{project_name}/logs", params=params, follow_links=retrieve_all
        )
        return [construct_model(AuditLog, l) for l in logs]

    # HEAD /projects
    async def project_exists(self, project_name: str) -> bool:
        """Check if a project exists.

        Parameters
        ----------
        project_name: str
            The name of the project
        """
        try:
            await self.head(f"/projects", params={"project_name": project_name})
        except NotFound:
            return False
        return True

    # POST /projects
    async def create_project(self, project: ProjectReq) -> str:
        """Create a new project. Returns location of the created project."""
        resp = await self.post(
            "/projects", json=project, headers={"X-Resource-Name-In-Location": "true"}
        )
        return urldecode_header(resp, "Location")

    # GET /projects

    async def get_projects(
        self,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        name: Optional[str] = None,
        public: Optional[bool] = None,
        owner: Optional[str] = None,
        with_detail: bool = True,
        page: int = 1,
        page_size: int = 10,
        retrieve_all: bool = True,
    ) -> List[Project]:
        """Get the artifacts for a repository.

        Parameters
        ----------
        query: Optional[str]
            Query string to query resources.

            Supported query patterns are:

                * exact match(`"k=v"`)
                * fuzzy match(`"k=~v"`)
                * range(`"k=[min~max]"`)
                * list with union releationship(`"k={v1 v2 v3}"`)
                * list with intersection relationship(`"k=(v1 v2 v3)"`).

            The value of range and list can be:

                * string(enclosed by `"` or `'`)
                * integer
                * time(in format `"2020-04-09 02:36:00"`)

            All of these query patterns should be put in the query string
            and separated by `","`. e.g. `"k1=v1,k2=~v2,k3=[min~max]"`
        sort : Optional[str]
            The sort order of the projects.
        name: str
            The name of the project.
        public: bool
            Only fetch public projects.
        owner: str
            The owner of the project.
        with_detail : bool
            Return detailed information about the project.
        page : int
            The page of results to return
        page_size : int
            The number of results to return per page
        retrieve_all: bool
            If true, retrieve all the resources,
            otherwise, retrieve only the number of resources specified by `page_size`.
        """
        params = {
            "query": query,
            "sort": sort,
            "name": name,
            "public": public,
            "owner": owner,
            "with_detail": with_detail,
            "page": page,
            "page_size": page_size,
        }
        params = {k: v for k, v in params.items() if v is not None}
        projects = await self.get("/projects", params=params, follow_links=retrieve_all)
        return [construct_model(Project, p) for p in projects]

    # PUT /projects/{project_name_or_id}
    async def update_project(
        self, project_name_or_id: Union[str, int], project: ProjectReq
    ) -> None:
        """Update a project.

        Parameters
        ----------
        project_name_or_id: str
            The name or ID of the project

                * String arguments are treated as project names.
                * Integer arguments are treated as project IDs.
        project: ProjectReq
            The updated project
        """
        headers = get_project_headers(project_name_or_id)
        await self.put(f"/projects/{project_name_or_id}", json=project, headers=headers)

    # GET /projects/{project_name_or_id}
    async def get_project(self, project_name_or_id: Union[str, int]) -> Project:
        """Fetch a project given its name or ID.

        Parameters
        ----------
        project_name_or_id: str
            The name or ID of the project

                * String arguments are treated as project names.
                * Integer arguments are treated as project IDs.
        """
        headers = get_project_headers(project_name_or_id)
        project = await self.get(f"/projects/{project_name_or_id}", headers=headers)
        return construct_model(Project, project)

    # DELETE /projects/{project_name_or_id}
    async def delete_project(
        self, project_name_or_id: Union[str, int], missing_ok: bool = False
    ) -> None:
        """Delete a project given its name or ID.

        Parameters
        ----------
        project_name_or_id: str
            The name or ID of the project

                * String arguments are treated as project names.
                * Integer arguments are treated as project IDs.
        missing_ok: bool
            If true, ignore 404 error when the project is not found.
        """
        headers = get_project_headers(project_name_or_id)
        await self.delete(
            f"/projects/{project_name_or_id}", headers=headers, missing_ok=missing_ok
        )

    # GET /projects/{project_name_or_id}/scanner/candidates
    async def get_project_scanner_candidates(
        self,
        project_name_or_id: Union[str, int],
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
    ) -> List[ScannerRegistration]:
        """Get the scanner candidates for a project.

        Parameters
        ----------
        project_name_or_id: str
            The name or ID of the project

                * String arguments are treated as project names.
                * Integer arguments are treated as project IDs.
        query: Optional[str]
            Query string to query resources.

            Supported query patterns are:

                * exact match(`"k=v"`)
                * fuzzy match(`"k=~v"`)
                * range(`"k=[min~max]"`)
                * list with union releationship(`"k={v1 v2 v3}"`)
                * list with intersection relationship(`"k=(v1 v2 v3)"`).

            The value of range and list can be:

                * string(enclosed by `"` or `'`)
                * integer
                * time(in format `"2020-04-09 02:36:00"`)

            All of these query patterns should be put in the query string
            and separated by `","`. e.g. `"k1=v1,k2=~v2,k3=[min~max]"`
        sort : Optional[str]
            The sort order of the scanners.
        page : int
            The page of results to return
        page_size : int
            The number of results to return per page
        """
        headers = get_project_headers(project_name_or_id)
        params = {
            "query": query,
            "sort": sort,
            "page": page,
            "page_size": page_size,
        }
        params = {k: v for k, v in params.items() if v is not None}
        candidates = await self.get(
            f"/projects/{project_name_or_id}/scanner/candidates",
            params=params,
            headers=headers,
        )
        return [construct_model(ScannerRegistration, c) for c in candidates]

    # GET /projects/{project_name_or_id}/summary
    async def get_project_summary(
        self, project_name_or_id: Union[str, int]
    ) -> ProjectSummary:
        """Get the summary of a project.

        Parameters
        ----------
        project_name_or_id: str
            The name or ID of the project

                * String arguments are treated as project names.
                * Integer arguments are treated as project IDs.
        """
        headers = get_project_headers(project_name_or_id)
        summary = await self.get(
            f"/projects/{project_name_or_id}/summary", headers=headers
        )
        return construct_model(ProjectSummary, summary)

    # GET /projects/{project_name_or_id}/_deletable
    async def get_project_deletable(
        self, project_name_or_id: Union[str, int]
    ) -> ProjectDeletable:
        """Get the deletable status of a project.

        Parameters
        ----------
        project_name_or_id: str
            The name or ID of the project

                * String arguments are treated as project names.
                * Integer arguments are treated as project IDs.

        Returns
        -------
        ProjectDeletable
            The deletable status of a project.

            If `.deletable` is `None`, the project is not deletable.
            This is an implementation detail, and might change in the future.
        """
        headers = get_project_headers(project_name_or_id)
        deletable = await self.get(
            f"/projects/{project_name_or_id}/_deletable", headers=headers
        )
        return construct_model(ProjectDeletable, deletable)

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
        """Get the log of a scan report.

        Parameters
        ----------
        project_name : str
            The name of the project
        repository_name : str
            The name of the repository
        reference : str
            The reference of the artifact, can be digest or tag
        report_id : str
            The ID of the scan report

        Returns
        -------
        str
            The log of a scan report
        """ """"""
        # TODO: investigate what exactly this endpoint returns
        path = get_artifact_path(project_name, repository_name, reference)
        return await self.get_text(f"{path}/scan/{report_id}/log")

    # # POST /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/scan/stop
    async def stop_artifact_scan(
        self, project_name: str, repository_name: str, reference: str
    ) -> None:
        """Stop a scan for a particular artifact.

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
        """Check the status of the registry.

        Parameters
        ----------
        ping : RegistryPing
            The ping request
        """
        await self.post("/registries/ping", json=ping)

    # GET /replication/adapters
    async def get_registry_adapters(self) -> List[str]:
        """Get the list of available registry adapters.

        Returns
        -------
        List[str]
            The list of available registry adapters
        """
        resp = await self.get("/replication/adapters")
        return resp  # type: ignore # we know this is a list of strings

    # GET /registries/{id}/info
    async def get_registry_info(self, id: int) -> RegistryInfo:
        """Get the info of a registry.

        Parameters
        ----------
        id : int
            The ID of the registry

        Returns
        -------
        RegistryInfo
            The info of a registry
        """
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

        Returns
        -------
        Registry
            The registry
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
    async def create_registry(self, registry: Registry) -> str:
        """Create a new registry.

        Parameters
        ----------
        registry : Registry
            The new registry values.

        Returns
        -------
        str
            The location of the created registry.
        """
        resp = await self.post("/registries", json=registry)
        return urldecode_header(resp, "Location")

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
            A query string to filter the registries.

            Supported query patterns are:

                * exact match(`"k=v"`)
                * fuzzy match(`"k=~v"`)
                * range(`"k=[min~max]"`)
                * list with union releationship(`"k={v1 v2 v3}"`)
                * list with intersection relationship(`"k=(v1 v2 v3)"`).

            The value of range and list can be:

                * string(enclosed by `"` or `'`)
                * integer
                * time(in format `"2020-04-09 02:36:00"`)

            All of these query patterns should be put in the query string
            and separated by `","`. e.g. `"k1=v1,k2=~v2,k3=[min~max]"`
        sort : Optional[str]
            The sort order of the artifacts.
        page : int
            The page of results to return
        page_size : int
            The number of results to return per page
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
        This method's API seems immature and may change in the future.
        Right now we just copy the API spec, which only takes a query string.

        Parameters
        ----------
        query : str
            Project and/or repository name to search for.

        Returns
        -------
        Search
            The search results.
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

        Returns
        -------
        str
            The location of the created tag
        """
        path = get_artifact_path(project_name, repository_name, reference)
        resp = await self.post(f"{path}/tags", json=tag)
        if resp.status_code != 201:
            logger.warning(
                "Create tag request for {} returned status code {}, expected 201",
                path,
                resp.status_code,
            )
        return urldecode_header(resp, "Location")

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

            Supported query patterns are:

                * exact match(`"k=v"`)
                * fuzzy match(`"k=~v"`)
                * range(`"k=[min~max]"`)
                * list with union releationship(`"k={v1 v2 v3}"`)
                * list with intersection relationship(`"k=(v1 v2 v3)"`).

            The value of range and list can be:

                * string(enclosed by `"` or `'`)
                * integer
                * time(in format `"2020-04-09 02:36:00"`)

            All of these query patterns should be put in the query string
            and separated by `","`. e.g. `"k1=v1,k2=~v2,k3=[min~max]"`
        sort : Optional[str]
            The sort order of the tags. TODO: document this parameter
        page : int
            The page of results to return
        page_size : int
            The number of results to return per page
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
            A query string to filter the accessories

            Supported query patterns are:

                * exact match(`"k=v"`)
                * fuzzy match(`"k=~v"`)
                * range(`"k=[min~max]"`)
                * list with union releationship(`"k={v1 v2 v3}"`)
                * list with intersection relationship(`"k=(v1 v2 v3)"`).

            The value of range and list can be:

                * string(enclosed by `"` or `'`)
                * integer
                * time(in format `"2020-04-09 02:36:00"`)

            All of these query patterns should be put in the query string
            and separated by `","`. e.g. `"k1=v1,k2=~v2,k3=[min~max]"`
        sort : Optional[str]
            The sort order of the tags.
        page : int
            The page of results to return
        page_size : int
            The number of results to return per page
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
    ) -> str:
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
        str
            The location of the new artifact
        """
        # We have to encode the destination repo name, but NOT the source repo name.
        path = get_repo_path(project_name, repository_name)
        resp = await self.post(f"{path}/artifacts", params={"from": source})
        if resp.status_code != 201:
            logger.warning(
                "Copy artifact request for {} returned status code {}, expected 201",
                path,
                resp.status_code,
            )
        return urldecode_header(resp, "Location")

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

            The value of range and list can be:

                * string(enclosed by `"` or `'`)
                * integer
                * time(in format `"2020-04-09 02:36:00"`)

            All of these query patterns should be put in the query string
            and separated by `","`. e.g. `"k1=v1,k2=~v2,k3=[min~max]"`
        sort : Optional[str]
            The sort order of the artifacts.
        page : int
            The page of results to return
        page_size : int
            The number of results to return per page
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

                * application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0
                * application/vnd.security.vulnerability.report; version=1.1
        retrieve_all: bool
            If true, retrieve all the resources,
            otherwise, retrieve only the number of resources specified by `page_size`.

        Returns
        -------
        List[Artifact]
            A list of artifacts in the repository matching the query.
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
            The page of results to return
        page_size : int
            The number of results to return per page
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

                * application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0
                * application/vnd.security.vulnerability.report; version=1.1

        Returns
        -------
        Artifact
            An artifact.
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
        """Get the vulnerabilities for an artifact.

        Parameters
        ----------
        project_name : str
            The name of the project
        repository_name : str
            The name of the repository
        reference : str
            The reference of the artifact, can be digest or tag
        mime_type : str
            A comma-separated lists of MIME types for the scan report or scan summary.

        Returns
        -------
        Optional[HarborVulnerabilityReport]
            The vulnerabilities for the artifact, or None if the artifact is not found
        """
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
        """Creates a new scanner. Returns location of the created scanner.

        Parameters
        ----------
        scanner : ScannerRegistrationReq
            The scanner to create.

        Returns
        -------
        str
            The location of the created scanner.
        """
        resp = await self.post("/scanners", json=scanner)
        return urldecode_header(resp, "Location")

    # GET /scanners
    async def get_scanners(
        self,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
    ) -> List[ScannerRegistration]:
        """Get a list of scanners.

        Parameters
        ----------
        query : Optional[str]
            A query string to filter the scanners.

            Supported query patterns are:

                * exact match(`"k=v"`)
                * fuzzy match(`"k=~v"`)
                * range(`"k=[min~max]"`)
                * list with union releationship(`"k={v1 v2 v3}"`)
                * list with intersection relationship(`"k=(v1 v2 v3)"`).

            The value of range and list can be:

                * string(enclosed by `"` or `'`)
                * integer
                * time(in format `"2020-04-09 02:36:00"`)

            All of these query patterns should be put in the query string
            and separated by `","`. e.g. `"k1=v1,k2=~v2,k3=[min~max]"`
        sort : Optional[str]
            The sort order of the scanners.
        page : int
            The page of results to return
        page_size : int
            The number of results to return per page

        Returns
        -------
        List[ScannerRegistration]
            _description_
        """
        params = {
            "q": query,
            "sort": sort,
            "page": page,
            "page_size": page_size,
        }
        params = {k: v for k, v in params.items() if v is not None}
        scanners = await self.get("/scanners", params=params)
        return [construct_model(ScannerRegistration, s) for s in scanners]

    # PUT /scanners/{registration_id}
    async def update_scanner(
        self, registration_id: Union[int, str], scanner: ScannerRegistrationReq
    ) -> None:
        """Update a scanner.

        Parameters
        ----------
        registration_id : Union[int, str]
            The ID of the scanner to update.
        scanner : ScannerRegistrationReq
            The updated scanner definition.
        """
        await self.put(f"/scanners/{registration_id}", json=scanner)

    # GET /scanners/{registration_id}
    async def get_scanner(
        self, registration_id: Union[int, str]
    ) -> ScannerRegistration:
        """Fetch a scanner by ID.

        Parameters
        ----------
        registration_id : Union[int, str]
            The ID of the scanner to fetch.

        Returns
        -------
        ScannerRegistration
            The scanner.
        """
        scanner = await self.get(f"/scanners/{registration_id}")
        return construct_model(ScannerRegistration, scanner)

    # DELETE /scanners/{registration_id}
    async def delete_scanner(
        self,
        registration_id: Union[int, str],
        missing_ok: bool = False,
    ) -> Optional[ScannerRegistration]:
        """Delete a scanner by ID.

        Parameters
        ----------
        registration_id : Union[int, str]
            The ID of the scanner to delete.
        missing_ok : bool
            Whether to ignore 404 error when deleting the scanner.

        Returns
        -------
        Optional[ScannerRegistration]
            The scanner, or None if the scanner is not found and `missing_ok` is True.

        Raises
        ------
        HarborAPIException
            Successful deletion request that returns an empty response.
        """
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
        """Set a scanner as the default scanner.

        Parameters
        ----------
        registration_id : Union[int, str]
            The ID of the scanner to set as the default.
        is_default : bool
            Whether to set the scanner as the default, by default `True`.
            Set to `False` to unset the scanner as the default.
        """
        await self.patch(
            f"/scanners/{registration_id}", json=IsDefault(is_default=is_default)
        )

    # POST /scanners/ping
    async def ping_scanner_adapter(self, settings: ScannerRegistrationSettings) -> None:
        """Ping a scanner adapter.

        Parameters
        ----------
        settings : ScannerRegistrationSettings
            The settings of the scanner adapter.
        """
        await self.post("/scanners/ping", json=settings)

    # GET /scanners/{registration_id}/metadata
    async def get_scanner_metadata(
        self, registration_id: int
    ) -> ScannerAdapterMetadata:
        """Get metadata of a scanner adapter given its registration ID.

        Parameters
        ----------
        registration_id : int
            The ID of the scanner adapter.

        Returns
        -------
        ScannerAdapterMetadata
            The metadata of the scanner adapter.
        """
        scanner = await self.get(f"/scanners/{registration_id}/metadata")
        return construct_model(ScannerAdapterMetadata, scanner)

    # CATEGORY: systeminfo

    # GET /systeminfo/volumes
    async def get_system_volume_info(self) -> SystemInfo:
        """Get info about the system's volumes.

        Returns
        -------
        SystemInfo
            Information about the system's volumes.
        """
        resp = await self.get("/systeminfo/volumes")
        return construct_model(SystemInfo, resp)

    # GET /systeminfo/getcert
    # async def get_system_certificate(self) -> str:
    #     """Get the certificate for the system."""
    #     raise NotImplementedError("File download not yet implemented")

    # GET /systeminfo
    async def get_system_info(self) -> GeneralInfo:
        """Get general info about the system.

        Returns
        -------
        GeneralInfo
            The general info about the system
        """
        resp = await self.get("/systeminfo")
        return construct_model(GeneralInfo, resp)

    # CATEGORY: statistic
    async def get_statistics(self) -> Statistic:
        """Get statistics on the Harbor server.

        Returns
        -------
        Statistic
            The statistics on the Harbor server
        """
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

            `-` denotes descending order

            `resource_name` should be the real resource name of the quota
        page: int
            The page number to retrieve resources from.
        page_size: int
            The number of resources to retrieve per page.
        retrieve_all: bool
            If true, retrieve all the resources,
            otherwise, retrieve only the number of resources specified by `page_size`.

        Returns
        -------
        List[Quota]
            The quotas
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

        Returns
        -------
        Quota
            The quota
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
        path = get_repo_path(project_id, repository_name)
        resp = await self.get(path)
        return construct_model(Repository, resp)

    # PUT /projects/{project_name}/repositories/{repository_name}
    async def update_repository(
        self,
        project_name: str,
        repository_name: str,
        repository: Repository,
    ) -> None:
        """Update a repository.

        Parameters
        ----------
        project_name : str
            The name of the project the repository belongs to.
        repository_name : str
            The name of the repository.
        repository : Repository
            The new repository values.
        """
        path = get_repo_path(project_name, repository_name)
        await self.put(path, json=repository)

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
        path = get_repo_path(project_id, repository_name)
        await self.delete(
            path,
            missing_ok=missing_ok,
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
            The query string to filter the repositories.

            Supported query patterns are:

                * exact match(`"k=v"`)
                * fuzzy match(`"k=~v"`)
                * range(`"k=[min~max]"`)
                * list with union releationship(`"k={v1 v2 v3}"`)
                * list with intersection relationship(`"k=(v1 v2 v3)"`).

            The value of range and list can be:

                * string(enclosed by `"` or `'`)
                * integer
                * time(in format `"2020-04-09 02:36:00"`)

            All of these query patterns should be put in the query string
            and separated by `","`. e.g. `"k1=v1,k2=~v2,k3=[min~max]"`
        sort : str
            The sort method.
            TODO: add boilerplate sort documentation
        page : int
            The page of results to return
        page_size : int
            The number of results to return per page
        retrieve_all : bool
            If true, retrieve all the resources,
            otherwise, retrieve only the number of resources specified by `page_size`.

        Returns
        -------
        List[Repository]
            A list of repositories matching the query.
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
        """Pings the Harbor server to check if it is alive.

        Returns
        -------
        str
            Text response from the server.
        """
        return await self.get_text("/ping")

    # CATEGORY: oidc
    # POST /system/oidc/ping
    async def test_oidc(self, oidcreq: OIDCTestReq) -> None:
        """Tests an OIDC endpoint. Can only be called by system admin.

        Raises `StatusError` if endpoint is unreachable.

        Parameters
        ----------
        oidcreq : OIDCTestReq
            The OIDC test request.
        """
        await self.post("/system/oidc/ping", json=oidcreq)

    # CATEGORY: SystemCVEAllowlist
    # PUT /system/CVEAllowlist
    async def update_cve_allowlist(self, allowlist: CVEAllowlist) -> None:
        """Overwrites the existing CVE allowlist with a new one.

        Parameters
        ----------
        allowlist : CVEAllowlist
            The new CVE allowlist.
        """
        await self.put("/system/CVEAllowlist", json=allowlist)

    # GET /system/CVEAllowlist
    async def get_cve_allowlist(self) -> CVEAllowlist:
        """Gets the current CVE allowlist.

        Returns
        -------
        CVEAllowlist
            The current CVE allowlist.
        """
        resp = await self.get("/system/CVEAllowlist")
        return construct_model(CVEAllowlist, resp)

    # CATEGORY: health
    # GET /health
    async def health_check(self) -> OverallHealthStatus:
        """Gets the health status of the Harbor server.

        Returns
        -------
        OverallHealthStatus
            The health status of the Harbor server.
        """
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

        !!! note

            Set `retrieve_all` to `True` to retrieve the entire audit log for all projects.

        Parameters
        ----------
        query: Optional[str]
            Query string to query resources.

            Supported query patterns are:

                * exact match(`"k=v"`)
                * fuzzy match(`"k=~v"`)
                * range(`"k=[min~max]"`)
                * list with union releationship(`"k={v1 v2 v3}"`)
                * list with intersection relationship(`"k=(v1 v2 v3)"`).

            The value of range and list can be:

                * string(enclosed by `"` or `'`)
                * integer
                * time(in format `"2020-04-09 02:36:00"`)

            All of these query patterns should be put in the query string
            and separated by `","`. e.g. `"k1=v1,k2=~v2,k3=[min~max]"`
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

    def _get_headers(self, headers: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
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
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        follow_links: bool = True,
        **kwargs: Any,
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
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> str:
        """Bad workaround in order to have a cleaner API for text/plain responses."""
        headers = headers or {}
        headers.update({"Accept": "text/plain"})
        resp = await self._get(path, params=params, headers=headers, **kwargs)
        return resp  # type: ignore

    # TODO: refactor this method so it looks like the other methods, while still supporting pagination.
    async def _get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        follow_links: bool = True,
        **kwargs: Any,
    ) -> JSONType:
        """Sends a GET request to the Harbor API.
        Returns JSON unless the response is text/plain.

        Parameters
        ----------
        path : str
            URL path to resource
        params : Optional[dict]
            Request parameters
        headers : Optional[dict]
            Request headers
        follow_links : bool
            Enable pagination by following links in response header

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
        if (link := resp.headers.get("link")) and 'rel="next"' in link and follow_links:
            logger.debug("Handling paginated results. Header value: {}", link)
            j = await self._handle_pagination(j, link)  # recursion (refactor?)
        return j

    async def _handle_pagination(self, data: JSONType, link: str) -> JSONType:
        """Handles paginated results by recursing until all results are returned."""
        # Parse the link header value and get next page URL
        next_url = parse_pagination_url(link)

        # ignoring params and only using the next URL
        # the next URL should contain the original params with page number adjusted
        j = await self.get(next_url)

        if not isinstance(j, list) or not isinstance(data, list):
            logger.warning(
                "Unable to handle paginated results, received non-list value. URL: {}",
                next_url,
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
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
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
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
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
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
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
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
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
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
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
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
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
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        missing_ok: bool = False,
        **kwargs: Any,
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
        headers: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        missing_ok: bool = False,
        **kwargs: Any,
    ) -> Response:
        resp = await self.client.delete(
            self.url + path,
            params=params,
            headers=self._get_headers(headers),
            **kwargs,
        )
        check_response_status(resp, missing_ok=missing_ok)
        return resp

    @backoff.on_exception(backoff.expo, RequestError, max_time=30)
    async def head(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        missing_ok: bool = False,
        **kwargs: Any,
    ) -> Response:
        resp = await self._head(
            path,
            headers=headers,
            params=params,
            missing_ok=missing_ok,
            **kwargs,
        )
        return resp

    async def _head(
        self,
        path: str,
        headers: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        missing_ok: bool = False,
        **kwargs: Any,
    ) -> Response:
        resp = await self.client.head(
            self.url + path,
            params=params,
            headers=self._get_headers(headers),
            **kwargs,
        )
        check_response_status(resp, missing_ok=missing_ok)
        return resp

    # TODO: add on_giveup callback for all backoff methods
