import json
from collections import deque
from http.cookiejar import CookieJar
from pathlib import Path
from typing import (
    Any,
    Dict,
    List,
    Literal,
    NamedTuple,
    Optional,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

import backoff
import httpx
from httpx import RequestError, Response, Timeout
from httpx._urls import URL
from loguru import logger
from pydantic import BaseModel, ValidationError

from ._types import JSONType
from .auth import load_harbor_auth_file, new_authfile_from_robotcreate
from .exceptions import (
    RETRY_ERRORS,
    BadRequest,
    HarborAPIException,
    NotFound,
    check_response_status,
)
from .models import (
    Accessory,
    Artifact,
    AuditLog,
    Configurations,
    ConfigurationsResponse,
    CVEAllowlist,
    GCHistory,
    GeneralInfo,
    InternalConfigurationsResponse,
    IsDefault,
    Label,
    LdapConf,
    LdapImportUsers,
    LdapPingResult,
    LdapUser,
    OIDCTestReq,
    OverallHealthStatus,
    PasswordReq,
    Permission,
    Project,
    ProjectDeletable,
    ProjectMetadata,
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
    ReplicationExecution,
    ReplicationPolicy,
    ReplicationTask,
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
    StartReplicationExecution,
    Statistic,
    Stats,
    SystemInfo,
    Tag,
    UserCreationReq,
    UserGroup,
    UserGroupSearchItem,
    UserProfile,
    UserResp,
    UserSearchRespItem,
    UserSysAdminFlag,
)
from .models.buildhistory import BuildHistoryEntry
from .models.models import RegistryProviders
from .models.scanner import HarborVulnerabilityReport
from .utils import (
    get_artifact_path,
    get_credentials,
    get_params,
    get_project_headers,
    get_repo_path,
    handle_optional_json_response,
    parse_pagination_url,
    urldecode_header,
)

__all__ = ["HarborAsyncClient"]

T = TypeVar("T", bound=BaseModel)

# TODO: move pydantic model functions to separate module


def model_to_dict(model: BaseModel) -> Any:
    """Creates a JSON-serializable dict from a Pydantic model."""
    # Round-trip through BaseModel.json() to ensure that all dict values
    # are JSON-serializable. BaseModel.dict() can contain Python objects
    # that are not natively serializable by the built-in JSON encoder.
    #
    # Until https://github.com/pydantic/pydantic/issues/1409 is fixed,
    # this is the easiest way to do this without having to implement
    # custom encoders for all Pydantic models.
    #
    # This is of course not ideal, but since we are dealing with network
    # requests here, this extra encoding should only represent a small
    # fraction of the overall time spent.
    #
    # This does put a spanner in the works with regards to typing, since
    # json.loads() returns Any. However, HTTPX expects Any for the `json`
    # parameter on its HTTP methods, so it's not a huge deal.
    return json.loads(model.json(exclude_unset=True))


class CookieDiscarder(CookieJar):
    """A CookieJar that discards all cookies."""

    def set_cookie(self, *args: Any, **kwargs: Any) -> None:
        # Overriding this method causes any attempt to set cookies
        # by the client to be ignored.
        pass


class ResponseLogEntry(NamedTuple):
    """A log entry for an HTTP response."""

    url: URL
    method: str
    status_code: int
    duration: float
    response_size: int


class HarborAsyncClient:
    def __init__(
        self,
        url: str,
        username: Optional[str] = None,
        secret: Optional[str] = None,
        credentials: Optional[str] = None,
        credentials_file: Optional[Union[str, Path]] = None,
        follow_redirects: bool = True,
        timeout: Union[float, Timeout] = 10.0,
        validate: bool = True,
        raw: bool = False,
        logging: bool = False,
        config: Optional[Any] = None,  # NYI
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
        follow_redirects : bool
            If True, follow redirects when making requests.
            Allows for coercion from HTTP to HTTPS.
        timeout : Union[float, Timeout]
            The timeout to use for requests.
            Can be either a float or a `httpx.Timeout` object.
        validate : bool
            If True, validate the results with Pydantic models.
            If False, data is returned as Pydantic models, but without
            validation, and as such may contain invalid data, and
            fields with submodels are not constructed (they are just dicts).
        raw : bool
            If True, return the raw response from the API, be it a dict or a list.
            If False, use Pydantic models to parse the response.
            Takes precedence over `validate` if `raw=True`.
        logging : bool
            Enable client logging with `Loguru`.
        config : Optional[Any]
            (NYI) config

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
            # TODO: perform this check somewhere else?
            #       it's likely the credentials file will ALWAYS require a username and secret
            #       so anytime load_harbor_auth_file() is called, this check should be performed
            if not crfile.name:
                raise ValueError("Credentials file missing value for 'name' field")
            elif not crfile.secret:
                raise ValueError("Credentials file missing value for 'secret' field")
            self.credentials = get_credentials(crfile.name, crfile.secret)
        else:
            raise ValueError(
                "Must provide username and secret, credentials, or credentials_file"
            )

        self.url = url.strip("/")  # make sure URL doesn't have a trailing slash
        self.config = config

        # Instantiate persistent HTTP client using the redirect policy
        # NOTE: any reason we don't specify headers here too?
        self.client = httpx.AsyncClient(
            follow_redirects=follow_redirects,
            timeout=timeout,
            cookies=CookieDiscarder(),
        )

        self.validate = validate
        self.raw = raw

        # NOTE: make env var?
        if logging:
            # we explicitly enable the logger here, because previous instantiations
            # of the client may have disabled it.
            logger.enable("harborapi")
        else:
            logger.disable("harborapi")

        self.response_log = deque()  # type: deque[ResponseLogEntry]

    def log_response(self, response: Response) -> None:
        """Log the response to a request.

        Parameters
        ----------
        response : Response
            The response to log.
        """
        self.response_log.append(
            ResponseLogEntry(
                url=response.url,
                method=response.request.method,
                status_code=response.status_code,
                duration=response.elapsed.total_seconds(),
                response_size=len(response.content),
            )
        )

    @property
    def last_response(self) -> Optional[ResponseLogEntry]:
        """Return the last response logged."""
        try:
            return self.response_log[-1]
        except IndexError:
            return None

    # NOTE: add destructor that closes client?

    @overload
    def construct_model(
        self, cls: Type[T], data: Any, is_list: Literal[True]
    ) -> List[T]:
        ...

    @overload
    def construct_model(
        self, cls: Type[T], data: Any, is_list: Literal[False] = False
    ) -> T:
        ...

    def construct_model(
        self, cls: Type[T], data: Any, is_list: bool = False
    ) -> Union[T, List[T]]:
        # NOTE: `raw` is an escape hatch, and should not be treated as part
        # of the normal flow of the client, or indeed a stable interface.
        # We provide it as a way to get the raw response from the API, but
        # we give no guarantees about the type of the response.
        if self.raw:
            return data  # type: ignore # this is not type-safe

        if is_list:
            return [self._construct_model(cls, item) for item in data]
        else:
            return self._construct_model(cls, data)

    def _construct_model(self, cls: Type[T], data: Any, is_list: bool = False) -> T:
        try:
            if self.validate:
                return cls.parse_obj(data)
            else:
                return cls.construct(**data)
        except ValidationError as e:
            logger.error("Failed to construct {} with {}", cls, data)
            raise e

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
    async def search_users_by_username(
        self,
        username: str,
        page: int = 1,
        page_size: int = 100,
        limit: Optional[int] = None,
        **kwargs: Any,
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
        limit: Optional[int]
            The maximum number of results to return.
        """
        params = get_params(username=username, page=page, page_size=page_size)
        users_resp = await self.get(
            "/users/search",
            params=params,
            limit=limit,
        )
        return self.construct_model(UserSearchRespItem, users_resp, is_list=True)

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
        params = get_params(scope=scope, relative=relative)
        resp = await self.get("/users/current/permissions", params=params)
        return self.construct_model(Permission, resp, is_list=True)

    # GET /users/current
    async def get_current_user(self) -> UserResp:
        """Get information about the current user.

        Returns
        -------
        UserResp
            Information about the current user.
        """
        user_resp = await self.get("/users/current")
        return self.construct_model(UserResp, user_resp)

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
    async def get_users(
        self,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
    ) -> List[UserResp]:
        """Get all users.

        Parameters
        ----------
        query : Optional[str]
            Query string to filter the users.

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
            Comma-separated string of fields to sort by.
            Prefix with `-` to sort descending.
            E.g. `"username,-email"`
        page : int
            The page number to retrieve
        page_size : int
            The number of users to retrieve per page

        Returns
        -------
        List[UserResp]
            A list of users.
        """
        params = get_params(q=query, sort=sort, page=page, page_size=page_size)
        users_resp = await self.get("/users", params=params)
        return self.construct_model(UserResp, users_resp, is_list=True)

    # PUT /users/{user_id}
    async def update_user(self, user_id: int, user: UserProfile) -> None:
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
        return self.construct_model(UserResp, user_resp)

    async def get_user_by_username(self, username: str) -> UserResp:
        """Get information about a user by username.

        This is a convenience method for searching for a user by username and
        then getting the full user information with its ID.

        See:

        * [search_users_by_username][harborapi.client.HarborAsyncClient.search_users_by_username]
        * [get_user][harborapi.client.HarborAsyncClient.get_user]

        Parameters
        ----------
        username : str
            The username of the user to get information about

        Returns
        -------
        UserResp
            Information about the user.
        """
        results = await self.search_users_by_username(username)
        if not results:
            raise NotFound(None, f"User with username {username} not found")
        user = results[0]
        if user.user_id is None:
            raise HarborAPIException(f"User with username {username} has no ID")
        return await self.get_user(user.user_id)

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

    # CATEGORY: gc (Garbage Collection)

    # GET /system/gc/schedule
    # Get gc's schedule.
    async def get_gc_schedule(self) -> Schedule:
        """Get Garbage Collection schedule.

        Returns
        -------
        Schedule
            The gc's schedule.
        """
        resp = await self.get("/system/gc/schedule")
        return self.construct_model(Schedule, resp)

    # POST /system/gc/schedule
    # Create a gc schedule.
    async def create_gc_schedule(self, schedule: Schedule) -> str:
        """Create a Garbage Collection schedule.

        Parameters
        ----------
        schedule : Schedule
            The schedule to create

        Returns
        -------
        str
            The location of the created schedule.
        """
        resp = await self.post("/system/gc/schedule", json=schedule)
        return urldecode_header(resp, "Location")

    # PUT /system/gc/schedule
    # Update gc's schedule.
    async def update_gc_schedule(self, schedule: Schedule) -> None:
        """Update the Garbage Collection schedule.

        Parameters
        ----------
        schedule : Schedule
            The new schedule to set
        """
        await self.put("/system/gc/schedule", json=schedule)

    # GET /system/gc
    # Get gc results.
    async def get_gc_jobs(
        self,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
    ) -> List[GCHistory]:
        # TODO: limit number of results?
        """Get Garbage Collection history for all jobs, optionally filtered by query.

        Parameters
        ----------
        query : Optional[str]
            A query string to filter the Garbage Collection results logs.

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
            The sort order of the logs.
        page : int
            The page of results to return
        page_size : int
            The number of results to return per page

        Returns
        -------
        List[GCHistory]
            List of Garbage Collection logs.
        """
        # TODO: refactor this and use with every method that uses queries + pagination
        params = get_params(q=query, sort=sort, page=page, page_size=page_size)
        resp = await self.get("/system/gc")
        return self.construct_model(GCHistory, resp, is_list=True)

    # GET /system/gc/{gc_id}/log
    # Get gc job log.
    async def get_gc_log(
        self, gc_id: int, as_list: bool = True
    ) -> Union[List[str], str]:
        """Get log output for a specific Garbage Collection job.

        Results are returned as a list of lines, or as a single string if
        `as_list` is False.

        Parameters
        ----------
        gc_id : int
            The ID of the Garbage Collection job to get the log for
        as_list : bool
            If `True`, return the log as a list of lines, otherwise as single string.

        Returns
        -------
        Union[List[str], str]
            The log output for the Garbage Collection job.
        """
        resp = await self.get_text(f"/system/gc/{gc_id}/log")
        if as_list:
            return resp.splitlines()
        return resp

    # GET /system/gc/{gc_id}
    # Get gc status.
    async def get_gc_job(
        self,
        gc_id: int,
    ) -> GCHistory:
        """Get a specific Garbage Collection job.

        Parameters
        ----------
        gc_id : int
            The ID of the Garbage Collection job to get information about.

        Returns
        -------
        GCHistory
            Information about the Garbage Collection job.
        """
        resp = await self.get(f"/system/gc/{gc_id}")
        return self.construct_model(GCHistory, resp)

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
        return self.construct_model(Stats, resp)

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
        return self.construct_model(Schedule, resp)

    # POST /system/scanAll/stop
    async def stop_scan_all_job(self) -> None:
        """Stop a Scan All job."""
        await self.post("/system/scanAll/stop")

    # CATEGORY: configure
    # GET /internalconfig (not supported)

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
        return self.construct_model(ConfigurationsResponse, resp)

    # CATEGORY: usergroup
    # GET /usergroups/search
    # Search groups by groupname
    async def search_usergroups(
        self, group_name: str, page: int = 1, page_size: int = 10
    ) -> List[UserGroupSearchItem]:
        """Search for user groups by group name.

        Parameters
        ----------
        group_name : str
            The group name to search for.
        page : int
            The page of results to return
        page_size : int
            The number of results to return per page

        Returns
        -------
        List[UserGroupSearchItem]
            List of user groups.
        """
        params = get_params(groupname=group_name, page=page, page_size=page_size)
        resp = await self.get("/usergroups/search", params=params)
        return self.construct_model(UserGroupSearchItem, resp, is_list=True)

    # POST /usergroups
    # Create user group
    async def create_usergroup(self, usergroup: UserGroup) -> str:
        """Create a new user group. Returns location of the created user group.

        Parameters
        ----------
        usergroup : UserGroup
            The user group to create

        Returns
        -------
        str
            The location of the created user group
        """
        resp = await self.post("/usergroups", json=usergroup)
        return urldecode_header(resp, "Location")

    # GET /usergroups
    # Get all user groups information
    async def get_usergroups(
        self, ldap_group_dn: Optional[str] = None, page: int = 1, page_size: int = 10
    ) -> List[UserGroup]:
        """Get all user groups.

        Parameters
        ----------
        ldap_group_dn : Optional[str]
            The LDAP group DN to filter by.
        page : int
            The page of results to return
        page_size : int
            The number of results to return per page

        Returns
        -------
        List[UserGroup]
            List of user groups.
        """
        params = get_params(ldap_group_dn=ldap_group_dn, page=page, page_size=page_size)
        resp = await self.get("/usergroups", params=params)
        return self.construct_model(UserGroup, resp, is_list=True)

    # PUT /usergroups/{group_id}
    # Update group information
    async def update_usergroup(self, group_id: int, usergroup: UserGroup) -> None:
        """Update group information.

        Parameters
        ----------
        group_id : int
            The group ID to update.
        usergroup : UserGroup
            The new definition for the usergroup.
        """
        await self.put(f"/usergroups/{group_id}", json=usergroup)

    # GET /usergroups/{group_id}
    # Get user group information
    async def get_usergroup(self, group_id: int) -> UserGroup:
        """Get a user group by ID.

        Parameters
        ----------
        group_id : int
            The group ID to get.

        Returns
        -------
        UserGroup
            The user group.
        """
        resp = await self.get(f"/usergroups/{group_id}")
        return self.construct_model(UserGroup, resp)

    # DELETE /usergroups/{group_id}
    # Delete user group
    async def delete_usergroup(self, group_id: int, missing_ok: bool = False) -> None:
        """Delete a user group.

        Parameters
        ----------
        group_id : int
            The group ID to delete.
        missing_ok : bool
            If `True`, do not raise an error if the group does not exist.
        """
        await self.delete(f"/usergroups/{group_id}", missing_ok=missing_ok)

    # CATEGORY: preheat

    # CATEGORY: replication

    # PUT /replication/executions/{id}
    # Stop the specific replication execution
    async def stop_replication(self, execution_id: int) -> None:
        """Stop a replication execution

        Parameters
        ----------
        execution_id : int
            The execution ID to stop.
        """
        await self.put(f"/replication/executions/{execution_id}")

    # GET /replication/executions/{id}
    # Get the specific replication execution
    async def get_replication(self, execution_id: int) -> ReplicationExecution:
        """Get a replication execution by ID.

        Parameters
        ----------
        execution_id : int
            The ID of the replication execution to get.

        Returns
        -------
        ReplicationExecution
            The replication execution.
        """
        resp = await self.get(f"/replication/executions/{execution_id}")
        return self.construct_model(ReplicationExecution, resp)

    # GET /replication/executions/{id}/tasks
    # List replication tasks for a specific execution
    async def get_replication_tasks(
        self,
        execution_id: int,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        status: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> List[ReplicationTask]:
        """Get a list of replication tasks for a specific execution.

        Parameters
        ----------
        execution_id : int
            The ID of the replication execution to get tasks for.
        sort : Optional[str]
            The sort order of the results.
        page : int
            The page of results to return.
        page_size : int
            The number of results to return per page.
        status : Optional[str]
            The status of the tasks to filter by.
        resource_type : Optional[str]
            The resource type of the tasks to filter by.

        Returns
        -------
        List[ReplicationTask]
            The list of replication tasks.
        """
        params = get_params(
            sort=sort,
            page=page,
            page_size=page_size,
            status=status,
            resource_type=resource_type,
        )
        resp = await self.get(
            f"/replication/executions/{execution_id}/tasks", params=params
        )
        return self.construct_model(ReplicationTask, resp, is_list=True)

    # POST /replication/policies
    # Create a replication policy
    async def create_replication_policy(self, policy: ReplicationPolicy) -> str:
        """Create a replication policy.

        Parameters
        ----------
        policy : ReplicationPolicy
            The policy to create.

        Returns
        -------
        str
            The location of the created policy.
        """
        resp = await self.post("/replication/policies", json=policy)
        return urldecode_header(resp, "Location")

    # GET /replication/policies
    # List replication policies
    async def get_replication_policies(
        self,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        name: Optional[str] = None,
    ) -> List[ReplicationPolicy]:
        """Get a list of replication policies.

        Parameters
        ----------
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
            The sort order of the results.
        page : int
            The page of results to return.
        page_size : int
            The number of results to return per page.
        name : Optional[str]
            (DEPRECATED: use `query`) The name of the policy to filter by.

        Returns
        -------
        List[ReplicationPolicy]
            The list of replication policies.
        """
        params = get_params(
            q=query, sort=sort, page=page, page_size=page_size, name=name
        )
        resp = await self.get("/replication/policies", params=params)
        return self.construct_model(ReplicationPolicy, resp, is_list=True)

    # POST /replication/executions
    # Start one replication execution
    async def start_replication(self, policy_id: int) -> str:
        """Start a replication execution.

        Parameters
        ----------
        policy_id : int
            The ID of the policy to start an execution for.

        Returns
        -------
        str
            The location of the replication execution.
        """
        execution = StartReplicationExecution(policy_id=policy_id)
        resp = await self.post("/replication/executions", json=execution)
        return urldecode_header(resp, "Location")

    # GET /replication/executions
    # List replication executions
    async def get_replications(
        self,
        sort: Optional[str] = None,
        policy_id: Optional[int] = None,
        status: Optional[str] = None,
        trigger: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
    ) -> List[ReplicationExecution]:
        """Get a list of replication executions.

        Parameters
        ----------
        sort : Optional[str]
            The sort order of the results.
        policy_id : Optional[int]
            The ID of the policy to filter by.
        status : Optional[str]
            The status of the executions to filter by.
        trigger : Optional[str]
            The trigger of the executions to filter by.
        page : int
            The page of results to return.
        page_size : int
            The number of results to return per page.

        Returns
        -------
        List[ReplicationExecution]
            The list of replication executions.
        """
        params = get_params(
            sort=sort,
            policy_id=policy_id,
            status=status,
            trigger=trigger,
            page=page,
            page_size=page_size,
        )
        resp = await self.get("/replication/executions", params=params)
        return self.construct_model(ReplicationExecution, resp, is_list=True)

    # PUT /replication/policies/{id}
    # Update the replication policy
    async def update_replication_policy(
        self, policy_id: int, policy: ReplicationPolicy
    ) -> None:
        """Update a replication policy.

        Parameters
        ----------
        policy_id : int
            The ID of the policy to update.
        policy : ReplicationPolicy
            The updated policy.
        """
        await self.put(f"/replication/policies/{policy_id}", json=policy)

    # GET /replication/policies/{id}
    # Get the specific replication policy
    async def get_replication_policy(self, policy_id: int) -> ReplicationPolicy:
        """Get a specific replication policy.

        Parameters
        ----------
        policy_id : int
            The ID of the policy to get.

        Returns
        -------
        ReplicationPolicy
            The replication policy.
        """
        resp = await self.get(f"/replication/policies/{policy_id}")
        return self.construct_model(ReplicationPolicy, resp)

    # DELETE /replication/policies/{id}
    # Delete the specific replication policy
    async def delete_replication_policy(self, policy_id: int) -> None:
        """Delete a replication policy.

        Parameters
        ----------
        policy_id : int
            The ID of the policy to delete.
        """
        await self.delete(f"/replication/policies/{policy_id}")

    # GET /replication/executions/{id}/tasks/{task_id}/log
    # Get the log of the specific replication task
    async def get_replication_task_log(self, execution_id: int, task_id: int) -> str:
        """Get the log of a replication task.

        Parameters
        ----------
        execution_id : int
            The ID of the execution the task belongs to.
        task_id : int
            The ID of the task to get the log for.

        Returns
        -------
        str
            The log of the task.
        """
        resp = await self.get_text(
            f"/replication/executions/{execution_id}/tasks/{task_id}/log"
        )
        return resp

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
        robot_created = self.construct_model(RobotCreated, j)
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
        params = get_params(q=query, sort=sort, page=page, page_size=page_size)
        resp = await self.get("/robots", params=params)
        return self.construct_model(Robot, resp, is_list=True)

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
        return self.construct_model(Robot, resp)

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
    async def refresh_robot_secret(self, robot_id: int, secret: str) -> RobotSec:
        """Refresh the secret of a robot account.

        Parameters
        ----------
        robot_id : int
            The ID of the robot account to refresh.
        secret : str
            The secret of the robot account.

        Returns
        -------
        RobotSec
            The updated Robot secret.
        """
        resp = await self.patch(f"/robots/{robot_id}", json=RobotSec(secret=secret))
        return self.construct_model(RobotSec, resp)

    # CATEGORY: webhookjob
    # CATEGORY: icon

    # CATEGORY: project

    # PUT /projects/{project_name_or_id}/scanner
    async def set_project_scanner(
        self, project_name_or_id: Union[str, int], scanner_uuid: str
    ) -> None:
        """Set one of the system configured scanner registration as the indepndent scanner of the specified project.

        Parameters
        ----------
        project_name_or_id: Union[str, int]
            The name or ID of the project
            String arguments are treated as project names.
            Integer arguments are treated as project IDs.

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
    async def get_project_scanner(
        self, project_name_or_id: Union[str, int]
    ) -> ScannerRegistration:
        """Get the scanner registration of the specified project.
        If no scanner registration is configured for the specified project, the system default scanner registration will be returned.

        Parameters
        ----------
        project_name_or_id: Union[str, int]
            The name or ID of the project
            Integer arguments are treated as project IDs.
            String arguments are treated as project names.
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
        return self.construct_model(ScannerRegistration, resp)

    # GET /projects/{project_name}/logs
    async def get_project_logs(
        self,
        project_name: str,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        limit: Optional[int] = None,
        **kwargs,
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
        limit : Optional[int]
            The maximum number of results to return
        """
        params = get_params(q=query, sort=sort, page=page, page_size=page_size)
        logs = await self.get(
            f"/projects/{project_name}/logs", params=params, limit=limit
        )
        return self.construct_model(AuditLog, logs, is_list=True)

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
        """Create a new project. Returns location of the created project.

        Parameters
        ----------
        project: ProjectReq
            The project to create

        Returns
        -------
        str
            The location of the created project.
        """
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
        limit: Optional[int] = None,
        **kwargs,
    ) -> List[Project]:
        """Get all projects, optionally filtered by query.

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
        limit : Optional[int]
            The maximum number of results to return

        Returns
        -------
        List[Project]
            The list of projects
        """
        params = get_params(
            q=query,
            sort=sort,
            name=name,
            public=public,
            owner=owner,
            with_detail=with_detail,
            page=page,
            page_size=page_size,
        )
        projects = await self.get("/projects", params=params, limit=limit)
        return self.construct_model(Project, projects, is_list=True)

    # PUT /projects/{project_name_or_id}
    async def update_project(
        self, project_name_or_id: Union[str, int], project: ProjectReq
    ) -> None:
        """Update a project.

        Parameters
        ----------
        project_name_or_id: Union[str, int]
            The name or ID of the project
            String arguments are treated as project names.
            Integer arguments are treated as project IDs.
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
        project_name_or_id: Union[str, int]
            The name or ID of the project
            String arguments are treated as project names.
            Integer arguments are treated as project IDs.

        Returns
        -------
        Project
            The project with the given name or ID.
        """
        headers = get_project_headers(project_name_or_id)
        project = await self.get(f"/projects/{project_name_or_id}", headers=headers)
        return self.construct_model(Project, project)

    # DELETE /projects/{project_name_or_id}
    async def delete_project(
        self, project_name_or_id: Union[str, int], missing_ok: bool = False
    ) -> None:
        """Delete a project given its name or ID.

        Parameters
        ----------
        project_name_or_id: Union[str, int]
            The name or ID of the project
            String arguments are treated as project names.
            Integer arguments are treated as project IDs.
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
        project_name_or_id: Union[str, int]
            The name or ID of the project
            String arguments are treated as project names.
            Integer arguments are treated as project IDs.
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

        Returns
        -------
        List[ScannerRegistration]
            The list of scanner candidates
        """
        headers = get_project_headers(project_name_or_id)
        params = get_params(q=query, sort=sort, page=page, page_size=page_size)
        candidates = await self.get(
            f"/projects/{project_name_or_id}/scanner/candidates",
            params=params,
            headers=headers,
        )
        return self.construct_model(ScannerRegistration, candidates, is_list=True)

    # GET /projects/{project_name_or_id}/summary
    async def get_project_summary(
        self, project_name_or_id: Union[str, int]
    ) -> ProjectSummary:
        """Get the summary of a project.

        Parameters
        ----------
        project_name_or_id: Union[str, int]
            The name or ID of the project
            String arguments are treated as project names.
            Integer arguments are treated as project IDs.

        Returns
        -------
        ProjectSummary
            The summary of a project.
        """
        headers = get_project_headers(project_name_or_id)
        summary = await self.get(
            f"/projects/{project_name_or_id}/summary", headers=headers
        )
        return self.construct_model(ProjectSummary, summary)

    # GET /projects/{project_name_or_id}/_deletable
    async def get_project_deletable(
        self, project_name_or_id: Union[str, int]
    ) -> ProjectDeletable:
        """Get the deletable status of a project.

        Parameters
        ----------
        project_name_or_id: Union[str, int]
            The name or ID of the project
            String arguments are treated as project names.
            Integer arguments are treated as project IDs.

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
        return self.construct_model(ProjectDeletable, deletable)

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

    # POST /ldap/ping
    # Ping available ldap service.
    async def ping_ldap(
        self, configuration: Optional[LdapConf] = None
    ) -> LdapPingResult:
        """Pings the LDAP service with a configuration.
        If the configuration is empty, the current configuration is loaded.

        !!! note
            The original documentation for this endpoint has extremely
            broken english, and it's unclear what its purpose is.

        ??? quote "Original documentation"
            This endpoint ping the available ldap service for test related configuration parameters.

            **param** `ldapconf`: ldap configuration. support input ldap service configuration. If it is a empty request, will load current configuration from the system


        Parameters
        ----------
        configuration : Optional[LdapConf]
            The configuration to use for the ping.
            Uses current system configuration if `None`.

        Returns
        -------
        LdapPingResult
            The result of the ping
        """
        resp = await self.post("/ldap/ping", json=configuration)
        j = handle_optional_json_response(resp)
        if not j:  # pragma: no cover # this shouldn't happen
            logger.warning(
                f"Empty response from LDAP ping ({resp.request.method} {resp.request.url})"
            )
            return LdapPingResult()
        return self.construct_model(LdapPingResult, j)

    # GET /ldap/groups/search
    # Search available ldap groups.
    async def search_ldap_groups(
        self, group_name: Optional[str] = None, group_dn: Optional[str] = None
    ) -> List[UserGroup]:
        """Search for LDAP groups with a name or DN.

        Parameters
        ----------
        group_name : str
            The name of the LDAP group to search for.

        group_dn : str
            The DN of the LDAP group to search for.

        Returns
        -------
        List[UserGroup]
            The list of LDAP groups that match the search.
        """
        # TODO: investigate if we can search without a name or DN
        if not group_dn and not group_name:
            raise ValueError("Must specify either group_dn or group_name")

        params = get_params(groupname=group_name, groupdn=group_dn)
        resp = await self.get("/ldap/groups/search", params=params)
        return self.construct_model(UserGroup, resp, is_list=True)

    # GET /ldap/users/search
    # Search available ldap users.
    async def search_ldap_users(self, username: str) -> List[LdapUser]:
        """Search for LDAP users with a given username.

        Parameters
        ----------
        username : str
            The username to search for.

        Returns
        -------
        List[LdapUser]
            The list of LDAP users that match the search.
        """
        params = get_params(username=username)
        resp = await self.get("/ldap/users/search", params=params)
        return self.construct_model(LdapUser, resp, is_list=True)

    # POST /ldap/users/import
    # Import selected available ldap users.
    async def import_ldap_users(self, user_ids: List[str]) -> None:
        """Import LDAP users with the given IDs.

        In case of failure, check the resulting exception's `errors` attribute for
        more information on which users failed to import.

        Parameters
        ----------
        user_ids : List[str]
            A list of strings representing the IDs of the users to import.
            The system attempts to determine the remaining user information
            based on each user's ID.
        """
        req = LdapImportUsers(
            ldap_uid_list=user_ids,
        )
        await self.post("/ldap/users/import", json=req)

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
        return self.construct_model(RegistryInfo, resp)

    # GET /replication/adapterinfos
    async def get_registry_providers(self) -> RegistryProviders:
        """Get all registered registry provider information.

        Returns
        -------
        RegistryProviders
            An overview of the registered registry providers.
        """
        resp = await self.get("/replication/adapterinfos")
        return self.construct_model(RegistryProviders, resp)

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
        return self.construct_model(Registry, resp)

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
        limit: Optional[int] = None,
        name: Optional[str] = None,
        **kwargs: Any,
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
        limit : Optional[int]
            The maximum number of results to return. If not specified, all
        name: str: Optional[str]
            The name of the registry (deprecated, use `query` instead)

        Returns
        -------
        List[Registry]
            A list of Registry objects.
        """
        params = get_params(
            q=query, sort=sort, page=page, page_size=page_size, name=name
        )
        resp = await self.get("/registries", params=params, limit=limit)
        return self.construct_model(Registry, resp, is_list=True)

    # CATEGORY: search
    # GET /search
    async def search(self, query: str) -> Search:
        """Search for projects, repositories and helm charts that the user has access to.

        !!! warning
            The endpoints's interface seems immature, and may change in the future.
            The query string is not documented, and the API spec is not clear.
            In the future, this method might change and take a separate argument
            for each of the search types (projects, repositories, helm charts).


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
        return self.construct_model(Search, resp)

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
        limit: Optional[int] = None,
        with_signature: bool = False,
        with_immutable_status: bool = False,
        **kwargs: Any,
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
        limit : Optional[int]
            The maximum number of results to return.
        with_signature : bool
            Whether to include the signature of the tag in the response
        with_immutable_status : bool
            Whether to include the immutable status of the tag in the response

        Returns
        -------
        List[Tag]
            A list of Tag objects for the artifact.
        """
        path = get_artifact_path(project_name, repository_name, reference)
        params = get_params(
            q=query,
            sort=sort,
            page=page,
            page_size=page_size,
            with_signature=with_signature,
            with_immutable_status=with_immutable_status,
        )
        resp = await self.get(
            f"{path}/tags",
            params=params,
            limit=limit,
        )
        return self.construct_model(Tag, resp, is_list=True)

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
        limit: Optional[int] = None,
        **kwargs: Any,
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
        limit : Optional[int]
            The maximum number of results to return.

        Returns
        -------
        List[Accessory]
            A list of Accessory objects for the artifact.
        """
        path = get_artifact_path(project_name, repository_name, reference)
        params = get_params(q=query, sort=sort, page=page, page_size=page_size)
        resp = await self.get(f"{path}/accessories", params=params, limit=limit)
        return self.construct_model(Accessory, resp, is_list=True)

    # DELETE /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/tags
    async def delete_artifact_tag(
        self,
        project_name: str,
        repository_name: str,
        reference: str,
        tag_name: str,
        missing_ok: bool = False,
    ) -> None:
        """Delete a tag for an artifact.

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
        limit: Optional[int] = None,
        with_tag: bool = True,
        with_label: bool = False,
        with_scan_overview: bool = False,
        with_signature: bool = False,
        with_immutable_status: bool = False,
        with_accessory: bool = False,
        mime_type: str = "application/vnd.security.vulnerability.report; version=1.1",
        **kwargs: Any,
    ) -> List[Artifact]:
        """Get the artifacts in a repository.

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
        limit : Optional[int]
            The maximum number of results to return.
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

        Returns
        -------
        List[Artifact]
            A list of artifacts in the repository matching the query.
        """
        path = f"{get_repo_path(project_name, repository_name)}/artifacts"
        params = get_params(
            q=query,
            sort=sort,
            page=page,
            page_size=page_size,
            with_tag=with_tag,
            with_label=with_label,
            with_scan_overview=with_scan_overview,
            with_signature=with_signature,
            with_immutable_status=with_immutable_status,
            with_accessory=with_accessory,
        )
        resp = await self.get(
            path,
            params=params,
            headers={"X-Accept-Vulnerabilities": mime_type},
            limit=limit,
        )
        return self.construct_model(Artifact, resp, is_list=True)

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
        return self.construct_model(Artifact, resp)

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

        return self.construct_model(HarborVulnerabilityReport, report)

    # GET /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/additions/build_history
    async def get_artifact_build_history(
        self, project_name: str, repository_name: str, reference: str
    ) -> List[BuildHistoryEntry]:
        """Get the build history for an artifact.

        Parameters
        ----------
        project_name : str
            The name of the project
        repository_name : str
            The name of the repository
        reference : str
            The reference of the artifact, can be digest or tag

        Returns
        -------
        BuildHistory
            The build history for the artifact
        """
        path = get_artifact_path(project_name, repository_name, reference)
        url = f"{path}/additions/build_history"
        resp = await self.get(url)
        return self.construct_model(BuildHistoryEntry, resp, is_list=True)

    # NYI:
    # GET /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/additions/values.yaml
    # GET /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/additions/readme.md
    # GET /projects/{project_name}/repositories/{repository_name}/artifacts/{reference}/additions/dependencies

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
        params = get_params(q=query, sort=sort, page=page, page_size=page_size)
        scanners = await self.get("/scanners", params=params)
        return self.construct_model(ScannerRegistration, scanners, is_list=True)

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
        return self.construct_model(ScannerRegistration, scanner)

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
        return self.construct_model(ScannerRegistration, scanner)

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
        return self.construct_model(ScannerAdapterMetadata, scanner)

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
        return self.construct_model(SystemInfo, resp)

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
        return self.construct_model(GeneralInfo, resp)

    # CATEGORY: statistic
    async def get_statistics(self) -> Statistic:
        """Get statistics on the Harbor server.

        Returns
        -------
        Statistic
            The statistics on the Harbor server
        """
        stats = await self.get("/statistics")
        return self.construct_model(Statistic, stats)

    # CATEGORY: quota
    async def get_quotas(
        self,
        reference: Optional[str] = None,
        reference_id: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        limit: Optional[int] = None,
        **kwargs: Any,
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
        limit : int
            The maximum number of quotas to retrieve.

        Returns
        -------
        List[Quota]
            The quotas
        """
        params = get_params(
            reference=reference,
            reference_id=reference_id,
            sort=sort,
            page=page,
            page_size=page_size,
        )
        quotas = await self.get("/quotas", params=params, limit=limit)
        return self.construct_model(Quota, quotas, is_list=True)

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
        return self.construct_model(Quota, quota)

    # CATEGORY: repository

    # GET /projects/{project_name}/repositories/{repository_name}
    async def get_repository(
        self,
        project_name: str,
        repository_name: str,
    ) -> Repository:
        """Get a repository.

        Parameters
        ----------
        project_name : str
            The name of the project the repository belongs to.
        repository_name : str
            The name of the repository.

        Returns
        -------
        Repository
            The repository.
        """
        path = get_repo_path(project_name, repository_name)
        resp = await self.get(path)
        return self.construct_model(Repository, resp)

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
        project_name: str,
        repository_name: str,
        missing_ok: bool = False,
    ) -> None:
        """Delete a repository.

        Parameters
        ----------
        project_name : str
            The name of the project the repository belongs to.
        repository_name : str
            The name of the repository.
        missing_ok : bool
            If true, do not raise an error if the repository does not exist.
        """
        path = get_repo_path(project_name, repository_name)
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
        limit: Optional[int] = None,
        **kwargs: Any,
    ) -> List[Repository]:
        """Get a list of all repositories, optionally only in a specific project.

        Parameters
        ----------
        project_name : Optional[str]
            The name of the project to retrieve repositories from.
            If None, retrieve repositories from all projects.
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
        limit : Optional[int]
            The maximum number of results to return.

        Returns
        -------
        List[Repository]
            A list of repositories matching the query.
        """
        params = get_params(q=query, sort=sort, page=page, page_size=page_size)
        if project_name:
            url = f"/projects/{project_name}/repositories"
        else:
            url = "/repositories"
        resp = await self.get(url, params=params, limit=limit)
        return self.construct_model(Repository, resp, is_list=True)

    # CATEGORY: ping
    # GET /ping
    async def ping(self) -> str:
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
        return self.construct_model(CVEAllowlist, resp)

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
        return self.construct_model(OverallHealthStatus, resp)

    # CATEGORY: robotv1
    # CATEGORY: projectMetadata

    # POST /projects/{project_name_or_id}/metadatas/
    async def set_project_metadata(
        self,
        project_name_or_id: Union[str, int],
        metadata: ProjectMetadata,
    ) -> None:
        """Add metadata for a project.

        Parameters
        ----------
        project_name_or_id : str
            The name or ID of the project to add metadata to.
            String arguments are treated as project names.
            Integer arguments are treated as project IDs.
        metadata : ProjectMetadata
            The metadata to add to the project.
            Supports adding arbitrary fields
        """
        headers = get_project_headers(project_name_or_id)
        await self.post(
            f"/projects/{project_name_or_id}/metadatas", json=metadata, headers=headers
        )

    # GET /projects/{project_name_or_id}/metadatas/
    async def get_project_metadata(
        self, project_name_or_id: Union[str, int]
    ) -> ProjectMetadata:
        """Get the metadata of a specific project.

        Parameters
        ----------
        project_name_or_id : str
            The name or ID of the project to get metadata from.
            String arguments are treated as project names.
            Integer arguments are treated as project IDs.

        Returns
        -------
        ProjectMetadata
            The metadata of the project.
        """
        headers = get_project_headers(project_name_or_id)
        resp = await self.get(
            f"/projects/{project_name_or_id}/metadatas", headers=headers
        )
        return self.construct_model(ProjectMetadata, resp)

    # PUT /projects/{project_name_or_id}/metadatas/{meta_name}
    async def update_project_metadata_entry(
        self,
        project_name_or_id: Union[str, int],
        metadata_name: str,
        metadata: Union[ProjectMetadata, Dict[str, Any]],
    ) -> None:
        """Update a specific metadata entry for a project.

        !!! warning "Possibly incorrect implementation"
            It's unclear what the request body should be for this endpoint.
            The API docs specifies that it should be a dict, but not its structure.
            We assume the dict is of the form:
            ```json
            {
                "<metadata_name>": "<metadata_value>",
            }
            ```

        !!! note "Validation"
            To validate the metadata before updating it, pass in
            `ProjectMetadata(field_to_set=value).dict(exclude_unset=True)`
            as the `metadata` argument.
            This will ensure that the metadata is valid according to the
            current version of the API spec that this client is using.

        Parameters
        ----------
        project_name_or_id : str
            The name or ID of the project to update metadata for.
            String arguments are treated as project names.
            Integer arguments are treated as project IDs.
        metadata_name: str
            The name of the metadata to update.
        metadata : Union[ProjectMetadata, Dict[str, Any]]
            The metadata to update for the project.
            Can be a ProjectMetadata object with the relevant field
            set to the desired value, or a dict where the key is the
            metadata name and the value is the metadata value.
        """
        headers = get_project_headers(project_name_or_id)
        # Parse the metadata as a ProjectMetadata object
        # to ensure that it's valid according to the API spec.
        m = ProjectMetadata.parse_obj(metadata)
        await self.put(
            f"/projects/{project_name_or_id}/metadatas/{metadata_name}",
            json=m,
            headers=headers,
        )

    # GET /projects/{project_name_or_id}/metadatas/{meta_name}
    async def get_project_metadata_entry(
        self, project_name_or_id: Union[str, int], metadata_name: str
    ) -> Dict[str, Any]:
        """Get a specific metadata for a project.

        Parameters
        ----------
        project_name_or_id : str
            The name or ID of the project to get metadata from.
            String arguments are treated as project names.
            Integer arguments are treated as project IDs.
        metadata_name : str
            The name of the metadata to get.

        Returns
        -------
        Dict[str, Any]
            The metadata with the given name.
        """
        resp = await self.get(
            f"/projects/{project_name_or_id}/metadatas/{metadata_name}"
        )
        return resp  # type: ignore

    # DELETE /projects/{project_name_or_id}/metadatas/{meta_name}
    async def delete_project_metadata_entry(
        self, project_name_or_id: Union[str, int], metadata_name: str
    ) -> None:
        """Delete a specific metadata for a project.

        Parameters
        ----------
        project_name_or_id : str
            The name or ID of the project to delete metadata for.
            String arguments are treated as project names.
            Integer arguments are treated as project IDs.
        metadata_name : str
            The name of the metadata to delete.
        """
        headers = get_project_headers(project_name_or_id)
        await self.delete(
            f"/projects/{project_name_or_id}/metadatas/{metadata_name}", headers=headers
        )

    # CATEGORY: auditlog
    # GET /audit-logs
    async def get_audit_logs(
        self,
        query: Optional[str] = None,
        sort: Optional[str] = None,
        page: int = 1,
        page_size: int = 10,
        limit: Optional[int] = None,
        **kwargs: Any,
    ) -> List[AuditLog]:
        """Get a list of audit logs for the projects the user is a member of.

        !!! note

            The audit log can be massive, so setting a `limit` is highly recommended.

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
        limit: Optional[int]
            The maximum number of audit logs to retrieve.

        Returns
        -------
        List[AuditLog]
            The list of audit logs.
        """
        params = get_params(q=query, sort=sort, page=page, page_size=page_size)
        resp = await self.get("/audit-logs", params=params, limit=limit)
        return self.construct_model(AuditLog, resp, is_list=True)

    def _get_headers(self, headers: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        headers = headers or {}
        base_headers = {
            "Authorization": "Basic " + self.credentials,
            "Accept": "application/json",
        }
        base_headers.update(headers)  # Override defaults with provided headers
        return base_headers

    @backoff.on_exception(backoff.expo, RETRY_ERRORS, max_time=30)
    async def get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        follow_links: bool = True,
        limit: Optional[int] = None,
        **kwargs: Any,
    ) -> JSONType:
        j, next_url = await self._get(
            path,
            params=params,
            headers=headers,
            follow_links=follow_links,
            **kwargs,
        )
        if not next_url:  # no pagination
            return j

        # Make sure j is a list
        if not isinstance(j, list):
            logger.warning(
                "Unable to handle paginated results: Expected a list from 'GET %s', but got %s",
                path,
                type(j),
            )
            # TODO: add toggle for this coercion (coerce or throw exception)
            #       or should we even accomodate this use-case? Always throw exception?
            logger.info("Coercing value from %s to list", path)
            j = [j]

        # Send requests as long as we get next links
        while next_url:
            paginated, next_url = await self._get(
                next_url,
                # don't pass params (they should be in next URL)
                headers=headers,
                follow_links=follow_links,
                **kwargs,
            )
            if not isinstance(paginated, list):
                logger.warning(
                    "Unable to handle paginated results: Expected a list from 'GET %s', but got %s",
                    next_url,
                    type(paginated),
                )
                # NOTE: we could also abort here, so we don't get partial results
                #       but right now it's unclear whether this can ever happen
                continue
            j.extend(paginated)

            # Check if we have reached our limit
            if limit is not None:
                if len(j) > limit:
                    j = j[:limit]
                    break

        return j

    @backoff.on_exception(backoff.expo, RETRY_ERRORS, max_time=30)
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
        resp, _ = await self._get(path, params=params, headers=headers, **kwargs)
        # assume text is never paginated
        return resp  # type: ignore

    # TODO: refactor this method so it looks like the other methods, while still supporting pagination.
    async def _get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        follow_links: bool = True,
        **kwargs: Any,
    ) -> Tuple[JSONType, Optional[str]]:
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
        Tuple[JSONType, Optional[str]]
            JSON data returned by the API, and the next URL if pagination is enabled.
        """
        url = f"{self.url}{path}"
        resp = await self.client.get(
            url,
            params=params,
            headers=self._get_headers(headers),
        )
        self.log_response(resp)
        check_response_status(resp)
        j = handle_optional_json_response(resp)
        if j is None:
            return resp.text, None  # type: ignore # FIXME: resolve this ASAP (use overload?)

        # If we have "Link" in headers, we need to parse the next page link
        if follow_links and (link := resp.headers.get("link")):
            logger.debug("Handling paginated results. Header value: {}", link)
            return j, parse_pagination_url(link)

        return j, None

    # NOTE: POST is not idempotent, should we still retry?
    @backoff.on_exception(backoff.expo, RETRY_ERRORS, max_tries=1)
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
            json = model_to_dict(json)
        resp = await self.client.post(
            self.url + path,
            json=json,
            params=params,
            headers=self._get_headers(headers),
        )
        self.log_response(resp)
        check_response_status(resp)
        return resp

    @backoff.on_exception(backoff.expo, RETRY_ERRORS, max_time=30)
    async def put(
        self,
        path: str,
        json: Optional[Union[BaseModel, JSONType]] = None,
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
        json: Optional[Union[BaseModel, JSONType]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Response:
        if isinstance(json, BaseModel):
            json = model_to_dict(json)
        resp = await self.client.put(
            self.url + path,
            json=json,
            params=params,
            headers=self._get_headers(headers),
            **kwargs,
        )
        self.log_response(resp)
        check_response_status(resp)
        return resp

    @backoff.on_exception(backoff.expo, RETRY_ERRORS, max_time=30)
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
            json = model_to_dict(json)

        resp = await self.client.patch(
            self.url + path,
            json=json,
            params=params,
            headers=self._get_headers(headers),
            **kwargs,
        )
        self.log_response(resp)
        check_response_status(resp)
        return resp

    @backoff.on_exception(backoff.expo, RETRY_ERRORS, max_time=30)
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
        self.log_response(resp)
        return resp

    @backoff.on_exception(backoff.expo, RETRY_ERRORS, max_time=30)
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
        self.log_response(resp)
        return resp

    # TODO: add on_giveup callback for all backoff methods
