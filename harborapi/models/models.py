"""## Models for the Harbor API.

These models are used by the various endpoints of the Harbor API.
"""

# NOTE: numerous models auto-generated from the Harbor API spec are broken.
# Some fields are marked as required when they are not, and some fields are
# given the wrong type. The development velocity for fixing these issues upstream
# is very slow, so we redefine the models here until they are fixed.
#
# We currently have no mechanism for detecting if a model is fixed upstream.
#
# In order to create more readable documentation, _every_ field on affected models
# are redefined here, even if they are not broken. This is because mkdocstrings
# struggles to render Pydantic models with inherited fields. We want users to
# be able to click on a model defintion in the Docs and see all the fields, not
# have to click through to the parent class to see the inherited fields.
#
# To maximize compatibility, redefined models still inherit from the original
# models, so that if the original models are assigned new fields upstream,
# they are at least still available to the user, even if they have to click
# through to the parent to see it.
#
# Since a lot of models reference each other, we have to redefine every model
# that references a broken model.

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel as PydanticBaseModel
from pydantic import Extra, Field, root_validator

from ..log import logger

# isort kind of mangles these imports by sorting them alphabetically
# but still splitting each "as _" import into its own line.
from ._models import (
    Access,
    Accessory,
    Action,
    ActionRequest,
    AdditionLink,
    AdditionLinks,
    Annotations,
)
from ._models import Artifact as _Artifact
from ._models import (
    AuditLog,
    AuthproxySetting,
    BoolConfigItem,
    ComponentHealthStatus,
    Configurations,
    ConfigurationsResponse,
    CVEAllowlist,
    CVEAllowlistItem,
    Error,
    Errors,
    EventType,
)
from ._models import ExecHistory as _ExecHistory
from ._models import Execution, ExtraAttrs, FilterStyle
from ._models import GCHistory as _GCHistory
from ._models import GeneralInfo as _GeneralInfo
from ._models import Icon
from ._models import ImmutableRule as _ImmutableRule
from ._models import (
    ImmutableSelector,
    Instance,
    IntegerConfigItem,
    InternalConfigurationsResponse,
    InternalConfigurationValue,
    IsDefault,
    JobQueue,
    Label,
)
from ._models import LdapConf as _LdapConf
from ._models import (
    LdapFailedImportUser,
    LdapImportUsers,
    LdapPingResult,
    LdapUser,
    Metadata,
    Metrics,
    Model,
)
from ._models import NativeReportSummary as _NativeReportSummary
from ._models import (
    NotifyType,
    OIDCCliSecretReq,
    OIDCUserInfo,
    OverallHealthStatus,
    Parameter,
    PasswordReq,
    Permission,
    Platform,
    PreheatPolicy,
    Project,
    ProjectDeletable,
    ProjectMember,
    ProjectMemberEntity,
    ProjectMetadata,
    ProjectReq,
    ProjectScanner,
    ProjectSummary,
    ProjectSummaryQuota,
    ProviderUnderProject,
    Quota,
    QuotaRefObject,
    QuotaUpdateReq,
    Reference,
    Registry,
    RegistryCredential,
    RegistryEndpoint,
    RegistryInfo,
    RegistryPing,
    RegistryProviderCredentialPattern,
    RegistryProviderEndpointPattern,
    RegistryProviderInfo,
    RegistryUpdate,
    ReplicationExecution,
)
from ._models import ReplicationFilter as _ReplicationFilter
from ._models import ReplicationPolicy as _ReplicationPolicy
from ._models import ReplicationTask, ReplicationTrigger, ReplicationTriggerSettings
from ._models import Repository as _Repository
from ._models import (
    ResourceList,
    RetentionExecution,
    RetentionExecutionTask,
    RetentionMetadata,
)
from ._models import RetentionPolicy as _RetentionPolicy
from ._models import RetentionPolicyScope
from ._models import RetentionRule as _RetentionRule
from ._models import (
    RetentionRuleMetadata,
    RetentionRuleParamMetadata,
    RetentionRuleTrigger,
    RetentionSelector,
    RetentionSelectorMetadata,
    Robot,
    RobotCreate,
    RobotCreated,
    RobotCreateV1,
    RobotPermission,
    RobotSec,
    RoleRequest,
    ScanAllPolicy,
    ScanDataExportExecution,
    ScanDataExportExecutionList,
    ScanDataExportJob,
    ScanDataExportRequest,
    Scanner,
    ScannerAdapterMetadata,
    ScannerCapability,
    ScannerRegistration,
    ScannerRegistrationReq,
    ScannerRegistrationSettings,
)
from ._models import ScanOverview as _ScanOverview
from ._models import Schedule as _Schedule
from ._models import ScheduleObj as _ScheduleObj
from ._models import (
    SchedulerStatus,
    ScheduleTask,
    Search,
    SearchRepository,
    StartReplicationExecution,
    Statistic,
    Stats,
    Storage,
    StringConfigItem,
    SupportedWebhookEventTypes,
    SystemInfo,
    Tag,
    Task,
    Trigger,
    UserCreationReq,
    UserEntity,
    UserGroup,
    UserGroupSearchItem,
    UserProfile,
    UserResp,
    UserSearch,
    UserSearchRespItem,
    UserSysAdminFlag,
)
from ._models import VulnerabilitySummary as _VulnerabilitySummary
from ._models import (
    WebhookJob,
    WebhookLastTrigger,
    WebhookPolicy,
    WebhookTargetObject,
    Worker,
    WorkerPool,
)
from .base import BaseModel
from .scanner import Severity

# Explicit re-export of all models

__all__ = [
    "Model",
    "Error",
    "SearchRepository",
    "Repository",
    "Tag",
    "ExtraAttrs",
    "Annotations",
    "AdditionLink",
    "Platform",
    "Label",
    "Scanner",
    "VulnerabilitySummary",
    "AuditLog",
    "Metadata",
    "Instance",
    "PreheatPolicy",
    "Metrics",
    "Execution",
    "Task",
    "ProviderUnderProject",
    "Icon",
    "ProjectDeletable",
    "ProjectMetadata",
    "ProjectScanner",
    "CVEAllowlistItem",
    "ReplicationTriggerSettings",
    "ReplicationFilter",
    "RegistryCredential",
    "Registry",
    "RegistryUpdate",
    "RegistryPing",
    "RegistryProviderCredentialPattern",
    "RegistryEndpoint",
    "FilterStyle",
    "ResourceList",
    "ReplicationExecution",
    "StartReplicationExecution",
    "ReplicationTask",
    "RobotCreated",
    "RobotSec",
    "Access",
    "RobotCreateV1",
    "Storage",
    "AuthproxySetting",
    "SystemInfo",
    "Type",
    "ScheduleObj",
    "Trigger",
    "Stats",
    "RetentionRuleParamMetadata",
    "RetentionSelectorMetadata",
    "RetentionRuleTrigger",
    "RetentionPolicyScope",
    "RetentionSelector",
    "RetentionExecution",
    "RetentionExecutionTask",
    "QuotaUpdateReq",
    "QuotaRefObject",
    "Quota",
    "ScannerRegistration",
    "ScannerRegistrationReq",
    "ScannerRegistrationSettings",
    "IsDefault",
    "ScannerCapability",
    "ScannerAdapterMetadata",
    "ImmutableSelector",
    "LdapConf",
    "LdapPingResult",
    "LdapImportUsers",
    "LdapFailedImportUser",
    "LdapUser",
    "UserGroup",
    "UserGroupSearchItem",
    "EventType",
    "NotifyType",
    "WebhookTargetObject",
    "WebhookPolicy",
    "WebhookLastTrigger",
    "WebhookJob",
    "InternalConfigurationValue",
    "Parameter",
    "ScanAllPolicy",
    "Configurations",
    "StringConfigItem",
    "BoolConfigItem",
    "IntegerConfigItem",
    "ProjectMemberEntity",
    "RoleRequest",
    "UserEntity",
    "UserProfile",
    "UserCreationReq",
    "OIDCUserInfo",
    "UserResp",
    "UserSysAdminFlag",
    "UserSearch",
    "PasswordReq",
    "UserSearchRespItem",
    "Permission",
    "OIDCCliSecretReq",
    "ComponentHealthStatus",
    "Statistic",
    "Accessory",
    "ScanDataExportRequest",
    "ScanDataExportJob",
    "ScanDataExportExecution",
    "ScanDataExportExecutionList",
    "WorkerPool",
    "Worker",
    "Action",
    "ActionRequest",
    "JobQueue",
    "ScheduleTask",
    "SchedulerStatus",
    "Errors",
    "AdditionLinks",
    "Reference",
    "NativeReportSummary",
    "ProjectSummaryQuota",
    "CVEAllowlist",
    "ReplicationTrigger",
    "RegistryInfo",
    "RegistryProviderEndpointPattern",
    "RobotPermission",
    "GeneralInfo",
    "GCHistory",
    "ExecHistory",
    "Schedule",
    "RetentionRuleMetadata",
    "RetentionRule",
    "ImmutableRule",
    "SupportedWebhookEventTypes",
    "InternalConfigurationsResponse",
    "ConfigurationsResponse",
    "ProjectMember",
    "OverallHealthStatus",
    "ScanOverview",
    "ProjectReq",
    "Project",
    "ProjectSummary",
    "ReplicationPolicy",
    "RegistryProviderInfo",
    "RegistryProviders",
    "Robot",
    "RobotCreate",
    "RetentionMetadata",
    "RetentionPolicy",
    "Search",
    "Artifact",
]


# START Repository


# Changed: Adds new methods and computed fields
class Repository(_Repository):
    id: Optional[int] = Field(None, description="The ID of the repository")
    project_id: Optional[int] = Field(
        None, description="The ID of the project that the repository belongs to"
    )
    name: Optional[str] = Field(None, description="The name of the repository")
    description: Optional[str] = Field(
        None, description="The description of the repository"
    )
    artifact_count: Optional[int] = Field(
        None, description="The count of the artifacts inside the repository"
    )
    pull_count: Optional[int] = Field(
        None, description="The count that the artifact inside the repository pulled"
    )
    creation_time: Optional[datetime] = Field(
        None, description="The creation time of the repository"
    )
    update_time: Optional[datetime] = Field(
        None, description="The update time of the repository"
    )

    @property
    def base_name(self) -> str:
        """The repository name without the project name

        Returns
        -------
        Optional[str]
            The basename of the repository name
        """
        s = self.split_name()
        return s[1] if s else ""

    @property
    def project_name(self) -> str:
        """The name of the project that the repository belongs to

        Returns
        -------
        Optional[str]
            The name of the project that the repository belongs to
        """
        s = self.split_name()
        return s[0] if s else ""

    # TODO: cache?
    def split_name(self) -> Optional[Tuple[str, str]]:
        """Split name into tuple of project and repository name

        Returns
        -------
        Optional[Tuple[str, str]]
            Tuple of project name and repo name
        """
        if not self.name:
            return None
        components = self.name.split("/", 1)
        if len(components) != 2:  # no slash in name
            # Shouldn't happen, but we account for it anyway
            logger.warning(
                "Repository name '%s' is not in the format <project>/<repo>", self.name
            )
            return None
        return components[0], components[1]


# END Repository


# START VulnerabilitySummary
class VulnerabilitySummary(_VulnerabilitySummary):
    # Changed: Add new fields populated by root validator
    total: Optional[int] = Field(
        None, description="The total number of the found vulnerabilities", example=500
    )
    fixable: Optional[int] = Field(
        None, description="The number of the fixable vulnerabilities", example=100
    )
    summary: Optional[Dict[str, int]] = Field(
        None,
        description="Numbers of the vulnerabilities with different severity",
        example={"Critical": 5, "High": 5},
    )
    # Summary dict keys added as fields
    critical: int = Field(
        0,
        alias="Critical",
        description="The number of critical vulnerabilities detected.",
    )
    high: int = Field(
        0, alias="High", description="The number of critical vulnerabilities detected."
    )
    medium: int = Field(
        0,
        alias="Medium",
        description="The number of critical vulnerabilities detected.",
    )
    low: int = Field(
        0, alias="Low", description="The number of critical vulnerabilities detected."
    )
    unknown: int = Field(
        0,
        alias="Unknown",
        description="The number of critical vulnerabilities detected.",
    )

    @root_validator(pre=True)
    def _assign_severity_breakdown(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        summary = values.get("summary") or {}  # account for None
        if not isinstance(summary, dict):
            raise ValueError("'summary' must be a dict")
        return {**values, **summary}


class NativeReportSummary(_NativeReportSummary):
    # Changed: Use new VulnerabilitySummary, add severity_enum computed field
    report_id: Optional[str] = Field(
        None,
        description="id of the native scan report",
        example="5f62c830-f996-11e9-957f-0242c0a89008",
    )
    scan_status: Optional[str] = Field(
        None,
        description="The status of the report generating process",
        example="Success",
    )
    severity: Optional[str] = Field(
        None, description="The overall severity", example="High"
    )
    duration: Optional[int] = Field(
        None, description="The seconds spent for generating the report", example=300
    )
    summary: Optional[VulnerabilitySummary] = None
    start_time: Optional[datetime] = Field(
        None,
        description="The start time of the scan process that generating report",
        example="2006-01-02T14:04:05Z",
    )
    end_time: Optional[datetime] = Field(
        None,
        description="The end time of the scan process that generating report",
        example="2006-01-02T15:04:05Z",
    )
    complete_percent: Optional[int] = Field(
        None,
        description="The complete percent of the scanning which value is between 0 and 100",
        example=100,
    )
    scanner: Optional[Scanner] = None

    @property
    def severity_enum(self) -> Optional[Severity]:
        """The severity of the vulnerability

        Returns
        -------
        Optional[Severity]
            The severity of the vulnerability
        """
        if self.severity:
            return Severity(self.severity)
        return None


# END VulnerabilitySummary


# START ScanOverview
class ScanOverview(_ScanOverview):
    class Config:
        extra = Extra.allow


class Artifact(_Artifact):
    id: Optional[int] = Field(None, description="The ID of the artifact")
    type: Optional[str] = Field(
        None, description="The type of the artifact, e.g. image, chart, etc"
    )
    media_type: Optional[str] = Field(
        None, description="The media type of the artifact"
    )
    manifest_media_type: Optional[str] = Field(
        None, description="The manifest media type of the artifact"
    )
    project_id: Optional[int] = Field(
        None, description="The ID of the project that the artifact belongs to"
    )
    repository_id: Optional[int] = Field(
        None, description="The ID of the repository that the artifact belongs to"
    )
    digest: Optional[str] = Field(None, description="The digest of the artifact")
    size: Optional[int] = Field(None, description="The size of the artifact")
    icon: Optional[str] = Field(None, description="The digest of the icon")
    push_time: Optional[datetime] = Field(
        None, description="The push time of the artifact"
    )
    pull_time: Optional[datetime] = Field(
        None, description="The latest pull time of the artifact"
    )
    extra_attrs: Optional[ExtraAttrs] = None
    annotations: Optional[Annotations] = None
    references: Optional[List[Reference]] = None
    tags: Optional[List[Tag]] = None
    addition_links: Optional[AdditionLinks] = None
    labels: Optional[List[Label]] = None
    scan_overview: Optional[NativeReportSummary] = Field(
        None, description="The overview of the scan result."
    )
    accessories: Optional[List[Accessory]] = None

    @root_validator(pre=True)
    def _get_native_report_summary(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        """Constructs a scan overview from a dict of `mime_type:scan_overview`
        and populates the `native_report_summary` field with it.

        The API spec does not specify the contents of the scan overview, but from
        investigating the behavior of the API, it seems to return a dict that looks like this:

        ```py
        {
            "application/vnd.security.vulnerability.report; version=1.1": {
                # dict that conforms to NativeReportSummary spec
                ...
            }
        }
        ```
        """
        mime_types = (
            "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
            "application/vnd.security.vulnerability.report; version=1.1",
        )
        overview = values.get("scan_overview")
        if not overview:
            return values

        if isinstance(overview, PydanticBaseModel):
            overview = overview.dict()

        # At this point we require that scan_overview is a dict
        if not isinstance(overview, dict):
            raise TypeError(
                f"scan_overview must be a dict, not {type(overview).__name__}"
            )

        # Extract overview for the first mime type that we recognize
        for k, v in overview.items():
            if k in mime_types:
                values["scan_overview"] = v
                break
        return values


# END ScanOverview


# START ReplicationFilter


class ReplicationFilter(_ReplicationFilter):
    # Changed: Type of 'value' changed from Dict[str, Any], as the type of
    # values this field was observed to receive was exclusively strings.
    # In order to not completely break if we do receive a dict, this field
    # also accepts a dict.
    type: Optional[str] = Field(None, description="The replication policy filter type.")
    value: Optional[Dict[str, Any]] = Field(
        None, description="The value of replication policy filter."
    )
    decoration: Optional[str] = Field(
        None, description="matches or excludes the result"
    )


class ReplicationPolicy(_ReplicationPolicy):
    id: Optional[int] = Field(None, description="The policy ID.")
    name: Optional[str] = Field(None, description="The policy name.")
    description: Optional[str] = Field(
        None, description="The description of the policy."
    )
    src_registry: Optional[Registry] = Field(None, description="The source registry.")
    dest_registry: Optional[Registry] = Field(
        None, description="The destination registry."
    )
    dest_namespace: Optional[str] = Field(
        None, description="The destination namespace."
    )
    dest_namespace_replace_count: Optional[int] = Field(
        None,
        description="Specify how many path components will be replaced by the provided destination namespace.\nThe default value is -1 in which case the legacy mode will be applied.",
    )
    trigger: Optional[ReplicationTrigger] = None
    filters: Optional[List[ReplicationFilter]] = Field(
        None, description="The replication policy filter array."
    )
    replicate_deletion: Optional[bool] = Field(
        None, description="Whether to replicate the deletion operation."
    )
    deletion: Optional[bool] = Field(
        None,
        description='Deprecated, use "replicate_deletion" instead. Whether to replicate the deletion operation.',
    )
    override: Optional[bool] = Field(
        None,
        description="Whether to override the resources on the destination registry.",
    )
    enabled: Optional[bool] = Field(
        None, description="Whether the policy is enabled or not."
    )
    creation_time: Optional[datetime] = Field(
        None, description="The create time of the policy."
    )
    update_time: Optional[datetime] = Field(
        None, description="The update time of the policy."
    )
    speed: Optional[int] = Field(None, description="speed limit for each task")
    copy_by_chunk: Optional[bool] = Field(
        None, description="Whether to enable copy by chunk."
    )


# END ReplicationFilter

# START LdapConf


class LdapConf(_LdapConf):
    # Changed: fix typos in field descriptions of ldap_filter, ldap_uid, ldap_scope
    ldap_url: Optional[str] = Field(None, description="The url of ldap service.")
    ldap_search_dn: Optional[str] = Field(
        None, description="The search dn of ldap service."
    )
    ldap_search_password: Optional[str] = Field(
        None, description="The search password of ldap service."
    )
    ldap_base_dn: Optional[str] = Field(
        None, description="The base dn of ldap service."
    )
    ldap_filter: Optional[str] = Field(
        None, description="The search filter of ldap service."
    )
    ldap_uid: Optional[str] = Field(
        None, description="The search uid from ldap service attributes."
    )
    ldap_scope: Optional[int] = Field(
        None, description="The search scope of ldap service."
    )
    ldap_connection_timeout: Optional[int] = Field(
        None, description="The connect timeout of ldap service(second)."
    )
    ldap_verify_cert: Optional[bool] = Field(
        None, description="Verify Ldap server certificate."
    )


# END LdapConf

# Custom models


# /replication/adapterinfos returns a dict of RegistryProviderInfo objects,
# where each key is the name of registry provider.
# There is no model for this in the spec.
class RegistryProviders(BaseModel):
    __root__: Dict[str, RegistryProviderInfo] = Field(
        {},
        description="The registry providers. Each key is the name of the registry provider.",
    )

    @property
    def providers(self) -> Dict[str, RegistryProviderInfo]:
        return self.__root__

    def __getitem__(self, key: str) -> RegistryProviderInfo:
        return self.__root__[key]


# Enums can't be subclassed, so they are redefined here.
class Type(Enum):
    # Changed: add `schedule` type
    hourly = "Hourly"
    daily = "Daily"
    weekly = "Weekly"
    custom = "Custom"
    manual = "Manual"
    none = "None"
    schedule = "Schedule"


class ScheduleObj(_ScheduleObj):
    # Changed: update schedule field type
    type: Optional[Type] = Field(
        None,
        description="The schedule type. The valid values are 'Hourly', 'Daily', 'Weekly', 'Custom', 'Manual' and 'None'.\n'Manual' means to trigger it right away and 'None' means to cancel the schedule.\n",
    )  # type: ignore # uses fixed definition
    cron: Optional[str] = Field(
        None, description="A cron expression, a time-based job scheduler."
    )
    next_scheduled_time: Optional[datetime] = Field(
        None, description="The next time to schedule to run the job."
    )


class GCHistory(_GCHistory):
    # Changed: update schedule field type
    id: Optional[int] = Field(None, description="the id of gc job.")
    job_name: Optional[str] = Field(None, description="the job name of gc job.")
    job_kind: Optional[str] = Field(None, description="the job kind of gc job.")
    job_parameters: Optional[str] = Field(
        None, description="the job parameters of gc job."
    )
    schedule: Optional[ScheduleObj] = None
    job_status: Optional[str] = Field(None, description="the status of gc job.")
    deleted: Optional[bool] = Field(None, description="if gc job was deleted.")
    creation_time: Optional[datetime] = Field(
        None, description="the creation time of gc job."
    )
    update_time: Optional[datetime] = Field(
        None, description="the update time of gc job."
    )


class ExecHistory(_ExecHistory):
    # Changed: update schedule field type
    id: Optional[int] = Field(None, description="the id of purge job.")
    job_name: Optional[str] = Field(None, description="the job name of purge job.")
    job_kind: Optional[str] = Field(None, description="the job kind of purge job.")
    job_parameters: Optional[str] = Field(
        None, description="the job parameters of purge job."
    )
    schedule: Optional[ScheduleObj] = None
    job_status: Optional[str] = Field(None, description="the status of purge job.")
    deleted: Optional[bool] = Field(None, description="if purge job was deleted.")
    creation_time: Optional[datetime] = Field(
        None, description="the creation time of purge job."
    )
    update_time: Optional[datetime] = Field(
        None, description="the update time of purge job."
    )


class Schedule(_Schedule):
    # Changed: update schedule field type & change parameters field type
    id: Optional[int] = Field(None, description="The id of the schedule.")
    status: Optional[str] = Field(None, description="The status of the schedule.")
    creation_time: Optional[datetime] = Field(
        None, description="the creation time of the schedule."
    )
    update_time: Optional[datetime] = Field(
        None, description="the update time of the schedule."
    )
    schedule: Optional[ScheduleObj] = None
    # REASON: The spec says that the `parameters` field is a dict of dicts, but
    # the API uses a dict of Any instead.
    # From API spec: The sample format is {"parameters":{"audit_retention_hour":168,"dry_run":true, "include_operations":"create,delete,pull"},"schedule":{"type":"Hourly","cron":"0 0 * * * *"}}
    parameters: Optional[Dict[str, Any]] = Field(
        None, description="The parameters of schedule job"
    )


class GeneralInfo(_GeneralInfo):
    # Changed: add with_chartmuseum field, but mark it as deprecated
    with_chartmuseum: Optional[bool] = Field(
        None,
        description="If the Harbor instance is deployed with nested chartmuseum.",
        deprecated=True,
    )
    current_time: Optional[datetime] = Field(
        None, description="The current time of the server."
    )
    registry_url: Optional[str] = Field(
        None,
        description="The url of registry against which the docker command should be issued.",
    )
    external_url: Optional[str] = Field(
        None, description="The external URL of Harbor, with protocol."
    )
    auth_mode: Optional[str] = Field(
        None, description="The auth mode of current Harbor instance."
    )
    primary_auth_mode: Optional[bool] = Field(
        None,
        description="The flag to indicate whether the current auth mode should consider as a primary one.",
    )
    project_creation_restriction: Optional[str] = Field(
        None,
        description="Indicate who can create projects, it could be 'adminonly' or 'everyone'.",
    )
    self_registration: Optional[bool] = Field(
        None,
        description="Indicate whether the Harbor instance enable user to register himself.",
    )
    has_ca_root: Optional[bool] = Field(
        None,
        description="Indicate whether there is a ca root cert file ready for download in the file system.",
    )
    harbor_version: Optional[str] = Field(
        None, description="The build version of Harbor."
    )
    registry_storage_provider_name: Optional[str] = Field(
        None, description="The storage provider's name of Harbor registry"
    )
    read_only: Optional[bool] = Field(
        None, description="The flag to indicate whether Harbor is in readonly mode."
    )
    notification_enable: Optional[bool] = Field(
        None,
        description="The flag to indicate whether notification mechanism is enabled on Harbor instance.",
    )
    authproxy_settings: Optional[AuthproxySetting] = Field(
        None,
        description="The setting of auth proxy this is only available when Harbor relies on authproxy for authentication.",
    )


class RetentionRule(_RetentionRule):
    # Changed: change params field type
    # Reason: params is a dict of Any, not a dict of dicts
    # TODO: add descriptions
    id: Optional[int] = None
    priority: Optional[int] = None
    disabled: Optional[bool] = None
    action: Optional[str] = None
    template: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    tag_selectors: Optional[List[RetentionSelector]] = None
    scope_selectors: Optional[Dict[str, List[RetentionSelector]]] = None


class RetentionPolicy(_RetentionPolicy):
    id: Optional[int] = None
    algorithm: Optional[str] = None
    rules: Optional[List[RetentionRule]] = None  # type: ignore
    trigger: Optional[RetentionRuleTrigger] = None
    scope: Optional[RetentionPolicyScope] = None


class ImmutableRule(_ImmutableRule):
    # Changed: change params field type
    # Reason: params is a dict of Any, not a dict of dicts
    id: Optional[int] = None
    priority: Optional[int] = None
    disabled: Optional[bool] = None
    action: Optional[str] = None
    template: Optional[str] = None
    params: Optional[Dict[str, Dict[str, Any]]] = None
    tag_selectors: Optional[List[ImmutableSelector]] = None
    scope_selectors: Optional[Dict[str, List[ImmutableSelector]]] = None
