"""Models for the Harbor API.

This module imports all auto generated models from the _models module,
and then overrides the models that have broken or incomplete definitions.

Furthermore, some models are extended with new validators and/or methods.
"""

# Right now, the redefining of models is done in the most naive way possible.
# We just redefine the models that have broken or incomplete definitions...
#
# !!IMPORTANT!!
# However, we also have to redefine/subclass the models that are extended
# from or reference the models that are redefined here. This is because
# the field type of Pydantic models are defined on the class level, and
# redefining a model here will not change the field type of the model in
# the _models module. Thus, if we change the model `Repository` here,
# models that reference `Repository` will still use the old definition.
# To that end, we currently have to redefine all models that reference
# `Repository` here as well. In the future, this should be done more dynamically
# to ensure that we don't miss any models that need to be redefined.

from typing import Any, Dict, List, Optional, Union

from loguru import logger
from pydantic import Extra, Field, root_validator

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
from ._models import AuditLog, AuthproxySetting, BoolConfigItem
from ._models import ChartMetadata as _ChartMetadata
from ._models import ChartVersion as _ChartVersion
from ._models import (
    ComponentHealthStatus,
    Configurations,
    ConfigurationsResponse,
    CVEAllowlist,
    CVEAllowlistItem,
    Error,
    Errors,
    EventType,
    ExecHistory,
    Execution,
    ExtraAttrs,
    FilterStyle,
    GCHistory,
    GeneralInfo,
    Icon,
    ImmutableRule,
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
    RetentionPolicy,
    RetentionPolicyScope,
    RetentionRule,
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
from ._models import Schedule, ScheduleObj, SchedulerStatus, ScheduleTask
from ._models import Search as _Search
from ._models import SearchRepository
from ._models import SearchResult as _SearchResult
from ._models import (
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
    Type,
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
from ._utils import optional_field
from .base import BaseModel

# Explicit re-export of all models

__all__ = [
    "Model",
    "Error",
    "SearchRepository",
    "ChartMetadata",
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
    "ChartVersion",
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
    "SearchResult",
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

# Shadow broken models with new definitions, and update references

# START ChartMetadata
class ChartMetadata(_ChartMetadata):
    # NOTE: only 'engine' has proven to be broken so far, but that makes
    # me less likely to trust that other "required" fields are actually
    # required. So we make all fields optional for now.
    name: Optional[str] = optional_field(_ChartMetadata, "name")  # type: ignore
    version: Optional[str] = optional_field(_ChartMetadata, "version")  # type: ignore
    engine: Optional[str] = optional_field(_ChartMetadata, "engine")  # type: ignore
    icon: Optional[str] = optional_field(_ChartMetadata, "icon")  # type: ignore
    api_version: Optional[str] = optional_field(_ChartMetadata, "api_version")  # type: ignore
    app_version: Optional[str] = optional_field(_ChartMetadata, "app_version")  # type: ignore


class ChartVersion(ChartMetadata, _ChartVersion):
    pass


class SearchResult(_SearchResult):
    chart: Optional[ChartVersion] = optional_field(_SearchResult, "chart")  # type: ignore


class Search(_Search):
    chart: Optional[List[SearchResult]] = optional_field(_Search, "chart")  # type: ignore


# END ChartMetadata

# START Repository
class Repository(_Repository):
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
    def split_name(self) -> Optional[List[str]]:
        """Split name into tuple of project and repository name

        Returns
        -------
        Optional[List[str]]
            The tuple of <project> and <repo>
        """
        if not self.name:
            return None
        components = self.name.split("/", 1)
        if len(components) == 1:  # no slash in name
            # Shouldn't happen, but we account for it anyway
            logger.warning(
                "Repository '{}' name is not in the format <project>/<repo>", self.name
            )
            return None
        return components


# END Repository


# START VulnerabilitySummary


class VulnerabilitySummary(_VulnerabilitySummary):
    # We expand the model with these fields, which are usually
    # present in the summary dict. To provide a better interface
    # for accessing these values, they are exposed as top-level
    # fields.
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

    @root_validator(pre=True)
    def assign_severity_breakdown(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        summary = values.get("summary", {})
        if not isinstance(summary, dict):
            raise ValueError("'summary' must be a dict")
        return {**values, **summary}


class NativeReportSummary(_NativeReportSummary):
    summary: Optional[VulnerabilitySummary] = optional_field(
        _NativeReportSummary, "summary"
    )  # type: ignore


# END VulnerabilitySummary


# START ScanOverview
class ScanOverview(_ScanOverview):
    """Constructs a scan overview from a dict of `mime_type:scan_overview`

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

    The `__new__` method constructs a `NativeReportSummary` object and returns it
    if the MIME type is one of the two MIME types specified in the spec.

    If the MIME type is not recognized, `__new__` returns a `ScanOverview` object
    with the dict assigned as an extra attribute. This behavior is not specified.
    """

    # TODO: make this way less hacky
    def __new__(  # type: ignore # mypy doesn't like __new__ that returns different classes
        cls, *args: Any, **kwargs: Any
    ) -> Union["ScanOverview", NativeReportSummary]:
        mime_types = (
            "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
            "application/vnd.security.vulnerability.report; version=1.1",
        )
        for k, v in kwargs.items():
            if k in mime_types:
                return NativeReportSummary(**v)
        # add logging call here
        return super().__new__(cls)

    class Config:
        extra = Extra.allow


class Artifact(_Artifact):
    scan_overview: Optional[ScanOverview] = optional_field(_Artifact, "scan_overview")  # type: ignore


# END ScanOverview


# START ReplicationFilter


class ReplicationFilter(_ReplicationFilter):
    # Type of 'value' changed from Dict[str, Any], as the type of
    # values this field was observed to receive was exclusively strings.
    # In order to not completely break if we do receive a dict, this field
    # also accepts a dict.
    value: Optional[Union[str, Dict[str, Any]]] = optional_field(
        _ReplicationFilter, "value"
    )  # type: ignore


class ReplicationPolicy(_ReplicationPolicy):
    filters: Optional[List[ReplicationFilter]] = optional_field(
        _ReplicationPolicy, "filters"
    )  # type: ignore


# END ReplicationFilter

# START LdapConf


class LdapConf(_LdapConf):
    # Changes from spec: fix typos in field descriptions
    ldap_filter: Optional[str] = optional_field(_LdapConf, "ldap_filter", description="The search filter of ldap service.")  # type: ignore
    ldap_uid: Optional[str] = optional_field(_LdapConf, "ldap_uid", description="The search uid from ldap service attributes.")  # type: ignore
    ldap_scope: Optional[int] = optional_field(_LdapConf, "ldap_scope", description="The search scope of ldap service.")  # type: ignore


# END LdapConf

# Custom models

# /replication/adapterinfos returns a dict of RegistryProviderInfo objects,
# where each key is the name of registry provider.
# There is, however, no model for this in the spec.
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
