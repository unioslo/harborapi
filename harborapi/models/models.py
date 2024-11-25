from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import Type as PyType
from typing import Union

from pydantic import AnyUrl
from pydantic import Field
from pydantic import RootModel
from pydantic import ValidationInfo
from pydantic import field_validator
from pydantic import model_validator

from ..log import logger
from .base import BaseModel
from .scanner import Severity


class Error(BaseModel):
    """Error response from Harbor."""

    code: Optional[str] = Field(default=None, description="The error code")
    message: Optional[str] = Field(default=None, description="The error message")


class SearchRepository(BaseModel):
    """Repository search result."""

    project_id: Optional[int] = Field(
        default=None, description="The ID of the project that the repository belongs to"
    )
    project_name: Optional[str] = Field(
        default=None,
        description="The name of the project that the repository belongs to",
    )
    project_public: Optional[bool] = Field(
        default=None,
        description="The flag to indicate the publicity of the project that the repository belongs to (1 is public, 0 is not)",
    )
    repository_name: Optional[str] = Field(
        default=None, description="The name of the repository"
    )
    pull_count: Optional[int] = Field(
        default=None, description="The count how many times the repository is pulled"
    )
    artifact_count: Optional[int] = Field(
        default=None, description="The count of artifacts in the repository"
    )


class Repository(BaseModel):
    id: Optional[int] = Field(default=None, description="The ID of the repository")
    project_id: Optional[int] = Field(
        default=None, description="The ID of the project that the repository belongs to"
    )
    name: Optional[str] = Field(default=None, description="The name of the repository")
    description: Optional[str] = Field(
        default=None, description="The description of the repository"
    )
    artifact_count: Optional[int] = Field(
        default=None, description="The count of the artifacts inside the repository"
    )
    pull_count: Optional[int] = Field(
        default=None,
        description="The count that the artifact inside the repository pulled",
    )
    creation_time: Optional[datetime] = Field(
        default=None, description="The creation time of the repository"
    )
    update_time: Optional[datetime] = Field(
        default=None, description="The update time of the repository"
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
        if len(components) != 2:
            logger.warning(
                "Repository name '%s' is not in the format <project>/<repo>", self.name
            )
            return None
        return (components[0], components[1])


class Tag(BaseModel):
    id: Optional[int] = Field(default=None, description="The ID of the tag")
    repository_id: Optional[int] = Field(
        default=None, description="The ID of the repository that the tag belongs to"
    )
    artifact_id: Optional[int] = Field(
        default=None, description="The ID of the artifact that the tag attached to"
    )
    name: Optional[str] = Field(default=None, description="The name of the tag")
    push_time: Optional[datetime] = Field(
        default=None, description="The push time of the tag"
    )
    pull_time: Optional[datetime] = Field(
        default=None, description="The latest pull time of the tag"
    )
    immutable: Optional[bool] = Field(
        default=None, description="The immutable status of the tag"
    )


class ExtraAttrs(RootModel[Optional[Dict[str, Dict[str, Any]]]]):
    root: Optional[Dict[str, Any]] = None


class Annotations(RootModel[Optional[Dict[str, str]]]):
    root: Optional[Dict[str, str]] = None


class AdditionLink(BaseModel):
    href: Optional[str] = Field(default=None, description="The link of the addition")
    absolute: Optional[bool] = Field(
        default=None, description="Determine whether the link is an absolute URL or not"
    )


class Platform(BaseModel):
    architecture: Optional[str] = Field(
        default=None, description="The architecture that the artifact applys to"
    )
    os: Optional[str] = Field(
        default=None, description="The OS that the artifact applys to"
    )
    field_os_version_: Optional[str] = Field(
        default=None,
        alias="'os.version'",
        description="The version of the OS that the artifact applys to",
    )
    field_os_features_: Optional[List[str]] = Field(
        default=None,
        alias="'os.features'",
        description="The features of the OS that the artifact applys to",
    )
    variant: Optional[str] = Field(default=None, description="The variant of the CPU")


class Label(BaseModel):
    id: Optional[int] = Field(default=None, description="The ID of the label")
    name: Optional[str] = Field(default=None, description="The name the label")
    description: Optional[str] = Field(
        default=None, description="The description the label"
    )
    color: Optional[str] = Field(default=None, description="The color the label")
    scope: Optional[str] = Field(default=None, description="The scope the label")
    project_id: Optional[int] = Field(
        default=None, description="The ID of project that the label belongs to"
    )
    creation_time: Optional[datetime] = Field(
        default=None, description="The creation time the label"
    )
    update_time: Optional[datetime] = Field(
        default=None, description="The update time of the label"
    )


class Scanner(BaseModel):
    name: Optional[str] = Field(
        default=None, description="Name of the scanner", examples=["Trivy"]
    )
    vendor: Optional[str] = Field(
        default=None,
        description="Name of the scanner provider",
        examples=["Aqua Security"],
    )
    version: Optional[str] = Field(
        default=None, description="Version of the scanner adapter", examples=["v0.9.1"]
    )


class SBOMOverview(BaseModel):
    """
    The generate SBOM overview information
    """

    start_time: Optional[datetime] = Field(
        default=None,
        description="The start time of the generating sbom report task",
        examples=["2006-01-02T14:04:05Z"],
    )
    end_time: Optional[datetime] = Field(
        default=None,
        description="The end time of the generating sbom report task",
        examples=["2006-01-02T15:04:05Z"],
    )
    scan_status: Optional[str] = Field(
        default=None, description="The status of the generating SBOM task"
    )
    sbom_digest: Optional[str] = Field(
        default=None, description="The digest of the generated SBOM accessory"
    )
    report_id: Optional[str] = Field(
        default=None,
        description="id of the native scan report",
        examples=["5f62c830-f996-11e9-957f-0242c0a89008"],
    )
    duration: Optional[int] = Field(
        default=None,
        description="Time in seconds required to create the report",
        examples=[300],
    )
    scanner: Optional[Scanner] = None


class VulnerabilitySummary(BaseModel):
    """Summary of vulnerabilities found in a scan."""

    total: Optional[int] = Field(
        default=None,
        description="The total number of the found vulnerabilities",
        examples=[500],
    )
    fixable: Optional[int] = Field(
        default=None,
        description="The number of the fixable vulnerabilities",
        examples=[100],
    )
    summary: Optional[Dict[str, int]] = Field(
        default=None,
        description="Numbers of the vulnerabilities with different severity",
        examples=[{"Critical": 5, "High": 5}],
    )
    critical: int = Field(
        default=0,
        alias="Critical",
        description="The number of critical vulnerabilities detected.",
    )
    high: int = Field(
        default=0,
        alias="High",
        description="The number of critical vulnerabilities detected.",
    )
    medium: int = Field(
        default=0,
        alias="Medium",
        description="The number of critical vulnerabilities detected.",
    )
    low: int = Field(
        default=0,
        alias="Low",
        description="The number of critical vulnerabilities detected.",
    )
    unknown: int = Field(
        default=0,
        alias="Unknown",
        description="The number of critical vulnerabilities detected.",
    )

    @model_validator(mode="before")
    @classmethod
    def _assign_severity_breakdown(cls, values: Dict[str, Any]) -> Dict[str, Any]:
        summary = values.get("summary") or {}
        if not isinstance(summary, dict):
            raise ValueError("'summary' must be a dict")
        return {**values, **summary}


class AuditLog(BaseModel):
    id: Optional[int] = Field(
        default=None, description="The ID of the audit log entry."
    )
    username: Optional[str] = Field(
        default=None, description="Username of the user in this log entry."
    )
    resource: Optional[str] = Field(
        default=None, description="Name of the repository in this log entry."
    )
    resource_type: Optional[str] = Field(
        default=None, description="Tag of the repository in this log entry."
    )
    operation: Optional[str] = Field(
        default=None,
        description="The operation against the repository in this log entry.",
    )
    op_time: Optional[datetime] = Field(
        default=None,
        description="The time when this operation is triggered.",
        examples=["2006-01-02T15:04:05Z"],
    )


class Metadata(BaseModel):
    id: Optional[str] = Field(default=None, description="id")
    name: Optional[str] = Field(default=None, description="name")
    icon: Optional[str] = Field(default=None, description="icon")
    maintainers: Optional[List[str]] = Field(default=None, description="maintainers")
    version: Optional[str] = Field(default=None, description="version")
    source: Optional[str] = Field(default=None, description="source")


class Instance(BaseModel):
    id: Optional[int] = Field(default=None, description="Unique ID")
    name: Optional[str] = Field(default=None, description="Instance name")
    description: Optional[str] = Field(
        default=None, description="Description of instance"
    )
    vendor: Optional[str] = Field(
        default=None, description="Based on which driver, identified by ID"
    )
    endpoint: Optional[str] = Field(
        default=None, description="The service endpoint of this instance"
    )
    auth_mode: Optional[str] = Field(
        default=None, description="The authentication way supported"
    )
    auth_info: Optional[Dict[str, str]] = Field(
        default=None, description="The auth credential data if exists"
    )
    status: Optional[str] = Field(default=None, description="The health status")
    enabled: Optional[bool] = Field(
        default=None, description="Whether the instance is activated or not"
    )
    default: Optional[bool] = Field(
        default=None, description="Whether the instance is default or not"
    )
    insecure: Optional[bool] = Field(
        default=None, description="Whether the instance endpoint is insecure or not"
    )
    setup_timestamp: Optional[int] = Field(
        default=None, description="The timestamp of instance setting up"
    )


class PreheatPolicy(BaseModel):
    id: Optional[int] = Field(default=None, description="The ID of preheat policy")
    name: Optional[str] = Field(default=None, description="The Name of preheat policy")
    description: Optional[str] = Field(
        default=None, description="The Description of preheat policy"
    )
    project_id: Optional[int] = Field(
        default=None, description="The ID of preheat policy project"
    )
    provider_id: Optional[int] = Field(
        default=None, description="The ID of preheat policy provider"
    )
    provider_name: Optional[str] = Field(
        default=None, description="The Name of preheat policy provider"
    )
    filters: Optional[str] = Field(
        default=None, description="The Filters of preheat policy"
    )
    trigger: Optional[str] = Field(
        default=None, description="The Trigger of preheat policy"
    )
    enabled: Optional[bool] = Field(
        default=None, description="Whether the preheat policy enabled"
    )
    scope: Optional[str] = Field(
        default=None, description="The scope of preheat policy"
    )
    creation_time: Optional[datetime] = Field(
        default=None, description="The Create Time of preheat policy"
    )
    update_time: Optional[datetime] = Field(
        default=None, description="The Update Time of preheat policy"
    )


class Metrics(BaseModel):
    task_count: Optional[int] = Field(default=None, description="The count of task")
    success_task_count: Optional[int] = Field(
        default=None, description="The count of success task"
    )
    error_task_count: Optional[int] = Field(
        default=None, description="The count of error task"
    )
    pending_task_count: Optional[int] = Field(
        default=None, description="The count of pending task"
    )
    running_task_count: Optional[int] = Field(
        default=None, description="The count of running task"
    )
    scheduled_task_count: Optional[int] = Field(
        default=None, description="The count of scheduled task"
    )
    stopped_task_count: Optional[int] = Field(
        default=None, description="The count of stopped task"
    )


class Execution(BaseModel):
    id: Optional[int] = Field(default=None, description="The ID of execution")
    vendor_type: Optional[str] = Field(
        default=None, description="The vendor type of execution"
    )
    vendor_id: Optional[int] = Field(
        default=None, description="The vendor id of execution"
    )
    status: Optional[str] = Field(default=None, description="The status of execution")
    status_message: Optional[str] = Field(
        default=None, description="The status message of execution"
    )
    metrics: Optional[Metrics] = None
    trigger: Optional[str] = Field(default=None, description="The trigger of execution")
    extra_attrs: Optional[ExtraAttrs] = None
    start_time: Optional[str] = Field(
        default=None, description="The start time of execution"
    )
    end_time: Optional[str] = Field(
        default=None, description="The end time of execution"
    )


class Task(BaseModel):
    id: Optional[int] = Field(default=None, description="The ID of task")
    execution_id: Optional[int] = Field(
        default=None, description="The ID of task execution"
    )
    status: Optional[str] = Field(default=None, description="The status of task")
    status_message: Optional[str] = Field(
        default=None, description="The status message of task"
    )
    run_count: Optional[int] = Field(default=None, description="The count of task run")
    extra_attrs: Optional[ExtraAttrs] = None
    creation_time: Optional[str] = Field(
        default=None, description="The creation time of task"
    )
    update_time: Optional[str] = Field(
        default=None, description="The update time of task"
    )
    start_time: Optional[str] = Field(
        default=None, description="The start time of task"
    )
    end_time: Optional[str] = Field(default=None, description="The end time of task")


class ProviderUnderProject(BaseModel):
    id: Optional[int] = None
    provider: Optional[str] = None
    enabled: Optional[bool] = None
    default: Optional[bool] = None


class Icon(BaseModel):
    content_type: Optional[str] = Field(
        default=None, alias="content-type", description="The content type of the icon"
    )
    content: Optional[str] = Field(
        default=None, description="The base64 encoded content of the icon"
    )


class ProjectDeletable(BaseModel):
    deletable: Optional[bool] = Field(
        default=None, description="Whether the project can be deleted."
    )
    message: Optional[str] = Field(
        default=None,
        description="The detail message when the project can not be deleted.",
    )


class ProjectMetadata(BaseModel):
    public: Optional[str] = Field(
        default=None,
        description='The public status of the project. The valid values are "true", "false".',
    )
    enable_content_trust: Optional[str] = Field(
        default=None,
        description='Whether content trust is enabled or not. If it is enabled, user can\'t pull unsigned images from this project. The valid values are "true", "false".',
    )
    enable_content_trust_cosign: Optional[str] = Field(
        default=None,
        description='Whether cosign content trust is enabled or not. If it is enabled, user can\'t pull images without cosign signature from this project. The valid values are "true", "false".',
    )
    prevent_vul: Optional[str] = Field(
        default=None,
        description='Whether prevent the vulnerable images from running. The valid values are "true", "false".',
    )
    severity: Optional[str] = Field(
        default=None,
        description='If the vulnerability is high than severity defined here, the images can\'t be pulled. The valid values are "none", "low", "medium", "high", "critical".',
    )
    auto_scan: Optional[str] = Field(
        default=None,
        description='Whether scan images automatically when pushing. The valid values are "true", "false".',
    )
    auto_sbom_generation: Optional[str] = Field(
        default=None,
        description='Whether generating SBOM automatically when pushing a subject artifact. The valid values are "true", "false".',
    )
    reuse_sys_cve_allowlist: Optional[str] = Field(
        default=None,
        description='Whether this project reuse the system level CVE allowlist as the allowlist of its own.  The valid values are "true", "false". If it is set to "true" the actual allowlist associate with this project, if any, will be ignored.',
    )
    retention_id: Optional[Union[str, int]] = Field(
        default=None, description="The ID of the tag retention policy for the project"
    )
    proxy_speed_kb: Optional[str] = Field(
        default=None,
        description="The bandwidth limit of proxy cache, in Kbps (kilobits per second). It limits the communication between Harbor and the upstream registry, not the client and the Harbor.",
    )

    @field_validator("*", mode="before")
    @classmethod
    def _validate_strbool(
        cls: PyType["BaseModel"], v: Any, info: ValidationInfo
    ) -> Any:
        """The project metadata model spec specifies that all fields are
        strings, but their valid values are 'true' and 'false'.

        Pydantic has built-in conversion from bool to str, but it yields
        'True' and 'False' instead of 'true' and 'false'. This validator
        converts bools to the strings 'true' and 'false' instead.

        This validator only converts the values if the field
        description contains the word '"true"' (with double quotes).
        """
        if not isinstance(v, bool):
            return v
        if not info.field_name:
            raise ValueError("Validator is not attached to a field.")
        field = cls.model_fields[info.field_name]
        if not field.description or '"true"' not in field.description:
            return v
        return str(v).lower()


class ProjectScanner(BaseModel):
    uuid: str = Field(..., description="The identifier of the scanner registration")


class CVEAllowlistItem(BaseModel):
    """CVE allowlist item."""

    cve_id: Optional[str] = Field(
        default=None, description='The ID of the CVE, such as "CVE-2019-10164"'
    )


class ReplicationTriggerSettings(BaseModel):
    cron: Optional[str] = Field(
        default=None, description="The cron string for scheduled trigger"
    )


class ReplicationFilter(BaseModel):
    type: Optional[str] = Field(
        default=None, description="The replication policy filter type."
    )
    value: Union[str, Dict[str, Any], None] = Field(
        default=None, description="The value of replication policy filter."
    )
    decoration: Optional[str] = Field(
        default=None, description="matches or excludes the result"
    )


class RegistryCredential(BaseModel):
    type: Optional[str] = Field(
        default=None, description="Credential type, such as 'basic', 'oauth'."
    )
    access_key: Optional[str] = Field(
        default=None,
        description="Access key, e.g. user name when credential type is 'basic'.",
    )
    access_secret: Optional[str] = Field(
        default=None,
        description="Access secret, e.g. password when credential type is 'basic'.",
    )


class Registry(BaseModel):
    id: Optional[int] = Field(default=None, description="The registry ID.")
    url: Optional[str] = Field(default=None, description="The registry URL string.")
    name: Optional[str] = Field(default=None, description="The registry name.")
    credential: Optional[RegistryCredential] = None
    type: Optional[str] = Field(
        default=None, description="Type of the registry, e.g. 'harbor'."
    )
    insecure: Optional[bool] = Field(
        default=None,
        description="Whether or not the certificate will be verified when Harbor tries to access the server.",
    )
    description: Optional[str] = Field(
        default=None, description="Description of the registry."
    )
    status: Optional[str] = Field(
        default=None, description="Health status of the registry."
    )
    creation_time: Optional[datetime] = Field(
        default=None, description="The create time of the policy."
    )
    update_time: Optional[datetime] = Field(
        default=None, description="The update time of the policy."
    )


class RegistryUpdate(BaseModel):
    name: Optional[str] = Field(default=None, description="The registry name.")
    description: Optional[str] = Field(
        default=None, description="Description of the registry."
    )
    url: Optional[str] = Field(default=None, description="The registry URL.")
    credential_type: Optional[str] = Field(
        default=None, description="Credential type of the registry, e.g. 'basic'."
    )
    access_key: Optional[str] = Field(
        default=None, description="The registry access key."
    )
    access_secret: Optional[str] = Field(
        default=None, description="The registry access secret."
    )
    insecure: Optional[bool] = Field(
        default=None,
        description="Whether or not the certificate will be verified when Harbor tries to access the server.",
    )


class RegistryPing(BaseModel):
    id: Optional[int] = Field(default=None, description="The registry ID.")
    type: Optional[str] = Field(
        default=None, description="Type of the registry, e.g. 'harbor'."
    )
    url: Optional[str] = Field(default=None, description="The registry URL.")
    credential_type: Optional[str] = Field(
        default=None, description="Credential type of the registry, e.g. 'basic'."
    )
    access_key: Optional[str] = Field(
        default=None, description="The registry access key."
    )
    access_secret: Optional[str] = Field(
        default=None, description="The registry access secret."
    )
    insecure: Optional[bool] = Field(
        default=None,
        description="Whether or not the certificate will be verified when Harbor tries to access the server.",
    )


class RegistryProviderCredentialPattern(BaseModel):
    """Pattern for a registry credential."""

    access_key_type: Optional[str] = Field(
        default=None, description="The access key type"
    )
    access_key_data: Optional[str] = Field(
        default=None, description="The access key data"
    )
    access_secret_type: Optional[str] = Field(
        default=None, description="The access secret type"
    )
    access_secret_data: Optional[str] = Field(
        default=None, description="The access secret data"
    )


class RegistryEndpoint(BaseModel):
    """Registry endpoint configuration."""

    key: Optional[str] = Field(default=None, description="The endpoint key")
    value: Optional[str] = Field(default=None, description="The endpoint value")


class FilterStyle(BaseModel):
    """Style of the resource filter."""

    type: Optional[str] = Field(default=None, description="The filter type")
    style: Optional[str] = Field(default=None, description="The filter style")
    values: Optional[List[str]] = Field(default=None, description="The filter values")


class ResourceList(RootModel[Optional[Dict[str, int]]]):
    root: Optional[Dict[str, int]] = None


class ReplicationExecution(BaseModel):
    """The execution of a replication job."""

    id: Optional[int] = Field(default=None, description="The ID of the execution")
    policy_id: Optional[int] = Field(
        default=None, description="The ID if the policy that the execution belongs to"
    )
    status: Optional[str] = Field(
        default=None, description="The status of the execution"
    )
    trigger: Optional[str] = Field(default=None, description="The trigger mode")
    start_time: Optional[datetime] = Field(default=None, description="The start time")
    end_time: Optional[datetime] = Field(default=None, description="The end time")
    status_text: Optional[str] = Field(default=None, description="The status text")
    total: Optional[int] = Field(
        default=None, description="The total count of all executions"
    )
    failed: Optional[int] = Field(
        default=None, description="The count of failed executions"
    )
    succeed: Optional[int] = Field(
        default=None, description="The count of succeed executions"
    )
    in_progress: Optional[int] = Field(
        default=None, description="The count of in_progress executions"
    )
    stopped: Optional[int] = Field(
        default=None, description="The count of stopped executions"
    )


class StartReplicationExecution(BaseModel):
    policy_id: Optional[int] = Field(
        default=None, description="The ID of policy that the execution belongs to."
    )


class ReplicationTask(BaseModel):
    """A task that is a part of a replication job."""

    id: Optional[int] = Field(default=None, description="The ID of the task")
    execution_id: Optional[int] = Field(
        default=None, description="The ID of the execution that the task belongs to"
    )
    status: Optional[str] = Field(default=None, description="The status of the task")
    job_id: Optional[str] = Field(
        default=None,
        description="The ID of the underlying job that the task related to",
    )
    operation: Optional[str] = Field(
        default=None, description="The operation of the task"
    )
    resource_type: Optional[str] = Field(
        default=None, description="The type of the resource that the task operates"
    )
    src_resource: Optional[str] = Field(
        default=None, description="The source resource that the task operates"
    )
    dst_resource: Optional[str] = Field(
        default=None, description="The destination resource that the task operates"
    )
    start_time: Optional[datetime] = Field(
        default=None, description="The start time of the task"
    )
    end_time: Optional[datetime] = Field(
        default=None, description="The end time of the task"
    )


class RobotCreated(BaseModel):
    """Response for robot account creation."""

    id: Optional[int] = Field(default=None, description="The ID of the robot")
    name: Optional[str] = Field(default=None, description="The name of the robot")
    secret: Optional[str] = Field(default=None, description="The secret of the robot")
    creation_time: Optional[datetime] = Field(
        default=None, description="The creation time of the robot."
    )
    expires_at: Optional[int] = Field(
        default=None, description="The expiration date of the robot"
    )


class RobotSec(BaseModel):
    """Response for robot account secret refresh/update."""

    secret: Optional[str] = Field(default=None, description="The secret of the robot")


class Access(BaseModel):
    resource: Optional[str] = Field(
        default=None,
        description="The resource of the access. Possible resources are listed here for system and project level https://github.com/goharbor/harbor/blob/main/src/common/rbac/const.go",
    )
    action: Optional[str] = Field(
        default=None,
        description="The action of the access. Possible actions are *, pull, push, create, read, update, delete, list, operate, scanner-pull and stop.",
    )
    effect: Optional[str] = Field(default=None, description="The effect of the access")


class RobotCreateV1(BaseModel):
    name: Optional[str] = Field(default=None, description="The name of robot account")
    description: Optional[str] = Field(
        default=None, description="The description of robot account"
    )
    expires_at: Optional[int] = Field(
        default=None,
        description="The expiration time on or after which the JWT MUST NOT be accepted for processing.",
    )
    access: Optional[List[Access]] = Field(
        default=None, description="The permission of robot account"
    )


class Storage(BaseModel):
    total: Optional[int] = Field(default=None, description="Total volume size.")
    free: Optional[int] = Field(default=None, description="Free volume size.")


class AuthproxySetting(BaseModel):
    endpoint: Optional[str] = Field(
        default=None,
        description="The fully qualified URI of login endpoint of authproxy, such as 'https://192.168.1.2:8443/login'",
    )
    tokenreivew_endpoint: Optional[str] = Field(
        default=None,
        description="The fully qualified URI of token review endpoint of authproxy, such as 'https://192.168.1.2:8443/tokenreview'",
    )
    skip_search: Optional[bool] = Field(
        default=None,
        description="The flag to determine whether Harbor can skip search the user/group when adding him as a member.",
    )
    verify_cert: Optional[bool] = Field(
        default=None,
        description="The flag to determine whether Harbor should verify the certificate when connecting to the auth proxy.",
    )
    server_certificate: Optional[str] = Field(
        default=None,
        description="The certificate to be pinned when connecting auth proxy.",
    )


class SystemInfo(BaseModel):
    storage: Optional[List[Storage]] = Field(
        default=None, description="The storage of system."
    )


class Type(Enum):
    """
    The schedule type. The valid values are 'Hourly', 'Daily', 'Weekly', 'Custom', 'Manual', 'None' and 'Schedule'.
    'Manual' means to trigger it right away, 'Schedule' means to trigger it by a specified cron schedule and
    'None' means to cancel the schedule.

    """

    hourly = "Hourly"
    daily = "Daily"
    weekly = "Weekly"
    custom = "Custom"
    manual = "Manual"
    "Trigger schedule right away."
    none = "None"
    "Cancel the schedule."
    schedule = "Schedule"
    "Trigger based on cron schedule."


class ScheduleObj(BaseModel):
    type: Optional[Type] = Field(
        default=None,
        description="The schedule type. The valid values are 'Hourly', 'Daily', 'Weekly', 'Custom', 'Manual', 'None' and 'Schedule'.\n'Manual' means to trigger it right away, 'Schedule' means to trigger it by a specified cron schedule and\n'None' means to cancel the schedule.\n",
    )
    cron: Optional[str] = Field(
        default=None, description="A cron expression, a time-based job scheduler."
    )
    next_scheduled_time: Optional[datetime] = Field(
        default=None, description="The next time to schedule to run the job."
    )


class Trigger(Enum):
    """Trigger type for a 'scan all' job."""

    manual = "Manual"
    schedule = "Schedule"
    event = "Event"


class Stats(BaseModel):
    """Progress of the 'scan all' process."""

    total: Optional[int] = Field(
        default=None,
        description="The total number of scan processes triggered by the scan all action",
        examples=[100],
    )
    completed: Optional[int] = Field(
        default=None,
        description="The number of the finished scan processes triggered by the scan all action",
        examples=[90],
    )
    metrics: Optional[Dict[str, int]] = Field(
        default=None,
        description="The metrics data for the each status",
        examples=[{"Success": 5, "Error": 2, "Running": 3}],
    )
    ongoing: Optional[bool] = Field(
        default=None, description="A flag indicating job status of scan all."
    )
    trigger: Optional[Trigger] = Field(
        default=None, description="The trigger of the scan all job."
    )


class RetentionRuleParamMetadata(BaseModel):
    """Parameters for a retention rule."""

    type: Optional[str] = None
    unit: Optional[str] = None
    required: Optional[bool] = None


class RetentionSelectorMetadata(BaseModel):
    """Metadata for a retention rule selector."""

    display_text: Optional[str] = None
    kind: Optional[str] = None
    decorations: Optional[List[str]] = None


class RetentionRuleTrigger(BaseModel):
    kind: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None
    references: Optional[Dict[str, Any]] = None


class RetentionPolicyScope(BaseModel):
    level: Optional[str] = None
    ref: Optional[int] = None


class RetentionSelector(BaseModel):
    kind: Optional[str] = None
    decoration: Optional[str] = None
    pattern: Optional[str] = None
    extras: Optional[str] = None


class RetentionExecution(BaseModel):
    id: Optional[int] = None
    policy_id: Optional[int] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    status: Optional[str] = None
    trigger: Optional[str] = None
    dry_run: Optional[bool] = None


class RetentionExecutionTask(BaseModel):
    id: Optional[int] = None
    execution_id: Optional[int] = None
    repository: Optional[str] = None
    job_id: Optional[str] = None
    status: Optional[str] = None
    status_code: Optional[int] = None
    status_revision: Optional[int] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    total: Optional[int] = None
    retained: Optional[int] = None


class QuotaUpdateReq(BaseModel):
    hard: Optional[ResourceList] = None


class QuotaRefObject(RootModel[Optional[Dict[str, Dict[str, Any]]]]):
    root: Optional[Dict[str, Any]] = None


class Quota(BaseModel):
    """Quota object."""

    id: Optional[int] = Field(default=None, description="ID of the quota")
    ref: Optional[QuotaRefObject] = None
    hard: Optional[ResourceList] = None
    used: Optional[ResourceList] = None
    creation_time: Optional[datetime] = Field(
        default=None, description="the creation time of the quota"
    )
    update_time: Optional[datetime] = Field(
        default=None, description="the update time of the quota"
    )


class ScannerRegistration(BaseModel):
    """A registered scanner adapter."""

    uuid: Optional[str] = Field(
        default=None, description="The unique identifier of this registration."
    )
    name: Optional[str] = Field(
        default=None, description="The name of this registration.", examples=["Trivy"]
    )
    description: Optional[str] = Field(
        default=None,
        description="An optional description of this registration.",
        examples=[
            "A free-to-use tool that scans container images for package vulnerabilities.\n"
        ],
    )
    url: Optional[AnyUrl] = Field(
        default=None,
        description="A base URL of the scanner adapter",
        examples=["http://harbor-scanner-trivy:8080"],
    )
    disabled: Optional[bool] = Field(
        default=False, description="Indicate whether the registration is enabled or not"
    )
    is_default: Optional[bool] = Field(
        default=False,
        description="Indicate if the registration is set as the system default one",
    )
    auth: Optional[str] = Field(
        default="",
        description='Specify what authentication approach is adopted for the HTTP communications.\nSupported types Basic", "Bearer" and api key header "X-ScannerAdapter-API-Key"\n',
        examples=["Bearer"],
    )
    access_credential: Optional[str] = Field(
        default=None,
        description="An optional value of the HTTP Authorization header sent with each request to the Scanner Adapter API.\n",
        examples=["Bearer: JWTTOKENGOESHERE"],
    )
    skip_cert_verify: Optional[bool] = Field(
        default=False,
        alias="skip_certVerify",
        description="Indicate if skip the certificate verification when sending HTTP requests",
    )
    use_internal_addr: Optional[bool] = Field(
        default=False,
        description="Indicate whether use internal registry addr for the scanner to pull content or not",
    )
    create_time: Optional[datetime] = Field(
        default=None, description="The creation time of this registration"
    )
    update_time: Optional[datetime] = Field(
        default=None, description="The update time of this registration"
    )
    adapter: Optional[str] = Field(
        default=None,
        description="Optional property to describe the name of the scanner registration",
        examples=["Trivy"],
    )
    vendor: Optional[str] = Field(
        default=None,
        description="Optional property to describe the vendor of the scanner registration",
        examples=["CentOS"],
    )
    version: Optional[str] = Field(
        default=None,
        description="Optional property to describe the version of the scanner registration",
        examples=["1.0.1"],
    )
    health: Optional[str] = Field(
        default="",
        description="Indicate the healthy of the registration",
        examples=["healthy"],
    )
    capabilities: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Indicates the capabilities of the scanner, e.g. support_vulnerability or support_sbom.",
        examples=[{"support_vulnerability": True, "support_sbom": True}],
    )


class ScannerRegistrationReq(BaseModel):
    name: str = Field(
        ..., description="The name of this registration", examples=["Trivy"]
    )
    description: Optional[str] = Field(
        default=None,
        description="An optional description of this registration.",
        examples=[
            "A free-to-use tool that scans container images for package vulnerabilities.\n"
        ],
    )
    url: AnyUrl = Field(
        ...,
        description="A base URL of the scanner adapter.",
        examples=["http://harbor-scanner-trivy:8080"],
    )
    auth: Optional[str] = Field(
        default=None,
        description='Specify what authentication approach is adopted for the HTTP communications.\nSupported types Basic", "Bearer" and api key header "X-ScannerAdapter-API-Key"\n',
        examples=["Bearer"],
    )
    access_credential: Optional[str] = Field(
        default=None,
        description="An optional value of the HTTP Authorization header sent with each request to the Scanner Adapter API.\n",
        examples=["Bearer: JWTTOKENGOESHERE"],
    )
    skip_cert_verify: Optional[bool] = Field(
        default=False,
        alias="skip_certVerify",
        description="Indicate if skip the certificate verification when sending HTTP requests",
    )
    use_internal_addr: Optional[bool] = Field(
        default=False,
        description="Indicate whether use internal registry addr for the scanner to pull content or not",
    )
    disabled: Optional[bool] = Field(
        default=False, description="Indicate whether the registration is enabled or not"
    )


class ScannerRegistrationSettings(BaseModel):
    name: str = Field(
        ..., description="The name of this registration", examples=["Trivy"]
    )
    url: AnyUrl = Field(
        ...,
        description="A base URL of the scanner adapter.",
        examples=["http://harbor-scanner-trivy:8080"],
    )
    auth: Optional[str] = Field(
        default="",
        description='Specify what authentication approach is adopted for the HTTP communications.\nSupported types Basic", "Bearer" and api key header "X-ScannerAdapter-API-Key"\n',
    )
    access_credential: Optional[str] = Field(
        default=None,
        description="An optional value of the HTTP Authorization header sent with each request to the Scanner Adapter API.\n",
        examples=["Bearer: JWTTOKENGOESHERE"],
    )


class IsDefault(BaseModel):
    is_default: Optional[bool] = Field(
        default=None,
        description="A flag indicating whether a scanner registration is default.",
    )


class ScannerCapability(BaseModel):
    type: Optional[str] = Field(
        default=None,
        description="Specify the type of scanner capability, like vulnerability or sbom\n",
        examples=["sbom"],
    )
    consumes_mime_types: Optional[List[str]] = None
    produces_mime_types: Optional[List[str]] = None


class ScannerAdapterMetadata(BaseModel):
    """Metadata for a scanner adapter."""

    scanner: Optional[Scanner] = None
    capabilities: Optional[List[ScannerCapability]] = None
    properties: Optional[Dict[str, str]] = Field(
        default=None,
        examples=[{"harbor.scanner-adapter/registry-authorization-type": "Bearer"}],
    )


class ImmutableSelector(BaseModel):
    kind: Optional[str] = None
    decoration: Optional[str] = None
    pattern: Optional[str] = None
    extras: Optional[str] = None


class LdapConf(BaseModel):
    """LDAP configuration properties."""

    ldap_url: Optional[str] = Field(
        default=None, description="The url of ldap service."
    )
    ldap_search_dn: Optional[str] = Field(
        default=None, description="The search dn of ldap service."
    )
    ldap_search_password: Optional[str] = Field(
        default=None, description="The search password of ldap service."
    )
    ldap_base_dn: Optional[str] = Field(
        default=None, description="The base dn of ldap service."
    )
    ldap_filter: Optional[str] = Field(
        default=None, description="The serach filter of ldap service."
    )
    ldap_uid: Optional[str] = Field(
        default=None, description="The serach uid from ldap service attributes."
    )
    ldap_scope: Optional[int] = Field(
        default=None, description="The serach scope of ldap service."
    )
    ldap_connection_timeout: Optional[int] = Field(
        default=None, description="The connect timeout of ldap service(second)."
    )
    ldap_verify_cert: Optional[bool] = Field(
        default=None, description="Verify Ldap server certificate."
    )


class LdapPingResult(BaseModel):
    """Result of a ping to an LDAP server."""

    success: Optional[bool] = Field(default=None, description="Test success")
    message: Optional[str] = Field(
        default=None, description="The ping operation output message."
    )


class LdapImportUsers(BaseModel):
    ldap_uid_list: Optional[List[str]] = Field(
        default=None, description="selected uid list"
    )


class LdapFailedImportUser(BaseModel):
    uid: Optional[str] = Field(default=None, description="the uid can't add to system.")
    error: Optional[str] = Field(default=None, description="fail reason.")


class LdapUser(BaseModel):
    username: Optional[str] = Field(default=None, description="ldap username.")
    realname: Optional[str] = Field(
        default=None, description='The user realname from "uid" or "cn" attribute.'
    )
    email: Optional[str] = Field(
        default=None,
        description='The user email address from "mail" or "email" attribute.',
    )


class UserGroup(BaseModel):
    id: Optional[int] = Field(default=None, description="The ID of the user group")
    group_name: Optional[str] = Field(
        default=None, description="The name of the user group"
    )
    group_type: Optional[int] = Field(
        default=None,
        description="The group type, 1 for LDAP group, 2 for HTTP group, 3 for OIDC group.",
    )
    ldap_group_dn: Optional[str] = Field(
        default=None,
        description="The DN of the LDAP group if group type is 1 (LDAP group).",
    )


class UserGroupSearchItem(BaseModel):
    id: Optional[int] = Field(default=None, description="The ID of the user group")
    group_name: Optional[str] = Field(
        default=None, description="The name of the user group"
    )
    group_type: Optional[int] = Field(
        default=None,
        description="The group type, 1 for LDAP group, 2 for HTTP group, 3 for OIDC group.",
    )


class EventType(RootModel[str]):
    root: str = Field(
        ..., description="Webhook supported event type.", examples=["PULL_ARTIFACT"]
    )


class NotifyType(RootModel[str]):
    root: str = Field(
        ..., description="Webhook supported notify type.", examples=["http"]
    )


class PayloadFormatType(RootModel[str]):
    root: str = Field(
        ..., description="The type of webhook paylod format.", examples=["CloudEvents"]
    )


class PayloadFormat(BaseModel):
    """Webhook payload format types."""

    notify_type: Optional[NotifyType] = None
    formats: Optional[List[PayloadFormatType]] = Field(
        default=None, description="The supported payload formats for this notify type."
    )


class WebhookTargetObject(BaseModel):
    """Webhook target"""

    type: Optional[str] = Field(
        default=None, description="The webhook target notify type."
    )
    address: Optional[str] = Field(
        default=None, description="The webhook target address."
    )
    auth_header: Optional[str] = Field(
        default=None, description="The webhook auth header."
    )
    skip_cert_verify: Optional[bool] = Field(
        default=None, description="Whether or not to skip cert verify."
    )
    payload_format: Optional[PayloadFormatType] = None


class WebhookPolicy(BaseModel):
    """Webhook policy definition."""

    id: Optional[int] = Field(default=None, description="The webhook policy ID.")
    name: Optional[str] = Field(default=None, description="The name of webhook policy.")
    description: Optional[str] = Field(
        default=None, description="The description of webhook policy."
    )
    project_id: Optional[int] = Field(
        default=None, description="The project ID of webhook policy."
    )
    targets: Optional[List[WebhookTargetObject]] = None
    event_types: Optional[List[str]] = None
    creator: Optional[str] = Field(
        default=None, description="The creator of the webhook policy."
    )
    creation_time: Optional[datetime] = Field(
        default=None, description="The create time of the webhook policy."
    )
    update_time: Optional[datetime] = Field(
        default=None, description="The update time of the webhook policy."
    )
    enabled: Optional[bool] = Field(
        default=None, description="Whether the webhook policy is enabled or not."
    )


class WebhookLastTrigger(BaseModel):
    """Last trigger of the webhook and the event type of the trigger."""

    policy_name: Optional[str] = Field(
        default=None, description="The webhook policy name."
    )
    event_type: Optional[str] = Field(
        default=None, description="The webhook event type."
    )
    enabled: Optional[bool] = Field(
        default=None, description="Whether or not the webhook policy enabled."
    )
    creation_time: Optional[datetime] = Field(
        default=None, description="The creation time of webhook policy."
    )
    last_trigger_time: Optional[datetime] = Field(
        default=None, description="The last trigger time of webhook policy."
    )


class WebhookJob(BaseModel):
    """A webhook job."""

    id: Optional[int] = Field(default=None, description="The webhook job ID.")
    policy_id: Optional[int] = Field(default=None, description="The webhook policy ID.")
    event_type: Optional[str] = Field(
        default=None, description="The webhook job event type."
    )
    notify_type: Optional[str] = Field(
        default=None, description="The webhook job notify type."
    )
    status: Optional[str] = Field(default=None, description="The webhook job status.")
    job_detail: Optional[str] = Field(
        default=None, description="The webhook job notify detailed data."
    )
    creation_time: Optional[datetime] = Field(
        default=None, description="The webhook job creation time."
    )
    update_time: Optional[datetime] = Field(
        default=None, description="The webhook job update time."
    )


class InternalConfigurationValue(BaseModel):
    value: Optional[Dict[str, Any]] = Field(
        default=None, description="The value of current config item"
    )
    editable: Optional[bool] = Field(
        default=None, description="The configure item can be updated or not"
    )


class Parameter(BaseModel):
    """Parameters for a 'scan all' policy."""

    daily_time: Optional[int] = Field(
        default=None,
        description='The offset in seconds of UTC 0 o\'clock, only valid when the policy type is "daily"',
    )


class ScanAllPolicy(BaseModel):
    type: Optional[str] = Field(
        default=None,
        description='The type of scan all policy, currently the valid values are "none" and "daily"',
    )
    parameter: Optional[Parameter] = Field(
        default=None,
        description="The parameters of the policy, the values are dependent on the type of the policy.",
    )


class Configurations(BaseModel):
    auth_mode: Optional[str] = Field(
        default=None,
        description='The auth mode of current system, such as "db_auth", "ldap_auth", "oidc_auth"',
    )
    primary_auth_mode: Optional[bool] = Field(
        default=None,
        description="The flag to indicate whether the current auth mode should consider as a primary one.",
    )
    ldap_base_dn: Optional[str] = Field(
        default=None, description="The Base DN for LDAP binding."
    )
    ldap_filter: Optional[str] = Field(
        default=None, description="The filter for LDAP search"
    )
    ldap_group_base_dn: Optional[str] = Field(
        default=None, description="The base DN to search LDAP group."
    )
    ldap_group_admin_dn: Optional[str] = Field(
        default=None,
        description="Specify the ldap group which have the same privilege with Harbor admin",
    )
    ldap_group_attribute_name: Optional[str] = Field(
        default=None,
        description="The attribute which is used as identity of the LDAP group, default is cn.'",
    )
    ldap_group_search_filter: Optional[str] = Field(
        default=None, description="The filter to search the ldap group"
    )
    ldap_group_search_scope: Optional[int] = Field(
        default=None,
        description="The scope to search ldap group. ''0-LDAP_SCOPE_BASE, 1-LDAP_SCOPE_ONELEVEL, 2-LDAP_SCOPE_SUBTREE''",
    )
    ldap_group_attach_parallel: Optional[bool] = Field(
        default=None,
        description="Attach LDAP user group information in parallel, the parallel worker count is 5",
    )
    ldap_scope: Optional[int] = Field(
        default=None,
        description="The scope to search ldap users,'0-LDAP_SCOPE_BASE, 1-LDAP_SCOPE_ONELEVEL, 2-LDAP_SCOPE_SUBTREE'",
    )
    ldap_search_dn: Optional[str] = Field(
        default=None, description="The DN of the user to do the search."
    )
    ldap_search_password: Optional[str] = Field(
        default=None, description="The password of the ldap search dn"
    )
    ldap_timeout: Optional[int] = Field(
        default=None, description="Timeout in seconds for connection to LDAP server"
    )
    ldap_uid: Optional[str] = Field(
        default=None,
        description='The attribute which is used as identity for the LDAP binding, such as "CN" or "SAMAccountname"',
    )
    ldap_url: Optional[str] = Field(default=None, description="The URL of LDAP server")
    ldap_verify_cert: Optional[bool] = Field(
        default=None,
        description="Whether verify your OIDC server certificate, disable it if your OIDC server is hosted via self-hosted certificate.",
    )
    ldap_group_membership_attribute: Optional[str] = Field(
        default=None, description="The user attribute to identify the group membership"
    )
    project_creation_restriction: Optional[str] = Field(
        default=None,
        description="Indicate who can create projects, it could be ''adminonly'' or ''everyone''.",
    )
    read_only: Optional[bool] = Field(
        default=None,
        description="The flag to indicate whether Harbor is in readonly mode.",
    )
    self_registration: Optional[bool] = Field(
        default=None,
        description="Whether the Harbor instance supports self-registration.  If it''s set to false, admin need to add user to the instance.",
    )
    token_expiration: Optional[int] = Field(
        default=None,
        description="The expiration time of the token for internal Registry, in minutes.",
    )
    uaa_client_id: Optional[str] = Field(
        default=None, description="The client id of UAA"
    )
    uaa_client_secret: Optional[str] = Field(
        default=None, description="The client secret of the UAA"
    )
    uaa_endpoint: Optional[str] = Field(
        default=None, description="The endpoint of the UAA"
    )
    uaa_verify_cert: Optional[bool] = Field(
        default=None, description="Verify the certificate in UAA server"
    )
    http_authproxy_endpoint: Optional[str] = Field(
        default=None, description="The endpoint of the HTTP auth"
    )
    http_authproxy_tokenreview_endpoint: Optional[str] = Field(
        default=None, description="The token review endpoint"
    )
    http_authproxy_admin_groups: Optional[str] = Field(
        default=None, description="The group which has the harbor admin privileges"
    )
    http_authproxy_admin_usernames: Optional[str] = Field(
        default=None, description="The username which has the harbor admin privileges"
    )
    http_authproxy_verify_cert: Optional[bool] = Field(
        default=None, description="Verify the HTTP auth provider's certificate"
    )
    http_authproxy_skip_search: Optional[bool] = Field(
        default=None, description="Search user before onboard"
    )
    http_authproxy_server_certificate: Optional[str] = Field(
        default=None, description="The certificate of the HTTP auth provider"
    )
    oidc_name: Optional[str] = Field(default=None, description="The OIDC provider name")
    oidc_endpoint: Optional[str] = Field(
        default=None, description="The endpoint of the OIDC provider"
    )
    oidc_client_id: Optional[str] = Field(
        default=None, description="The client ID of the OIDC provider"
    )
    oidc_client_secret: Optional[str] = Field(
        default=None, description="The OIDC provider secret"
    )
    oidc_groups_claim: Optional[str] = Field(
        default=None, description="The attribute claims the group name"
    )
    oidc_admin_group: Optional[str] = Field(
        default=None, description="The OIDC group which has the harbor admin privileges"
    )
    oidc_group_filter: Optional[str] = Field(
        default=None,
        description="The OIDC group filter which filters out the group name doesn't match the regular expression",
    )
    oidc_scope: Optional[str] = Field(
        default=None, description="The scope of the OIDC provider"
    )
    oidc_user_claim: Optional[str] = Field(
        default=None, description="The attribute claims the username"
    )
    oidc_verify_cert: Optional[bool] = Field(
        default=None, description="Verify the OIDC provider's certificate'"
    )
    oidc_auto_onboard: Optional[bool] = Field(
        default=None, description="Auto onboard the OIDC user"
    )
    oidc_extra_redirect_parms: Optional[str] = Field(
        default=None,
        description="Extra parameters to add when redirect request to OIDC provider",
    )
    robot_token_duration: Optional[int] = Field(
        default=None, description="The robot account token duration in days"
    )
    robot_name_prefix: Optional[str] = Field(
        default=None, description="The rebot account name prefix"
    )
    notification_enable: Optional[bool] = Field(
        default=None, description="Enable notification"
    )
    quota_per_project_enable: Optional[bool] = Field(
        default=None, description="Enable quota per project"
    )
    storage_per_project: Optional[int] = Field(
        default=None, description="The storage quota per project"
    )
    audit_log_forward_endpoint: Optional[str] = Field(
        default=None, description="The audit log forward endpoint"
    )
    skip_audit_log_database: Optional[bool] = Field(
        default=None, description="Skip audit log database"
    )
    session_timeout: Optional[int] = Field(
        default=None, description="The session timeout for harbor, in minutes."
    )
    scanner_skip_update_pulltime: Optional[bool] = Field(
        default=None, description="Whether or not to skip update pull time for scanner"
    )
    banner_message: Optional[str] = Field(
        default=None,
        description="The banner message for the UI.It is the stringified result of the banner message object",
    )


class StringConfigItem(BaseModel):
    value: Optional[str] = Field(
        default=None, description="The string value of current config item"
    )
    editable: Optional[bool] = Field(
        default=None, description="The configure item can be updated or not"
    )


class BoolConfigItem(BaseModel):
    value: Optional[bool] = Field(
        default=None, description="The boolean value of current config item"
    )
    editable: Optional[bool] = Field(
        default=None, description="The configure item can be updated or not"
    )


class IntegerConfigItem(BaseModel):
    value: Optional[int] = Field(
        default=None, description="The integer value of current config item"
    )
    editable: Optional[bool] = Field(
        default=None, description="The configure item can be updated or not"
    )


class ProjectMemberEntity(BaseModel):
    id: Optional[int] = Field(default=None, description="the project member id")
    project_id: Optional[int] = Field(default=None, description="the project id")
    entity_name: Optional[str] = Field(
        default=None, description="the name of the group member."
    )
    role_name: Optional[str] = Field(default=None, description="the name of the role")
    role_id: Optional[int] = Field(default=None, description="the role id")
    entity_id: Optional[int] = Field(
        default=None,
        description="the id of entity, if the member is a user, it is user_id in user table. if the member is a user group, it is the user group's ID in user_group table.",
    )
    entity_type: Optional[str] = Field(
        default=None,
        description="the entity's type, u for user entity, g for group entity.",
    )


class RoleRequest(BaseModel):
    role_id: Optional[int] = Field(
        default=None,
        description="The role id 1 for projectAdmin, 2 for developer, 3 for guest, 4 for maintainer",
    )


class UserEntity(BaseModel):
    user_id: Optional[int] = Field(default=None, description="The ID of the user.")
    username: Optional[str] = Field(default=None, description="The name of the user.")


class UserProfile(BaseModel):
    email: Optional[str] = None
    realname: Optional[str] = None
    comment: Optional[str] = None


class UserCreationReq(BaseModel):
    email: Optional[str] = Field(default=None, max_length=255)
    realname: Optional[str] = None
    comment: Optional[str] = None
    password: Optional[str] = None
    username: Optional[str] = Field(default=None, max_length=255)


class OIDCUserInfo(BaseModel):
    id: Optional[int] = Field(
        default=None, description="the ID of the OIDC info record"
    )
    user_id: Optional[int] = Field(default=None, description="the ID of the user")
    subiss: Optional[str] = Field(
        default=None, description="the concatenation of sub and issuer in the ID token"
    )
    secret: Optional[str] = Field(
        default=None,
        description="the secret of the OIDC user that can be used for CLI to push/pull artifacts",
    )
    creation_time: Optional[datetime] = Field(
        default=None, description="The creation time of the OIDC user info record."
    )
    update_time: Optional[datetime] = Field(
        default=None, description="The update time of the OIDC user info record."
    )


class UserResp(BaseModel):
    email: Optional[str] = None
    realname: Optional[str] = None
    comment: Optional[str] = None
    user_id: Optional[int] = None
    username: Optional[str] = None
    sysadmin_flag: Optional[bool] = None
    admin_role_in_auth: Optional[bool] = Field(
        default=None,
        description="indicate the admin privilege is grant by authenticator (LDAP), is always false unless it is the current login user",
    )
    oidc_user_meta: Optional[OIDCUserInfo] = None
    creation_time: Optional[datetime] = Field(
        default=None, description="The creation time of the user."
    )
    update_time: Optional[datetime] = Field(
        default=None, description="The update time of the user."
    )


class UserSysAdminFlag(BaseModel):
    sysadmin_flag: Optional[bool] = Field(
        default=None, description="true-admin, false-not admin."
    )


class UserSearch(BaseModel):
    user_id: Optional[int] = Field(default=None, description="The ID of the user.")
    username: Optional[str] = None


class PasswordReq(BaseModel):
    old_password: Optional[str] = Field(
        default=None, description="The user's existing password."
    )
    new_password: Optional[str] = Field(
        default=None, description="New password for marking as to be updated."
    )


class UserSearchRespItem(BaseModel):
    user_id: Optional[int] = Field(default=None, description="The ID of the user.")
    username: Optional[str] = None


class Permission(BaseModel):
    resource: Optional[str] = Field(default=None, description="The permission resoruce")
    action: Optional[str] = Field(default=None, description="The permission action")


class Permissions(BaseModel):
    system: Optional[List[Permission]] = Field(
        default=None, description="The system level permissions"
    )
    project: Optional[List[Permission]] = Field(
        default=None, description="The project level permissions"
    )


class OIDCCliSecretReq(BaseModel):
    secret: Optional[str] = Field(default=None, description="The new secret")


class ComponentHealthStatus(BaseModel):
    """Health status of a component."""

    name: Optional[str] = Field(default=None, description="The component name")
    status: Optional[str] = Field(
        default=None,
        description='The health status of component. Is either "healthy" or "unhealthy".',
    )
    error: Optional[str] = Field(
        default=None,
        description='(optional) The error message when the status is "unhealthy"',
    )


class Statistic(BaseModel):
    private_project_count: Optional[int] = Field(
        default=None, description="The count of the private projects"
    )
    private_repo_count: Optional[int] = Field(
        default=None, description="The count of the private repositories"
    )
    public_project_count: Optional[int] = Field(
        default=None, description="The count of the public projects"
    )
    public_repo_count: Optional[int] = Field(
        default=None, description="The count of the public repositories"
    )
    total_project_count: Optional[int] = Field(
        default=None,
        description="The count of the total projects, only be seen by the system admin",
    )
    total_repo_count: Optional[int] = Field(
        default=None,
        description="The count of the total repositories, only be seen by the system admin",
    )
    total_storage_consumption: Optional[int] = Field(
        default=None,
        description="The total storage consumption of blobs, only be seen by the system admin",
    )


class Accessory(BaseModel):
    """Accessory of an artifact."""

    id: Optional[int] = Field(default=None, description="The ID of the accessory")
    artifact_id: Optional[int] = Field(
        default=None, description="The artifact id of the accessory"
    )
    subject_artifact_id: Optional[int] = Field(
        default=None,
        description="Going to be deprecated, use repo and digest for insteand. The subject artifact id of the accessory.",
    )
    subject_artifact_digest: Optional[str] = Field(
        default=None, description="The subject artifact digest of the accessory"
    )
    subject_artifact_repo: Optional[str] = Field(
        default=None,
        description="The subject artifact repository name of the accessory",
    )
    size: Optional[int] = Field(
        default=None, description="The artifact size of the accessory"
    )
    digest: Optional[str] = Field(
        default=None, description="The artifact digest of the accessory"
    )
    type: Optional[str] = Field(
        default=None, description="The artifact size of the accessory"
    )
    icon: Optional[str] = Field(default=None, description="The icon of the accessory")
    creation_time: Optional[datetime] = Field(
        default=None, description="The creation time of the accessory"
    )


class ScanDataExportRequest(BaseModel):
    """Criteria for selecting scan data to export."""

    job_name: Optional[str] = Field(
        default=None, description="Name of the scan data export job"
    )
    projects: Optional[List[int]] = Field(
        default=None,
        description="A list of one or more projects for which to export the scan data, currently only one project is supported due to performance concerns, but define as array for extension in the future.",
    )
    labels: Optional[List[int]] = Field(
        default=None,
        description="A list of one or more labels for which to export the scan data, defaults to all if empty",
    )
    repositories: Optional[str] = Field(
        default=None,
        description="A list of repositories for which to export the scan data, defaults to all if empty",
    )
    cve_ids: Optional[str] = Field(
        default=None,
        alias="cveIds",
        description="CVE-IDs for which to export data. Multiple CVE-IDs can be specified by separating using ',' and enclosed between '{}'. Defaults to all if empty",
    )
    tags: Optional[str] = Field(
        default=None,
        description="A list of tags enclosed within '{}'. Defaults to all if empty",
    )


class ScanDataExportJob(BaseModel):
    """Metadata for a scan data export job."""

    id: Optional[int] = Field(
        default=None, description="The id of the scan data export job"
    )


class ScanDataExportExecution(BaseModel):
    """Execution of a scan data export job."""

    id: Optional[int] = Field(default=None, description="The ID of the execution")
    user_id: Optional[int] = Field(
        default=None, description="The ID if the user triggering the export job"
    )
    status: Optional[str] = Field(
        default=None, description="The status of the execution"
    )
    trigger: Optional[str] = Field(default=None, description="The trigger mode")
    start_time: Optional[datetime] = Field(default=None, description="The start time")
    end_time: Optional[datetime] = Field(default=None, description="The end time")
    status_text: Optional[str] = Field(default=None, description="The status text")
    user_name: Optional[str] = Field(
        default=None, description="The name of the user triggering the job"
    )
    file_present: Optional[bool] = Field(
        default=None,
        description="Indicates whether the export artifact is present in registry",
    )


class ScanDataExportExecutionList(BaseModel):
    """List of executed scan data export jobs."""

    items: Optional[List[ScanDataExportExecution]] = Field(
        default=None, description="The list of scan data export executions"
    )


class WorkerPool(BaseModel):
    """Worker pool for job service."""

    pid: Optional[int] = Field(default=None, description="the process id of jobservice")
    worker_pool_id: Optional[str] = Field(
        default=None, description="the id of the worker pool"
    )
    start_at: Optional[datetime] = Field(
        default=None, description="The start time of the work pool"
    )
    heartbeat_at: Optional[datetime] = Field(
        default=None, description="The heartbeat time of the work pool"
    )
    concurrency: Optional[int] = Field(
        default=None, description="The concurrency of the work pool"
    )
    host: Optional[str] = Field(default=None, description="The host of the work pool")


class Worker(BaseModel):
    """Worker in a pool."""

    id: Optional[str] = Field(default=None, description="the id of the worker")
    pool_id: Optional[str] = Field(
        default=None, description="the id of the worker pool"
    )
    job_name: Optional[str] = Field(
        default=None, description="the name of the running job in the worker"
    )
    job_id: Optional[str] = Field(
        default=None, description="the id of the running job in the worker"
    )
    start_at: Optional[datetime] = Field(
        default=None, description="The start time of the worker"
    )
    check_in: Optional[str] = Field(
        default=None, description="the checkin of the running job in the worker"
    )
    checkin_at: Optional[datetime] = Field(
        default=None, description="The checkin time of the worker"
    )


class Action(Enum):
    """Action to perform. Should be 'stop', 'pause', or 'resume'."""

    stop = "stop"
    pause = "pause"
    resume = "resume"


class ActionRequest(BaseModel):
    """Request to perform an action."""

    action: Optional[Action] = Field(
        default=None,
        description="The action of the request, should be stop, pause or resume",
    )


class JobQueue(BaseModel):
    """Information about a job queue."""

    job_type: Optional[str] = Field(
        default=None, description="The type of the job queue"
    )
    count: Optional[int] = Field(
        default=None, description="The count of jobs in the job queue"
    )
    latency: Optional[int] = Field(
        default=None, description="The latency the job queue (seconds)"
    )
    paused: Optional[bool] = Field(
        default=None, description="The paused status of the job queue"
    )


class ScheduleTask(BaseModel):
    """Information about a scheduled task."""

    id: Optional[int] = Field(default=None, description="the id of the Schedule task")
    vendor_type: Optional[str] = Field(
        default=None, description="the vendor type of the current schedule task"
    )
    vendor_id: Optional[int] = Field(
        default=None, description="the vendor id of the current task"
    )
    cron: Optional[str] = Field(
        default=None, description="the cron of the current schedule task"
    )
    update_time: Optional[datetime] = Field(
        default=None, description="the update time of the schedule task"
    )


class SchedulerStatus(BaseModel):
    """Status of the scheduler."""

    paused: Optional[bool] = Field(
        default=None, description="if the scheduler is paused"
    )


class DangerousCVE(BaseModel):
    """A CVE marked as dangerous."""

    cve_id: Optional[str] = Field(default=None, description="the cve id")
    severity: Optional[str] = Field(default=None, description="the severity of the CVE")
    cvss_score_v3: Optional[float] = Field(
        default=None, description="the cvss score v3"
    )
    desc: Optional[str] = Field(default=None, description="the description of the CVE")
    package: Optional[str] = Field(default=None, description="the package of the CVE")
    version: Optional[str] = Field(
        default=None, description="the version of the package"
    )


class DangerousArtifact(BaseModel):
    """An artifact marked as dangerous."""

    project_id: Optional[int] = Field(
        default=None, description="the project id of the artifact"
    )
    repository_name: Optional[str] = Field(
        default=None, description="the repository name of the artifact"
    )
    digest: Optional[str] = Field(
        default=None, description="the digest of the artifact"
    )
    critical_cnt: Optional[int] = Field(
        default=None, description="the count of critical vulnerabilities"
    )
    high_cnt: Optional[int] = Field(
        default=None, description="the count of high vulnerabilities"
    )
    medium_cnt: Optional[int] = Field(
        default=None, description="the count of medium vulnerabilities"
    )


class VulnerabilityItem(BaseModel):
    """Vulnerability found by a scan."""

    project_id: Optional[int] = Field(
        default=None, description="the project ID of the artifact"
    )
    repository_name: Optional[str] = Field(
        default=None, description="the repository name of the artifact"
    )
    digest: Optional[str] = Field(
        default=None, description="the digest of the artifact"
    )
    tags: Optional[List[str]] = Field(
        default=None, description="the tags of the artifact"
    )
    cve_id: Optional[str] = Field(
        default=None, description="the CVE id of the vulnerability."
    )
    severity: Optional[str] = Field(
        default=None, description="the severity of the vulnerability"
    )
    cvss_v3_score: Optional[float] = Field(
        default=None, description="the nvd cvss v3 score of the vulnerability"
    )
    package: Optional[str] = Field(
        default=None, description="the package of the vulnerability"
    )
    version: Optional[str] = Field(
        default=None, description="the version of the package"
    )
    fixed_version: Optional[str] = Field(
        default=None, description="the fixed version of the package"
    )
    desc: Optional[str] = Field(
        default=None, description="The description of the vulnerability"
    )
    links: Optional[List[str]] = Field(
        default=None, description="Links of the vulnerability"
    )


class ScanType1(Enum):
    """
    The scan type for the scan request. Two options are currently supported, vulnerability and sbom
    """

    vulnerability = "vulnerability"
    sbom = "sbom"


class ScanType(BaseModel):
    scan_type: Optional[ScanType1] = Field(
        default=None,
        description="The scan type for the scan request. Two options are currently supported, vulnerability and sbom",
    )


class Errors(BaseModel):
    """Errors that occurred while handling a request."""

    errors: Optional[List[Error]] = None


class AdditionLinks(RootModel[Optional[Dict[str, AdditionLink]]]):
    root: Optional[Dict[str, AdditionLink]] = None


class Reference(BaseModel):
    parent_id: Optional[int] = Field(
        default=None, description="The parent ID of the reference"
    )
    child_id: Optional[int] = Field(
        default=None, description="The child ID of the reference"
    )
    child_digest: Optional[str] = Field(
        default=None, description="The digest of the child artifact"
    )
    platform: Optional[Platform] = None
    annotations: Optional[Annotations] = None
    urls: Optional[List[str]] = Field(default=None, description="The download URLs")


class NativeReportSummary(BaseModel):
    """Summary of a native scan report."""

    report_id: Optional[str] = Field(
        default=None,
        description="id of the native scan report",
        examples=["5f62c830-f996-11e9-957f-0242c0a89008"],
    )
    scan_status: Optional[str] = Field(
        default=None,
        description="The status of the report generating process",
        examples=["Success"],
    )
    severity: Optional[str] = Field(
        default=None, description="The overall severity", examples=["High"]
    )
    duration: Optional[int] = Field(
        default=None,
        description="The seconds spent for generating the report",
        examples=[300],
    )
    summary: Optional[VulnerabilitySummary] = None
    start_time: Optional[datetime] = Field(
        default=None,
        description="The start time of the scan process that generating report",
        examples=["2006-01-02T14:04:05Z"],
    )
    end_time: Optional[datetime] = Field(
        default=None,
        description="The end time of the scan process that generating report",
        examples=["2006-01-02T15:04:05Z"],
    )
    complete_percent: Optional[int] = Field(
        default=None,
        description="The complete percent of the scanning which value is between 0 and 100",
        examples=[100],
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


class ProjectSummaryQuota(BaseModel):
    hard: Optional[ResourceList] = None
    used: Optional[ResourceList] = None


class CVEAllowlist(BaseModel):
    """CVE allowlist for a system or project."""

    id: Optional[int] = Field(default=None, description="ID of the allowlist")
    project_id: Optional[int] = Field(
        default=None,
        description="ID of the project which the allowlist belongs to.  For system level allowlist this attribute is zero.",
    )
    expires_at: Optional[int] = Field(
        default=None,
        description="the time for expiration of the allowlist, in the form of seconds since epoch.  This is an optional attribute, if it's not set the CVE allowlist does not expire.",
    )
    items: Optional[List[CVEAllowlistItem]] = None
    creation_time: Optional[datetime] = Field(
        default=None, description="The creation time of the allowlist."
    )
    update_time: Optional[datetime] = Field(
        default=None, description="The update time of the allowlist."
    )


class ReplicationTrigger(BaseModel):
    type: Optional[str] = Field(
        default=None,
        description="The replication policy trigger type. The valid values are manual, event_based and scheduled.",
    )
    trigger_settings: Optional[ReplicationTriggerSettings] = None


class RegistryInfo(BaseModel):
    """Registry information, including base info and capabilities."""

    type: Optional[str] = Field(default=None, description="The registry type")
    description: Optional[str] = Field(default=None, description="The description")
    supported_resource_filters: Optional[List[FilterStyle]] = Field(
        default=None, description="The filters that the registry supports"
    )
    supported_triggers: Optional[List[str]] = Field(
        default=None, description="The triggers that the registry supports"
    )
    supported_copy_by_chunk: Optional[bool] = Field(
        default=None, description="The registry whether support copy by chunk."
    )


class RegistryProviderEndpointPattern(BaseModel):
    """Pattern for a registry provider endpoint."""

    endpoint_type: Optional[str] = Field(default=None, description="The endpoint type")
    endpoints: Optional[List[RegistryEndpoint]] = Field(
        default=None, description="The endpoint list"
    )


class RobotPermission(BaseModel):
    kind: Optional[str] = Field(default=None, description="The kind of the permission")
    namespace: Optional[str] = Field(
        default=None, description="The namespace of the permission"
    )
    access: Optional[List[Access]] = None


class GeneralInfo(BaseModel):
    banner_message: Optional[str] = Field(
        default=None,
        description="The banner message for the UI. It is the stringified result of the banner message object.",
        examples=[
            '{"closable":true,"message":"your banner message content","type":"warning","fromDate":"06/19/2023","toDate":"06/21/2023"}'
        ],
    )
    current_time: Optional[datetime] = Field(
        default=None, description="The current time of the server."
    )
    registry_url: Optional[str] = Field(
        default=None,
        description="The url of registry against which the docker command should be issued.",
    )
    external_url: Optional[str] = Field(
        default=None, description="The external URL of Harbor, with protocol."
    )
    auth_mode: Optional[str] = Field(
        default=None, description="The auth mode of current Harbor instance."
    )
    primary_auth_mode: Optional[bool] = Field(
        default=None,
        description="The flag to indicate whether the current auth mode should consider as a primary one.",
    )
    project_creation_restriction: Optional[str] = Field(
        default=None,
        description="Indicate who can create projects, it could be 'adminonly' or 'everyone'.",
    )
    self_registration: Optional[bool] = Field(
        default=None,
        description="Indicate whether the Harbor instance enable user to register himself.",
    )
    has_ca_root: Optional[bool] = Field(
        default=None,
        description="Indicate whether there is a ca root cert file ready for download in the file system.",
    )
    harbor_version: Optional[str] = Field(
        default=None, description="The build version of Harbor."
    )
    registry_storage_provider_name: Optional[str] = Field(
        default=None, description="The storage provider's name of Harbor registry"
    )
    read_only: Optional[bool] = Field(
        default=None,
        description="The flag to indicate whether Harbor is in readonly mode.",
    )
    notification_enable: Optional[bool] = Field(
        default=None,
        description="The flag to indicate whether notification mechanism is enabled on Harbor instance.",
    )
    authproxy_settings: Optional[AuthproxySetting] = None
    oidc_provider_name: Optional[str] = Field(
        default=None,
        description="The OIDC provider name, empty if current auth is not OIDC_auth or OIDC provider is not configured.",
    )
    with_chartmuseum: Optional[bool] = Field(
        default=None,
        description="DEPRECATED: Harbor instance is deployed with nested chartmuseum.",
    )


class GCHistory(BaseModel):
    id: Optional[int] = Field(default=None, description="the id of gc job.")
    job_name: Optional[str] = Field(default=None, description="the job name of gc job.")
    job_kind: Optional[str] = Field(default=None, description="the job kind of gc job.")
    job_parameters: Optional[str] = Field(
        default=None, description="the job parameters of gc job."
    )
    schedule: Optional[ScheduleObj] = None
    job_status: Optional[str] = Field(default=None, description="the status of gc job.")
    deleted: Optional[bool] = Field(default=None, description="if gc job was deleted.")
    creation_time: Optional[datetime] = Field(
        default=None, description="the creation time of gc job."
    )
    update_time: Optional[datetime] = Field(
        default=None, description="the update time of gc job."
    )


class ExecHistory(BaseModel):
    id: Optional[int] = Field(default=None, description="the id of purge job.")
    job_name: Optional[str] = Field(
        default=None, description="the job name of purge job."
    )
    job_kind: Optional[str] = Field(
        default=None, description="the job kind of purge job."
    )
    job_parameters: Optional[str] = Field(
        default=None, description="the job parameters of purge job."
    )
    schedule: Optional[ScheduleObj] = None
    job_status: Optional[str] = Field(
        default=None, description="the status of purge job."
    )
    deleted: Optional[bool] = Field(
        default=None, description="if purge job was deleted."
    )
    creation_time: Optional[datetime] = Field(
        default=None, description="the creation time of purge job."
    )
    update_time: Optional[datetime] = Field(
        default=None, description="the update time of purge job."
    )


class Schedule(BaseModel):
    id: Optional[int] = Field(default=None, description="The id of the schedule.")
    status: Optional[str] = Field(
        default=None, description="The status of the schedule."
    )
    creation_time: Optional[datetime] = Field(
        default=None, description="the creation time of the schedule."
    )
    update_time: Optional[datetime] = Field(
        default=None, description="the update time of the schedule."
    )
    schedule: Optional[ScheduleObj] = None
    parameters: Optional[Dict[str, Any]] = Field(
        default=None, description="The parameters of schedule job"
    )


class RetentionRuleMetadata(BaseModel):
    """Metadata for a tag retention rule."""

    rule_template: Optional[str] = Field(default=None, description="rule id")
    display_text: Optional[str] = Field(default=None, description="rule display text")
    action: Optional[str] = Field(default=None, description="rule action")
    params: Optional[List[RetentionRuleParamMetadata]] = Field(
        default=None, description="rule params"
    )


class RetentionRule(BaseModel):
    id: Optional[int] = None
    priority: Optional[int] = None
    disabled: Optional[bool] = None
    action: Optional[str] = None
    template: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    tag_selectors: Optional[List[RetentionSelector]] = None
    scope_selectors: Optional[Dict[str, List[RetentionSelector]]] = None


class ImmutableRule(BaseModel):
    id: Optional[int] = None
    priority: Optional[int] = None
    disabled: Optional[bool] = None
    action: Optional[str] = None
    template: Optional[str] = None
    params: Optional[Dict[str, Any]] = None
    tag_selectors: Optional[List[ImmutableSelector]] = None
    scope_selectors: Optional[Dict[str, List[ImmutableSelector]]] = None


class SupportedWebhookEventTypes(BaseModel):
    """Supported event and notification types for webhooks."""

    event_type: Optional[List[EventType]] = None
    notify_type: Optional[List[NotifyType]] = None
    payload_formats: Optional[List[PayloadFormat]] = None


class InternalConfigurationsResponse(
    RootModel[Optional[Dict[str, InternalConfigurationValue]]]
):
    root: Optional[Dict[str, InternalConfigurationValue]] = None


class ConfigurationsResponse(BaseModel):
    auth_mode: Optional[StringConfigItem] = None
    primary_auth_mode: Optional[BoolConfigItem] = None
    ldap_base_dn: Optional[StringConfigItem] = None
    ldap_filter: Optional[StringConfigItem] = None
    ldap_group_base_dn: Optional[StringConfigItem] = None
    ldap_group_admin_dn: Optional[StringConfigItem] = None
    ldap_group_attribute_name: Optional[StringConfigItem] = None
    ldap_group_search_filter: Optional[StringConfigItem] = None
    ldap_group_search_scope: Optional[IntegerConfigItem] = None
    ldap_group_attach_parallel: Optional[BoolConfigItem] = None
    ldap_scope: Optional[IntegerConfigItem] = None
    ldap_search_dn: Optional[StringConfigItem] = None
    ldap_timeout: Optional[IntegerConfigItem] = None
    ldap_uid: Optional[StringConfigItem] = None
    ldap_url: Optional[StringConfigItem] = None
    ldap_verify_cert: Optional[BoolConfigItem] = None
    ldap_group_membership_attribute: Optional[StringConfigItem] = None
    project_creation_restriction: Optional[StringConfigItem] = None
    read_only: Optional[BoolConfigItem] = None
    self_registration: Optional[BoolConfigItem] = None
    token_expiration: Optional[IntegerConfigItem] = None
    uaa_client_id: Optional[StringConfigItem] = None
    uaa_client_secret: Optional[StringConfigItem] = None
    uaa_endpoint: Optional[StringConfigItem] = None
    uaa_verify_cert: Optional[BoolConfigItem] = None
    http_authproxy_endpoint: Optional[StringConfigItem] = None
    http_authproxy_tokenreview_endpoint: Optional[StringConfigItem] = None
    http_authproxy_admin_groups: Optional[StringConfigItem] = None
    http_authproxy_admin_usernames: Optional[StringConfigItem] = None
    http_authproxy_verify_cert: Optional[BoolConfigItem] = None
    http_authproxy_skip_search: Optional[BoolConfigItem] = None
    http_authproxy_server_certificate: Optional[StringConfigItem] = None
    oidc_name: Optional[StringConfigItem] = None
    oidc_endpoint: Optional[StringConfigItem] = None
    oidc_client_id: Optional[StringConfigItem] = None
    oidc_groups_claim: Optional[StringConfigItem] = None
    oidc_admin_group: Optional[StringConfigItem] = None
    oidc_group_filter: Optional[StringConfigItem] = None
    oidc_scope: Optional[StringConfigItem] = None
    oidc_user_claim: Optional[StringConfigItem] = None
    oidc_verify_cert: Optional[BoolConfigItem] = None
    oidc_auto_onboard: Optional[BoolConfigItem] = None
    oidc_extra_redirect_parms: Optional[StringConfigItem] = None
    robot_token_duration: Optional[IntegerConfigItem] = None
    robot_name_prefix: Optional[StringConfigItem] = None
    notification_enable: Optional[BoolConfigItem] = None
    quota_per_project_enable: Optional[BoolConfigItem] = None
    storage_per_project: Optional[IntegerConfigItem] = None
    audit_log_forward_endpoint: Optional[StringConfigItem] = None
    skip_audit_log_database: Optional[BoolConfigItem] = None
    scanner_skip_update_pulltime: Optional[BoolConfigItem] = None
    scan_all_policy: Optional[ScanAllPolicy] = None
    session_timeout: Optional[IntegerConfigItem] = None
    banner_message: Optional[StringConfigItem] = None


class ProjectMember(BaseModel):
    role_id: Optional[int] = Field(
        default=None,
        description="The role id 1 for projectAdmin, 2 for developer, 3 for guest, 4 for maintainer",
    )
    member_user: Optional[UserEntity] = None
    member_group: Optional[UserGroup] = None


class OverallHealthStatus(BaseModel):
    """Overall health status of the system."""

    status: Optional[str] = Field(
        default=None,
        description='The overall health status. It is "healthy" only when all the components\' status are "healthy"',
    )
    components: Optional[List[ComponentHealthStatus]] = None


class SecuritySummary(BaseModel):
    """Artifact security summary."""

    critical_cnt: Optional[int] = Field(
        default=None, description="the count of critical vulnerabilities"
    )
    high_cnt: Optional[int] = Field(
        default=None, description="the count of high vulnerabilities"
    )
    medium_cnt: Optional[int] = Field(
        default=None, description="the count of medium vulnerabilities"
    )
    low_cnt: Optional[int] = Field(
        default=None, description="the count of low vulnerabilities"
    )
    none_cnt: Optional[int] = Field(
        default=None, description="the count of none vulnerabilities"
    )
    unknown_cnt: Optional[int] = Field(
        default=None, description="the count of unknown vulnerabilities"
    )
    total_vuls: Optional[int] = Field(
        default=None, description="the count of total vulnerabilities"
    )
    scanned_cnt: Optional[int] = Field(
        default=None, description="the count of scanned artifacts"
    )
    total_artifact: Optional[int] = Field(
        default=None, description="the total count of artifacts"
    )
    fixable_cnt: Optional[int] = Field(
        default=None, description="the count of fixable vulnerabilities"
    )
    dangerous_cves: Optional[List[DangerousCVE]] = Field(
        default=None, description="the list of dangerous CVEs"
    )
    dangerous_artifacts: Optional[List[DangerousArtifact]] = Field(
        default=None, description="the list of dangerous artifacts"
    )


class ScanOverview(RootModel[Optional[Dict[str, NativeReportSummary]]]):
    """Overview of scan results."""

    root: Optional[Dict[str, NativeReportSummary]] = None


class ProjectReq(BaseModel):
    project_name: Optional[str] = Field(
        default=None, description="The name of the project.", max_length=255
    )
    public: Optional[bool] = Field(
        default=None,
        description="deprecated, reserved for project creation in replication",
    )
    metadata: Optional[ProjectMetadata] = None
    cve_allowlist: Optional[CVEAllowlist] = None
    storage_limit: Optional[int] = Field(
        default=None, description="The storage quota of the project."
    )
    registry_id: Optional[int] = Field(
        default=None,
        description="The ID of referenced registry when creating the proxy cache project",
    )


class Project(BaseModel):
    project_id: Optional[int] = Field(default=None, description="Project ID")
    owner_id: Optional[int] = Field(
        default=None,
        description="The owner ID of the project always means the creator of the project.",
    )
    name: Optional[str] = Field(default=None, description="The name of the project.")
    registry_id: Optional[int] = Field(
        default=None,
        description="The ID of referenced registry when the project is a proxy cache project.",
    )
    creation_time: Optional[datetime] = Field(
        default=None, description="The creation time of the project."
    )
    update_time: Optional[datetime] = Field(
        default=None, description="The update time of the project."
    )
    deleted: Optional[bool] = Field(
        default=None, description="A deletion mark of the project."
    )
    owner_name: Optional[str] = Field(
        default=None, description="The owner name of the project."
    )
    togglable: Optional[bool] = Field(
        default=None,
        description="Correspond to the UI about whether the project's publicity is  updatable (for UI)",
    )
    current_user_role_id: Optional[int] = Field(
        default=None,
        description="The role ID with highest permission of the current user who triggered the API (for UI).  This attribute is deprecated and will be removed in future versions.",
    )
    current_user_role_ids: Optional[List[int]] = Field(
        default=None,
        description="The list of role ID of the current user who triggered the API (for UI)",
    )
    repo_count: Optional[int] = Field(
        default=None, description="The number of the repositories under this project."
    )
    metadata: Optional[ProjectMetadata] = None
    cve_allowlist: Optional[CVEAllowlist] = None


class ProjectSummary(BaseModel):
    repo_count: Optional[int] = Field(
        default=None, description="The number of the repositories under this project."
    )
    project_admin_count: Optional[int] = Field(
        default=None, description="The total number of project admin members."
    )
    maintainer_count: Optional[int] = Field(
        default=None, description="The total number of maintainer members."
    )
    developer_count: Optional[int] = Field(
        default=None, description="The total number of developer members."
    )
    guest_count: Optional[int] = Field(
        default=None, description="The total number of guest members."
    )
    limited_guest_count: Optional[int] = Field(
        default=None, description="The total number of limited guest members."
    )
    quota: Optional[ProjectSummaryQuota] = None
    registry: Optional[Registry] = None


class ReplicationPolicy(BaseModel):
    id: Optional[int] = Field(default=None, description="The policy ID.")
    name: Optional[str] = Field(default=None, description="The policy name.")
    description: Optional[str] = Field(
        default=None, description="The description of the policy."
    )
    src_registry: Optional[Registry] = None
    dest_registry: Optional[Registry] = None
    dest_namespace: Optional[str] = Field(
        default=None, description="The destination namespace."
    )
    dest_namespace_replace_count: Optional[int] = Field(
        default=None,
        description="Specify how many path components will be replaced by the provided destination namespace.\nThe default value is -1 in which case the legacy mode will be applied.",
    )
    trigger: Optional[ReplicationTrigger] = None
    filters: Optional[List[ReplicationFilter]] = Field(
        default=None, description="The replication policy filter array."
    )
    replicate_deletion: Optional[bool] = Field(
        default=None, description="Whether to replicate the deletion operation."
    )
    deletion: Optional[bool] = Field(
        default=None,
        description='Deprecated, use "replicate_deletion" instead. Whether to replicate the deletion operation.',
    )
    override: Optional[bool] = Field(
        default=None,
        description="Whether to override the resources on the destination registry.",
    )
    enabled: Optional[bool] = Field(
        default=None, description="Whether the policy is enabled or not."
    )
    creation_time: Optional[datetime] = Field(
        default=None, description="The create time of the policy."
    )
    update_time: Optional[datetime] = Field(
        default=None, description="The update time of the policy."
    )
    speed: Optional[int] = Field(default=None, description="speed limit for each task")
    copy_by_chunk: Optional[bool] = Field(
        default=None, description="Whether to enable copy by chunk."
    )


class RegistryProviderInfo(BaseModel):
    """Registry provider information, including base info and capabilities."""

    endpoint_pattern: Optional[RegistryProviderEndpointPattern] = None
    credential_pattern: Optional[RegistryProviderCredentialPattern] = None


class Robot(BaseModel):
    id: Optional[int] = Field(default=None, description="The ID of the robot")
    name: Optional[str] = Field(default=None, description="The name of the robot")
    description: Optional[str] = Field(
        default=None, description="The description of the robot"
    )
    secret: Optional[str] = Field(default=None, description="The secret of the robot")
    level: Optional[str] = Field(
        default=None, description="The level of the robot, project or system"
    )
    duration: Optional[int] = Field(
        default=None,
        description="The duration of the robot in days, duration must be either -1(Never) or a positive integer",
    )
    editable: Optional[bool] = Field(
        default=None, description="The editable status of the robot"
    )
    disable: Optional[bool] = Field(
        default=None, description="The disable status of the robot"
    )
    expires_at: Optional[int] = Field(
        default=None, description="The expiration date of the robot"
    )
    permissions: Optional[List[RobotPermission]] = None
    creator_type: Optional[str] = Field(
        default=None,
        description="The type of the robot creator, like local(harbor_user) or robot.",
    )
    creator_ref: Optional[int] = Field(
        default=None,
        description="The reference of the robot creator, like the id of harbor user.",
    )
    creation_time: Optional[datetime] = Field(
        default=None, description="The creation time of the robot."
    )
    update_time: Optional[datetime] = Field(
        default=None, description="The update time of the robot."
    )


class RobotCreate(BaseModel):
    """Request for robot account creation."""

    name: Optional[str] = Field(default=None, description="The name of the robot")
    description: Optional[str] = Field(
        default=None, description="The description of the robot"
    )
    secret: Optional[str] = Field(default=None, description="The secret of the robot")
    level: Optional[str] = Field(
        default=None, description="The level of the robot, project or system"
    )
    disable: Optional[bool] = Field(
        default=None, description="The disable status of the robot"
    )
    duration: Optional[int] = Field(
        default=None,
        description="The duration of the robot in days, duration must be either -1(Never) or a positive integer",
    )
    permissions: Optional[List[RobotPermission]] = None


class RetentionMetadata(BaseModel):
    """Metadata for a tag retention rule."""

    templates: Optional[List[RetentionRuleMetadata]] = Field(
        default=None, description="templates"
    )
    scope_selectors: Optional[List[RetentionSelectorMetadata]] = Field(
        default=None, description="supported scope selectors"
    )
    tag_selectors: Optional[List[RetentionSelectorMetadata]] = Field(
        default=None, description="supported tag selectors"
    )


class RetentionPolicy(BaseModel):
    """Retention policy."""

    id: Optional[int] = None
    algorithm: Optional[str] = None
    rules: Optional[List[RetentionRule]] = None
    trigger: Optional[RetentionRuleTrigger] = None
    scope: Optional[RetentionPolicyScope] = None


class Search(BaseModel):
    project: Optional[List[Project]] = Field(
        default=None,
        description="Search results of the projects that matched the filter keywords.",
    )
    repository: Optional[List[SearchRepository]] = Field(
        default=None,
        description="Search results of the repositories that matched the filter keywords.",
    )


class Artifact(BaseModel):
    id: Optional[int] = Field(default=None, description="The ID of the artifact")
    type: Optional[str] = Field(
        default=None, description="The type of the artifact, e.g. image, chart, etc"
    )
    media_type: Optional[str] = Field(
        default=None, description="The media type of the artifact"
    )
    manifest_media_type: Optional[str] = Field(
        default=None, description="The manifest media type of the artifact"
    )
    artifact_type: Optional[str] = Field(
        default=None, description="The artifact_type in the manifest of the artifact"
    )
    project_id: Optional[int] = Field(
        default=None, description="The ID of the project that the artifact belongs to"
    )
    repository_id: Optional[int] = Field(
        default=None,
        description="The ID of the repository that the artifact belongs to",
    )
    repository_name: Optional[str] = Field(
        default=None,
        description="The name of the repository that the artifact belongs to",
    )
    digest: Optional[str] = Field(
        default=None, description="The digest of the artifact"
    )
    size: Optional[int] = Field(default=None, description="The size of the artifact")
    icon: Optional[str] = Field(default=None, description="The digest of the icon")
    push_time: Optional[datetime] = Field(
        default=None, description="The push time of the artifact"
    )
    pull_time: Optional[datetime] = Field(
        default=None, description="The latest pull time of the artifact"
    )
    extra_attrs: Optional[ExtraAttrs] = None
    annotations: Optional[Annotations] = None
    references: Optional[List[Reference]] = None
    tags: Optional[List[Tag]] = None
    addition_links: Optional[AdditionLinks] = None
    labels: Optional[List[Label]] = None
    scan_overview: Optional[ScanOverview] = None
    sbom_overview: Optional[SBOMOverview] = None
    accessories: Optional[List[Accessory]] = None

    @property
    def scan(self) -> Optional[NativeReportSummary]:
        """
        Returns the first scan overview found for the Artifact,
        or None if there are none.

        Artifacts are typically scanned in a single format, represented
        by its MIME type. Thus, most Artifacts will have only one
        scan overview. This property provides a quick access to it.
        """
        if self.scan_overview and self.scan_overview.root:
            return self.scan_overview.root[next(iter(self.scan_overview))]
        return None


class RegistryProviders(RootModel[Dict[str, RegistryProviderInfo]]):
    root: Dict[str, RegistryProviderInfo] = Field(
        default={},
        description="The registry providers. Each key is the name of the registry provider.",
    )
