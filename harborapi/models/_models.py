"""DEPRECATED: This module will be removed in a future version.
Module kept only for backwards compatibility with old code generation scheme."""
from __future__ import annotations

from .models import Access
from .models import Accessory
from .models import Action
from .models import ActionRequest
from .models import AdditionLink
from .models import AdditionLinks
from .models import Annotations
from .models import Artifact
from .models import AuditLog
from .models import AuthproxySetting
from .models import BoolConfigItem
from .models import ComponentHealthStatus
from .models import Configurations
from .models import ConfigurationsResponse
from .models import CVEAllowlist
from .models import CVEAllowlistItem
from .models import Error
from .models import Errors
from .models import EventType
from .models import ExecHistory
from .models import Execution
from .models import ExtraAttrs
from .models import FilterStyle
from .models import GCHistory
from .models import GeneralInfo
from .models import Icon
from .models import ImmutableRule
from .models import ImmutableSelector
from .models import Instance
from .models import IntegerConfigItem
from .models import InternalConfigurationsResponse
from .models import InternalConfigurationValue
from .models import IsDefault
from .models import JobQueue
from .models import Label
from .models import LdapConf
from .models import LdapFailedImportUser
from .models import LdapImportUsers
from .models import LdapPingResult
from .models import LdapUser
from .models import Metadata
from .models import Metrics
from .models import NativeReportSummary
from .models import NotifyType
from .models import OIDCCliSecretReq
from .models import OIDCUserInfo
from .models import OverallHealthStatus
from .models import Parameter
from .models import PasswordReq
from .models import Permission
from .models import Platform
from .models import PreheatPolicy
from .models import Project
from .models import ProjectDeletable
from .models import ProjectMember
from .models import ProjectMemberEntity
from .models import ProjectMetadata
from .models import ProjectReq
from .models import ProjectScanner
from .models import ProjectSummary
from .models import ProjectSummaryQuota
from .models import ProviderUnderProject
from .models import Quota
from .models import QuotaRefObject
from .models import QuotaUpdateReq
from .models import Reference
from .models import Registry
from .models import RegistryCredential
from .models import RegistryEndpoint
from .models import RegistryInfo
from .models import RegistryPing
from .models import RegistryProviderCredentialPattern
from .models import RegistryProviderEndpointPattern
from .models import RegistryProviderInfo
from .models import RegistryUpdate
from .models import ReplicationExecution
from .models import ReplicationFilter
from .models import ReplicationPolicy
from .models import ReplicationTask
from .models import ReplicationTrigger
from .models import ReplicationTriggerSettings
from .models import Repository
from .models import ResourceList
from .models import RetentionExecution
from .models import RetentionExecutionTask
from .models import RetentionMetadata
from .models import RetentionPolicy
from .models import RetentionPolicyScope
from .models import RetentionRule
from .models import RetentionRuleMetadata
from .models import RetentionRuleParamMetadata
from .models import RetentionRuleTrigger
from .models import RetentionSelector
from .models import RetentionSelectorMetadata
from .models import Robot
from .models import RobotCreate
from .models import RobotCreated
from .models import RobotCreateV1
from .models import RobotPermission
from .models import RobotSec
from .models import RoleRequest
from .models import ScanAllPolicy
from .models import ScanDataExportExecution
from .models import ScanDataExportExecutionList
from .models import ScanDataExportJob
from .models import ScanDataExportRequest
from .models import Scanner
from .models import ScannerAdapterMetadata
from .models import ScannerCapability
from .models import ScannerRegistration
from .models import ScannerRegistrationReq
from .models import ScannerRegistrationSettings
from .models import ScanOverview
from .models import Schedule
from .models import ScheduleObj
from .models import SchedulerStatus
from .models import ScheduleTask
from .models import Search
from .models import SearchRepository
from .models import StartReplicationExecution
from .models import Statistic
from .models import Stats
from .models import Storage
from .models import StringConfigItem
from .models import SupportedWebhookEventTypes
from .models import SystemInfo
from .models import Tag
from .models import Task
from .models import Trigger
from .models import UserCreationReq
from .models import UserEntity
from .models import UserGroup
from .models import UserGroupSearchItem
from .models import UserProfile
from .models import UserResp
from .models import UserSearch
from .models import UserSearchRespItem
from .models import UserSysAdminFlag
from .models import VulnerabilitySummary
from .models import WebhookJob
from .models import WebhookLastTrigger
from .models import WebhookPolicy
from .models import WebhookTargetObject
from .models import Worker
from .models import WorkerPool

# Explicit re-export of all models

__all__ = [
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
