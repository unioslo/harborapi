# Changelog

All notable changes to this project will be documented in this file.

The format is based on [*Keep a Changelog 1.0.0*](https://keepachangelog.com/en/1.0.0/) and this project adheres to [*Semantic Versioning 2.0.0*](https://semver.org/).

The **first number** is the major version (API changes, breaking changes)
The **second number** is the minor version (new features)
The **third number** is the patch version (bug fixes)

<!-- changelog follows -->

<!-- ## Unreleased -->

## [0.15.3](https://github.com/pederhan/harborapi/tree/harborapi-v0.15.3) - 2023-04-20

### Fixed

- Models with fields that wrongly required dicts of dicts now accept dicts of any for the affected fields:
  - `harborapi.models.RetentionRule.params`
  - `harborapi.models.ImutableRule.params`
Until the official API spec is fixed, this is the best we can do.

## [0.15.2](https://github.com/pederhan/harborapi/tree/harborapi-v0.15.2) - 2023-04-18

### Removed

- `harbor` being added as an executable script installed by the project. This was a mistake, as the `harbor` executable script is intended to be exposed by [harbor-cli](https://github.com/pederhan/harbor-cli).


## [0.15.1](https://github.com/pederhan/harborapi/tree/harborapi-v0.15.1) - 2023-04-17

### Added

- `HarborAsyncClient.authenticate()`. This method can be used to re-authenticate the client with new credentials without having to create a new client instance.

### Changed

- `HarborAsyncClient.get_artifact_vulnerabilities()` now always returns a `harborapi.models.HarborVulnerabilityReport` object. If the artifact has no vulnerabilities or the report cannot be processed, an exception is raised.

### Removed
- `config` argument from `HarborAsyncClient.__init__()`. The `config` argument was never implemented.



## [0.15.0](https://github.com/pederhan/harborapi/tree/harborapi-v0.15.0) - 2023-04-13

### Added

- Retention methods:
  - `HarborAsyncClient.get_project_retention_id()`
  - `HarborAsyncClient.get_retention_policy()`
  - `HarborAsyncClient.create_retention_policy()`
  - `HarborAsyncClient.update_retention_policy()`
  - `HarborAsyncClient.delete_retention_policy()`
  - `HarborAsyncClient.get_retention_tasks()`
  - `HarborAsyncClient.get_retention_metadata()`
  - `HarborAsyncClient.get_retention_execution_task_log()`
  - `HarborAsyncClient.get_retention_executions()`
  - `HarborAsyncClient.start_retention_execution()`
  - `HarborAsyncClient.stop_retention_execution()`

## [0.14.1](https://github.com/pederhan/harborapi/tree/harborapi-v0.14.1) - 2023-04-11

### Added

- `verify` kwarg for `HarborAsyncClient` and `HarborClient` which is passed to the underlying `httpx.AsyncClient`. This is useful for self-signed certificates, or if you want to control the SSL verification yourself. See [httpx documentation](https://www.python-httpx.org/advanced/#ssl-certificates) for more information.

### Fixed

- Potential circular import error in `harborapi.ext`, where `HarborAsyncClient` is imported as a type annotation.

## [0.14.0](https://github.com/pederhan/harborapi/tree/harborapi-v0.14.0) - 2023-04-05

### Changed

- `limit` kwarg now treats `0` as no limit. Previously, `0` meant no results would be returned.
- **BREAKING:** `harborapi.ext.artifact.ArtifactInfo.tags` now returns a list of tags instead of a comma-separated string of tags. This gives more flexibility to work with the various tags, and is more consistent with the rest of the library. If you need the comma-separated string, you can use `", ".join(artifact_info.tags)`.

## [0.13.1](https://github.com/pederhan/harborapi/tree/harborapi-v0.13.1) - 2023-04-03

### Fixed

- Pagination URLs containing spaces are now properly handled. This could occur if passing a a query parameter with a list of items, such as `?q=operation={push pull}` or `?q=operation=(push pull)`.

## [0.13.0](https://github.com/pederhan/harborapi/tree/harborapi-v0.13.0) - 2023-03-31

### Changed

- `HarborAsyncClient.update_project_member_role()` now accepts integer arguments for its `role_id` parameter, since `RoleRequest` only has a single field (`role_id`).


### Fixed

- Potential bug with `models.VulnerabilitySummary` if `summary` is `None`.
- JSON parsing exception in `HarborAsyncClient.get_audit_log_rotation_schedule()` that could occur if no schedule exists. The API returns an emtpy `200 OK` response, which is now handled correctly (empty `ExecHistory` object).
- Missing docstring for `HarborAsycClient.get_project_members`.

## [0.12.0](https://github.com/pederhan/harborapi/tree/harborapi-v0.12.0) - 2023-03-14

### Changed

- **BREAKING:** `HarborAsyncClient.export_scan_data()` now takes the arguments in the order (`criteria`, `scan_type`). Furthermore, `scan_type` now has a default argument of `"application/vnd.security.vulnerability.report; version=1.1"`, per the [blog post](https://goharbor.io/blog/harbor-2.6/#:~:text=Accessing%20CSV%20Export%20Programmatically) describing this new feature. It should not be necessary specify this argument, but it is still possible to do so if you need to.

## [0.11.2](https://github.com/pederhan/harborapi/tree/harborapi-v0.11.2) - 2023-03-14

### Fixed

- Actually adds `group_name` parameter for `HarborAsyncClient.get_usergroups()` this time.

### Added

- Missing `group_name` and `limit` parameters for `HarborAsyncClient.get_usergroups()`.

## [0.11.1](https://github.com/pederhan/harborapi/tree/harborapi-v0.11.1) - 2023-03-14

### Added

- Missing `group_name` and `limit` parameters for `HarborAsyncClient.get_usergroups()`.

## [0.11.0](https://github.com/pederhan/harborapi/tree/harborapi-v0.11.0) - 2023-03-10

### Added

- `HarborAsyncClient.get_system_certificate()`
  - Returns the system certificate. (`GET /api/v2.0/systeminfo/getcert`)


### Changed

- **BREAKING**: Methods that download files, now return `FileResponse` instead of a bytes object. `FileResponse` contains the file contents along with its metadata. The object can be passed to `bytes()` to get the response contents, otherwise it can be accessed via the `FileResponse.content` attribute.
- **BREAKING**: Renamed "purge" methods to better reflect their purpose of audit log rotation:
  - `HarborAsyncClient.get_purge_audit_log_status()` -> `HarborAsyncClient.get_audit_log_rotation()`
  - `HarborAsyncClient.get_purge_audit_log()` -> `HarborAsyncClient.get_audit_log_rotation_log()`
  - `HarborAsyncClient.stop_purge_audit_log()` -> `HarborAsyncClient.stop_audit_log_rotation()`
  - `HarborAsyncClient.get_purge_audit_log_schedule()` -> `HarborAsyncClient.get_audit_log_rotation_schedule()`
  - `HarborAsyncClient.create_purge_audit_log_schedule()` -> `HarborAsyncClient.create_audit_log_rotation_schedule()`
  - `HarborAsyncClient.update_purge_audit_log_schedule()` -> `HarborAsyncClient.update_audit_log_rotation_schedule()`
  - `HarborAsyncClient.get_purge_audit_logs()` -> `HarborAsyncClient.get_audit_log_rotation_history()`

## [0.10.0](https://github.com/pederhan/harborapi/tree/harborapi-v0.10.0) - 2023-02-28

### Added

- `harborapi.ext.artifact.ArtifactInfo.name_with_digest_full` which returns the artifact name with the full SHA256 digest, not just the first 15 characters like `name_with_digest`.
- Audit log purging methods.
  - `HarborAsyncClient.get_purge_audit_log_status()`
  - `HarborAsyncClient.get_purge_audit_log()`
  - `HarborAsyncClient.stop_purge_audit_log()`
  - `HarborAsyncClient.get_purge_audit_log_schedule()`
  - `HarborAsyncClient.create_purge_audit_log_schedule()`
  - `HarborAsyncClient.update_purge_audit_log_schedule()`
  - `HarborAsyncClient.get_purge_audit_logs()`
- Documentation for `HarborAsyncClient.get_project_deletable()`.
- Webhook methods.
  - `HarborAsyncClient.get_webhook_jobs()`
  - `HarborAsyncClient.get_webhook_policies()`
  - `HarborAsyncClient.get_webhook_policy()`
  - `HarborAsyncClient.create_webhook_policy()`
  - `HarborAsyncClient.update_webhook_policy()`
  - `HarborAsyncClient.delete_webhook_policy()`
  - `HarborAsyncClient.get_webhook_policy_last_trigger()`
  - `HarborAsyncClient.get_webhook_supported_events()`
- Scan Data Export Methods
  - `HarborAsyncClient.get_scan_export()`
  - `HarborAsyncClient.get_scan_exports()`
  - `HarborAsyncClient.export_scan_data()`
  - `HarborAsyncClient.download_scan_export()`
- Icon methods
  - `HarborAsyncClient.get_icon()`
- Label methods
  - `HarborAsyncClient.get_label()`
  - `HarborAsyncClient.create_label()`
  - `HarborAsyncClient.delete_label()`
  - `HarborAsyncClient.get_labels()`
- Project member methods
  - `HarborAsyncClient.get_project_member()`
  - `HarborAsyncClient.add_project_member()`
  - `HarborAsyncClient.add_project_member_user()`
  - `HarborAsyncClient.add_project_member_group()`
  - `HarborAsyncClient.update_project_member_role()`
  - `HarborAsyncClient.remove_project_member()`
  - `HarborAsyncClient.get_project_members()`
- New methods for controlling the size of the response log.
  - `harborapi.client.ResponseLog.resize()`
  - `harborapi.client.ResponseLog.clear()`
  - Documented [here](https://pederhan.github.io/harborapi/usage/responselog)
- `basicauth` as a parameter for `HarborAsyncClient.__init__()` to pass in base64 basic auth credentials.

### Changed

- `missing_ok` parameter for DELETE methods has been deprecated. Manually  handle `harborapi.exceptions.NotFound` instead. This parameter will stop working in version 1.0.0, and be removed altogether in a later release.
- `harborapi.models.Repository.split_name()` now returns a tuple instead of a list, as its docstring states it should.
- DEPRECATED: Using `credentials` as a parameter for `HarborAsyncClient.__init__` is deprecated. Use `basicauth` instead.
- `HarborAsyncClient.credentials` is now a Pydantic SecretStr, which prevents it from being printed in clear text when locals are dumped, such as when printing the client object. To access the value, use `HarborAsyncClient.credentials.get_secret_value()`.


### Removed

- Explicit logging calls from `HarborAsyncClient.set_user_cli_secret()` and `HarborAsyncClient.set_user_password()`. The exception handler handles logging if configured.


## [0.9.0](https://github.com/pederhan/harborapi/tree/harborapi-v0.9.0) - 2023-02-21

### Changed

- Updated `harborapi.models` to match the latest version of the Harbor API spec [goharbor/harbor@d03f0dc](https://github.com/goharbor/harbor/blob/99b37117e15ee25e54c4d67f4a9bd14d6df95d5a/api/v2.0/swagger.yaml).

- `harborapi.models.GeneralInfo.with_chartmuseum` has been removed from the API spec, but remains on the model for backwards compatibility. In the future, this field will be removed, as the API will never return this it in sufficiently new versions of Harbor.

## [0.8.6](https://github.com/pederhan/harborapi/tree/harborapi-v0.8.6) - 2023-02-20


### Fixed

- Models with `harborapi.models.ScheduleObj` fields are now correctly validated when the Harbor API responds with a value of `"Schedule"` for the field `ScheduleObj.type`, which is not a valid value for the enum according to their own spec.


## [0.8.5](https://github.com/pederhan/harborapi/tree/harborapi-v0.8.5) - 2023-02-20

### Added

`NativeReportSummary.severity_enum` which returns the severity of the report as a `harborarpi.scanner.Severity` enum, which can be used for comparisons between reports.


### Fixed

`harborarpi.scanner.Severity` enum not having a `None` value, which is observed when a report has no vulnerabilities.

## [0.8.4](https://github.com/pederhan/harborapi/tree/harborapi-v0.8.4) - 2023-02-14

### Fixed

- Certain resource enumeration methods missing the `limit` parameter.
- `HarborAsyncClient.get_gc_jobs()` ignoring user parameters.


## [0.8.3](https://github.com/pederhan/harborapi/tree/harborapi-v0.8.3) - 2023-02-14

### Changed

- **BREAKING**: `HarborAsyncClient.update_robot_token` renamed to `HarborAsyncClient.refresh_robot_token` to better reflect the API endpoint name and purpose.

### Fixed

- Pagination failing when one or more query parameter values included a comma.
- Certain `HarborAsyncClient` methods having missing or incomplete docstrings.

## [0.8.2](https://github.com/pederhan/harborapi/tree/harborapi-v0.8.2) - 2023-02-09

### Fixed

- `HarborAsyncClient.get_registry_providers` now returns a `RegistryProviders` object, which is a model whose only attribute `providers` is a dict of `RegistryProviderInfo` objects. Previously this method attempted to return a list of `RegistryProviderInfo` objects, but this was incorrect.


## [0.8.1](https://github.com/pederhan/harborapi/tree/harborapi-v0.8.1) - 2023-02-09

### Changed

- Backoff handlers for HTTP methods now handle a more strict subset of `httpx.RequestError` exceptions. This is to avoid retrying on exceptions that will never succeed such as [`httpx.UnsupportedProtocol`](https://www.python-httpx.org/exceptions/).

## [0.8.0](https://github.com/pederhan/harborapi/tree/harborapi-v0.8.0) - 2023-02-08

### Added

- `limit` parameter for all methods that return a list of items. This parameter is used to limit the number of items returned by the API. See the [docs](https://pederhan.github.io/harborapi/usage/limit/) for more details.


### Removed

- `retrieve_all` parameter for all methods that return a list of items. Use the new `limit` parameter to control the number of results to retrieve. Passing `retrieve_all` to these methods will be silently ignored. In the future this will raise a DeprecationWarning.

## [0.7.1](https://github.com/pederhan/harborapi/tree/harborapi-v0.7.1) - 2023-02-07

### Added

- New parameters `raw` and `validate` to `HarborAsyncClient` and `HarborClient` to control whether the client returns the raw data from the API, and whether the client validates the data from the API, respectively. See the [docs](https://pederhan.github.io/harborapi/usage/validation/) for more details.


## [0.7.0](https://github.com/pederhan/harborapi/tree/harborapi-v0.7.0) - 2023-02-06

### Added

- New models from [2022-11-28 spec update](https://github.com/goharbor/harbor/blob/402363d50bbff867c15efa17117f9a4ab1623736/api/v2.0/swagger.yaml).

### Changed

- Updated models from [2022-11-28 spec update](https://github.com/goharbor/harbor/blob/402363d50bbff867c15efa17117f9a4ab1623736/api/v2.0/swagger.yaml).
- Generated models are now defined in `models._models` and `models._scanner`, and the overrides for these models are defined in `models.models` and `models.scanner` respectively. This is to make it easier to regenerate the models in the future while keeping the extended functionality (such as `Repository.project_name`, `ScanOverview.__new__`, etc.) for these classes intact, since that is now declared separately from the generated models. Furthermore, `models.models` and `models.scanner` both re-export all the generated models so that the API remains unchanged. See the Justfile for more details on how the models are generated.

### Fixed

- `HarborAsyncClient.search()` raising an error when finding Helm Charts with an empty `engine` field.


### Removed

- **BREAKING**: `HarborAsyncClient.get_internal_config()`. This endpoint is meant for internal usage only, and the new model definitions don't seem to play well with it. If you need this endpoint, please open an issue.

## [0.6.0](https://github.com/pederhan/harborapi/tree/harborapi-v0.6.0) - 2023-01-30

### Changed

- **BREAKING**: The `max_depth` parameter of the `as_table()` and `as_panel()` methods on all models now starts counting from 1 instead of 0.
  - `max_depth=0` now means "no limit", and `max_depth=1` means "only show the top level" (previously `max_depth=0` meant "only show the top level" and `max_depth=1` meant "show the top level and one level below")

## [0.5.0](https://github.com/pederhan/harborapi/tree/harborapi-v0.5.0) - 2023-01-17

### Added

- Changelog
- Rich as optional dependency: `pip install harborapi[rich]`

### Changed

- Use Hatch as build system.

<!-- ### Fixed -->
