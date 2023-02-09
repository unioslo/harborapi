# Changelog

All notable changes to this project will be documented in this file.

The format is based on [*Keep a Changelog 1.0.0*](https://keepachangelog.com/en/1.0.0/) and this project adheres to [*Semantic Versioning 2.0.0*](https://semver.org/).

The **first number** is the major version (API changes, breaking changes)
The **second number** is the minor version (new features)
The **third number** is the patch version (bug fixes)

<!-- changelog follows -->

<!-- ## [Unreleased] -->

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
