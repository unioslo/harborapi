# Changelog

All notable changes to this project will be documented in this file.

The format is based on [*Keep a Changelog 1.0.0*](https://keepachangelog.com/en/1.0.0/) and this project adheres to [*Semantic Versioning 2.0.0*](https://semver.org/).

The **first number** is the major version (API changes, breaking changes)
The **second number** is the minor version (new features)
The **third number** is the patch version (bug fixes)

<!-- changelog follows -->

## [Unreleased]

### Added

- New models (TBD)

### Changed

- Updated models (TBD)
- Generated models are now defined in `models._models`, and the overrides for these models are defined in `models.models`. This is to make it easier to regenerate the models in the future. Furthermore, the `models._models` module is accessible via `models.models`, which should make this change backwards compatible.

### Fixed

- Fixed models (TBD)

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
