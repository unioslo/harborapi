# harborapi

[![PyPI - Version](https://img.shields.io/pypi/v/harborapi.svg)](https://pypi.org/project/harborapi)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/harborapi.svg)](https://pypi.org/project/harborapi)

-----


Python async client for the Harbor REST API v2.0 based on the official Harbor REST API specification.

## Features

- Async API
- Extensive type hint coverage
- Data validation with [Pydantic](https://github.com/pydantic/pydantic)
- Built-in retry functionality with [backoff](https://github.com/litl/backoff)
- Extensive test coverage powered by [Hypothesis](https://github.com/HypothesisWorks/hypothesis)
- Optional [rich](https://github.com/Textualize/rich/) support

## Installation

```bash
pip install harborapi
```


## Documentation

Documentation is available [here](https://pederhan.github.io/harborapi/)

## Quick Start


### Authentication


```python
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://demo.goharbor.io/api/v2.0/",
    username="username",
    secret="secret",
    # OR
    basicauth="base64-basic-auth-credentials",
    # OR
    credentials_file="path/to/robot-credentials-file.json",
)
```

### Get all projects

```python
import asyncio

async def main() -> None:
    # Get all projects
    projects = await client.get_projects()
    for project in projects:
        print(project.name)

    # If you have rich installed:
    import rich

    for project in projects:
        rich.print(project)


asyncio.run(main())
```


### Create a project

```python
import asyncio
from harborapi.models import ProjectReq, ProjectMetadata

async def main() -> None:
    project_path = await client.create_project(
        ProjectReq(
            project_name="test-project",
            metadata=ProjectMetadata(
                public=True,
            ),
        )
    )
    print(f"Project created: {project_path}")


asyncio.run(main())
```

----

All endpoints are documented in the [endpoints documentation](https://pederhan.github.io/harborapi/endpoints/).



## Disclaimer

Harborapi make use of code generation for its data models, but it doesn't entirely rely on it like, for example, [githubkit](https://github.com/yanyongyu/githubkit). Thus, while the library is based on the Harbor REST API specification, it is not beholden to it. The schema contains several inconsistencies and errors, and the library takes steps to rectify some of these until they are fixed in Harbor's own specification.

Harborapi attempts to improve endpoint descriptions where possible and fix models with fields given the wrong type or wrongly marked as required. Without these changes, the validation provided by the library would be unusable for certain endpoints, as these endpoints return data that is inconsistent with the specification, thus making it impossible to construct valid models from the data.


## Implemented endpoints

<!-- - [ ] Products
- [ ] Chart Repository
- [ ] Label -->
- [x] Artifact
- [x] Auditlog
- [x] Configure
- [x] Garbage Collection
- [x] Health
- [x] Icon
- [ ] Immutable
- [x] Label
- [x] Ldap
- [x] OIDC
- [x] Ping
- [ ] Preheat
- [x] Project
- [x] Project Metadata
- [x] Purge
- [x] Quota
- [x] Registry
- [x] Replication
- [x] Repository
- [ ] Retention
- [x] Robot
- [ ] Robotv1
- [x] Scan
- [x] Scan Data Export
- [x] Scanall
- [x] Scanner
- [x] Search
- [x] Statistic
- [x] System CVE Allowlist
- [x] System Info**
- [x] User
- [x] Usergroup
- [x] Webhooks


\*\* `/systeminfo/getcert` NYI
