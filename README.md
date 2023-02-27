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

## Quick Start

```python
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://demo.goharbor.io/api/v2.0/",
    username="username",
    secret="secret",
    # OR
    credentials="base64-basic-auth-credentials",
    # OR
    credentials_file="path/to/robot-credentials-file.json",
)


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

## Documentation

Documentation is available [here](https://pederhan.github.io/harborapi/)


## Disclaimer

Harborapi make use of code generation for its data models, but it doesn't entirely rely on it like, for example, [githubkit](https://github.com/yanyongyu/githubkit). Thus, while the library is based on the Harbor REST API specification, it is not beholden to it. The schema contains several inconsistencies and errors, and the library takes steps to rectify some of these until they are fixed in the official specification.

Harborapi attempts to improve endpoint descriptions where possible and fix models with fields given the wrong type or wrongly marked as required. Without these changes, the validation provided by the library would not have been useable, as it would have been impossible to create valid models for many endpoints.


## Implemented endpoints

<!-- - [ ] Products
- [ ] Chart Repository
- [ ] Label -->
- [x] user
- [x] gc
- [x] scanAll
- [x] configure
- [x] usergroup
- [ ] preheat
- [x] replication
- [ ] label
- [x] robot
- [ ] webhookjob
- [ ] icon
- [x] project
- [ ] webhook
- [x] scan
- [ ] member
- [x] ldap
- [x] registry
- [x] search
- [x] artifact
- [ ] immutable
- [ ] retention
- [x] scanner
- [x] systeminfo**
- [x] statistic
- [x] quota
- [x] repository
- [x] ping
- [x] oidc
- [x] SystemCVEAllowlist
- [x] Health
- [ ] robotv1
- [x] projectMetadata
- [x] auditlog

\*\* `/systeminfo/getcert` NYI
