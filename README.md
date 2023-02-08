# harborapi

[![PyPI - Version](https://img.shields.io/pypi/v/harborapi.svg)](https://pypi.org/project/harborapi)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/harborapi.svg)](https://pypi.org/project/harborapi)

-----


Python async client for the Harbor REST API v2.0.

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
