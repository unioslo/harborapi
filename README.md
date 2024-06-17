# harborapi

[![PyPI - Version](https://img.shields.io/pypi/v/harborapi.svg)](https://pypi.org/project/harborapi)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/harborapi.svg)](https://pypi.org/project/harborapi)
![Tests](https://github.com/unioslo/harborapi/workflows/test/badge.svg)
[![Docs](https://github.com/unioslo/harborapi/workflows/docs/badge.svg)](https://unioslo.github.io/harborapi/)
[![Checked with mypy](https://www.mypy-lang.org/static/mypy_badge.svg)](https://mypy-lang.org/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Linting: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/charliermarsh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

-----

Python async client for the Harbor REST API v2.0 based on the official Harbor REST API specification.

**NOTE:** The official Harbor API spec is hand-written, and numerous errors and inconsistencies have been found in it. This library attempts to work around these issues as much as possible, but errors may still occur. If you find any errors, please open an issue.

## Features

- [Async API](https://unioslo.github.io/harborapi/usage/)
- Extensive type hint coverage
- [Data validation](https://unioslo.github.io/harborapi/usage/models/) with [Pydantic](https://github.com/pydantic/pydantic)
- Built-in [retry functionality](https://unioslo.github.io/harborapi/usage/retry/) with [backoff](https://github.com/litl/backoff)
- Optional [Rich](https://github.com/Textualize/rich/) [support](https://unioslo.github.io/harborapi/usage/rich/)

## Installation

```bash
pip install harborapi
```

## Documentation

Documentation is available [here](https://unioslo.github.io/harborapi/). The documentation is still a work in progress, and you may have to dig around a bit to find what you're looking for.

Creating proper documentation for the Pydantic models is priority number one right now, but is largely blocked by the lack of inheritance support in the [mkdocstrings python plugin](https://github.com/mkdocstrings/python/issues/58#issuecomment-1435962980).

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
    credentials_file="/path/to/robot-credentials-file.json",
)
```

### Get all projects

```python
import asyncio

from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    # ...
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

### Create a project

```python
import asyncio

from harborapi import HarborAsyncClient
from harborapi.models import ProjectReq, ProjectMetadata

client = HarborAsyncClient(
    # ...
)

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

All endpoints are documented in the [endpoints documentation](https://unioslo.github.io/harborapi/endpoints/).

## Disclaimer

`harborapi` makes use of code generation for its data models, but it doesn't entirely rely on it like, for example, [githubkit](https://github.com/yanyongyu/githubkit). Thus, while the library is based on the Harbor REST API specification, it is not beholden to it. The official schema contains several inconsistencies and errors, and this package takes steps to rectify some of these locally until they are fixed in the official Harbor API spec.

`harborapi` attempts to improve endpoint descriptions where possible and fix models with fields given the wrong type or wrongly marked as required. Without these changes, the validation provided by the library would be unusable for certain endpoints, as these endpoints can, in certain cases, return data that is inconsistent with the official API specification, thus breaking the model validation.

To return the raw API responses without validation and type conversion, set `raw=True` when instantiating the client. For more information, check the [documentation](https://unioslo.github.io/harborapi/usage/validation/) on validation.

## TODO

### Endpoints

- [ ] Preheat
