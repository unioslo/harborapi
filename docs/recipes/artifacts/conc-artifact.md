# Fetch artifacts

With the help of asyncio, we can fetch artifacts from multiple repositories concurrently.
The number of concurrent connections can be controlled by the `max_connections` argument.

By default, [`get_artifacts()`][harborapi.ext.api.get_artifacts] will fetch all artifacts in all repositories in all projects.



```py title="all_artifacts.py"
from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    username="username",
    secret="secret",
)

async def main() -> None:
    artifacts = await api.get_artifacts(client)
```



## Repos in specific projects

Passing a list of project names to the `projects` argument will fetch artifacts from all repositories in the specified projects.

```py title="artifacts_in_projects.py" hl_lines="11 12"
from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    username="username",
    secret="secret",
)

async def main() -> None:
    projects = ["library", "my-project-1"]
    artifacts = await api.get_artifacts(client, projects=projects)
```

This will fetch all artifacts in all repositories in the projects `library` and `my-project-1` concurrently.


## Specific repositories

Passing a list of [`Repository`][harborapi.models.models.Repository] objects to the `repos` argument will fetch artifacts from the specified repositories.

```py title="artifacts_in_repos.py" hl_lines="12 13"
from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    username="username",
    secret="secret",
)

async def main() -> None:
    projects = ["library", "my-project-1"]
    repos = await api.get_repositories(client, projects=projects)
    artifacts = await api.get_artifacts(client, repos)
```

!!! note
    We use `return_exceptions=True` as an argument to `asyncio.gather` in the example, which means exceptions are returned in the list of results. These exceptions should be filtered out and handled.
    Set `return_exceptions` to `False` if you wish any encountered exceptions to be raised automatically.


## Using the `ext` module

The recipe above has been baked into the `ext` module to allow for quick and easy retrieval of artifacts in multiple repositories. See: [Extended Functionality](/ext/index.md) for more information.
