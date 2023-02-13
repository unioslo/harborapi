# Fetch artifacts

With the help of asyncio, we can fetch artifacts from multiple repositories concurrently.
The number of concurrent connections can be controlled by the `max_connections` parameter for [harborapi.ext.api.get_artifacts][].

By default, `get_artifacts()` will fetch all artifacts in all repositories in all projects.

```py title="all_artifacts.py"
from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(...)

async def main() -> None:
    artifacts = await api.get_artifacts(client)
```

## Repos in specific projects

Passing a list of project names to the `projects` argument will fetch artifacts from all repositories in the specified projects.

```py title="artifacts_in_projects.py" hl_lines="11 12"
from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(...)

async def main() -> None:
    projects = ["library", "my-project-1"]
    artifacts = await api.get_artifacts(client, projects=projects)
```

This will fetch all artifacts in all repositories in the projects `library` and `my-project-1` concurrently.

## Specific repositories

Passing a list of [`Repository`][harborapi.models.models.Repository] objects to the `repos` argument will fetch artifacts from the specified repositories.

```py title="artifacts_in_repos.py" hl_lines="12-14"
from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(...)

async def main() -> None:
    projects = ["library", "my-project-1"]
    repos = await api.get_repositories(client, projects=projects)
    repos = [repo for repo in repos if repo.name != "hello-world"]
    artifacts = await api.get_artifacts(client, repos)
```

By fetching the repositories ourselves before calling `get_artifacts()`, we can filter out repositories that we don't want to fetch artifacts from, if we want to.
