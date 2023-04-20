# Fetch artifacts

With the help of asyncio, we can fetch artifacts from multiple repositories concurrently.
The number of concurrent connections can be controlled by the `max_connections` parameter for [harborapi.ext.api.get_artifacts][].


## All artifacts

By default, `get_artifacts()` will fetch all artifacts in all repositories in all projects.

```py
from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(...)

async def main() -> None:
    artifacts = await api.get_artifacts(client)
```

This will give us a list of [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] objects, which contain information about the artifact.

## Artifacts in specific projects

Passing a list of project names to the `projects` argument will fetch artifacts from all repositories in the specified projects.

```py hl_lines="9"
from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(...)

async def main() -> None:
    artifacts = await api.get_artifacts(
        client,
        projects=["library", "my-project-1"],
    )
```

This will fetch all artifacts in all repositories in the projects `library` and `my-project-1` concurrently.


## Artifacts in specific repos in specific projects


We can specify names of projects and repositories to fetch artifacts from.

```py hl_lines="9-10"
from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(...)

async def main() -> None:
    artifacts = await api.get_artifacts(
        client,
        projects=["library", "test-project"],
        repositories=["nginx"]
    )
```

This will fetch all artifacts in `library/nginx` and `test-project/nginx` concurrently (if they exist).



## Artifacts in specific repos


We can fetch artifacts from specific repositories by passing a list of repository names to the `repositories` argument for [harborapi.ext.api.get_artifacts][].


```py hl_lines="9"
from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(...)

async def main() -> None:
    artifacts = await api.get_artifacts(
        client,
        repositories=["library/hello-world", "nginx"]
    )
```

This will fetch all artifacts in the repository `library/hello-world`, as well as all artifacts from any repository named `nginx` in any project.

The `"nginx"` value demonstrates the flexible behavior of the function. By omitting both the `projects` parameter and the project name from the argument `"nginx"`, the library looks for repositories named `nginx` in all projects.
