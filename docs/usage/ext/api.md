# API

The `ext.api` module contains helper functions that take in a `HarborAsyncClient` and use it to provide new or extended functionality. In most cases, the functions return [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] objects, which is composed of an artifact, its repository and optionally also the artifact's complete vulnerability report.

The module makes heavy use of concurrent requests to speed up the process of fetching information from the Harbor API. This is done using the [`asyncio`][asyncio] module, which is part of the Python standard library.

## Handling exceptions in bulk operations

Certain functions, such as [`get_artifacts`][harborapi.ext.api.get_artifacts] and [`get_artifact_vulnerabilities`][harborapi.ext.api.get_artifact_vulnerabilities] send a large number of requests. In order to not fail the entire operation if a single request fails, exceptions are ignored by default.

To handle these exceptions, a `callback` parameter is available for these functions, which takes a function that receives a list of exceptions as its only argument. This callback function can be used to handle exceptions that occur during the concurrent requests. The function always fires even if there are no exceptions. If no callback function is specified, exceptions are ignored.

### Example

```py title="callback.py" hl_lines="15-23 30"
import asyncio
import os
from typing import List

from harborapi import HarborAsyncClient
from harborapi.ext import api
from httpx._exceptions import HTTPError

client = HarborAsyncClient(
    url=os.getenv("HARBOR_URL"),
    credentials=os.getenv("HARBOR_CREDENTIALS"),
)


def handle_exceptions(exceptions: List[Exception]) -> None:
    if not exceptions:
        return
    print("The following exceptions occurred:")
    for e in exceptions:
        if isinstance(e, HTTPError):
            print(f"HTTPError: {e.request.method} {e.request.url}")
        else:
            print(e)


async def main() -> None:
    artifacts = await api.get_artifacts(
        client,
        projects=["library"],
        callback=handle_exceptions,
    )
    for artifact in artifacts:
        print(artifact.artifact.digest)


if __name__ == "__main__":
    asyncio.run(main())
```

## Fetch multiple artifacts concurrently


The previous error handling example showcased the [`harborapi.ext.api.get_artifacts`][harborapi.ext.api.get_artifacts] function in some capacity. By default this function fetches all artifacts in all repositories in all projects and returns a list of [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] objects.

Using the `project`, `repository` and `tag` parameters, we can limit the artifacts that are fetched.

* The `project` parameter can be a list of one or more project names.
* The `repository` parameter can be a list of one or more repositories (without the project name, e.g. `foo` instead of `library/foo`).
* The `tag` parameter is a single tag name to filter on.

### Example

```py title="get_artifacts.py" hl_lines="15-17"
import asyncio
import os

from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(
    url=os.getenv("HARBOR_URL"),
    credentials=os.getenv("HARBOR_CREDENTIALS"),
)

async def main() -> None:
    artifacts = await api.get_artifacts(
        client,
        projects=["library", "mirrors"],
        repositories=["alpine", "busybox", "debian", "internal-repo"],
        tag="latest",
    )
    for artifact in artifacts:
        print(artifact.artifact.digest)


if __name__ == "__main__":
    asyncio.run(main())
```

The `query` parameter, found on most [`HarborAsyncClient`][harborapi.client.HarborAsyncClient] methods, can also be passed to [`harborapi.ext.api.get_artifacts`][harborapi.ext.api.get_artifacts] for a more granular filtering of artifacts.

See [HarborAsyncClient.get_artifacts][harborapi.client.HarborAsyncClient.get_artifacts] for more information on the `query` parameter.
