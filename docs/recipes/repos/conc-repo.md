# Fetch repositories

Given a list of project names, we can use Asyncio to dispatch multiple requests concurrently to the Harbor API to fetch repositories in a list of projects (or all projects if `None` is passed in) with the help of [`ext.api.get_repositories()`][harborapi.ext.api.get_repositories]

## List of names

We can use a list of project names to fetch repositories from.


```py hl_lines="13"
from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(...)

async def main() -> None:
    repos = await api.get_repositories(
        client,
        projects=["library", "my-project-1"],
    )
```

This will fetch all repositories from the projects `library` and `my-project-1` concurrently.


## All projects

We can also fetch the repositories from all projects by passing `None` in as the `projects` argument.

```py hl_lines="13"
from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(...)

async def main() -> None:
    repos = await api.get_repositories(
        client,
        projects=None,
    )
```

This will fetch all repositories from all projects concurrently.

!!! note
    The function has a named parameter [`callback`][harborapi.ext.api.get_repositories], which takes a function that receives a list of exceptions as its only argument. This can be used to handle exceptions that occur during the concurrent requests. The function always fires even if there are no exceptions. If no callback function is specified, exceptions are ignored.
