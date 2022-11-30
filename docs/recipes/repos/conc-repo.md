# Fetch repositories

Given a list of project names, we can use Asyncio to dispatch multiple requests concurrently to the Harbor API to fetch repositories in a list of projects (or all projects if `None` is passed in) with the help of [`ext.api.get_repositories()`][harborapi.ext.api.get_repositories]

## List of names

We can use a list of project names to fetch repositories from.


```py hl_lines="13"
from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    username="username",
    secret="secret",
)

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

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    username="username",
    secret="secret",
)

async def main() -> None:
    repos = await api.get_repositories(
        client,
        projects=None,
    )
```

This will fetch all repositories from all projects concurrently.

!!! note
    The function has a named parameter [`return_exceptions`][harborapi.ext.api.get_repositories], which makes the function ignore exceptions when encountered, and simply log them (if `exc_ok` is `True`)

    If you wish to handle the exceptions yourself, set `return_exceptions` to `False`.

    The default kwarg `return_exceptions=False`is passed to `get_repositories()` in the examples, which means exceptions are not returned in the list of results. If `return_exceptions` is `True`, these exceptions should be filtered out and handled as you see fit. If `exc_ok=False`, these exceptions will be raised automatically. And as such, `exc_ok` should always be set to `False` if you wish to handle exceptions yourself with `return_exceptions=True`.
