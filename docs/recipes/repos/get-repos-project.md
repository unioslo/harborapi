# Get repositories in a project

We can fetch all repositories in a specific project by using [`get_repositories`][harborapi.client.HarborAsyncClient.get_repositories] and passing the project name to the `project_name` parameter. The method returns a list of [`Repository`][harborapi.models.Repository] objects.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)

async def main() -> None:
    repos = await client.get_repositories(
        project_name="library",
    )


asyncio.run(main())
```

Fetching repos in multiple specific projects must either be done by calling the method multiple times, or omitting the `project_name` parameter and fetching all repositories in all projects, and then filtering the results afterwards.

`harborapi.ext` provides a helper function for fetching from multiple specific projects, and the recipe for that is available [here](../ext/conc-repo.md)
