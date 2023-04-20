# Get repository

We can fetch a specific repository using [`get_repository`][harborapi.client.HarborAsyncClient.get_repository]. The method takes a project name and a repository name, and returns a [`Repository`][harborapi.models.Repository] object.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)

async def main() -> None:
    repo = await client.get_repository(
        project_name="library",
        repository_name="hello-world",
    )


asyncio.run(main())
```
