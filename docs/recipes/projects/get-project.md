# Get project

We can fetch a single project using [`get_project`][harborapi.client.HarborAsyncClient.get_project]. The method takes a project name (string) or a project ID (integer) as its only argument.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    project = await client.get_project("library")
    # or
    project = await client.get_project(1)


asyncio.run(main())
```

This will return a [`Project`][harborapi.models.Project] object.
