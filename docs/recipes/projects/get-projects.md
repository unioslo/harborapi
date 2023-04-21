# Get all projects

We can fetch all projects using [`get_projects`][harborapi.client.HarborAsyncClient.get_projects]. The method returns a list of [`Project`][harborapi.models.Project] objects.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    projects = await client.get_projects()


asyncio.run(main())
```
