# Delete project

We can delete a project using [`delete_project`][harborapi.client.HarborAsyncClient.delete_project]. The method takes a project name (string) or a project ID (integer) as its only argument. The method returns nothing on success.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    await client.delete_project("library")
    # or
    await client.delete_project(1)


asyncio.run(main())
```
