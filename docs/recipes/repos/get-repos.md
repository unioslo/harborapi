# Get all repositories

Fetching all repositories is done by calling [`get_repositories`][harborapi.client.HarborAsyncClient.get_repositories]. The method returns a list of [`Repository`][harborapi.models.Repository] objects.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    repos = await client.get_repositories()


asyncio.run(main())
```
