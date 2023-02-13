# Delete

Endpoints that delete resources usually require a resource identifier or name as the first parameter. Most of these endpoints return `None` on success. Failure to delete a resource will raise an exception.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    await client.delete_project("test-project")


asyncio.run(main())
```
