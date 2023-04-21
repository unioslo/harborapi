# Update project

We can update an existing project using [`update_project`][harborapi.client.HarborAsyncClient.update_project]. The method takes the name or ID of the project and a [`ProjectReq`][harborapi.models.ProjectReq] object. Nothing is returned on success.

!!! note
    Updating a project is an `HTTP PUT` operation in the API, which according to idiomatic REST should replace the existing resource with the resource in the request body. However, the Harbor API will actually only update the existing resource with the fields defined in the request, not replace it entirely. This library provides no guarantees that this behavior will persist in future versions of Harbor.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    await client.update_project(
        "test-project2",
        ProjectReq(
            public=False,
            metadata=ProjectMetadata(
                auto_scan=False,
            ),
        ),
    )


asyncio.run(main())
```
