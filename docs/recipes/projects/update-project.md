# Update project

We can update an existing project using [`update_project`][harborapi.client.HarborAsyncClient.update_project]. The method takes the name or ID of the project and a [`ProjectReq`][harborapi.models.ProjectReq] object. Nothing is returned on success.

!!! note
    Updating a project is an `HTTP PUT` operation in the API, which according to idiomatic REST should replace the existing project settings with the project settings in the `ProjectReq` in the request body. However, in practice, the Harbor API supports partial updates, and thus will only update the fields that are actually set on the `ProjectReq` object in the request body. It is not guaranteed that this behavior will persist in future versions of Harbor, or is indeed supported by all versions of Harbor.

    See [Idiomatic REST Updating](../../usage/methods/create-update/#idiomatic-rest-updating) for more information.

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
