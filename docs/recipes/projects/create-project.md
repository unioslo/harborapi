# Create project

We can create a new project using [`create_project`][harborapi.client.HarborAsyncClient.create_project]. The method takes a [`ProjectReq`][harborapi.models.ProjectReq] object, and returns the location of the created project.

One feature of creating projects via the API is that we can provide more detailed configuration than what is available in the web UI. For example, we can enable content trust and auto scanning when creating the project, instead of having to do it manually after the project has been created.

Check the [`ProjectReq`][harborapi.models.ProjectReq] documentation for more information about the available options.


```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    location = await client.create_project(
        ProjectReq(
            project_name="new-project",
            public=True,
            metadata=ProjectMetadata(
                auto_scan=True,
                enable_content_trust=True,
            ),
        )
    )
    print(location)


asyncio.run(main())
```
