# Get project retention policy

Fetching the retention policy for a given project is somewhat convoluted in the API, as there is no endpoint for fetching the retention policy ID of a specific project.

To that end, `harborapi` adds the helper method [`get_project_retention_id`][harborapi.client.HarborAsyncClient.get_project_retention_id] for fetching the retention policy ID for a given project. With this method, we can first fetch the retention policy ID, and then use that ID to fetch the retention policy itself.


```py
import asyncio

from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://demo.goharbor.io/api/v2.0",
    username="username",
    secret="secret",
)


async def main() -> None:
    # Get the retention policy ID for the project "library"
    project_name = "library"
    retention_id = await client.get_project_retention_id(project_name)
    if not retention_id:
        print(f"No retention policy found for project {project_name!r}")
        exit(1)

    # Get the retention policy for the project "library"
    policy = await client.get_retention_policy(retention_id)

    # work with the policy...
    print(policy)


asyncio.run(main())
```
