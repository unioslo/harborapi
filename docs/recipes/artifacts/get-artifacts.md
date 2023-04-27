# Get artifacts in repository

To fetch all artifacts in a repository, we can use the [`get_artifacts`][harborapi.client.HarborAsyncClient.get_artifacts] method. It returns a list of [`Artifact`][harborapi.models.Artifact] objects.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)

async def main() -> None:
    artifacts = await client.get_artifacts("library", "hello-world")


asyncio.run(main())
```


## Filter by tag

Providing an argument for `query` can help narrow down the results. For example, if we want to retrieve artifacts tagged `latest`, we can pass `"tags=latest"` to `query`:

```py hl_lines="4"
artifacts = await client.get_artifacts(
    "project",
    "repository",
    query="tags=latest",
)
```

See [query](../../usage/methods/read.md#query) for more information about how to use this parameter.


## With extra data

Similar to [`get_artifact`][harborapi.client.HarborAsyncClient.get_artifact], we can fetch extra data for the artifacts by using the `with_tag`, `with_label`, `with_scan_overview`, `with_signature`, `with_immutable_status`, `with_accessory` arguments. See the [get artifact](get-artifact.md) recipe for more information about how to use them and what they return.
