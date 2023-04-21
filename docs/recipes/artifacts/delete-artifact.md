# Delete artifact

We can delete an artifact using [`delete_artifact`][harborapi.client.HarborAsyncClient.delete_artifact]. The method takes a project name, repository name, and a tag or digest.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    await client.delete_artifact("library", "hello-world", "latest")
    # or
    await client.delete_artifact("library", "hello-world", "sha256:123456abcdef...")


asyncio.run(main())

```
