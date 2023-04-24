# Scan an artifact

We can scan an artifact using [`scan_artifact`][harborapi.client.HarborAsyncClient.scan_artifact]. The method takes a project name, repository name, and a tag or digest. The method starts a scan and returns nothing on success.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)

async def main() -> None:
    await client.scan_artifact("library", "hello-world", "latest")
    # or
    await client.scan_artifact("library", "hello-world", "sha256:123456abcdef...")



asyncio.run(main())
```


## Stop a scan

We can stop a running scan by using [`stop_artifact_scan`][harborapi.client.HarborAsyncClient.stop_artifact_scan]. The method takes a project name, repository name, and a tag or digest. The method returns nothing on success.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)

async def main() -> None:
    await client.stop_artifact_scan("library", "hello-world", "latest")
    # or
    await client.stop_artifact_scan("library", "hello-world", "sha256:123456abcdef...")


asyncio.run(main())
```
