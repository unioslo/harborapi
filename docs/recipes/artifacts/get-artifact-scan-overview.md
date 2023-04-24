# Get artifact scan overview

We can fetch the scan overview for an artifact using [`get_artifact_vulnerabilities`][harborapi.client.HarborAsyncClient.get_artifact_vulnerabilities]. The vulnerability report contains all the vulnerabilities found in the artifact.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    report = await client.get_artifact_vulnerabilities(
        "library",
        "hello-world",
        "latest",
    )
    for vulnerability in report.vulnerabilities:
        print(
            vulnerability.id,
            vulnerability.severity,
            vulnerability.package,
        )

asyncio.run(main())
```

<!-- See ext recipe for a maidaofowqwfq -->
