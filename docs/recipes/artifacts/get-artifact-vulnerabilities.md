# Get artifact vulnerability report

We can fetch the vulnerability report for an artifact using [`get_artifact_vulnerabilities`][harborapi.client.HarborAsyncClient.get_artifact_vulnerabilities]. It returns a [`HarborVulnerabilityReport`][harborapi.models.HarborVulnerabilityReport] object. The vulnerability report contains all the vulnerabilities found in the artifact.

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
