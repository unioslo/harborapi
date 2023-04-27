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

The [`HarborVulnerabilityReport`][harborapi.models.HarborVulnerabilityReport] class provides a simple interface for filtering the vulnerabilities by severity. For example, if we only want to see vulnerabilities with a [`Severity`][harborapi.models.Severity] of [`critical`][harborapi.models.Severity.critical] we can access the [`HarborVulnerabilityReport.critical`][harborapi.models.HarborVulnerabilityReport.critical] attribute, which is a property that returns a list of [`VulnerabilityItem`][harborapi.models.VulnerabilityItem] objects:

```py
for vulnerability in report.critical:
    print(vulnerability.id)
```

Similarly, we can also get [low][harborapi.models.HarborVulnerabilityReport.low], [medium][harborapi.models.HarborVulnerabilityReport.medium], and [high][harborapi.models.HarborVulnerabilityReport.high] severity vulnerabilities, as well as [fixable][harborapi.models.HarborVulnerabilityReport.fixable] and [unfixable][harborapi.models.HarborVulnerabilityReport.unfixable] vulnerabilities:


```py
for vulnerability in report.low:...
for vulnerability in report.medium:...
for vulnerability in report.high:...
for vulnerability in report.critical: ...
for vulnerability in report.fixable: ...
for vulnerability in report.unfixable: ...
```

Each [`VulnerabilityItem`][harborapi.models.VulnerabilityItem] contains information about a vulnerability that affects the artifact. This includes information such as [id][harborapi.models.VulnerabilityItem.id], [severity][harborapi.models.VulnerabilityItem.severity], [package][harborapi.models.VulnerabilityItem.package], [version][harborapi.models.VulnerabilityItem.version], [description][harborapi.models.VulnerabilityItem.description], [links][harborapi.models.VulnerabilityItem.links] and more.

```py
for vulnerability in report.vulnerabilities:
    print(
        vulnerability.id,
        vulnerability.severity,
        vulnerability.package,
        vulnerability.description,
        vulnerability.version,
    )
    if vulnerability.links:
        for link in vulnerability.links:
            print("\t", link)
```
