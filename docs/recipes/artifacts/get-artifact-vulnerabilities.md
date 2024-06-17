# Get artifact vulnerability report

We can fetch the vulnerability report for an artifact using [`get_artifact_vulnerability_reports`][harborapi.client.HarborAsyncClient.get_artifact_vulnerability_reports]. It returns a dict of [`HarborVulnerabilityReport`][harborapi.models.HarborVulnerabilityReport] objects indexed by MIME type. If no reports are found, the dict will be empty.

A [`HarborVulnerabilityReport`][harborapi.models.HarborVulnerabilityReport] is more comprehensive than the [`NativeReportSummary`][harborapi.models.models.NativeReportSummary] returned by [`get_artifact(..., with_scan_overview=True)`](../get-artifact-scan-overview). It contains detailed information about the vulnerabilities found in the artifact.

## Example

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
    for mime_type, report in reports.items():
        print(mime_type)
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

## The `mime_type` parameter

We can pass in a list of MIME types or a single MIME type to the `mime_type` parameter. The returned dict will only contain the vulnerability reports for the specified MIME types.

```py
reports = await client.get_artifact_vulnerabilities(
    ...,
    mime_type=[
        "application/vnd.security.vulnerability.report; version=1.1",
        "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
    ],
)
for report in reports:
    print(report)

# OR

reports = await client.get_artifact_vulnerabilities(
    ...,
    mime_type="application/vnd.security.vulnerability.report; version=1.1",
)
reports.get("application/vnd.security.vulnerability.report; version=1.1")
```

Remember, the Artifact might not have a vulnerability report for the specified MIME type. In that case, the dict will be empty.

```py
reports = await client.get_artifact_vulnerabilities(
    ...,
    mime_type=["Lots", "Of", "Mime", "Types"],
)
if not reports:
    print("No vulnerability reports found for the specified MIME types.")
```
