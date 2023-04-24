# Get artifact scan overview

We can fetch the scan overview for an artifact using the `with_scan_overview` argument. This will populate the [`scan_overview`][harborapi.models.Artifact.scan_overview] field of the artifact with a [`NativeReportSummary`][harborapi.models.NativeReportSummary] object. This object contains a brief overview of the scan results for the artifact. To fetch the full vulnerability report (a separate API call), see the [Get artifact vulnerability report](get-artifact-vulnerabilities.md) recipe.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)

async def main() -> None:
    artifact = await client.get_artifact(
        "library",
        "hello-world",
        "latest",
        with_scan_overview=True,
    )
    print(artifact.scan_overview)


asyncio.run(main())
```

This will populate the [`scan_overview`][harborapi.models.Artifact.scan_overview] field of the artifact with a [`NativeReportSummary`][harborapi.models.NativeReportSummary] object, which contains a summary of the scan results for the artifact. Check the [`NativeReportSummary`][harborapi.models.NativeReportSummary] API reference for all the possible fields.

```py
print("Status:", artifact.scan_overview.status)
print("Severity:", artifact.scan_overview.severity)
print("Report ID:", artifact.scan_overview.id)
# etc.
```


The [`scan_overview.summary`][harborapi.models.NativeReportSummary.summary] field is a [`VulnerabilitySummary`][harborapi.models.VulnerabilitySummary] object, which we can use to get a summary of the number of vulnerabilities found:

```py
print("Critical:", artifact.scan_overview.summary.critical)
print("High:", artifact.scan_overview.summary.high)
print("Medium:", artifact.scan_overview.summary.medium)
print("Low:", artifact.scan_overview.summary.low)
print("Unknown:", artifact.scan_overview.summary.unknown)
print("Total:", artifact.scan_overview.summary.total)
print("Fixable:", artifact.scan_overview.summary.critical)
```

## Specific MIME type scan overview

If we want to fetch the scan overview given a specific MIME-type, we can use the `mime_type` argument. This will fetch the scan overview for the artifact, but only for the specified MIME-type.

```py hl_lines="6"
artifact = await client.get_artifact(
        "library",
        "hello-world",
        "latest",
        with_scan_overview=True,
        mime_type="application/vnd.security.vulnerability.report; version=1.1",
)
```
