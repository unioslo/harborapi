# Get artifact scan overview

We can fetch the scan overview for an artifact using the `with_scan_overview` argument. This will include a brief overview of the scan results for the artifact. To fetch the full vulnerability report (a separate API call), see the [Get artifact vulnerability report](get-artifact-vulnerabilities.md) recipe.

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

This will populate the [`scan_overview`][harborapi.models.Artifact.scan_overview] field of the artifact with a mapping of the different scan overviews available for the artifact, each key being a MIME-type and each value being a [`NativeReportSummary`][harborapi.models.NativeReportSummary] object.

```py
print(list(artifact.scan_overview))
# ['application/vnd.security.vulnerability.report; version=1.1']
print(artifact.scan_overview["application/vnd.security.vulnerability.report; version=1.1"])
# NativeReportSummary(report_id="foo123", ...)
```

In almost every case, only a single scan overview will be available for the artifact. In those cases, we can use the `scan` attribute to access the first [`NativeReportSummary`][harborapi.models.NativeReportSummary] object found in the `scan_overview` mapping.

```py
print(artifact.scan)
# NativeReportSummary(report_id="foo123", ...)
```

Check the [`NativeReportSummary`][harborapi.models.NativeReportSummary] API reference for all available fields. For example, we can get the status, severity, and ID of the scan overview:

```py
print("Status:", artifact.scan.scan_status)
# 'Success'
print("Severity:", artifact.scan.severity)
# 'Critical'
print("Report ID:", artifact.scan.report_id)
# 'foo123'
```


The [`scan.summary`][harborapi.models.NativeReportSummary.summary] field is a [`VulnerabilitySummary`][harborapi.models.VulnerabilitySummary] object, which we can use to get a summary of the number of vulnerabilities found:

```py
print("Critical:", artifact.scan.summary.critical)
print("High:", artifact.scan.summary.high)
print("Medium:", artifact.scan.summary.medium)
print("Low:", artifact.scan.summary.low)
print("Unknown:", artifact.scan.summary.unknown)
print("Total:", artifact.scan.summary.total)
print("Fixable:", artifact.scan.summary.critical)
```

## Specific MIME type scan overview

If we want to fetch the scan overview given a specific MIME-type, we can use the `mime_type` argument:

```py hl_lines="6"
artifact = await client.get_artifact(
        "library",
        "hello-world",
        "latest",
        with_scan_overview=True,
        mime_type="application/vnd.security.vulnerability.report; version=1.1",
)
scan = artifact.scan_overview["application/vnd.security.vulnerability.report; version=1.1"]
```
