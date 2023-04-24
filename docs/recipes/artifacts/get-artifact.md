# Get artifact

We can fetch a single artifact using [`get_artifact`][harborapi.client.HarborAsyncClient.get_artifact]. The method takes a project name, repositry name and a tag or digest. It returns an [`Artifact`][harborapi.models.Artifact] object.


```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    artifact = await client.get_artifact("library", "hello-world", "latest")
    # or
    artifact = await client.get_artifact(
        "library", "hello-world", "sha256:123456abcdef..."
    )


asyncio.run(main())
```

We can optionally fetch a number of extra attributes for the artifact using any of the following arguments:

- `with_tag` - Fetches the tags for the artifact. This is a list of [`Tag`][harborapi.models.Tag] objects.
- `with_label` - Fetches the labels for the artifact (`False` by default). This is a list of [`Label`][harborapi.models.Label] objects.
- `with_scan_overview` - Fetches the scan overview for the artifact. This is a [`ScanOverview`][harborapi.models.ScanOverview] object.
- `with_signature` - Fetches the signature for the artifact.
- `with_immutable_status` - Fetches the immutable status for the artifact.
- `with_accessory` - Fetches the accessories for the artifact. This is a list of [`Accessory`][harborapi.models.Accessory] objects.

All these arguments can be mixed and matched, and will control the attributes that are fetched for the artifact.

See below for examples of how to use these arguments and what they return.


## Fetching tags

We can fetch the tags for an artifact using the `with_tag` argument. This will populate the `tags` field of the artifact with a list of [`Tag`][harborapi.models.Tag] objects. This parameter is `True` by default, so we only need to specify this if we _don't_ want to fetch the tags.


```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    artifact = await client.get_artifact(
        project="library",
        repository="hello-world",
        reference="latest"
        with_tag=True,
    )

    for tag in artifact.tags:
        print(tag.name)


asyncio.run(main())
```


## Fetching labels

We can fetch the labels for an artifact using the `with_tag` argument. This will populate the [`labels`][harborapi.models.Artifact.labels] field of the artifact with a list of [`Label`][harborapi.models.Label] objects. This parameter is `False` by default.


```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    artifact = await client.get_artifact(
        project="library",
        repository="hello-world",
        reference="latest"
        with_label=True,
    )

    for label in artifact.labels:
        print(label.name)


asyncio.run(main())
```


## Fetching scan overview

We can fetch the scan overview for an artifact using the `with_scan_overview` argument. This will populate the [`scan_overview`][harborapi.models.Artifact.scan_overview] field of the artifact with a [`ScanOverview`][harborapi.models.ScanOverview] object. This object contains a brief overview of the scan results for the artifact. To fetch the full vulnerability report (a separate API call), see the [Get artifact vulnerability report](get-artifact-vulnerabilities.md) recipe.

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

### Specific MIME type scan overview

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
