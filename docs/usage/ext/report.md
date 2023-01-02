# Report

The `ext.report` module defines the [`ArtifactReport`][harborapi.ext.report.ArtifactReport] class, which aggregates several [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] objects. Through this class, one can query the aggregated data for all artifacts affected by a given vulnerability, all artifacts who have a given vulnerable package, etc.

This allows for a deeper analysis of the vulnerabilities affecting your artifacts, and can be used to generate reports, or to take action on the artifacts that are affected by a given vulnerability.

Given a list of ArtifactInfo objects, we can query the aggregated data to find all artifacts affected by a given vulnerability:

```py title="report_filter_cve.py" hl_lines="11"
from harborapi import HarborAsyncClient
from harborapi.ext.api import get_artifact_vulnerabilities
from harborapi.ext.report import ArtifactReport

client = HarborAsyncClient(...)

artifacts = await get_artifact_vulnerabilities(client)

# Instantiate the ArtifactReport from the fetched artifacts
report = ArtifactReport(artifacts)
filtered_report = report.with_cve("CVE-2020-0001")

# iterating on ArtifactReport yields ArtifactInfo objects
for artifact in filtered_report:
    print(artifact.repository.name, artifact.artifact.digest)
```

All `ArtifactReport.with_*` methods return new ArtifactReport objects.

## More granular package filtering

We can also query the report for all artifacts who have a given vulnerable package:

```py
filtered_report = report.with_package("openssl")
```

The search is case-insensitive by default, but can be made case-sensitive by setting the `case_sensitive` argument to `True`:

```py hl_lines="3"
filtered_report = report.with_package(
    "OpenSSL", # WARNING: package is likely named openssl!
    case_sensitive=True,
)
```

We can further narrow down the results by specifying minimum and/or maximum versions of the package:

```py hl_lines="3 4"
filtered_report = report.with_package(
    "openssl",
    min_version=(3, 0, 0),
    max_version=(3, 0, 2)
)
```

All text-based queries support regular expressions. For example, to find all artifacts with a package name that starts with `openssl`:

```py
filtered_report = report.with_package("openssl.*")
```

## Chaining filters

As previously mentioned, all `ArtifactReport.with_*` methods return new [`ArtifactReport`][harborapi.ext.report.ArtifactReport] objects, so they can be chained together to easily filter a report with multiple criteria.

```py
filtered_report = (
    report.with_package("openssl")
    .with_cve("CVE-2020-0001")
    .with_repository("my-repo")
)   .with_tag("latest")
```
