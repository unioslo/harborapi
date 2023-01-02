# Fetching vulnerabilities from all artifacts

This page describes how to fetch all vulnerabilities from all artifacts in all repositories in all (or a subset of) projects using the helper functions defined in [`ext.api`](/reference/ext/api.md).

The recipe demonstrates how to fetch all artifacts that have vulnerabilities affecting OpenSSL version 3.x. It makes use of the built-in rate limiting implemented in [`get_artifact_vulnerabilities`][harborapi.ext.api.get_artifact_vulnerabilities]. By default, a maximum of 5 requests are sent concurrently, which prevents the program from accidentally performing a DoS attack on your Harbor instance.

Attempting to fetch too many resources simultaneously can lead to extreme slowdowns and in some cases completely locking up your Harbor instance. Experiment with the `max_connections` argument of [`get_artifact_vulnerabilities`][harborapi.ext.api.get_artifact_vulnerabilities] to find the optimal value for your Harbor instance.



```py
import asyncio
from typing import Set

from harborapi import HarborAsyncClient
from harborapi.ext.api import get_artifact_vulnerabilities
from harborapi.ext.artifact import ArtifactInfo
from harborapi.ext.report import ArtifactReport

client = HarborAsyncClient(
    url="<your-harbor-url>",
    credentials="",
    logging=True,
    timeout=120.0,
)


async def main():
    artifacts = await get_artifact_vulnerabilities(
        client,
        max_connections=5,
    )

    # Aggregate the artifacts by making an ArtifactReport
    report = ArtifactReport(artifacts)

    # Filter report by only including artifacts with OpenSSL 3.x.y vulnerabilities
    filtered_report = report.with_package(
        "openssl", case_sensitive=False, min_version=(3, 0, 0)
    )

    for artifact in filtered_report.artifacts:
        versions = get_all_openssl_versions(artifact)
        v = ", ".join(versions)  # will likely just be 1 version
        print(f"{artifact.name_with_digest}: OpenSSL version: {v}")


def get_all_openssl_versions(artifact: ArtifactInfo) -> Set[str]:
    """Get all affected OpenSSL versions for the artifact,
    with duplicates removed."""
    return set(
        filter(None, [vuln.version for vuln in artifact.vulns_with_package("openssl")])
    )


if __name__ == "__main__":
    asyncio.run(main())
```

Example output:

```txt
library/foo@sha256:f2f9fddc: OpenSSL version: 3.0.2-0ubuntu1.6
other-project/bar@sha256:b498b376: OpenSSL version: 3.0.2-0ubuntu1.6
legacy/baz@sha256:ddf6b9db: OpenSSL version: 3.0.2-0ubuntu1.6
```

In the example above, we make use of [`ArtifactReport.with_package`][harborapi.ext.report.ArtifactReport.with_package] to filter the report to only include artifacts with vulnerabilities affecting OpenSSL version 3.x. See the [ArtifactReport reference][harborapi.ext.report.ArtifactReport] for more information on other methods that can be used to filter the report.

## Fetching from a subset of projects

In the example above we omitted the `projects` parameter for [`get_artifact_vulnerabilities`][harborapi.ext.api.get_artifact_vulnerabilities], which means that all projects will be queried. If you only want to query a subset of projects, you can pass a list of project names to the `projects` parameter.

```py hl_lines="3"
artifacts = await get_artifact_vulnerabilities(
    client,
    projects=["library", "other-project"],
    max_connections=5,
)
```
