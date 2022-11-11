# Fetching Vulnerabilities from All Artifacts

This page describes how to fetch all vulnerabilities from all artifacts in all repositories in all (or a subset of) projects.

The recipe below demonstrates how to fetch all artifacts that have vulnerabilities affecting OpenSSL version 3.x.

The recipe makes use of the built-in rate limiting implemented in [`get_artifact_vulnerabilities`][harborapi.ext.api.get_artifact_vulnerabilities]. By default, a maximum of 5 requests are sent concurrently, which prevents accidentally performing a DoS attack on your Harbor instance.

Attempting to fetch too many resources simultaneously can lead to extreme slowdowns and in some cases completely locking up your Harbor instance. Experiment with the `max_connections` argument of [`get_artifact_vulnerabilities`][harborapi.ext.api.get_artifact_vulnerabilities] to find the optimal value for your Harbor instance.

```py
import asyncio
import os
from pathlib import Path
from typing import List, Optional
from harborapi import HarborAsyncClient
from auspex2.harbor.api import get_artifact_vulnerabilities
from auspex2.harbor.artifact import ArtifactInfo
from auspex2.report import ArtifactReport

client = HarborAsyncClient(
    url="<your-harbor-url>",
    credentials="",
    logging=True,
    timeout=120.0,
)


async def main():
    artifacts = await get_artifact_vulnerabilities(
        client,
        max_connections=5, # number of concurrent requests
        exc_ok=True,
    )

    report = ArtifactReport(artifacts, remove_duplicates=False)
    print_openssl_info(report)
    print()


def print_openssl_info(report: ArtifactReport) -> None:
    for artifact in report.with_package("openssl"):
        version = get_openssl_version(artifact)
        if version is None or not version.startswith("3"):
            continue
        digest = artifact.artifact.digest
        if digest:
            digest = digest[:15]  # mimic harbor digest notation
        print(f"{artifact.repository.name}@{digest}: OpenSSL version: {version}")


def get_openssl_version(artifact: ArtifactInfo) -> Optional[str]:
    """Get the highest affected OpenSSL version for the artifact."""
    max_version = None
    for vuln in artifact.vulns_with_package("openssl"):
        if not max_version:
            max_version = vuln.version
        else:
            max_version = max(max_version, vuln.version)
    return max_version



asyncio.run(main())
```

Example output:

```txt
library/foo@sha256:f2f9fddc: OpenSSL version: 3.0.2-0ubuntu1.6
other-project/bar@sha256:b498b376: OpenSSL version: 3.0.2-0ubuntu1.6
legacy/baz@sha256:ddf6b9db: OpenSSL version: 3.0.2-0ubuntu1.6
```
