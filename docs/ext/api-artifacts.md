# Fetching Vulnerabilities from All Artifacts

This page describes how to fetch all vulnerabilities from all artifacts in all repositories in all (or a subset of) projects.

The recipe below shows how to fetch all artifacts and determine if any of them are affected by an OpenSSL 3.x vulnerability. Notice how we specify each project manually, instead of fetching from all projects.

There are two primary reasons for this:
    * We don't want to fetch all projects, as we only care about a subset of them.
    * We don't want to overload our harbor instance by requesting all artifacts at once, as this will result in a lot of concurrent requests.


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
        exc_ok=True,
    )
    artifacts.extend(project_artifacts)

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
