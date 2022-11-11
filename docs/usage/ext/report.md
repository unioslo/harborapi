# Reports

The `ext.report` module defines the [`ArtifactReport`][harborapi.ext.report.ArtifactReport] class, which aggregates several [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] objects. Through this class, one can query the aggregated data for all artifacts affected by a given vulnerability, all artifacts who has a given vulnerable package, etc.

This allows for a deeper analysis of the vulnerabilities in your Harbor instance, and can be used to generate reports for your Harbor instance.

Given a list of ArtifactInfo objects, we can query the aggregated data to find all artifacts affected by a given vulnerability:

```py
from harborapi import HarborAsyncClient
from harborapi.ext.api import get_artifact_vulnerabilities
from harborapi.ext.report import ArtifactReport

client = HarborAsyncClient(...)

artifacts = await get_artifact_vulnerabilities(client)

report = ArtifactReport(artifacts)
affected_artifacts = await report.with_cve("CVE-2020-0001")

for artifact in affected_artifacts:
    print(artifact.repository.name, artifact.artifact.digest)
```
