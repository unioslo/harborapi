# Artifact info

The `harborapi.ext.artifact` module defines the [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] class, which is a class that is composed of multiple Harbor API models:

* [`Artifact`][harborapi.models.models.Artifact]
* [`Repository`][harborapi.models.models.Repository]
* [`HarborVulnerabilityReport`][harborapi.models.scanner.HarborVulnerabilityReport]

Which in simplified Python code looks like this:

```py
class ArtifactInfo:
    artifact: Artifact
    repository: Repository
    report: HarborVulnerabilityReport
```

The [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] class thus provides the complete information for a given artifact, including its repository and its vulnerability report. This makes all the information about an artifact available in one place.

Several helper methods are defined to make use of the information available in the `ArtifactInfo` object. See the [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo]  object reference for more information.

Most functions defined in `harborapi.ext.api` return [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo]  objects (or lists of them), unless otherwise specified.


## Why `ArtifactInfo`?

The [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] class exists because the full information about an artifact is not returned by [`HarborAsyncClient.get_artifact`][harborapi.client.HarborAsyncClient.get_artifact] due to the way the API specification is written. The API specification for an [`Artifact`][harborapi.models.models.Artifact] does not include its repository name (the name by which you usally refer to the artifact, e.g. _library/hello-world_), nor its vulnerabilities.

To that end, we also need to fetch the artifact's [`Repository`][harborapi.models.models.Repository] in a separate API call. This gives us the project name and the repository name for the artifact, among other things.

Furthermore, if we wish to fetch the vulnerabilities of an Artifact, we need to fetch its [`HarborVulnerabilityReport`][harborapi.models.scanner.HarborVulnerabilityReport]. This is, again, a separate API call. The report we get from [`HarborAsyncClient.get_artifact(..., with_scan_overview=True)`][harborapi.client.HarborAsyncClient.get_artifact] is not sufficient, as it is merely an overview of the vulnerabilities, not the full report. Hence the need for this separate API call.

Together, these 3 models combine to make an [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] object.

Through functions such as `harborapi.ext.get_artifacts` and `harborapi.ext.get_artifact_vulnerabilities`, we can fetch multiple artifacts and their associated repo and report with a single function call, which also executes the requests concurrently. This is much more efficient than fetching each artifact, repo, and report individually and in sequence.
