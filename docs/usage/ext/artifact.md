# Artifact info

The `ext.artifact` module defines the `ArtifactInfo` class, which is a class that is composed of several different Harbor API models. These models are:

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

The `ArtifactInfo` thus provides the complete information for a given artifact, including its repository and its vulnerability report. This makes all the information about an artifact available in one place.

Several helper methods are defined to make use of the information available in the `ArtifactInfo` object. See the [ArtifactInfo reference][harborapi.ext.artifact.ArtifactInfo] for more information.

Most functions defined in `ext.api` return `ArtifactInfo` objects (or lists of them), unless otherwise specified.


## Why `ArtifactInfo`?

The [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] class exists because the full information about an artifact is not returned by [`HarborAsyncClient.get_artifact`][harborapi.client.HarborAsyncClient.get_artifact] due to the way the API specification is designed. The API specification for an [`Artifact`][harborapi.models.models.Artifact] does not include its repository name (the name by which you usally refer to the artifact with, e.g. _library/myimage_), nor its vulnerabilities.

To that end, we also need to fetch the artifact's [`Repository`][harborapi.models.models.Repository] in a separate API call. This gives us the project name and the repository name for the artifact, among other things.

Furthermore, if we wish to fetch the vulnerabilities of an Artifact, we need to fetch its [`HarborVulnerabilityReport`][harborapi.models.scanner.HarborVulnerabilityReport]. This is, again, a separate API call, and it is not returned by [`HarborAsyncClient.get_artifact`][harborapi.client.HarborAsyncClient.get_artifact] either (though you can get a summary of the vulnerability report with `get_artifact(..., with_scan_overview=True)`).
