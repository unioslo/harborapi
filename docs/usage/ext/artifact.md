# Artifact Info

The `ext.artifact` module defines the `ArtifactInfo` class that composes several different Harbor API models into one object. The models it is composed of are:

* [`Artifact`][harborapi.models.models.Artifact]
* [`Repository`][harborapi.models.models.Repository]
* [`HarborVulnerabilityReport`][harborapi.models.scanner.HarborVulnerabilityReport]

This thus provides the complete information for a given artifact, including its repository and its vulnerability report. Through this, it is possible to easily access all information about an artifact in one place.

Several helper methods are defined to make use of the information available in the `ArtifactInfo` object.

Most functions defined in `ext.api` return `ArtifactInfo` objects.


## Why `ArtifactInfo`?

The [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] class exists because the full information about an artifact is not returned by [`HarborAsyncClient.get_artifact`][harborapi.client.HarborAsyncClient.get_artifact] due to the way the API specification is designed. The API specification for an [`Artifact`][harborapi.models.models.Artifact] does not include its repository name (the name by which you usally refer to the artifact with, e.g. _library/myimage_), nor its vulnerabilities.

To that end, we also need to fetch the artifact's [`Repository`][harborapi.models.models.Repository] in a separate API call. This gives us the project name and the repository name for the artifact, among other things.

Furthermore, if we wish to fetch the vulnerabilities of an Artifact, we need to fetch its [`HarborVulnerabilityReport`][harborapi.models.scanner.HarborVulnerabilityReport]. This is, again, a separate API call, and it is not returned by [`HarborAsyncClient.get_artifact`][harborapi.client.HarborAsyncClient.get_artifact] either (though you can get a summary of the vulnerability report with `get_artifact(..., with_scan_overview=True)`).

## What is `ArtifactInfo`?

[`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] is a class that is composed of the 3 aforementioned classes in order to provide a single object with the complete information of an artifact, and an interface that is more convenient to work with than having to manually stitch together the information from the 3 different classes.

The `ext.report` module contains functionality for taking multiple `ArtifactInfo` objects and aggregating them into a single `ArtifactReport` object. This can then in turn be used to query the aggregated data for all artifacts affected by a given vulnerability, all artifacts who have a given vulnerable package, and more. See [`ext.report`](./report.md) for more information.
