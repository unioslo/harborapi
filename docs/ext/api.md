# API

The `ext.api` module contains helper functions that take in a `HarborAsyncClient` and use it to provide new or extended functionality. In most cases, the functions return [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] objects, which is composed of an artifact, its repository and optionally also the artifact's complete vulnerability report.

## Get an Artifact and its Vulnerabilities by Digest

The [`get_artifactinfo_by_digest`][harborapi.ext.api.get_artifactinfo_by_digest] function fetches an [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] object with its `report` field populated for the artifact with the given digest. If no artifact with the given digest exists, `None` is returned.

### Example

```py
get_artifactinfo_by_digest()
```


## Get All Artifacts in (All) Repositories


Returns a list of [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] objects, where the `artifact` and `repository` fields are populated, while `report` is not.

### Example

```py
get_artifacts()
```


## Get All Artifacts and Their Vulnerabilities in All Projects

Similar to `get_artifacts`, except each artifact's complete vulnerability report is also fetched in addition to the artifacts and their repositories. This function completely replaces `get_artifacts` in such cases.

The major difference between the two functions is that each [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] object has its `report` field populated by a [`HarborVulnerabilityReport`][harborapi.models.scanner.HarborVulnerabilityReport] object. The report is fetched for each artifact individually, which can cause some strain on your Harbor instance. As such, it is advised to use the `batch_size` argument to limit the number of concurrent requests this function makes.

### Example

```py
get_artifact_vulnerabilities()
```



## Get All Repositories in a Project

### Example

```py
get_repositories()
```
