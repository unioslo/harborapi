# API

The `ext.api` module contains helper functions that take in a `HarborAsyncClient` and use it to provide new or extended functionality. In most cases, the functions return [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] objects, which is composed of an artifact, its repository and optionally also the artifact's complete vulnerability report.


## Get All Artifacts in (All) Repositories


Returns a list of [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] objects, where the `artifact` and `repository` fields are populated, while `report` is not.

### Example

```py
get_artifacts()
```




### Example

```py
get_artifact_vulnerabilities()
```



## Get All Repositories in a Project

### Example

```py
get_repositories()
``` -->
