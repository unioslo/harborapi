# Get all artifacts and their vulnerabilities in all projects

Similar to `get_artifacts`, except each artifact's complete vulnerability report is also fetched in addition to the artifacts and their repositories. This function completely replaces `get_artifacts` in such cases.

The major difference between the two functions is that each [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] object has its `report` field populated by a [`HarborVulnerabilityReport`][harborapi.models.scanner.HarborVulnerabilityReport] object. The report is fetched for each artifact individually, which can cause some strain on your Harbor instance. As such, it is advised to use the `max_connections` argument to limit the number of concurrent requests this function makes (by default 5).
