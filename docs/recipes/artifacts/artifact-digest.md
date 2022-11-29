## Get an artifact and its vulnerabilities by digest

The [`get_artifactinfo_by_digest`][harborapi.ext.api.get_artifactinfo_by_digest] function fetches an [`ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] object with its `report` field populated for the artifact with the given digest. If no artifact with the given digest exists, `None` is returned.
