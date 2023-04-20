# Get artifact owner

We can fetch information about owners of artifacts using [`harborapi.ext.api.get_artifact_owner`][harborapi.ext.api.get_artifact_owner]. The function takes in a [`harborapi.models.Artifact`][harborapi.models.Artifact] or [`harborapi.ext.artifact.ArtifactInfo`][harborapi.ext.artifact.ArtifactInfo] object, and returns a [`harborapi.models.UserResp`][harborapi.models.UserResp] object.


!!! warning
    The method requires elevated privileges, as it has to look up information about users. A lack of privileges will likely result in [`harborapi.exceptions.Unauthorized`][harborapi.exceptions.Unauthorized] being raised.

```py
import asyncio

from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(...)

sync def main() -> None:
    artifacts = await api.get_artifacts(client, projects=["library"])
    for artifact in artifacts:
        try:
            owner_info = await api.get_artifact_owner(client, artifact.artifact)
        except ValueError as e:
            # something is wrong with the artifact, and we can't fetch its owner
            print(e)
        else:
            print(owner_info)


if __name__ == "__main__":
    asyncio.run(main())
```

In the above example, we fetch all artifacts in the `library` project, and then fetch the owner information for each artifact. If the artifact is not owned by a user or does not belong to a project, the function will raise a `ValueError`.

The function returns a [`UserResp`][harborapi.models.UserResp] object, which contains information about the owner of the artifact.

See [api.get_artifacts][harborapi.ext.api.get_artifacts] and [api.get_artifact_owner][harborapi.ext.api.get_artifact_owner] for more information.
