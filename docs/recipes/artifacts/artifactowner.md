# Get artifact owner

Retrieve user information about the owners of artifacts in a project.


!!! note
    The function [`api.get_artifact_owner`][harborapi.ext.api.get_artifact_owner] requires elevated privileges in order to to work. This is because the API endpoint used to fetch the owner information requires permissions to view user info.

```py title="artifactowner.py"
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
