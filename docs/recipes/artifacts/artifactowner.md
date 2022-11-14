# Get artifact owner

Retrieve the complete information about the owner of the project an artifact belongs to.

```py title="all_artifacts.py"
from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    username="username",
    secret="secret",
)

async def main() -> None:
    artifacts = await api.get_artifacts(client)
    for artifact in artifacts:
        owner_info = api.get_artifact_owner(client, artifact)
```

```py
async def get_artifact_owner(client: HarborAsyncClient, artifact: Artifact) -> UserResp:
    project_id = artifact.project_id
    if project_id is None:
        raise ValueError("Artifact has no project_id")
    project = await client.get_project(project_id)
    if project.owner_id is None:
        raise ValueError("Project has no owner_id")
    return await client.get_user(project.owner_id)
```
