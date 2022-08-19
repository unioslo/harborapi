# Get Artifact Owner

Fetch the complete user information for the owner of the project an artifact belongs to.

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
