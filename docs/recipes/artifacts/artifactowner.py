import asyncio

from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    credentials_file="/path/to/file.json",
)


async def main() -> None:
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
