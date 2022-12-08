import asyncio
import os

from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(
    url=os.getenv("HARBOR_URL"),
    credentials=os.getenv("HARBOR_CREDENTIALS"),
)


async def main() -> None:
    artifacts = await api.get_artifacts(
        client,
        projects=["library", "mirrors"],
        repositories=["alpine", "busybox", "debian", "internal-repo"],
        tag="latest",
    )
    for artifact in artifacts:
        print(artifact.artifact.digest)


if __name__ == "__main__":
    asyncio.run(main())
