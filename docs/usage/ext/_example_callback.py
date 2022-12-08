import asyncio
import os
from typing import List

from httpx._exceptions import HTTPError

from harborapi import HarborAsyncClient
from harborapi.ext import api

client = HarborAsyncClient(
    url=os.getenv("HARBOR_URL"),
    credentials=os.getenv("HARBOR_CREDENTIALS"),
)


def handle_exceptions(exceptions: List[Exception]) -> None:
    if not exceptions:
        return
    print("The following exceptions occurred:")
    for e in exceptions:
        if isinstance(e, HTTPError):
            print(f"HTTPError: {e.request.method} {e.request.url}")
        else:
            print(e)


async def main() -> None:
    artifacts = await api.get_artifacts(
        client,
        projects=["library"],
        callback=handle_exceptions,
    )
    for artifact in artifacts:
        print(artifact.artifact.digest)


if __name__ == "__main__":
    asyncio.run(main())
