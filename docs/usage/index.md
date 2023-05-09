# Usage

The `harborapi` library provides a class called [`HarborAsyncClient`][harborapi.HarborAsyncClient] that can be used to interact with the Harbor API. To use it, you need to create a `HarborAsyncClient` instance with your Harbor instance's API URL, as well as some authentication credentials.

The endpoint methods in the `HarborAsyncClient` class are all asynchronous, which means they can only be called inside an async function using the `await` keyword. Here's an example of using the [`get_project()`][harborapi.HarborAsyncClient.get_project] method:

```python
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://harbor.example.com/api/v2.0",
    username="admin",
    secret="password",
)

async def main() -> None:
    project = await client.get_project("library")
    print(project)

asyncio.run(main())
```

For a full list of implemented endpoints on `HarborAsyncClient`, check out the [Endpoints](../endpoints/index.md) page. If you're new to asyncio, you can find a good introduction in the [FastAPI package's docs](https://fastapi.tiangolo.com/async/#async-and-await). You can also find more examples in the [Recipes](../recipes/index.md) page. Lastly, the [offical Python asyncio documentation](https://docs.python.org/3/library/asyncio.html) contains the complete reference for the `asyncio` module as well as examples of how it's used.

There are several ways to authenticate with the Harbor API, and they are documented on the [Authentication](authentication.md) page. The [Methods](methods) page shows basic usage of the different types of methods exposed by the client object.
