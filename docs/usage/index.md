# Usage

Most of the time you'll be instantiating a `harborapi.HarborAsyncClient` object and using it to interact with the Harbor API.

The `HarborAsyncClient` strives to provide most endpoints in the Harbor API spec as methods. See [Endpoints](/endpoints) for a complete list of implemented endpoints on `HarborAsyncClient`.

The methods are all asynchronous, and must be used in an async context, meaning they must be awaited inside an async function. If you are unsure how to do this, the FastAPI package's docs has a [good section on `async` and `await`](https://fastapi.tiangolo.com/async/#async-and-await). The examples in [Examples](./methods/examples.md) and [Recipes](../recipes/index.md) should give a fairly good idea of how to use the client.


```python
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)
```

There are multiple ways to authenticate with the Harbor API, and they are documented on the [Authentication](authentication.md) page, along with a few examples of basic usage. For more advanced usage, check out the [Recipes](/recipes) section.
