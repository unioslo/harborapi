# Clients

## Async Client

`harborapi` is predominantly focused on providing an async API for interacting with the Harbor API. The various code snippets on these pages all assume the instantiated client is [`HarborAsyncClient`][harborapi.client.HarborAsyncClient], and it is running within a coroutine where `await` can be used.

If you only intend to use the Async Client, skip ahead to [Getting Started](getting-started.md).

## Non-Async Client

`harborapi` provides `HarborClient` as a non-async alternative. `HarborClient` provides all the same methods as `HarborAsyncClient`, except it schedules the asynchronous methods to run as coroutines in the event loop by intercepting attribute access on the class.

All\* methods on `HarborClient` have the same interface as the methods on `HarborAsyncClient`, except `await` is not required.

It is not recommended to use this client, but is provided as an alternative if you _absolutely_ don't want to deal with anything related to `asyncio`.

See: [Sync Client](sync-client.md)

---

\* Private methods (prefixed with `_`) and HTTP methods such as `get`, `post`, etc. cannot be called without `await`.
