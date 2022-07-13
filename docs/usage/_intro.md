# Usage

## Async Client

`harborapi` is predominantly focused on providing an async API for interacting with the Harbor API. The various pages in this section all assume the client is running within a coroutine where `await` can be used.

## Non-Async Client

`harborapi` provides `HarborClient` as a non-async alternative. `HarborClient` provides all the same methods as `HarborAsyncClient`, except it schedules the asynchronous methods to run as coroutines in the event loop by intercepting attribute access on the class.

All\* methods on `HarborClient` have the same interface as the methods on `HarborAsyncClient`, except `await` is not required.

It is not recommended to use this client, but is provided as an alternative if you _absolutely_ don't want to deal with anything related to `asyncio`.

See: [Sync Client](sync-client.md)

---

\* Private methods (prefixed with `_`) and HTTP methods such as `get`, `post`, etc. cannot be called without `await`.
