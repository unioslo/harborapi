# `harborapi.ext`
The `harborapi.ext` module provides additional functionality for common tasks such as concurrency and aggregation of multiple API calls. The recipes in this section make use of this module.

Everything the `harborapi.ext` module provides is also available in the `harborapi` module, just without the built-in concurrency and aggregation functionality. For example, [harborapi.ext.api.get_repositories][] is also available as [harborapi.HarborAsyncClient.get_repositories][]. The `harborapi.ext` module is mostly a convenience wrapper around the `harborapi` module.
