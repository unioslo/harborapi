# Retry

The client supports retrying requests that fail due to network errors or server errors. This is useful for handling intermittent network issues or server issues.

## Basic configuration

Retrying is enabled by default, and uses exponential backoff to retry requests for up to a minute. The behavior of the retry functionality can be customized by passing a `RetrySettings` object to the client constructor.

```py
from harborapi import HarborAsyncClient
from harborapi.retry import RetrySettings

client = HarborAsyncClient(
    ...,
    retry=RetrySettings(
        max_retries=5,
        max_time=120,
    ),
)
```


## Disabling retry

We can also disable retrying by passing `retry=None` to the client constructor.

```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    ...,
    retry=None,
)
```

## Advanced Configuration

[`RetrySettings`][harborapi.retry.RetrySettings] supports a wide range of configuration options:

```
