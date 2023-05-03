# Retry

The client supports retrying requests that fail due to network errors or server errors. This is useful for handling intermittent network issues or server issues. The retry functionality is powered by [backoff](https://github.com/litl/backoff). Most of the retry functionality is exposed through the [`RetrySettings`][harborapi.retry.RetrySettings] class, which is used to configure the retry behavior.

## Basic configuration

Retrying is enabled by default, and uses exponential backoff to retry requests for up to a minute. The behavior of the retry functionality can be customized by passing a [`RetrySettings`][harborapi.retry.RetrySettings] object to the client constructor.

```py
from harborapi import HarborAsyncClient
from harborapi.retry import RetrySettings

client = HarborAsyncClient(
    ...,
    retry=RetrySettings(
        max_tries=5,
        max_time=120,
    ),
)
```

The configuration can be changed at any time by modifying the `retry` attribute on the client object.

```py
client.retry.max_tries = 10
client.max_time = 300
```

Or by replacing it altogether:

```py
client.retry = RetrySettings(
    max_tries=10,
    max_time=300,
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

```py
from typing import Any, Generator

import backoff
from backoff._typing import Details

from harborapi import HarborAsyncClient
from harborapi.exceptions import InternalServerError, MethodNotAllowed, StatusError
from harborapi.retry import RetrySettings


def adder(
    base: float = 1,
    value: float = 1,
) -> Generator[float, Any, None]:
    """Generator that yields a number that increases by a constant value."""
    # Advance past initial .send() call
    yield  # type: ignore[misc]

    # just add the factor to the base
    while True:
        yield base
        base += value


def giveup_predicate(e: Exception) -> bool:
    # give up on 404 errors
    if isinstance(e, StatusError):
        return e.status_code == 404
    return False  # don't give up otherwise


def on_success(details: Details) -> None:
    print(f"Success after {details['tries']} tries. Elapsed: {details['elapsed']}s")


def on_giveup(details: Details) -> None:
    print(f"Giving up calling {details['target']} after {details['tries']} tries.")
    # can raise here


def on_backoff(details: Details) -> None:
    # NOTE: only on_backoff has the "wait" key in details
    print(
        f"Backing off calling {details['target']} after {details['tries']} tries for {details['wait']}s."
    )


client = HarborAsyncClient(
    ...,
    retry=RetrySettings(
        max_tries=5,
        max_time=20,
        exception=(InternalServerError, MethodNotAllowed),
        wait_gen=adder,
        base=1,  # wait_gen kwarg
        value=2,  # wait_gen kwarg
        jitter=backoff.full_jitter,  # default jitter function
        giveup=giveup_predicate,
        on_success=on_success,
        on_backoff=on_backoff,
        on_giveup=on_giveup,
        raise_on_giveup=True,
    ),
)
```

### Exception types

The `exception` field takes a single exception type or a tuple of exception types. If an exception raised by a request is an instance of one of the given exception types, the request will be retried. Other exception types are raised immediately.

By default, all network and timeout errors are retried, but no HTTP errors (301, 404, 500, etc.) are retried. We can change this behavior by passing a tuple of HTTP error types to the `exception` field with the HTTP status errors we want to retry:

```py
from harborapi.exceptions import InternalServerError, MethodNotAllowed

RetrySettings(
    exception=(InternalServerError, MethodNotAllowed),
)
```

#### Status errors

If we want to retry all HTTP errors, we can pass `StatusError` to the `exception` field:

```py
from harborapi.exceptions import StatusError

RetrySettings(
    exception=StatusError,
)
```

#### Status and network errors

If we also want to retry all status errors _and_ network errors, we can import `NetworkError` and `TimeoutException` from httpx and use them too:

```py
from httpx import NetworkError, TimeoutException
from harborapi.exceptions import StatusError

RetrySettings(
    exception=(StatusError, NetworkError, TimeoutException),
)
```

### Wait generators

In the example we define the custom wait generator function `adder`, which takes the arguments `base` and `value`. These parameters both have the default value `1`. If we want to, we can override the default arguments by passing them to the `RetrySettings` constructor as keyword arguments.

Any extra keyword arguments passed to the `RetrySettings` constructor will in turn be passed to the wait generator function:

```py
RetrySettings(
    wait_gen=adder,
    base=1,
    value=2,
)
```

Internally, `adder` uses the extra kwargs and is called like this:

```py
adder(base=1, value=2)
```

!!! note
    In the custom wait generator function `adder`, we account for the fact that `backoff` pumps the generator once before using it by yielding an initial value of `None`. This is consistent with the internal wait generator functions in `backoff` itself, such as [`backoff.expo`](https://github.com/litl/backoff/blob/d82b23c42d7a7e2402903e71e7a7f03014a00076/backoff/_wait_gen.py#L8-L32) and [`backoff.fibo`](https://github.com/litl/backoff/blob/d82b23c42d7a7e2402903e71e7a7f03014a00076/backoff/_wait_gen.py#L64-L83).

### Jitter

The `jitter` field takes a callable that takes a wait value (float) generated by the wait generator and returns a float. The default jitter function is [`backoff.full_jitter`](https://github.com/litl/backoff/blob/d82b23c42d7a7e2402903e71e7a7f03014a00076/backoff/_jitter.py#L18-L28), which jitters the wait value between 0 and the original wait value.

A custom jitter function could look like this:


```py
import random

def custom_jitter(wait: float) -> float:
    return wait * random.random()
```


### Event handlers

Furthermore, we can define custom event handlers for the `on_success`, `on_backoff` and `on_giveup` events. Event handlers are callback functions that take a `details` argument, which is a dictionary containing information about the current retry attempt. It has the following keys:

* `target`: reference to the function or method being invoked
* `args`: positional arguments to func
* `kwargs`: keyword arguments to func
* `tries`: number of invocation tries so far
* `elapsed`: elapsed time in seconds so far
* `wait`: seconds to wait (`on_backoff` handler only)


Check Backoff's [event handler documentation](https://github.com/litl/backoff#event-handlers) for more information on how to use the `on_backoff`, `on_giveup` and `on_success` parameters, and the `details` dict.
