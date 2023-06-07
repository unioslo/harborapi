# Retry

The client supports retrying requests that fail due to network errors or server errors. This is useful for handling intermittent network issues or server issues. The retry functionality is powered by [backoff](https://github.com/litl/backoff). Most of the retry functionality is exposed through the [`RetrySettings`][harborapi.retry.RetrySettings] class, which is used to configure the retry behavior.

## Basic configuration

Retrying is enabled by default and uses exponential backoff to retry requests for up to a minute. The behavior of the retry functionality can be customized by passing a [`RetrySettings`][harborapi.retry.RetrySettings] object to the client constructor.

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

The default waiting strategy uses exponential backoff ([Wikipedia](https://en.wikipedia.org/wiki/Exponential_backoff), [Google](https://cloud.google.com/iot/docs/how-tos/exponential-backoff#example_algorithm)), which is represented internally by the [`backoff.expo`](https://github.com/litl/backoff/blob/d82b23c42d7a7e2402903e71e7a7f03014a00076/backoff/_wait_gen.py#L8-L32) function. See [Advanced configuration](#advanced-configuration) for how to modify and/or replace the waiting strategy.


## Changing configuration

The configuration can be changed at any time by modifying the `retry` attribute on the client object.

```py
client.retry.max_tries = 10
client.retry.max_time = 300
```

Or by replacing it altogether:

```py
client.retry = RetrySettings(
    max_tries=10,
    max_time=300,
)
```

### Validation

Pydantic will attempt to validate the assignments, so invalid values will raise a `ValidationError`.

```py
client.retry.max_tries = -1
```

Results in the following error:

```
pydantic.error_wrappers.ValidationError: 1 validation error for RetrySettings
max_tries
  ensure this value is greater than 0 (type=value_error.number.not_gt; limit_value=0)
```


## Disabling retry

Retrying can be disabled entirely by passing `retry=None` to the client constructor.

```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    ...,
    retry=None,
)
```

### `no_retry()` context manager

We can also temporarily disable retry without having to discard the current retry settings by using the [`no_retry()`][harborapi.HarborAsyncClient.no_retry] context manager. The context manager lets us disable retry for just a single block of code.

```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)

with client.no_retry():
    # do something that should not be retried
    ...

# retry settings are restored outside the block
```

## Advanced configuration

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

    # increment by value for each iteration
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
    # can (and should) raise here


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
        base=1,  # kwarg passed to adder
        value=2,  # kwarg passed to adder
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

By default, all network and timeout errors are retried, but no HTTP errors (such as 301, 404, 500, etc.) are retried. This behavior can be modified by passing a tuple of HTTP error types to the `exception` field, specifying the HTTP status code errors to be retried.

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

The `wait_gen` field takes a [`_WaitGenerator`][backoff._typing._WaitGenerator], which is a callable that takes any number of keyword arguments and returns a generator that yields floats. The generator is used to generate the wait time between retries. The default wait generator is [`backoff.expo`](https://github.com/litl/backoff/blob/d82b23c42d7a7e2402903e71e7a7f03014a00076/backoff/_wait_gen.py#L8-L32).

In the example, we define the custom wait generator function `adder`, which takes the arguments `base` and `value`. These parameters both have the default value `1`. If we want to, we can override the default arguments by passing them to the `RetrySettings` constructor as keyword arguments.

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

The `jitter` field takes a [_Jitterer][backoff._typing._Jitterer], which is callable that takes a wait value (float) generated by the wait generator and returns a float. The default jitter function is [`backoff.full_jitter`](https://github.com/litl/backoff/blob/d82b23c42d7a7e2402903e71e7a7f03014a00076/backoff/_jitter.py#L18-L28), which jitters the wait value between 0 and the original wait value.

A custom jitter function could look like this:


```py
import random

def custom_jitter(wait: float) -> float:
    return wait * random.random()


client = HarborAsyncClient(
    ...,
    retry=RetrySettings(
        jitter=custom_jitter,
    ),
)
```


### Event handlers

Furthermore, we can define custom event handlers for the `on_success`, `on_backoff` and `on_giveup` events. Event handlers are callback functions that take an argument of type [`Details`][backoff._typing.Details], which is a dictionary containing information about the current retry attempt. It has the following keys:

* `target`: reference to the function or method being invoked
* `args`: positional arguments to func
* `kwargs`: keyword arguments to func
* `tries`: number of invocation tries so far
* `elapsed`: elapsed time in seconds so far
* `wait`: seconds to wait (`on_backoff` handler only)


Check Backoff's [event handler documentation](https://github.com/litl/backoff#event-handlers) for more information on how to use the `on_backoff`, `on_giveup` and `on_success` parameters, and the `details` dict.
