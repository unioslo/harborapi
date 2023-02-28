# Response log

The `HarborAsyncClient` keeps track of all responses it receives in a response log. This is a [`ResponseLog`][harborapi.client.ResponseLog] object, which contains a list of [`ResponseLogEntry`][harborapi.client.ResponseLogEntry] objects, and can be accessed via the [`response_log`][harborapi.client.HarborAsyncClient.response_log] attribute of the client. Each entry contains the request URL, the request method, the response status code, the response duration, and the size of the response body.



```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)

await client.get_system_info()
await client.get_system_info()
await client.get_system_info()

print(client.response_log)
```

```
[
    <ResponseLogEntry [GET https://demo.goharbor.io/api/v2.0/systeminfo 200]>,
    <ResponseLogEntry [GET https://demo.goharbor.io/api/v2.0/systeminfo 200]>,
    <ResponseLogEntry [GET https://demo.goharbor.io/api/v2.0/systeminfo 200]>,
]
```

[`ResponseLog`][harborapi.client.ResponseLog] behaves like an iterable and supports indexing, iteration and sizing:

```py
client.response_log[0]
client.response_log[-1]
client.response_log[1:3]
len(client.response_log)
for response in client.response_log:
    pass
```

## Last response

The last response can be accessed via the [`last_response`][harborapi.client.HarborAsyncClient.last_response] attribute of the client:

```py
print(client.last_response)
```

```py
<ResponseLogEntry [GET https://demo.goharbor.io/api/v2.0/systeminfo 200]>
```

If no responses are stored, this returns `None`.

## Limiting log size

By specifying the `max_logs` parameter when constructing the client, the response log will be limited to the specified number of responses.


```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(..., max_logs=2)

await client.get_system_info()
await client.get_system_info()
await client.get_system_info()

print(client.response_log)
```

```py
[
    <ResponseLogEntry [GET https://demo.goharbor.io/api/v2.0/systeminfo 200]>,
    <ResponseLogEntry [GET https://demo.goharbor.io/api/v2.0/systeminfo 200]>,
    <ResponseLogEntry [GET https://demo.goharbor.io/api/v2.0/systeminfo 200]>,
]
```

The response log operates with a FIFO (first in, first out) policy, meaning that the oldest response will be removed when the log is full.

### Adjusting the limit

The maximum size of the response log can be adjusted on the fly with the [`ResponseLog.resize()`][harborapi.client.ResponseLog.resize] method:

```py
client.response_log.resize(3)
assert client.response_log.entries.maxlen == 3 # implementation detail
```

## Clear the log

The response log can be cleared with the [`ResponseLog.clear()`][harborapi.client.ResponseLog.clear] method:

```py
client.response_log.clear()
assert len(client.response_log) == 0
```
