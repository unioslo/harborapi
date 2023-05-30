# Logging

The library uses the standard Python logging library for logging purposes, and provides a single logger named `harborapi`. The logger is disabled by default, but can be enabled if desired.


## Enable logging

Logging can be enabled by passing in `logging=True` to the client constructor:

```python hl_lines="7"
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://harbor.example.com/api/v2.0",
    username="admin",
    secret="password",
    logging=True,
)
```

Alternatively, it can be enabled by setting the `HARBORAPI_LOGGING` environment variable to `1`:

```bash
HARBORAPI_LOGGING=1 python myscript.py
```

When logging is enabled, the handler will be configured to log to stderr with the log level set to `INFO`.

## Configure logging

Should you wish to configure the logger, you can import it and configure it as you would any other logger:

```python
import logging
from harborapi.log import logger

logger.setLevel(logging.DEBUG)
# ... other changes to the logger
```

## Limitations

* Currently, the library uses a single logger for all logging purposes. This means that it is not possible to enable logging for only a specific part of the library or individually configure loggers for multiple clients.
* Configuring logging for one `HarborAsyncClient` instance will affect all other instances, should you have multiple client instances.
* The library does not support changing the log level through the `HarborAsyncClient` constructor nor env vars. If you wish to change the log level, you must do so through the logger itself. See [Configure logging](#configure-logging) for an example of how to do this.
* Logging to streams other than stderr is not directly supported through the `HarborAsyncClient` constructor. However, you can configure the logger object to change the handler or add one to log to a different stream.
