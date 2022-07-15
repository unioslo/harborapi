# Sync Client

When using the non-async client [`HarborClient`][harborapi.HarborClient], all methods are invoked identically to methods on [`HarborAsyncClient`][harborapi.client.HarborAsyncClient], except the `await` keyword in front of the method call is omitted.

### Example

```py
import asyncio
from harborapi import HarborClient

client = HarborClient(
    url="https://your-harbor-instance.com/api/v2.0",
    username="username",
    secret="secret",
)

res = client.get_current_user()
```
