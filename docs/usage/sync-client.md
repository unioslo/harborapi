# Sync Client

When using the non-async client `HarborClient`, all methods are invoked identically to methods on `HarborAsyncClient`, except the `await` keyword in front of the method call is omitted.

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
