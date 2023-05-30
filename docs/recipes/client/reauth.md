# Change client credentials

To change the authentication credentials and/or API URL after the client has been instantiated, we can use the [`authenticate`][harborapi.HarborAsyncClient.authenticate] method:

```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://example.com/api/v2.0",
    username="user1",
    secret="user1pw",
)

# Client uses API @ https://example.com as user1
await client.get_projects()

# NOTE: not async!
client.authenticate(
    username="user2",
    secret="user2pw",
    url="https://demo.goharbor.io/api/v2.0",  # optionally set a new url
)

# Client uses API @ https://demo.goharbor.io as user2
await client.get_projects()
```

We can also use it to only set a new URL:

```py
client.authenticate(url="https://demo.goharbor.io/api/v2.0")
```
