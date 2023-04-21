# Change client credentials

To change the authentication credentials and/or API URL after the client has been instantiated, we can use the [`authenticate`][harborapi.HarborAsyncClient.authenticate] method:

```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://example.com", username="user1", secret="user1pwd"
)

# Use API @ https://example.com as user1
# ...

client.authenticate(
    username="other_user1",
    secret="new_password1",
    url="https://demo.goharbor.io/api/v2.0",  # optionally set a new url
)

# Use API @ https://demo.goharbor.io as other_user1
# ...
```

We can also use it to only set a new URL:

```py
client.authenticate(url="https://demo.goharbor.io/api/v2.0")
```
