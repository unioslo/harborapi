# Harbor API

Python async API wrapper for the Harbor v2.0 REST API.

## Usage

The client can be instatiated with either a username and password, or a base64-encoded [HTTP Basic Access Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) credential string.

### Username and Password

```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    username="username",
    secret="secret",
)
```

### Basic Access Authentication Credentials

```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    credentials="base64_string_here",
)
```


## Examples

### Get Current User

```py
import asyncio

from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    username="username",
    secret="secret",
)


async def main():
    res = await client.get_current_user()
    print(repr(res))


asyncio.run(main())
```

Displays:

```py
UserResp(email=None, realname='Firstname Lastname', comment='from LDAP.', user_id=123, username='firstname-lastname', sysadmin_flag=False, admin_role_in_auth=True, oidc_user_meta=None, creation_time=datetime.datetime(2022, 7, 1, 13, 19, 36, 26000, tzinfo=datetime.timezone.utc), update_time=datetime.datetime(2022, 7, 1, 13, 19, 36, 26000, tzinfo=datetime.timezone.utc))
```

## Non-Async Client (Blocking)

In order to support use cases where users do not want to use the async client, a non-async client exists in the form of `HarborClient`.

All methods should be invoked identically to the async client, with `await` omitted.

**NOTE:** The implementation of `HarborClient` is extremely hacky, and it is _highly_ recommended to use the async client whenever possible.

### Example

```py
import asyncio
from harborapi import HarborClient

client = HarborClient(
    loop=asyncio.new_event_loop(), # pass a new event loop from main thread
    url="https://your-harbor-instance.com/api/v2.0",
    username="username",
    secret="secret",
)

res = client.get_current_user()
print(res)
```