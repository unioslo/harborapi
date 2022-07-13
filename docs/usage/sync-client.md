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
print(res)
```

```py
UserResp(
    email=None,
    realname='Alice Bob',
    comment='I am user.',
    user_id=1234,
    username='username',
    sysadmin_flag=False,
    admin_role_in_auth=True,
    oidc_user_meta=None,
    creation_time=datetime.datetime(2022, 7, 1, 13, 19, 36, 26000, tzinfo=datetime.timezone.utc),
    update_time=datetime.datetime(2022, 7, 1, 13, 19, 36, 26000, tzinfo=datetime.timezone.utc),
)
```
