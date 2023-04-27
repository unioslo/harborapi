## Get current user

To fetch information about the currently authenticated API user, we can use the [`get_current_user`][harborapi.client.HarborAsyncClient.get_current_user] method. It returns a [`UserResp`][harborapi.models.UserResp] object.


```py
import asyncio

from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main():
    res = await client.get_current_user()
    print(res)


asyncio.run(main())
```

Produces something like this:

```py
UserResp(
    email=None,
    realname='Firstname Lastname',
    comment='from LDAP.',
    user_id=123,
    username='firstname-lastname',
    sysadmin_flag=False,
    admin_role_in_auth=True,
    oidc_user_meta=None,
    creation_time=datetime.datetime(2022, 7, 1, 13, 19, 36, 26000, tzinfo=datetime.timezone.utc),
    update_time=datetime.datetime(2022, 7, 1, 13, 19, 36, 26000, tzinfo=datetime.timezone.utc)
)
```
