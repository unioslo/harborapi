# Privileged robot accounts

By default, the Robot account creation process in the Harbor web interface only allows for a limited permission scope when creating new Robot accounts. As of Harbor v.2.5.2, this is still the case.

In order to circumvent this limitation, one can create robot accounts through the API with system resource permissions that go beyond the options offered in the web interface.

This page is based on [this](https://github.com/goharbor/harbor/issues/14145#issuecomment-781006533) comment by Harbor developer [wy65701436](https://github.com/wy65701436). Also check out the Harbor [source code](https://github.com/goharbor/harbor/blob/main/src/common/rbac/const.go) for more information on all the possible resource permissions that can be granted to Robot accounts.

All examples on this page will be using `harborapi` to create privileged robot accounts.

## Example: Robot with project creation privileges

Following the example provided in the GitHub comment above, `harborapi` provides [`HarborAsyncClient.create_robot`][harborapi.client.HarborAsyncClient.create_robot] to achieve the same functionality.

When creating privileged robot accounts, `HarborAsyncClient` must be instantiated with a privileged user's credentials.

```py title="createrobot.py"
from harborapi.models import RobotCreate, RobotPermission, Access

# Client is instantiated with administrator account.
# This is required to create robot accounts with system resource permissions.

await client.create_robot(
    RobotCreate(
        name="from_api",
        description="Created from harborapi Python client",
        secret="Secret1234",
        level="system",
        duration=30,
        permissions=[
            RobotPermission(
                kind="system",
                namespace="/",
                access=[
                    Access(resource="project", action="create"),
                ],
            )
        ],
    )
)
```

Produces:

```py
RobotCreated(
    id=11,
    name='robot$from_api',
    secret='tBuDZ700tPkKLNQ0z1EAYndMOFEzvgM8',
    creation_time=datetime.datetime(2022, 7, 14, 10, 3, 40, 906000, tzinfo=datetime.timezone.utc),
    expires_at=1660385020,
)
```

### Saving credentials to a file

The resulting Robot account can be saved to a Harbor credentials file by providing an argument to the `path` parameter specifying the location to save the credentials to. The `path` argument can be either a string or a [pathlib.Path][] object.

```py hl_lines="3"
await client.create_robot(
    RobotCreate(...),
    path="/path/to/file.json",
)
```

By default, the file must not already exist. This can be overriden by adding `overwrite=True`, which overwrites the file if it already exists.

```py hl_lines="4"
await client.create_robot(
    RobotCreate(...),
    path="/path/to/file.json",
    overwrite=True
)
```

The resulting file can then be used when instantiating `HarborAsyncClient` to authenticate with the Robot account.

```py title="from_credentials_file.py" hl_lines="5"
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    credentials_file="/path/to/file.json",
)
```


For more information, see [`HarborAsyncClient.create_robot`][harborapi.client.HarborAsyncClient.create_robot] and [`HarborAsyncClient.__init__`][harborapi.HarborAsyncClient.__init__]
