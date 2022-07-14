# Geting Started

This page contains examples on how to instantiate and use `HarborAsyncClient`.


## Instantiate Client

The client can be instatiated with either a username and password, a base64-encoded [HTTP Basic Access Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) credential string, or JSON-encoded Harbor credentials file.

### Username and Password

Username and password (titled `secret` to conform with Harbor naming schemes) can be used by instantiating the client with the `username` and `secret` parameters. This is the most straight forward method of authenticating.

```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    username="username",
    secret="secret",
)
```

### Basic Access Authentication Credentials

In place of `username` and `secret`, a Base64-encoded [HTTP Basic Access Authentication](https://en.wikipedia.org/wiki/Basic_access_authentication) credentials string can be used to authenticate.
This string is simply `username:secret` encoded to Base64, and as such provides no stronger security than username and password authentication; it only obscures the actual values.

```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    credentials="base64_string_here",
)
```

### Credentials File

When [creating Robot accounts](https://goharbor.io/docs/1.10/working-with-projects/project-configuration/create-robot-accounts/), the robot account's credentials can be exported as a JSON file. The `credentials_file` parameter takes an argument specifying the path to such a file.

```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    url="https://your-harbor-instance.com/api/v2.0",
    credentials_file="/path/to/file.json",
)
```
## Examples

This section contains some basic examples showing the general usage of `harborapi`. Consult the [Endpoints Reference](../endpoints/_overview.md) for an overview of all the available client methods.

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

Produces:

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

### Get Artifacts

```py
await client.get_artifacts("project", "repository")
```

Produces:

```py
[
    Artifact(
        id=1,
        type='IMAGE',
        media_type='application/vnd.docker.container.image.v1+json',
        manifest_media_type='application/vnd.docker.distribution.manifest.v2+json',
        project_id=1,
        repository_id=1,
        digest='sha256:f8410cc846de810e23ada839511f04efd998e0e4728d63ea997001f4ead0acac',
        size=106474226,
        icon='sha256:0048162a053eef4d4ce3fe7518615bef084403614f8bca43b40ae2e762e11e06',
        push_time=datetime.datetime(2022, 7, 4, 8, 18, 46, 891000, tzinfo=datetime.timezone.utc),
        pull_time=datetime.datetime(2022, 7, 4, 8, 19, 7, 131000, tzinfo=datetime.timezone.utc),
        extra_attrs=ExtraAttrs(...),
        annotations=None,
        references=None,
        tags=[Tag[...], Tag[...]],
        labels=None,
        scan_overview=None,
        accessories=None,
    ),
    Artifact(
        ...
    ),
    ...
]
```

Passing `with_scan_overview=True` will also include a `NativeReportSummary` if possible (otherwise `ScanOverview`) along with the artifact if the artifact has a scan report associated with it.

```py
await client.get_artifacts("project", "repository", with_scan_overview=True)
```

```py
Artifact(
    ...,
    scan_overview=NativeReportSummary(
        report_id='a0c40f3b-0403-441b-72e6-38cc725e3bfb',
        scan_status='Success',
        severity='Critical',
        duration=20,
        summary=VulnerabilitySummary(
            total=1179,
            fixable=394,
            critical=3,
            high=50,
            medium=615,
            low=511,
            summary={'Critical': 3, 'High': 50, 'Low': 511, 'Medium': 615},
        ),
        start_time=datetime.datetime(2022, 7, 4, 8, 18, 58, tzinfo=datetime.timezone.utc),
        end_time=datetime.datetime(2022, 7, 4, 8, 19, 18, tzinfo=datetime.timezone.utc),
        complete_percent=100,
        version='v0.29.2'
    ),
)
```
