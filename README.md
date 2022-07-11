# Harbor API

Python async API wrapper for the Harbor v2.0 REST API.

## Features

- Async API
- Fully typed
- Data validation with [Pydantic](https://pydantic-docs.helpmanual.io/)
- HTTP handled by [HTTPX](https://www.python-httpx.org/)
- Extensive test coverage powered by [Hypothesis](https://hypothesis.works/)

## Implemented endpoints

- [x] user
- [ ] gc
- [x] scanAll
- [ ] configure
- [ ] usergroup
- [ ] preheat
- [ ] replication
- [ ] label
- [ ] robot
- [ ] webhookjob
- [ ] icon
- [ ] project
- [ ] webhook
- [x] scan
- [ ] member
- [ ] ldap
- [x] registry
- [x] search
- [x] artifact
- [ ] immutable
- [ ] retention
- [x] scanner
- [x] systeminfo**
- [x] statistic
- [x] quota
- [x] repository
- [x] ping
- [x] oidc
- [x] SystemCVEAllowlist
- [x] Health
- [ ] robotv1
- [ ] projectMetadata
- [x] auditlog

\*\* `/systeminfo/getcert` NYI


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

## Exception Handling (WIP)

All methods raise exceptions derived from `harborapi.exceptions.StatusError` for responses with non-2xx status codes unless otherwise specified.

### Status Code

```py
try:
    await client.delete_artifact("project", "repository", "latest")
except StatusError as e:
    print(e.status_code)
```

### Granular Exception Handling

If more granular exception handling is required, all documented HTTP exceptions in the API spec are implemented as discrete classes derived from `StatusError`

```py
from harborapi.exceptions import (
    BadRequest,
    Forbidden,
    NotFound,
    Unauthorized,
    PreconditionFailed,
    InternalServerError,
    StatusError
)

project, repo, tag = "testproj", "testrepo", "latest"

try:
    await client.delete_artifact(project, repo, tag)
except NotFound as e:
    print(f"'{repo}:{tag}' not found for project '{project}'")
except StatusError as e:
    # catch all other HTTP exceptions
```

### Inspecting Errors

The `StatusError.errors` attribute contains a list of `Error` objects that contain
more detailed information about the error(s) that have occured.

```py
try:
    await client.delete_artifact("project", "repository", "latest")
except StatusError as e:
    for error in e.errors:
        print(error.code, error.message)
```

An `Error` object has the following structure

```py
class Error(BaseModel):
    code: Optional[str] = Field(None, description="The error code")
    message: Optional[str] = Field(None, description="The error message")
```

(It is likely that `code` and `message` are both not `None` on runtime, but the API specification states that both these fields are optional.)

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
