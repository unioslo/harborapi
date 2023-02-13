# Examples

This page contains some basic examples showing the general usage of `harborapi`. Consult the [Endpoints Reference](/endpoints) for an overview of all the available client methods that conform to the Harbor API specification. For more specialized uses, check out [Recipes](/recipes).

## Get current user

```py title="current_user.py"
import asyncio

from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


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

## Get artifacts in a specific project and repository

```py title="get_artifacts.py" hl_lines="13"
import asyncio

from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main():
    res = await client.get_artifacts("project", "repository")
    print(res)

asyncio.run(main())


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

### Filter by tag

Providing an argument for `query` can help narrow down the results. For example, if you only want to retrieve artifacts tagged `latest`, you can pass `"tags=latest"` to `query`:

```py title="get_artifacts_filter_tag.py" hl_lines="16"
import asyncio

from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main():
    artifacts = await client.get_artifacts(
        "project",
        "repository",
        query="tags=latest",
    )
    print(res)
```

See [`HarborAsyncClient.get_artifacts`][harborapi.HarborAsyncClient.get_artifacts] for more information about possible queries.

### Including scan overview (summary)

Passing `with_scan_overview=True` will also include a [`NativeReportSummary`][harborapi.models.NativeReportSummary] in the Artifact's `summary` field. This is _not_ the full vulnerability report, but rather a summary of the report's findings.


```py title="get_artifacts_with_summary.py" hl_lines="16"
import asyncio

from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main():
    await client.get_artifacts(
        "project",
        "repository",
        with_scan_overview=True,
    )


```

```py hl_lines="8-16"
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

### Fetching an artifact's full vulnerability report

In order to fetch the full full vulnerability report of an artifact, you can use the [`HarborAsyncClient.get_artifact_vulnerabilities`][harborapi.HarborAsyncClient.get_artifact_vulnerabilities] method. This method takes the artifact's project name, repository name and digest/tag as arguments.

```py title="get_scan_report.py"
import asyncio

from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main():
    project = "project"
    repo = "repository"


    # First fetch all artifacts in a specific repository
    artifacts = await client.get_artifacts(project, repo)

    # Then fetch the full vulnerability report for each artifact
    for artifact in artifacts:
        vuln_report = await client.get_artifact_vulnerabilities(
            project,
            repo,
            artifact.digest,
        )
        # Print all critical vulnerabilities for the artifact
        for vuln in vuln_report.critical:
            print(
                f"ID: {vuln.id}, Severity: {vuln.severity}, Package: {vuln.package}, Version: {vuln.version}"
            )

asyncio.run(main())
```

The output will look something like this:

```
ID: CVE-2022-23219, Severity: Severity.critical, Package: libc-bin, Version: 2.28-10
ID: CVE-2021-33574, Severity: Severity.critical, Package: libc6, Version: 2.28-10
ID: CVE-2022-22822, Severity: Severity.critical, Package: libexpat1, Version: 2.2.6-2+deb10u1
```

The downside of this approach to fetching vulnerabilities, is that each request is performed sequentially instead of concurrently. This can be improved by using the functionality defined in [`harborapi.ext`](/usage/ext), which provides helper functions for concurrently fetching data from the Harbor API. Otherwise, you can use [`asyncio.gather`](https://docs.python.org/3/library/asyncio-task.html#asyncio.gather) yourself to perform this task concurrently.

!!! warning
    The Harbor API can be quite slow when fetching vulnerability reports. This is especially true when fetching reports for multiple artifacts at once. If too many reports are attempted to be fetched concurrently, you risk locking up your Harbor instance, and possibly even crashing it, if you have no rate limiting in place (either in your code or on the web server).
