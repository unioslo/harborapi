import asyncio
from typing import Any, Awaitable, Callable, List, Optional, Sequence, TypeVar, Union

import backoff
from httpx import TimeoutException
from loguru import logger

from .. import HarborAsyncClient
from ..exceptions import NotFound
from ..models import Artifact, Repository, UserResp
from .artifact import ArtifactInfo

T = TypeVar("T")

ExceptionCallback = Callable[[List[Exception]], None]

# TODO: support passing in existing project/repo objects
async def get_artifact(
    client: HarborAsyncClient,
    project: str,
    repository: str,
    reference: str,
    with_report: bool = True,
) -> ArtifactInfo:
    """Fetch an artifact, optionally with a report.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    project : str
        The artifact's project.
    repository : str
        The artifact's repository.
    reference : str
        The artifact's reference.
    with_report : bool
        Whether or not to fetch the artifact's report if it exists.
    """
    artifact_task = asyncio.create_task(
        client.get_artifact(
            project_name=project,
            repository_name=repository,
            reference=reference,
        )
    )
    repo_task = asyncio.create_task(
        client.get_repository(
            project_name=project,
            repository_name=repository,
        )
    )

    # Wait for both tasks to complete
    await asyncio.wait([artifact_task, repo_task])  # type: ignore # not sure why mypy doesn't like this

    # Get the results of the coroutines
    artifact = artifact_task.result()
    repo = repo_task.result()

    report = None
    if with_report:
        try:
            report = await client.get_artifact_vulnerabilities(
                project_name=project,
                repository_name=repo.base_name,
                reference=reference,
            )
        except NotFound:
            pass

    kwargs = {"report": report} if report else {}
    return ArtifactInfo(artifact=artifact, repository=repo, **kwargs)


# TODO: add with_<references, labels, scan_overview> kwargs for parity
#       with the client.get_artifacts method
async def get_artifacts(
    client: HarborAsyncClient,
    projects: Optional[List[str]] = None,
    repositories: Optional[List[str]] = None,
    tag: Optional[str] = None,
    query: Optional[str] = None,
    callback: Optional[Callable[[List[Exception]], None]] = None,
    max_connections: Optional[int] = 5,
    **kwargs: Any,
) -> List[ArtifactInfo]:
    """Fetch all artifacts in all repositories.
    Optionally specify a list of repositories or projects to fetch from.

    The Harbor API doesn't support getting all artifacts in all projects at once,
    so we have to retrieve all artifacts in each repository and then combine them.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    projects : Optional[List[str]]
        List of projects to fetch artifacts from.
    repositories : Optional[str]]
        List of repositories to fetch artifacts from.
        Can be either the full name or only the repository name:
        `project/repo` or `repo`. `repo` matches all repositories in the
        specified projects with that name, while `project/repo` only matches
        the exact repository name.
        Names are case-sensitive.
        Missing repositories are silently skipped.
    tag : Optional[str]
        The tag to filter the artifacts by.
        A shorthand for `query="tags=<tag>"`.
        If specified, the `query` argument is ignored.
    query : Optional[str]
        The query to filter the artifacts by.
        Follows the same format as the Harbor API.
        Has no effect if `tag` is specified.
    callback : Optional[Callable[[List[Exception]], None]]
        A callback function to handle exceptions raised by the API calls.
        The function takes a list of exceptions as its only argument.
        If not specified, exceptions are ignored.
        The function always fires even if there are no exceptions.
    max_connections : Optional[int]
        The maximum number of concurrent connections to open.
    **kwargs : Any
        Additional arguments to pass to the `HarborAsyncClient.get_artifacts` method.

    Returns
    -------
    List[ArtifactInfo]
        A list of ArtifactInfo objects, without the .report field populated.
    """
    # Fetch repos first.
    # We need these to construct the ArtifactInfo objects.
    repos = await get_repositories(client, projects=projects)
    if repositories:
        repos = [
            r for r in repos if r.name in repositories or r.base_name in repositories
        ]
    # FIXME: invalid repository names are silently skipped

    # Fetch artifacts from each repository concurrently
    coros = [
        _get_artifacts_in_repository(client, repo, tag=tag, query=query, **kwargs)
        for repo in repos
    ]
    a = await run_coros(coros, max_connections=max_connections)
    return handle_gather(a, callback=callback)


@backoff.on_exception(
    backoff.expo, (TimeoutException, asyncio.TimeoutError), max_tries=5
)
async def _get_artifacts_in_repository(
    client: HarborAsyncClient,
    repo: Repository,
    tag: Optional[str] = None,
    query: Optional[str] = None,
    **kwargs: Any,
) -> List[ArtifactInfo]:
    """Fetch all artifacts in a repository given a Repository object.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    repo : Repository
        The repository to get the artifacts from.
    tag : Optional[str]
        The tag to filter the artifacts by.
        If specified, the `query` argument is ignored.
    query : Optional[str]
        The query to filter the artifacts by.
        Follows the same format as the Harbor API.

    Returns
    -------
    List[ArtifactInfo]
        A list of ArtifactInfo objects, combining each artifact with its
        repository.
    """
    s = repo.split_name()
    if not s:
        return []  # TODO: add warning or raise error
    project_name, repo_name = s

    # If a tag is specified, it takes precedence over the query
    if query is None and tag is not None:
        query = f"tags={tag}"

    # We always fetch with scan_overview=True, so we can more easily
    # determine if a vulnerability report exists
    artifacts = await client.get_artifacts(
        project_name,
        repo_name,
        query=query,
        with_scan_overview=True,
        **kwargs,
    )
    return [ArtifactInfo(artifact=artifact, repository=repo) for artifact in artifacts]


async def get_repositories(
    client: HarborAsyncClient,
    projects: Optional[List[str]] = None,
) -> List[Repository]:
    """Fetch all repositories in a list of projects or all projects.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    projects : Optional[List[str]]
        The list of projects to fetch repositories from.
        If not specified, will fetch repos from all projects.

    Returns
    -------
    List[Repository]
        A list of Repository objects.
    """
    # We have 2 options for fetching repositories when projects are specified:
    # 1. Fetch all repositories from all projects, and filter the results
    # 2. Fetch all repositories from each project concurrently
    #
    # We use the first option, as it is simpler, and only requires 1 API call.
    # Simple benchmarks revealed that the second option is slightly faster
    # for a registry with 8 projects and a total of 359 repositories,
    # but it's probably not worth the additional complexity cost it introduces.

    repos = await client.get_repositories()
    if projects:
        # TODO: verify that the project_name property is correct in this regard
        repos = [r for r in repos if r.project_name in projects]
    return repos


async def get_artifact_vulnerabilities(
    client: HarborAsyncClient,
    tags: Optional[List[str]] = None,
    projects: Optional[List[str]] = None,
    repositories: Optional[List[str]] = None,
    max_connections: Optional[int] = 5,
    callback: Optional[Callable[[List[Exception]], None]] = None,
    **kwargs: Any,
) -> List[ArtifactInfo]:
    """Fetch all artifact vulnerability reports in all projects or a subset of projects,
    optionally filtered by tags.

    The Harbor API doesn't support getting all artifacts in all projects at once,
    so we have to retrieve all artifacts in each repository and then combine them
    into a single list of ArtifactInfo objects afterwards.

    Attempting to fetch all artifact vulnerability reports in all projects
    simultaneously will likely DoS your harbor instance, and as such it is not advisable
    to set `max_connections` to a large value. The default value of 5 is a known safe value,
    but you may need to experiment with your own instance to find the optimal value.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    tags : Optional[List[str]]
        The tag(s) to filter the artifacts by.
    projects : Optional[List[str]]
        The project(s) to fetch artifacts from.
        If not specified, all projects will be used.
    max_connections : Optional[int]
        The maximum number of concurrent connections to the Harbor API.
        If None, the number of connections is unlimited.
        WARNING: uncapping connections will likely cause a DoS on the Harbor server.
    callback : Optional[Callable[[List[Exception]], None]]
        A callback function to handle exceptions raised by the API calls.
        The function takes a list of exceptions as its only argument.
        If not specified, exceptions are ignored.
        The function always fires even if there are no exceptions.
    **kwargs : Any
        Additional arguments to pass to the `HarborAsyncClient.get_artifacts` method.

    Returns
    -------
    List[ArtifactInfo]
        A list of ArtifactInfo objects, where each object's `report` field
        is populated with the vulnerability report.
    """

    # We first retrieve all artifacts before we get the vulnerability reports
    # since the reports themselves lack information about the artifact.
    artifacts = await get_artifacts(
        client,
        projects=projects,
        repositories=repositories,
        tags=tags,
        max_connections=max_connections,
        callback=callback,
        **kwargs,
    )
    # Filter out artifacts without a successful scan
    # A failed scan will not produce a report
    artifacts = [
        a
        for a in artifacts
        if a.artifact.scan_overview is not None
        and a.artifact.scan_overview.scan_status != "Error"  # type: ignore
    ]

    # We must fetch each report individually, since the API doesn't support
    # getting all reports in one call.
    # This is done concurrently to speed up the process.
    coros = [_get_artifact_report(client, artifact) for artifact in artifacts]
    artifacts = await run_coros(coros, max_connections=max_connections)
    return handle_gather(artifacts, callback=callback)


async def run_coros(
    coros: Sequence[Awaitable[T]],
    max_connections: Optional[int],
) -> List[T]:
    """Runs an iterable of coroutines concurrently and returns the results.

    Given a `max_connections` value, the number of concurrent coroutines is limited.
    All coroutines are run with `asyncio.gather(..., return_exceptions=True)`,
    so the list of results can contain exceptions, which must be handled
    by the caller.

    Parameters
    ----------
    coros : Sequence[Awaitable[T]]
        An iterable of coroutines to run.
    max_connections : Optional[int]
        The maximum number of concurrent coroutines to run.

    Returns
    -------
    List[T]
        A list of results from running the coroutines, which may contain exceptions.
    """
    results = []

    # Create semaphore to limit concurrent connections
    maxconn = max_connections or 0  # semamphore expects an int
    sem = asyncio.Semaphore(maxconn)
    logger.debug("Running with max connections: {}", maxconn)

    # Instead of passing the semaphore to each coroutine, we wrap each coroutine
    # in a function that acquires the semaphore before calling the coroutine.
    # This lets us run any coroutine without having to explicitly pass the semaphore.
    async def _wrap_coro(coro: Awaitable[T]) -> T:
        async with sem:
            return await coro

    res = await asyncio.gather(
        *[_wrap_coro(coro) for coro in coros], return_exceptions=True
    )
    results.extend(res)
    return results


async def _get_artifact_report(
    client: HarborAsyncClient, artifact: ArtifactInfo
) -> ArtifactInfo:
    """Given an ArtifactInfo, fetches the vulnerability report for the artifact,
    and assigns it to the `report` field of the ArtifactInfo object.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    artifact : ArtifactInfo
        The artifact to get the vulnerability report for.

    Returns
    -------
    ArtifactInfo
        The `ArtifactInfo` object with the vulnerability report attached.
    """
    digest = artifact.artifact.digest
    if digest is None:  # should never happen
        logger.error(f"Artifact {artifact.name_with_tag} has no digest")
        return artifact

    s = artifact.repository.split_name()
    if not s:
        # Should never happen at this point, since we already filtered out
        # the invalid names earlier
        return artifact

    project_name, repo_name = s
    report = await client.get_artifact_vulnerabilities(
        project_name,
        repo_name,
        digest,
    )
    if report is None:
        logger.debug(
            "No vulnerabilities found for artifact '{}'".format(
                f"{project_name}/{repo_name}@{digest}"
            )
        )
    else:
        artifact.report = report
    return artifact


def handle_gather(
    results: Sequence[Union[T, Sequence[T], Exception]],
    callback: Optional[Callable[[List[Exception]], None]] = None,
) -> List[T]:
    """Handles the returned values of an `asyncio.gather()` call, handling
    any exceptions and returning a list of the results with exceptions removed.
    Flattens lists of results. TODO: toggle this?

    Parameters
    ----------
    results : Sequence[Union[T, Sequence[T], Exception]],
        The results of an `asyncio.gather()` call.
    callback : Optional[Callable[[List[Exception]], None]]
        A callback function to handle exceptions raised by the API calls.
        The function takes a list of exceptions as its only argument.
        If not specified, exceptions are ignored.
        The function always fires even if there are no exceptions.

    Returns
    -------
    List[T]
        The list of results with exceptions removed.
    """
    ok = []  # type: List[T]
    err = []  # type: List[Exception]
    for res_or_exc in results:
        if isinstance(res_or_exc, Exception):
            err.append(res_or_exc)
        else:
            if isinstance(res_or_exc, Sequence):
                ok.extend(res_or_exc)
            else:
                ok.append(res_or_exc)

    if callback is not None:
        callback(err)

    return ok


async def get_artifact_owner(
    client: HarborAsyncClient, artifact: Union[Artifact, ArtifactInfo]
) -> UserResp:
    """Get the full owner information for an artifact.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    artifact : Union[Artifact, ArtifactInfo]
        The artifact to get the owner for.

    Returns
    -------
    UserResp
        The full owner information for the artifact.
    """
    if isinstance(artifact, ArtifactInfo):
        artifact = artifact.artifact
    project_id = artifact.project_id
    if project_id is None:
        raise ValueError("Artifact has no project_id")
    project = await client.get_project(project_id)
    if project.owner_id is None:
        raise ValueError("Project has no owner_id")
    return await client.get_user(project.owner_id)
