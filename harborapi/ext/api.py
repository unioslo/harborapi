import asyncio
from typing import (
    Any,
    Awaitable,
    List,
    Literal,
    Optional,
    Sequence,
    TypeVar,
    Union,
    overload,
)

import backoff
from httpx import TimeoutException
from loguru import logger

from .. import HarborAsyncClient
from ..exceptions import NotFound
from ..models import Artifact, Repository, UserResp
from .artifact import ArtifactInfo

T = TypeVar("T")

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
    get_artifact = client.get_artifact(
        project_name=project,
        repository_name=repository,
        reference=reference,
    )
    # TODO: use with_scan_overview to determine if we should try
    # to fetch report?

    get_repo = client.get_repository(
        project_name=project,
        repository_name=repository,
    )

    coros = [get_artifact, get_repo]
    resp = await run_coros(coros, max_connections=2)
    res = handle_gather(resp, exc_ok=False, return_exceptions=False)

    artifact = repo = None
    for r in res:
        if isinstance(r, Artifact):
            artifact = r
        elif isinstance(r, Repository):
            repo = r
    if repo is None or artifact is None:
        # we should never reach this
        logger.bind(res=res).error("Unexpected response from API")
        raise ValueError("Could not find artifact or repository")

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


@overload
async def get_artifacts(
    client: HarborAsyncClient,
    *,
    return_exceptions: Literal[True],
    **kwargs: Any,
) -> List[Union[ArtifactInfo, Exception]]:
    ...


@overload
async def get_artifacts(
    client: HarborAsyncClient,
    *,
    return_exceptions: Literal[False] = False,
    **kwargs: Any,
) -> List[ArtifactInfo]:
    ...


async def get_artifacts(
    client: HarborAsyncClient,
    projects: Optional[List[str]] = None,
    repositories: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    exc_ok: bool = True,
    return_exceptions: bool = False,
    max_connections: Optional[int] = 5,
    **kwargs: Any,
) -> Union[List[ArtifactInfo], List[Union[ArtifactInfo, Exception]]]:
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
        A stricter filter than `projects`. Repositories
        that are not part of the specified projects are ignored.
    tags : Optional[List[str]]
        The tag(s) to filter the artifacts by.
    exc_ok : bool
        Whether or not to continue on error.
        If True, the failed artifact is skipped, and the exception
        is logged. If False, the exception is raised.
    return_exceptions : bool
        Whether or not to return exceptions in the result list.
    max_connections : Optional[int]
        The maximum number of concurrent connections to open.
    **kwargs : Any
        Additional arguments to pass to the `HarborAsyncClient.get_artifacts` method.

    Returns
    -------
    Union[List[ArtifactInfo], List[Union[ArtifactInfo, Exception]]]
        A list of ArtifactInfo objects, without the .report field populated.
        Can contain exceptions if `return_exceptions` is True.
    """
    # Fetch repos first.
    # We need these to construct the ArtifactInfo objects.
    repos = await get_repositories(client, projects=projects)
    if repositories:
        repos = [r for r in repos if r.base_name in repositories]
    # FIXME: invalid repository names are silently skipped

    # Fetch artifacts from each repository concurrently
    coros = [
        _get_artifacts_in_repository(client, repo, tags=tags, **kwargs)
        for repo in repos
    ]
    a = await run_coros(coros, max_connections=max_connections)
    return handle_gather(a, exc_ok=exc_ok, return_exceptions=return_exceptions)


@backoff.on_exception(
    backoff.expo, (TimeoutException, asyncio.TimeoutError), max_tries=5
)
async def _get_artifacts_in_repository(
    client: HarborAsyncClient,
    repo: Repository,
    tags: Optional[List[str]],
    **kwargs: Any,
) -> List[ArtifactInfo]:
    """Fetch all artifacts in a repository given a Repository object.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    repo : Repository
        The repository to get the artifacts from.
    tags : Optional[List[str]]
        The tag(s) to filter the artifacts by.

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

    if tags:
        t = " ".join(tags) if tags else None
        query = f"tags=" + "{" + f"{t}" + "}"
    else:
        query = None

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
    exc_ok: bool = True,
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
    exc_ok : bool
        Whether or not to continue on error.
        If True, the failed artifact is skipped, and the exception is logged.
        If False, the exception is raised.
        For processing a large number of artifacts, it is recommended to set this to True.
        NOTE: there is no functionality in place for scheduling retry of failed coros.
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
        exc_ok=exc_ok,
        return_exceptions=False,
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
    return handle_gather(artifacts, exc_ok=True, return_exceptions=False)


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


@overload
def handle_gather(
    results: Sequence[Union[T, Sequence[T], Exception]],
    exc_ok: bool,
    return_exceptions: Literal[True],
) -> List[Union[T, Exception]]:
    ...


@overload
def handle_gather(
    results: Sequence[Union[T, Sequence[T], Exception]],
    exc_ok: bool,
    return_exceptions: Literal[False],
) -> List[T]:
    ...


@overload
def handle_gather(
    results: Sequence[Union[T, Sequence[T], Exception]],
    exc_ok: bool,
    return_exceptions: bool = ...,
) -> List[Union[T, Exception]]:
    ...


def handle_gather(
    results: Sequence[Union[T, Sequence[T], Exception]],
    exc_ok: bool,
    return_exceptions: bool = False,
) -> Union[List[T], List[Union[T, Exception]]]:
    """Handles the returned values of an `asyncio.gather()` call, handling
    any exceptions and returning a list of the results with exceptions removed.
    Flattens lists of results. TODO: toggle this?

    Parameters
    ----------
    results : List[Union[T, List[T], Exception]]
        The results of an `asyncio.gather)` call.
    exc_ok : bool
        Whether to log and skip exceptions, or raise them.
        If True, exceptions are logged and skipped.
        If False, exceptions are raised.
    return_exceptions : bool
        Whether to return exceptions in the list of results.
        If True, exceptions are returned in the list of results.

    Returns
    -------
    List[T]
        The list of results with exceptions removed.
    """
    ok = []  # type: List[Union[T, Exception]]
    for res_or_exc in results:
        if isinstance(res_or_exc, Exception):
            if exc_ok:
                logger.error(res_or_exc)
                if return_exceptions:
                    ok.append(res_or_exc)
            else:
                raise res_or_exc
        else:
            if isinstance(res_or_exc, Sequence):
                ok.extend(res_or_exc)
            else:
                ok.append(res_or_exc)
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
