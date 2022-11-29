import asyncio
from typing import (
    Any,
    Coroutine,
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


async def get_artifactinfo_by_digest(
    client: HarborAsyncClient,
    project: str,
    repository: str,
    tag: Optional[str] = None,
    digest: Optional[str] = None,
) -> Optional[ArtifactInfo]:
    """Fetch an artifact and its vulnerability report by digest."""
    reference = tag or digest
    if not reference:
        raise ValueError("Must specify either tag or digest")
    try:
        artifact = await client.get_artifact(
            project_name=project,
            repository_name=repository,
            reference=reference,
        )
    except NotFound:
        return None

    try:
        repo = await client.get_repository(
            project_id=project,  # type: ignore
            repository_name=repository,
        )
    except NotFound:
        return None

    def _no_report() -> None:
        delim = ":" if tag else "@"
        logger.error(
            f"No vulnerability report for {project}/{repository}{delim}{reference}"
        )
        return None

    try:
        report = await client.get_artifact_vulnerabilities(
            project_name=project, repository_name=repo.base_name, reference=reference
        )
    except NotFound:
        return _no_report()  # type: ignore
    if not report:
        return _no_report()  # type: ignore

    return ArtifactInfo(artifact=artifact, repository=repo, report=report)


@overload
async def get_artifacts(
    client: HarborAsyncClient,
    repos: Optional[List[Repository]] = ...,
    tags: Optional[List[str]] = ...,
    exc_ok: bool = ...,
    return_exceptions: Literal[True] = True,
    max_connections: Optional[int] = ...,
    **kwargs: Any,
) -> List[Union[ArtifactInfo, Exception]]:
    ...


@overload
async def get_artifacts(
    client: HarborAsyncClient,
    repos: Optional[List[Repository]] = ...,
    tags: Optional[List[str]] = ...,
    exc_ok: bool = ...,
    return_exceptions: Literal[False] = False,
    max_connections: Optional[int] = ...,
    **kwargs: Any,
) -> List[ArtifactInfo]:
    ...


async def get_artifacts(
    client: HarborAsyncClient,
    repos: Optional[List[Repository]] = None,
    projects: Optional[List[str]] = None,
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
    repos : Optional[List[Repository]]
        The list of repositories to fetch artifacts from.
        If not specified, all repositories will be used.
    projects : Optional[List[str]]
        The list of projects to fetch repositories from which artifacts
        are fetched from.
        If not specified, all projects will be used.
        Has no effect if `repos` is specified.
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
    if not repos:
        repos = await get_repositories(client, projects=projects)
    # Fetch artifacts from each repository concurrently
    coros = [_get_repo_artifacts(client, repo, tags=tags, **kwargs) for repo in repos]
    a = await run_coros(coros, max_connections=max_connections)
    return handle_gather(a, exc_ok=exc_ok, return_exceptions=return_exceptions)
    # return list(itertools.chain.from_iterable(a))


@backoff.on_exception(
    backoff.expo, (TimeoutException, asyncio.TimeoutError), max_tries=5
)
async def _get_repo_artifacts(
    client: HarborAsyncClient, repo: Repository, tags: Optional[List[str]], **kwargs
) -> List[ArtifactInfo]:
    """Fetch all artifacts in a repository.

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
    artifacts = await client.get_artifacts(
        project_name,
        repo_name,
        query=(f"tags={','.join(tags)}" if tags else None),
        with_scan_overview=True,
        **kwargs,
    )
    return [ArtifactInfo(artifact=artifact, repository=repo) for artifact in artifacts]


@overload
async def get_repositories(
    client: HarborAsyncClient,
    projects: Optional[List[str]] = ...,
    exc_ok: bool = ...,
    return_exceptions: Literal[False] = False,
    max_connections: Optional[int] = ...,
) -> List[Repository]:
    ...


@overload
async def get_repositories(
    client: HarborAsyncClient,
    projects: Optional[List[str]] = ...,
    exc_ok: bool = ...,
    return_exceptions: Literal[True] = True,
    max_connections: Optional[int] = ...,
) -> List[Union[Repository, Exception]]:
    ...


async def get_repositories(
    client: HarborAsyncClient,
    projects: Optional[List[str]] = None,
    exc_ok: bool = True,
    return_exceptions: bool = False,
    max_connections: Optional[int] = 5,
) -> Union[List[Repository], List[Union[Repository, Exception]]]:
    """Fetch all repositories in a list of projects.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    projects : Optional[List[str]]
        The list of projects to fetch repositories from.
        If not specified, all projects will be used.
    exc_ok : bool
        Whether or not to continue on error.
        If True, the failed repository is skipped, and the exception
        is logged. If False, the exception is raised.
    return_exceptions : bool
        Whether or not to return exceptions in the result list.
    max_connections : Optional[int]
        The maximum number of concurrent connections to open.

    Returns
    -------
    Union[List[Repository], List[Union[Repository, Exception]]]
        A list of Repository objects.
        Can contain exceptions if `return_exceptions` is True.
    """
    if projects is None:
        projects = [None]
    coros = [_get_project_repos(client, project) for project in projects]
    rtn = await run_coros(coros, max_connections=max_connections)
    return handle_gather(rtn, exc_ok=exc_ok, return_exceptions=return_exceptions)


async def _get_project_repos(
    client: HarborAsyncClient, project: Optional[str]
) -> List[Repository]:
    """Fetch all repositories in a project.

    Parameters
    ----------
    client : HarborAsyncClient
        The client to use for the API call.
    project : str
        The project to fetch repositories from.

    Returns
    -------
    List[Repository]
        A list of Repository objects.
    """
    repos = await client.get_repositories(project_name=project)
    return repos


async def get_artifact_vulnerabilities(
    client: HarborAsyncClient,
    tags: Optional[List[str]] = None,
    projects: Optional[List[str]] = None,
    exc_ok: bool = True,
    max_connections: Optional[int] = 5,
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
    exc_ok : bool
        Whether or not to continue on error.
        If True, the failed artifact is skipped, and the exception
        is logged.
        If False, the exception is raised.
        For processing a large number of artifacts, it is recommended to set this to True.
        NOTE: there is no functionality in place for scheduling retry of failed coros.
    max_connections : Optional[int]
        The maximum number of concurrent connections to the Harbor API.
        If None, the number of connections is unlimited.
        WARNING: uncapping connections will likely cause a DoS on the Harbor server.
    **kwargs : Any
        Additional arguments to pass to the `HarborAsyncClient.get_artifacts` method.

    Returns
    -------
    List[ArtifactInfo]
        A list of ArtifactInfo objects, where each object's `report` field
        is populated with the vulnerability report.
    """
    # Get all projects if not specified
    if not projects:
        p = await client.get_projects()
        projects = [project.name for project in p if project.name]

    repos = await get_repositories(
        client, projects, max_connections=max_connections, exc_ok=exc_ok
    )

    # We first retrieve all artifacts before we get the vulnerability reports
    # since the reports themselves lack information about the artifact.
    artifacts = await get_artifacts(
        client,
        repos=repos,
        tags=tags,
        max_connections=max_connections,
        **kwargs,
    )
    # Filter out artifacts without a scan overview (no vulnerability report)
    artifacts = [a for a in artifacts if a.artifact.scan_overview is not None]

    # We must fetch each report individually, since the API doesn't support
    # getting all reports in one call.
    # This is done concurrently to speed up the process.
    coros = [_get_artifact_report(client, artifact) for artifact in artifacts]
    artifacts = await run_coros(coros, max_connections=max_connections)
    return handle_gather(artifacts, exc_ok=exc_ok)


async def run_coros(
    coros: List[Coroutine[Any, Any, Any]],
    max_connections: Optional[int],
) -> List[Any]:
    """Runs a list of coroutines and returns the results.
    Given a `max_connections` value, the number of concurrent coroutines is limited.
    All coroutines are run with `asyncio.gather(..., return_exceptions=True)`,
    so the list of results can contain exceptions, which must be handled
    by the caller.

    Parameters
    ----------
    coros : List[Coroutine[Any, Any, Any]]
        The list of coroutines to run.
    max_connections : Optional[int]
        The maximum number of concurrent coroutines to run.

    Returns
    -------
    List[Any]
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
    async def _wrap_coro(coro: Coroutine[Any, Any, Any]) -> Any:
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
    """Get the vulnerability report for an artifact.

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
    tag = artifact.artifact.tags[0].name if artifact.artifact.tags else None
    if not tag:
        tag = "latest"

    s = artifact.repository.split_name()
    if not s:
        # Should never happen at this point, since we already filtered out
        # the invalid names earlier
        return artifact

    project_name, repo_name = s
    report = await client.get_artifact_vulnerabilities(
        project_name,
        repo_name,
        tag,
    )
    if report is None:
        logger.debug(
            "No vulnerabilities found for artifact '{}'".format(
                f"{project_name}/{repo_name}:{tag}"
            )
        )
    else:
        artifact.report = report
    return artifact


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
    ok = []  # type: Union[List[T], List[Union[T, Exception]]]
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
