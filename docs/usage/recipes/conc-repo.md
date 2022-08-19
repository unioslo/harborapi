# Concurrent Repository Retrieval

Given a list of project names, we can use Asyncio to dispatch multiple requests concurrently to the Harbor API to fetch repositories in all of the projects.

## List of Names

We can use a list of project names to fetch repositories from.


```py
projects = ["library", "my-project-1"]

coros = [client.get_repositories(project) for project in projects]
rtn = await asyncio.gather(*coros, return_exceptions=True)

artifacts = list(itertools.chain.from_iterable(r))
```


## All Projects

We can also first fetch all projects, then use their names as argument to `get_repositories`

```py
projects = [project.name for project in await client.get_projects()]

coros = [client.get_repositories(project) for project in projects]
rtn = await asyncio.gather(*coros, return_exceptions=True)

artifacts = list(itertools.chain.from_iterable(r))
```

!!! note
    We use `return_exceptions=True` as an argument to `asyncio.gather` in the examples, which means you have to manually
    filter out these exceptions from the list and choose how to handle them.
    Set `return_exceptions` to `False` if you wish any encountered exceptions to abort execution.
