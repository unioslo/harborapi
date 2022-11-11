# Concurrent Artifact Retrieval

Given a list of repository names and a project name, we can use Asyncio to dispatch multiple requests concurrently to the Harbor API to fetch all artifacts in the repositories.

Because the result is a list of lists, we flatten it with `itertools.chain.from_iterable`.

```py
repos = ["foo", "bar", "baz"]

coros = [client.get_artifacts(project_name, repo) for repo in repos]
r = await asyncio.gather(*coros, return_exceptions=True)

artifacts = list(itertools.chain.from_iterable(r))
```

!!! note
    We use `return_exceptions=True` as an argument to `asyncio.gather` in the example, which means exceptions are returned in the list of results. These exceptions should be filtered out and handled.
    Set `return_exceptions` to `False` if you wish any encountered exceptions to be raised automatically.


## Using the `ext` module

The recipe above has been baked into the `ext` module to allow for quick and easy retrieval of artifacts in multiple repositories. See: [Extended Functionality](../ext/index.md) for more information.
