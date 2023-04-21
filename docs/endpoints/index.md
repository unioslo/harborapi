# Endpoints Overview

This section contains API documentation for the methods implementing the different Harbor API endpoints.

The methods listed can be called on an instance of the [`HarborAsyncClient`][harborapi.client.HarborAsyncClient] class:


```py
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)

def main() -> None:
    projects = await client.get_projects()
    repos = await client.get_repositories()

    # Resource creation requires a model object
    from harborapi.models import ProjectReq
    await client.create_project(
        ProjectReq(
            project_name="my-project",
            public=False,
        ),
    )

    # etc...
```

See [Recipes](../recipes/index.md) for more examples on how to use the methods.

## Implemented Endpoints

Check the [GitHub README](https://github.com/pederhan/harborapi/blob/main/README.md) for the most up to date overview of the implemented endpoints.
