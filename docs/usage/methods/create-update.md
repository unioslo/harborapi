# Create/update

Methods that create and update resources make use of [Pydantic](https://docs.pydantic.dev/) models that have been generated from the official [Harbor REST API Swagger schema](https://github.com/goharbor/harbor/blob/main/api/v2.0/swagger.yaml).

The endpoint methods themselves have no parameters beyond the single model instance that is passed as the request body. This is done so that models can be updated in the future without breaking the methods that use them. We are at all times beholden to the official Swagger schema, and the models are generated from that schema. To see how to disable this validation and pass arbitrary data to the API, see the [Validation](./validation.md/#validation) page.

## Create

Creating resources is done by calling the `create_*` methods on the client object. The model type expected for these methods is usually subtly different from the ones returned by `get_*` methods, and is usually named `*Req`. For example, the [`create_project()`][harborapi.client.HarborAsyncClient.create_project] method expects a [`ProjectReq`][harborapi.models.Project] model, while the [`get_project()`][harborapi.client.HarborAsyncClient.get_project] method returns a [`Project`][harborapi.models.Project] model.

However, we can use the `Project` model to create a `ProjectReq` by passing into the `parse_obj` method on the `ProjectReq` class.

``

```python
import asyncio
from harborapi import HarborAsyncClient
from harborapi.models import ProjectReq, ProjectMetadata

client = HarborAsyncClient(...)


async def main() -> None:
    project_path = await client.create_project(
        ProjectReq(
            project_name="test-project2",
            metadata=ProjectMetadata(
                public=True,
            ),
        )
    )
    print(f"Project created: {project_path}")


asyncio.run(main())
```

## Update

The various `update_*` methods on the client object, expect a `*Req` model similar to the `create_*` methods. However, one important difference is that these methods expect the resource identifier as the first parameter, and the model instance as the second parameter.


```py
import asyncio
from harborapi import HarborAsyncClient
from harborapi.models import ProjectReq, ProjectMetadata

client = HarborAsyncClient(...)


async def main() -> None:
    # Update the project
    await client.update_project(
        "test-project",
        ProjectReq(
            metadata=ProjectMetadata(
                enable_content_trust="true",  # yeah, it's a string...
            ),
            # OR
            # metadata={"enable_content_trust": "true"}
        ),
    )


asyncio.run(main())

```


### Idiomatic REST updating

The update endpoints are exposed as HTTP `PUT` endpoints, which according to [RFC 7231](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.4) should expect the full resource definition, not just the fields to update. Manual testing has revealed this to not be the case, however; the API supports updating with partial models, and only updates the fields that are present in the request body. When HarborAPI serializes models, it only includes fields that have been set, so this is the default behavior.

It is, however, recommended to pass the full resource definition to the `update_*` methods, as the support for partial updates may change in the future independently of this library.

Below is an example demonstrating how to fetch the existing resource, use it to construct the update model, and then update the resource with the new model.

```py
import asyncio
from harborapi import HarborAsyncClient
from harborapi.models import ProjectReq

client = HarborAsyncClient(...)

async def main() -> None:
    # Get the project
    project = await client.get_project("test-project")

    # Create the update model from the existing project
    req = ProjectReq.parse_obj(
        project,
        # OR
        # optionally only include fields from the request model:
        # project.dict(include=ProjectReq.__fields__.keys()),
    )
    req.metadata.enable_content_trust = "true"

    # Update the project
    await client.update_project("test-project", req)


asyncio.run(main())
```
