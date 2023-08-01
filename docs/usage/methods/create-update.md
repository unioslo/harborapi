# Create/update

Methods that create and update resources make use of [Pydantic](https://docs.pydantic.dev/) models that have been generated from the official [Harbor REST API Swagger schema](https://github.com/goharbor/harbor/blob/main/api/v2.0/swagger.yaml).

The endpoint methods themselves have no parameters beyond the single model instance that is passed as the request body. This is done so that models can be updated in the future without breaking the methods that use them. We are at all times beholden to the official Swagger schema, and the models are generated from that schema. To see how to disable this validation and pass arbitrary data to the API, see the [Validation](./validation.md/#validation) page.

## Create

Creating resources is done by calling one of the `create_*` methods on the client object. The model type expected for these methods is usually subtly different from the ones returned by `get_*` methods, and generally has the suffix `*Req` (e.g. [`ProjectReq`][harborapi.models.ProjectReq] instead of [`Project`][harborapi.models.Project]).

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

The various `update_*` methods on the client object expect a `*Req` model similar to the `create_*` methods. However, one important distinction is that these methods also expect one or more identifiers for the resource to update the as the first argument(s) and then the model as the following argument:

```py
client.update_project("name-of-project", ProjectReq(...))
```

Generally, only a single identifier is required to uniquely identify the resource to update, but some endpoints require multiple identifiers, such as the [`update_project_member_role`][harborapi.HarborAsyncClient.update_project_member_role] method which expects both a project name/ID and a member ID:

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
                enable_content_trust=True,
            ),
        ),
    )


asyncio.run(main())
```

In a departure from traditional REST semantics, the API updates only the fields that are explicitly defined on the model instance, preserving the undefined values as-is. This approach, while not aligning with the idiomatic use of HTTP PUT requests in REST, provides a measure of convenience from a user's perspective, since it allows us to update only the fields we care about, and leave the rest unchanged.

In the example, we only set the `metadata.enable_content_trust` field on the `ProjectReq` model, which means that only that one setting will be updated on the project. The rest of the project settings will be left unchanged.

See the [Idiomatic REST updating](#idiomatic-rest-updating) section for more information on why this _might_ not be the correct way to do things, and why it _could_ change in the future if Harbor changes the API.

## Idiomatic REST updating


!!! note
    The following sections are _optional_ reading, and are only relevant if you want to following idiomatic REST principles when updating resources. If you don't care about that, you can safely ignore the following sections.

The update endpoints are HTTP PUT endpoints that should expect a full resource definition according to [RFC 7231](https://datatracker.ietf.org/doc/html/rfc7231#section-4.3.4). However, as described above, testing has shown that the API supports updating with partial models. By default, `harborapi` will only include the fields that are present in the request model, and leave out the rest, which enables us to take advantage of this behavior in the API:

```py
from harborapi.models import ProjectReq, ProjectMetadata

project = ProjectReq(
    public=True,
    metadata=ProjectMetadata(
        auto_scan=True,
    ),
)
```

Will send the following over the wire, where unset fields are excluded:

```json
{
  "public": true,
  "metadata": {
    "auto_scan": "true"
  }
}
```

Even though the internal representation of the model is:

```py
ProjectReq(
    project_name=None,
    public=True,
    metadata=ProjectMetadata(
        public=None,
        enable_content_trust=None,
        enable_content_trust_cosign=None,
        prevent_vul=None,
        severity=None,
        auto_scan='true',
        reuse_sys_cve_allowlist=None,
        retention_id=None
    ),
    cve_allowlist=None,
    storage_limit=None,
    registry_id=None
)
```

This is because Pydantic knows which fields have been set and which have not on the model instance, and only serializes the fields that have been set. This way, we ensure that we don't send any data the user hasn't explicitly set.

!!! note
    The reason for `"auto_scan": "true"` instead of `"auto_scan": true` can be found [here](../../models/#string-fields-with-true-and-false-values-in-api-spec).

Despite this behavior, it _might_ a good idea to pass the full resource definition to the `update_*` methods, as the support for partial updates through the API may change in the future independently of this library without notice. The following sections demonstrate how to do this.


### Converting GET models to PUT models

As outlined in [Update](#update), `update_*` methods expect subtly different models from the ones returned by `get_*` methods. By using the method [`convert_to()`][harborapi.models.base.BaseModel.convert_to] which is available on all models, we can easily convert a model we receive from a `get_*` method to the model type that the corresponding `update_*` method expects.

The method expects a model type as its first argument, and returns an instance of that model type:

```py
from harborapi.models import Project, ProjectReq

project = Project(...)
req = project.convert_to(ProjectReq)
assert isinstance(req, ProjectReq)

print(req.metadata) # OK
print(req.owner_id) # FAIL - ProjectReq does not have an owner_id field
```

!!! note
    The `extra` parameter is mainly available to ensure compatibility with future API changes, so unless you know you need to use it, you can safely ignore it.

If we want to, we can also pass in `extra=True` to include all fields of the original model on converted model, even if they are not defined in the schema of the model type we are converting to:

```py hl_lines="4"
from harborapi.models import Project, ProjectReq

project = Project(owner_id=1, ...)
req = project.convert_to(ProjectReq, extra=True)
assert isinstance(req, ProjectReq)

print(req.metadata) # OK
print(req.owner_id) # OK - Inherited from Project via extra=True
```

Even though the `ProjectReq` model does not have an `owner_id` field in its schema, the resulting model instance received it from the `Project` model that it was converted from because we used `convert_to(..., extra=True)`.

### Updating a resource using `convert_to()`

Below is an example demonstrating how to fetch the existing resource ([`Project`][harborapi.models.Project]) and convert it to the model type the update method expects ([`ProjectReq`][harborapi.models.ProjectReq]):

```py
import asyncio
from harborapi import HarborAsyncClient
from harborapi.models import ProjectReq

client = HarborAsyncClient(...)

async def main() -> None:
    # Get the project
    project = await client.get_project("test-project")

    # Convert to ProjectReq
    req = project.convert_to(ProjectReq)

    # Change the field we want to update
    req.metadata.enable_content_trust = True

    # Update the project
    await client.update_project("test-project", req)


asyncio.run(main())
```

[^1]: You can defend this behavior with certain interpretations of this quote from the RFC: *"When a PUT
   representation is inconsistent with the target resource, the origin
   server SHOULD either make them consistent, by transforming the
   representation or changing the resource configuration [...]"*. However, this implicit behavior is not documented anywhere by Harbor, so we have no way of knowing if it is intentional or not.
