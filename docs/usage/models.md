# Models

Most client methods either return a Pydantic model or take one as an argument. You don't need to know anything about Pydantic to use the models, but it's a good idea to familiarize yourself with the basics through the [Pydantic v1.x docs](https://docs.pydantic.dev/1.10/) to get the most out of the library.

All models are located in the [`harborapi.models`][harborapi.models.models] module.

```py
from harborapi.models import *
```

## Pydantic models

Through the Pydantic models, we get a lot of nice features for free, such as:

- Validation of data
- Automatic conversion of data types
- Utility functions for (de)serializing data

We'll look at some of these features later, but first, let's look at how the models are used at a basic level.

## Using models returned by the API

When calling a GET endpoint with a `get_*` method, we usually get a model instance back. For example, when calling the [`get_project`](../methods/get.md/#get_project) method, we get a [`Project`](../models/project.md/#project) instance back:

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)

async def main() -> None:
    project = await client.get_project("library")


asyncio.run(main())
```

In the IDE, we can see the various attributes the model instance has:

![IDE screenshot showing the attributes of a project model instance](../img/usage/models/autocomplete0.png)

Also shown in the screenshot are the utility methods `json` and `dict`, which allows you to convert models to JSON and Python dictionaries, respectively.


## Using models to create and update resources

Similar to how the `get_*` methods _return_ models, the `create_*` and `update_*` methods _take_ models as arguments. For example, the [`create_project`](../methods/create-update.md/#create_project) method takes a [`ProjectReq`](../models/project.md/#projectreq) model as an argument:

```py
import asyncio
from harborapi import HarborAsyncClient
from harborapi.models import ProjectReq, ProjectMetadata

client = HarborAsyncClient(...)

async def main() -> None:
    location = await client.create_project(
        ProjectReq(
            project_name="test-project",
            public=True,
            metadata=ProjectMetadata(
                auto_scan=True,
                enable_content_trust=True,
            ),
        )
    )
    print(location)


asyncio.run(main())
```

### IDE autocompletion

When using the models, the IDE can help us out by showing us the available fields and their types. For example, when calling the [`create_project`][harborapi.HarborAsyncClient.create_project] method, we know we need to pass a model to the method.

The IDE tells us the name of the model to pass to the method:

![IDE screenshot showing the type of the argument to the create_project method](../img/usage/models/autocomplete1.png)

Since we know all models can be imported from `harborapi.models`, all we have to do is to add:

```py
from harborapi.models import ProjectReq
```

Again, we are assisted by the IDE when creating the model instance we pass to the method:

![IDE screenshot showing the types of the model fields](../img/usage/models/autocomplete2.png)

We get IDE autocompletion for the different fields when constructing the model instance:

![IDE screenshot showing autocomplete for a project model instance](../img/usage/models/autocomplete3.png)

When assigning a value to a field, we can see the type of the field:

![IDE screenshot showing the type of a model field](../img/usage/models/autocomplete4.png)

Certain models contain fields that are of a different model type. For example, the [`ProjectReq`][harborapi.models.ProjectReq] model has a field named `metadata` which expects a [`ProjectMetadata`](../models/project.md/#projectmetadata) instance. When assigning a value to such a field, we can see the type of the field:

![IDE screenshot showing the type of a model field that is also a model](../img/usage/models/autocomplete5.png)


First we need to import the model we want to use:

```py
from harborapi.models import ProjectMetadata
```

After which, the IDE will help us construct the model instance:

![IDE screenshot showing autocomplete for a project metadata model instance](../img/usage/models/autocomplete6.png)


The IDE used for demonstration (VSCode) does _not_ show the Pydantic model field descriptions, however. So it's recommended to always check the documentation to gain a more complete understanding of the models:

* [`ProjectReq`][harborapi.models.ProjectReq]
* [`ProjectMetadata`][harborapi.models.ProjectMetadata]

Unfortunately, the documentation does not yet generate clickable links to other models referenced in a model's field type, so you'll have to search for the model name in the sidebar or use the search field if a field type is not immediately clear to you. CTRL+F is your friend.


## Model validation

Pydantic models validate the data they are given. This can take the form of checking that a given argument is of the correct type, or that it is within a certain range of values. Other validation methods include checking that a string matches a certain regular expression, or it is a valid URL, or is of a certain length. See the [Pydantic docs](https://docs.pydantic.dev/latest/usage/types/) for more information. The [Data validation](validation.md) page also contains more in-depth information about validation.

### Validation

When we fetch data from the API, it is validated through the models. For example, when we call the [`get_project`][harborapi.HarborAsyncClient.get_project] method, we get a [`Project`][harborapi.models.Project] instance back. The model provides certain guarantees about the type of the data it contains. For example, the `project_id` field is guaranteed to be an `int` or `None`:

```py title="models.py (excerpt)"
class Project(BaseModel):
    project_id: Optional[int] = Field(None, description="Project ID")
```

Meaning that when we access the `project_id` field, we can be sure it is an `int` or `None`:

```py
project = await client.get_project("library")
if project.project_id is not None:
    new_id = project.project_id + 1 # Guaranteed to be an int
```

This guards against unexpected values returned by the API, and it allows us to write code that is more robust. Furtermore, should the API change in the future, the validation will fail and we will get an error. This is a good thing, as it allows us to catch breaking changes early. If you need to use a method that return a model that fails validation, you can use the [`no_validation()`](validation.md#no_validation-context-manager) context manager to disable validation for that specific request.

### Type coercion

Fields will generally attempt to coerce a value to its target type if possible. For example, the [`ProjectReq`][harborapi.models.ProjectReq] model has a field named `project_name` which expects a string argument. Pydantic provides some leniency with regards to which types it accepts, so we can pass not only a `str` to the field, but also number types, certain bytes types and `str` enums, and they will both be converted to a string:


```pycon
>>> from harborapi.models import ProjectReq
>>> ProjectReq(project_name="test-project")
ProjectReq(project_name='test-project', public=None, metadata=None, cve_allowlist=None, storage_limit=None, registry_id=None)
>>> ProjectReq(project_name=123)
ProjectReq(project_name='123', public=None, metadata=None, cve_allowlist=None, storage_limit=None, registry_id=None)
```

Not every type will be converted, so if we try to pass an arbitrary object to the field, we get an error:

```pycon
>>> ProjectReq(project_name=object())
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "pydantic/main.py", line 341, in pydantic.main.BaseModel.__init__
pydantic.error_wrappers.ValidationError: 1 validation error for ProjectReq
project_name
  str type expected (type=type_error.str)
```

See the [Pydantic docs](https://docs.pydantic.dev/latest/usage/types/#standard-library-types) on standard library types for more information about how coercion works.



## String fields with 'true' and 'false' values in API spec

!!! info
    This section only refers to a very particular subset of models. The vast majority of models use `bool` fields as they should.

For some reason, some model fields in the API spec that by all accounts should have been bools are actually string fields that accept `'true'` and `'false'`.

```yaml title="swagger.yaml (excerpt)"
# ...
  ProjectMetadata:
    type: object
    properties:
      public:
        type: string
        description: 'The public status of the project. The valid values are "true", "false".'
```

This mainly affects the `ProjectMetadata` model, which contains a whopping 6 fields following this pattern:

- `public`
- `enable_content_trust`
- `enable_content_trust_cosign`
- `prevent_vul`
- `auto_scan`
- `reuse_sys_cve_allowlist`

For compatibility with the API, the type of these fields in the model have _not_  been changed to `bool`. When you access these fields, they will one of the strings `'true'` or `'false'`:

```py
project = await client.get_project("test-project")
assert project.metadata.public in ["true", "false"]
```

However, you _can_ instantiate these fields with bools, and they will be converted to the appropriate strings once the model is created:

```py
from harborapi.models import ProjectMetadata


project = ProjectMetadata(
    public=True,
    enable_content_trust=False,
)
assert project.public == "true"
assert project.enable_content_trust == "false"
```

With the model's custom field validator, the arguments are coerced into the strings `'true'` and `'false'`. This maintains compatibility with the API while allowing you to use bools in your code.

So in general, when you assign to these fields, you don't need to think about this at all. Just use bools as you normally would. However, when you access them, you need to be aware that they are strings:

```py
if project.metadata.public: # WRONG - will match 'false' too
    print("Project is public")

if project.metadata.public == "true": # CORRECT
    print("Project is public")
```


This is a bit unfortunate, but it's the best we can do without breaking compatibility with the API.


!!! quote "Author's note"
    It was decided to keep the offending fields as strings to maintain consistency with the API spec and avoid obscure bugs stemming from improper (de)serialization and validation.

    It's probably also a good idea to keep the models as close to the API spec as possible, so that the library doesn't diverge too much from the spec over time. There are, after all, a _lot_ of endpoints and models to keep track of.
