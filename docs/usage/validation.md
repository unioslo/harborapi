# Data validation

By default, data validation is enabled for all requests, which means the data in HTTP responses are validated by passing them to Pydantic models defined for each specific endpoint. This process ensures that the data returned from the API is both valid and in the correct format. In turn, we get a Pydantic model instance (or a list of them), that we can use to access the data through attributes (dot notation). See [`harborapi.models`][harborapi.models.models] for a list of all available models and their fields. The [Models](models.md) page contains more information about how models are used in `harborapi`.

By having access to the data through instance attributes intead of dictionary keys, users are provided with auto-completion and type hints in their IDEs, which makes it easier to work with and reason about the data. Furthermore, the data is already validated, so we can be sure that it is in the correct format when working with it.

Despite all this, users might want to disable validation for various reasons, such as:

- The version of Harbor they are using is not yet supported by the latest version of `harborapi`
- A model fails to validate due to a bug in the library or the API spec
- They want to use the data in a way that is not supported by the models



## Disable validation

We can disable validation of data from the API by setting the `validate` attribute on `HarborAsyncClient` to `False` either when instantiating the client or directly on the client object itself:

```python
from harborapi import HarborAsyncClient

client = HarborAsyncClient(..., validate=False)
# or
client = HarborAsyncClient(...)
client.validate = False
```

This will cause the client to skip validation of data from the API, and instead return the data as a Pydantic model where none of the fields have been validated.

This can be useful if using a version of Harbor that is not yet supported by the latest version of `harborapi` and/or a model fails to validate due to a bug in the library or the API spec.


!!! warning
    Nested models will not be constructed when `validate=False` is set. The type of any submodel fields will be `dict` or `list`, depending on the type of the field in the API response. This will effectively break any code that relies on the submodels being constructed.

    Pydantic does not support constructing nested models without validation. This is a limitation of Pydantic, and not `harborapi`.


### `no_validation()` context manager

`HarborAsyncClient` also provides the [`no_validation()`][harborapi.HarborAsyncClient.no_validation] context manager, which temporarily disables validation inside the `with` block:

```py

from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)

with client.no_validation():
    projects = await client.get_projects()
```

### Example

Without validation, the data is still returned as a [`GeneralInfo`][harborapi.models.GeneralInfo] model, but none of the fields are validated:

```python
import asyncio
from harborapi import HarborAsyncClient
from harborapi.models import GeneralInfo

client = HarborAsyncClient()

async def main():
    # temporarily disable validation
    with client.no_validation():
        info = await client.get_system_info()
        assert isinstance(info, dict)

    print(info)


asyncio.run(main())
```
```py
GeneralInfo.construct(
    current_time="2023-02-06T14:34:42.449000+00:00",
    with_chartmuseum=True,
    registry_url="demo.goharbor.io",
    external_url="https://demo.goharbor.io",
    auth_mode="db_auth",
    project_creation_restriction="everyone",
    self_registration=True,
    has_ca_root=False,
    harbor_version="v2.7.0-864aca34",
    registry_storage_provider_name="filesystem",
    read_only=False,
    notification_enable=2,
    authproxy_settings=None,
)
```
In the example, the [`GeneralInfo`][harborapi.models.GeneralInfo] model is constructed, but the values of the fields aren't validated and/or coereced into the types specified on model's fields. `current_time` is still a string, even though the model says this is a datetime field. When validation is enabled, this field is converted into a datetime object.

Furthermore, in this fictional example, the API returned the value `2` for the `notification_enable` field, even though the spec says this is a boolean field. With validation disabled, the model is still constructed successfully, and the value of `notification_enable` remains `2`.

If we had enabled validation, and the API returned the value `2` for the field `notification_enable`, we would get an error, because `2` cannot be parsed as a boolean value:

```
pydantic.error_wrappers.ValidationError: 1 validation error for GeneralInfo
notification_enable
  value could not be parsed to a boolean (type=type_error.bool)
```

## Getting Raw Data

In certain cases, we might want to access the raw JSON response from the API, and completely skip the conversion to Pydantic models altogether. In such cases, we can set the `raw` attribute on the client object.

This means that the return type of the various API endpoint methods will be `dict` or `list` (or a primitive type like `str`, `int`, `float`, `bool`, `None`) instead of a Pydantic model.

!!! note
    In cases where an endpoint stops returning JSON responses altogether, `raw` will not help. In such cases, you will have to use a different tool to interact with the API.

```python
from harborapi import HarborAsyncClient

client = HarborAsyncClient(..., raw=True)
# or
client = HarborAsyncClient(...)
client.raw = True
```

### `raw_mode()` context manager

We can also use the [`raw_mode()`][harborapi.HarborAsyncClient.raw_mode] context manager to temporarily enable raw mode for a single request:

```py

from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)

with client.raw_mode():
    projects = await client.get_projects()
    # projects is a list of dicts
```

### Example

With raw mode enabled, the client returns the parsed JSON data as a dict:

```python
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)

async def main():
    # temporarily enable raw mode
    with client.raw_mode():
        info = await client.get_system_info()
        assert isinstance(info, dict)

    print(info)

asyncio.run(main())
```
```py
{
  "current_time": "2023-02-06T14:34:42.449000+00:00",
  "with_chartmuseum": True,
  "registry_url": "demo.goharbor.io",
  "external_url": "https://demo.goharbor.io",
  "auth_mode": "db_auth",
  "project_creation_restriction": "everyone",
  "self_registration": True,
  "has_ca_root": False,
  "harbor_version": "v2.7.0-864aca34",
  "registry_storage_provider_name": "filesystem",
  "read_only": False,
  "notification_enable": 2,
  "authproxy_settings": None
}
```


## The difference between `raw` and `validate`

[Raw mode](#getting-raw-data) will cause the client to return the raw JSON data from the API, while [no validation](#disable-validation) will cause the client to skip validation of the data from the API, but still return the expected Pydantic model.


!!! info
    `validate=False` is equivalent to constructing Pydantic models with [`BaseModel.construct()`](https://docs.pydantic.dev/usage/models/#creating-models-without-validation) instead of the usual [`BaseModel.parse_obj()`](https://docs.pydantic.dev/usage/models/#parsing-data-into-a-specified-type). The latter method will validate the data and construct submodels, while the former will not.


`raw` always takes precedence over `validate` if it is set. By default, `raw` is set to `False` and `validate` is set to `True`. I.e.:

```py
client = HarborAsyncClient(
    ...,
    raw=False,
    validate=True
)
```

## Skipping validation for request models

An undocumented feature of the various endpoint methods that take Pydantic models as one of their arguments, is that they also accept dict representations of that model. Even though the type hints specify that a method expects a model of a specific type, any dict can technically be passed in.

This functionality is useful if an endpoint changes in a backwards-incompatible way that `harborapi` hasn't been updated to reflect yet, or `harborapi` has an error in a model that causes it to fail to validate against the API.

```python
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    project_path = await client.create_project(
        {
            "project_name": "test-project",
            "metadata": {
                "public": "false",
                "enable_content_trust": "false",
                "prevent_vul": "false",
                "auto_scan": "false",
                "severity": "low",
            },
        }
    )
    print(f"Project created: {project_path}")

asyncio.run(main())
```

In the future, the type hints will be updated to reflect this behavior, but for now it remains undocumented in the code itself.

!!! note
    If you are using a static type checker in your CI or pre-commit config, you will need to add a `# type: ignore` comment to the line where you pass in the dict to prevent the type checker from complaining about the type mismatch.
