# Validation

By default, validation is enabled for all requests, meaning responses are validated through Pydantic models defined for each specific endpoint. You can disable validation of data from the API by setting the `validate` attribute on `HarborAsyncClient` to `False` either when instantiating the client or directly on the client object itself:

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
    Nested models will not be constructed when `validate=False` is set. The type of any submodel fields will be `dict` or `list`, depending on the type of the field in the API response, as the submodels will not be constructed by Pydantic. This will effectively break any code that relies on the submodels being constructed.

    Pydantic does not support constructing nested models without validation. This is a limitation of Pydantic, and not `harborapi`.


## Getting Raw Data

Set the `raw` attribute on the client object to return the raw JSON responses from the API. When we say "raw" we mean the response's JSON body after it has been serialized into a Python object, but before any other processing has been done by the library. This means that the response will be a `dict` or `list` (or a primitive type like `str`, `int`, `float`, `bool`, `None`), and not a Pydantic model.

In cases where an endpoint stops returning JSON responses altogether, `raw` will not help. In such cases, you will have to use a different tool to interact with the API.

```python
from harborapi import HarborAsyncClient

client = HarborAsyncClient(..., raw=True)
# or
client = HarborAsyncClient(...)
client.raw = True
```

## The difference between `raw` and `validate`

The `raw=True` attribute on the client object will cause the client to return the raw JSON data from the API, while the `validate=False` attribute will cause the client to skip validation of the data from the API, but still return the expected Pydantic model. `validate=False` is equivalent to constructing Pydantic models with [`BaseModel.construct()`](https://docs.pydantic.dev/usage/models/#creating-models-without-validation) instead of the usual [`BaseModel.parse_obj()`](https://docs.pydantic.dev/usage/models/#parsing-data-into-a-specified-type).


`raw` always takes precedence over `validate` if it is set. By default, `raw` is set to `False` and `validate` is set to `True`. I.e.:

```py
client = HarborAsyncClient(
    ...,
    raw=False,
    validate=True
)
```

### Examples

#### `validate=False`

```python
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    ...,
    validate=False
)
# This will print the Pydantic model with validation disabled
async def main():
  print(await client.get_system_info())

asyncio.run(main())
```
```py
GeneralInfo.construct(
    current_time="2023-02-06T14:34:42.449000+00:00",
    with_notary=True,
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
In the example, the model is constructed, but the values of the fields aren't validated and/or converted into the types specified in the model. `current_time` is still a string, even though the model says this is a datetime field. When validation is enabled, this field is converted into a datetime object.

Furthermore, in this fictional example, the API returned the value `2` for the `notification_enable` field, even though the spec says this is a boolean field. With validation disabled, the model is still constructed, and the value of `notification_enable` remains `2`. If we had enabled validation, and the value of `notification_enable` was `2`, we would get an error:

```
pydantic.error_wrappers.ValidationError: 1 validation error for GeneralInfo
notification_enable
  value could not be parsed to a boolean (type=type_error.bool)
```

#### `raw=True`

With `raw=True`, the client returns the parsed JSON data as a dict:

```python
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(..., raw=True)

# This will return the raw data from the API
async def main():
  print(await client.get_system_info())

asyncio.run(main())
```
```py
{
  "current_time": "2023-02-06T14:34:42.449000+00:00",
  "with_notary": True,
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

## Disabling validation on requests

An undocumented feature of the various HarborAPI endpoints is that the argument they accept can be a dict representing the model the endpoint expects. Even though the type hints say that it expects a specific model, any dict can be passed in. This is useful if the endpoint changes in a backwards-incompatible way, and HarborAPI has not yet been updated.

```python
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    # Create a project
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
