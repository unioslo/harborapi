# Validation

By default, validation is enabled for all requests, meaning responses are validated through Pydantic models defined for each specific endpoint. You can disable validation of data from the API by setting the `validate` attribute on `HarborAsyncClient` to `False` either when instantiating the client or directly on the client object itself:

```python
from harborapi import HarborAsyncClient

client = HarborAsyncClient(..., validate=False)
# or
client = HarborAsyncClient(...)
client.validate = False
```

This will cause the client to skip validation of data from the API, and instead return the data as a Pydantic model where none of the fields have been validated. This can be useful if you are using a version of Harbor that is not yet supported by the latest version of `harborapi`, but stil want to use dot notation to access the data, and use the various helper methods on the Pydantic models.

!!! warning
    Nested models will not be constructed when `validate=False` is set. This means that if you have a model that has a field that is a Pydantic model, the value of the field will be a `dict` instead of a Pydantic model.

    Pydantic does not support constructing nested models without validation. This is a limitation of Pydantic, and not `harborapi`.


## Getting Raw Data

If you want to get the raw JSON data from the API, you can set the `raw` attribute on the client object. When we say "raw" we mean the response's JSON body after it has been serialized into a Python dict, but before any other processing has been done.

In cases where an endpoint stops returning JSON responses altogether when expected to do so, `raw` will not help. In that case, you should use a tool like curl or something similar to fetch the data, as this library will be of little use at that point.

```python
from harborapi import HarborAsyncClient

client = HarborAsyncClient(..., raw=True)
# or
client = HarborAsyncClient(...)
client.raw = True
```

## The difference between `raw` and `validate`

The `raw=True` attribute on the client object will cause the client to return the raw JSON data from the API, while the `validate=False` attribute will cause the client to skip validation of the data from the API, but still return the corresponding Pydantic model. `validate=False` is equivalent to constructing Pydantic models with [`BaseModel.construct()`](https://docs.pydantic.dev/usage/models/#creating-models-without-validation) instead of [`BaseModel.parse_obj()`](https://docs.pydantic.dev/usage/models/#parsing-data-into-a-specified-type).


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
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    ...,
    validate=False
)

# This will print the Pydantic model with validation disabled
print(client.get_system_info())
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

Furthermore, in this fictional example, the API returned an integer value for the `notification_enable` field, even though the spec says this is a boolean field. With validation disabled, the model is still constructed, and the value of `notification_enable` is still an integer. If we had enabled validation, and the value of `notification_enable` was an integer, we would get an error:

```
pydantic.error_wrappers.ValidationError: 1 validation error for GeneralInfo
notification_enable
  value could not be parsed to a boolean (type=type_error.bool)
```

#### `raw=True`

```python
from harborapi import HarborAsyncClient

client = HarborAsyncClient(..., raw=True)

# This will return the raw data from the API
print(client.get_system_info())
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
