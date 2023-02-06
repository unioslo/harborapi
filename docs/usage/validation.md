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


## Getting Raw Data

If you want to get the raw data from the API, you can set the `raw` attribute on the client object:

```python
from harborapi import HarborAsyncClient

client = HarborAsyncClient(..., raw=True)
# or
client = HarborAsyncClient(...)
client.raw = True
```

## The difference between `raw` and `validate`

The `raw=True` attribute on the client object will cause the client to return the raw data from the API, while the `validate=False` attribute will cause the client to skip validation of the data from the API, but still return the corresponding Pydantic model. `validate=False` is equivalent to constructing Pydantic models with [`BaseModel.construct()`](https://docs.pydantic.dev/usage/models/#creating-models-without-validation) instead of [`BaseModel.parse_obj()`](https://docs.pydantic.dev/usage/models/#parsing-data-into-a-specified-type).

### Examples

#### `validate=False`

```python
from harborapi import HarborAsyncClient

client = HarborAsyncClient(
    ...,
    raw=False, # This is the default
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

If, for example, `notification_enable` happened to be an integer instead of `True` or `False` as the spec states (bool), the model would still be constructed, since validation is disabled. If we enabled Validation, and the value of `notification_enable` was an integer, we would get an error:

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
