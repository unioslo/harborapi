# Exceptions

All methods that interact with the Harbor API raise exceptions derived from [`harborapi.exceptions.StatusError`][harborapi.exceptions.StatusError] for responses with non-2xx status codes unless otherwise specified.

## Response

Each exception contains the response that caused the exception to be raised, and the status code of the response. The response object is a [`httpx.Response`](https://www.python-httpx.org/api/#response) object.

```py
try:
    await client.delete_artifact("project", "repository", "latest")
except StatusError as e:
    print(e.response)
    print(e.status_code) # or e.response.status_code
```

Through the response object, we can also get the corresponding [`httpx.Request`](https://www.python-httpx.org/api/#request) through the `request` attribute.

```py
e.response.request
```

## Granular exception handling

If more granular exception handling is required, all documented HTTP exceptions in the API spec are implemented as discrete subclasses of [`harborapi.exceptions.StatusError`][harborapi.exceptions.StatusError].

```py
from harborapi.exceptions import (
    BadRequest,
    Forbidden,
    NotFound,
    MethodNotAllowed,
    Conflict,
    Unauthorized,
    PreconditionFailed,
    UnsupportedMediaType,
    InternalServerError,
    StatusError
)

project, repo, tag = "testproj", "testrepo", "latest"

try:
    await client.delete_artifact(project, repo, tag)
except NotFound as e:
    print(f"'{repo}:{tag}' not found for project '{project}'")
except StatusError as e:
    # catch all other HTTP exceptions
```

## Inspecting errors

The [`StatusError.errors`][harborapi.exceptions.StatusError.errors] attribute is a list of [`Error`][harborapi.models.models.Error] objects that contains more detailed information about the error(s) that have occured.

```py
try:
    await client.delete_artifact("project", "repository", "latest")
except StatusError as e:
    for error in e.errors:
        print(error.code, error.message)
```

An [`Error`][harborapi.models.models.Error] object has the following structure:

```py
class Error(BaseModel):
    code: Optional[str] = Field(None, description="The error code")
    message: Optional[str] = Field(None, description="The error message")
```

(It is likely that `code` and `message` are both not `None` on runtime, but the API specification states that both these fields are optional.)
