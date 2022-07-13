# Exceptions

All methods that interact with the Harbor API raise exceptions derived from [`StatusError`](../../reference/exceptions/#harborapi.exceptions.StatusError) for responses with non-2xx status codes unless otherwise specified.

## Status Code

```py
try:
    await client.delete_artifact("project", "repository", "latest")
except StatusError as e:
    print(e.status_code)
```

## Granular Exception Handling

If more granular exception handling is required, all documented HTTP exceptions in the API spec are implemented as discrete classes derived from [`StatusError`](../../reference/exceptions/#harborapi.exceptions.StatusError)

```py
from harborapi.exceptions import (
    BadRequest,
    Forbidden,
    NotFound,
    Unauthorized,
    PreconditionFailed,
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

## Inspecting Errors

The `StatusError.errors` attribute is a list of [`Error`](../../reference/models/#harborapi.models.models.Error) objects that contain
more detailed information about the error(s) that have occured.

```py
try:
    await client.delete_artifact("project", "repository", "latest")
except StatusError as e:
    for error in e.errors:
        print(error.code, error.message)
```

An [`Error`](../../reference/models/#harborapi.models.models.Error) object has the following structure

```py
class Error(BaseModel):
    code: Optional[str] = Field(None, description="The error code")
    message: Optional[str] = Field(None, description="The error message")
```

(It is likely that `code` and `message` are both not `None` on runtime, but the API specification states that both these fields are optional.)
