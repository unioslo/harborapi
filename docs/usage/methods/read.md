# Read

## Fetch a single resource

When fetching a single resource, the method usually expects a resource identifier or name as the first parameter, and returns a single instance of the Pydantic model corresponding to the resource type.

Each method's return type is documented in the [Endpoints Overview](../../endpoints/index.md)


```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)

async def main() -> None:
    project = await client.get_project("test-project")
    print(project)


asyncio.run(main())
```

In this case we pass in a project name to [`get_project`][harborapi.HarborAsyncClient.get_project] and receive a [`Project`][harborapi.models.Project] object.


## Fetch multiple resources

Certain methods fetch multiple resources and return a list of Pydantic models. Below is a basic example of how to use these methods.

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    projects = await client.get_projects()
    for project in projects:
        print(project)


asyncio.run(main())
```

In this case we call [`get_projects`][harborapi.HarborAsyncClient.get_projects] with no arguments, and receive a list of [`Project`][harborapi.models.Project] objects.

Methods that fetch multiple resources have a number of optional arguments that can be provided to filter, sort and limit the results. These arguments are documented below.


### `query`

A query string to filter the results by.

#### Syntax

`field1[operator][value],[field2[operator][value]],...`

#### Query patterns

* exact match(`"k=v"`)
* fuzzy match(`"k=~v"`)
* range(`"k=[min~max]"`)
* list with union releationship(`"k={v1 v2 v3}"`)
* list with intersection relationship(`"k=(v1 v2 v3)"`).


#### Value types

* string(enclosed by `"` or `'`)
* integer
* time(in format `"2020-04-09 02:36:00"`)


#### Example

```py
await client.get_projects(
    query="name=test-project,created_at=[2020-01-01~2023-12-31]",
)
```

----

### `sort`

The field(s) to sort the results by. Must match the field names of the API response model.

#### Syntax

`field1,field2,...`

Prepend fields with `-` to sort in descending order.

#### Example

```py
await client.get_projects(
    sort="name,-created_at",
)
```

!!! note

    Not all fields support sorting. This is not documented anywhere by Harbor, and the only way to know which fields work is to try them out. Unsortable fields are ignored by the API.

----

### `limit`

The maximum number of results to return. By default unlimited (`None`).

For certain methods, such as [`HarborAsyncClient.get_audit_logs()`][harborapi.HarborAsyncClient.get_audit_logs], it is highly advised to set a limit to avoid fetching every single entry in the database.

### Example

```py
await client.get_projects(
    limit=10,
)
```

----

### `page`

The page number to start fetching from. This is a parameter that is used in conjunction with `page_size` to control how results are fetched from the API. In the vast majority of cases, this specific parameter does not need to be changed.

### Example

```py
await client.get_projects(
    page=2,
)
```

----

### `page_size`

The number of results to return per page. This is a parameter that is used in conjunction with `page` to control how results are fetched from the API. Used in situtations where you want to either reduce or increase the number of requests to the API, and conversely the size of each response. (Higher page size = fewer requests, but larger responses).

As with `page`, this specific parameter does not need to be changed in the vast majority of cases.

### Example

```py
await client.get_projects(
    page_size=20,
)
```

### Example (with all parameters)

```py
import asyncio
from harborapi import HarborAsyncClient

client = HarborAsyncClient(...)


async def main() -> None:
    projects = await client.get_projects(
        query="name=test-project,created_at=[2020-01-01~2023-12-31]",
        sort="name",
        page=1,
        page_size=10,
        limit=100,
    )
    for project in projects:
        print(project)


asyncio.run(main())
```
