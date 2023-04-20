# Rich support

All data models in harborapi support the [Rich](https://rich.readthedocs.io/) `__rich_console__` [protocol](https://rich.readthedocs.io/en/stable/protocol.html#console-render), which allows these models to be specially rendered in Rich consoles.

In order to use this feature, you must first install `rich`:

```bash
pip install rich
```

The `__rich_console__` method on a model creates a [Rich Panel](https://rich.readthedocs.io/en/stable/panel.html) containing one or more [Rich Tables](https://rich.readthedocs.io/en/stable/tables.html) representing the model. This method is automatically called when the model is printed to a Rich console.

## Printing models

Printing a model to a Rich console will automatically render the model as a table:

```py
from rich import print
from harborapi.models import Repository

r = Repository(
    ..., # omitted for brevity
)
print(r)
```

Produces:

```
╭───────────────────────────────────────────────────────────────╮
│ Repository                                                    │
│ ┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│ ┃ Field             ┃ Value                                 ┃ │
│ ┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩ │
│ │ id                │ 1234                                  │ │
│ │ project_id        │ 1                                     │ │
│ │ name              │ library/foo                           │ │
│ │ description       │ Foo application repository            │ │
│ │ artifact_count    │ 123                                   │ │
│ │ pull_count        │ 456                                   │ │
│ │ creation_time     │ 2020-01-01 13:20:46.230000+00:00      │ │
│ │ update_time       │ 2023-01-01 13:20:46.230000+00:00      │ │
│ └───────────────────┴───────────────────────────────────────┘ │
╰───────────────────────────────────────────────────────────────╯
```


Nested models are rendered as individual tables within the panel:

```py
from rich import print

from harborapi.models import Schedule, ScheduleObj

s = Schedule(
    ..., # omitted for brevity
    schedule=ScheduleObj(
        ...,
    ),
)
print(s)

```

Produces:

```
╭───────────────────────────────────────────────────────────────╮
│ Schedule                                                      │
│ ┏━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓ │
│ ┃ Field            ┃ Value                                  ┃ │
│ ┡━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩ │
│ │ id               │ 1234                                   │ │
│ │ status           │ None                                   │ │
│ │ creation_time    │ 2020-01-01 13:20:46.230000+00:00       │ │
│ │ update_time      │ 2023-01-01 13:20:46.230000+00:00       │ │
│ │ schedule         │ See below (Schedule.schedule)          │ │
│ │ parameters       │ None                                   │ │
│ └──────────────────┴────────────────────────────────────────┘ │
│ Schedule.schedule                                             │
│ ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓ │
│ ┃ Field                              ┃ Value                ┃ │
│ ┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩ │
│ │ type                               │ Type.daily           │ │
│ │ cron                               │ 0 0 0 * * *          │ │
│ │ next_scheduled_time                │ None                 │ │
│ └────────────────────────────────────┴──────────────────────┘ │
╰───────────────────────────────────────────────────────────────╯
```


## Get model tables

If you want to retrieve the table representation(s) of a model, you can use the [`as_table`][harborapi.models.base.BaseModel.as_table] method. This method returns a generator of Rich Table objects.

Since the returned object is a [generator](https://docs.python.org/3/glossary.html#term-generator), we must either iterate over it manually, or consume it by passing it to a container type, such as a list or tuple.

By calling this function ourselves, we can pass parameters such as `max_depth` to customize the recursion depth of the table, as well as `with_description` to include the description of each field in the table.


```py
from rich import print

a = Artifact(...)

# We can print each table individually
for table in a.as_table():
    print(table)

# Or print them all at once
print(*(a.as_table()))

# We can use the parameters of `as_table` to customize the table:
tables = a.as_table(max_depth=0) # don't recurse into nested models

# We can consume the generator by passing it to a list
tables = list(a.as_table())
tables = tables[:2]
for table in tables:
    print(table)
```

The same kwargs that can be passed to [`as_table`][harborapi.models.base.BaseModel.as_panel] can also be passed to [`as_panel`][harborapi.models.base.BaseModel.as_panel], which is the method that `__rich_console__` calls under the hood to wrap the tables in a panel.
