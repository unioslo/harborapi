# Rich support

All data models in harborapi support the [Rich](https://rich.readthedocs.io/) `__rich_console__` [protocol](https://rich.readthedocs.io/en/stable/protocol.html#console-render), which allows these models to be specially rendered in Rich consoles.

In order to use this feature, you must first install `rich`:

```bash
pip install rich
```

The `__rich_console__` method on a model creates a [Rich Table](https://rich.readthedocs.io/en/stable/tables.html) representation of the model. This method is automatically called when printing the model to a Rich console.

## Printing models

Printing a model to a Rich console will automatically render the model as a table:

```py
from rich import print

a = Repository(...)
print(a)
```

Produces:

```
Repository
┏━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Setting                 ┃ Value                               ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ id                      │ 1234                                │
│ project_id              │ 1                                   │
│ name                    │ library/foo                         │
│ description             │ 'Foo application images'            │
│ artifact_count          │ 16                                  │
│ pull_count              │ 388                                 │
│ creation_time           │ 2020-02-02 16:34:35.364000+00:00    │
│ update_time             │ 2022-12-04 01:00:44.702000+00:00    │
└─────────────────────────┴─────────────────────────────────────┘
```


## Get model tables

If you want to retrieve the table representation(s) of a model, you can use the [`BaseModel.as_table`][harborapi.models.base.BaseModel.as_table] method. This method returns a generator of Rich Table objects.

Since the returned object is a [generator](https://docs.python.org/3/glossary.html#term-generator), we must either iterate over it manually, or consume it by passing it to a container type, such as a list or tuple.

By calling this function ourselves, we can pass parameters such as `max_depth` to customize the recursion depth of the table, as well as `with_description` to include the description of each field in the table.


```py
from rich import print

a = Artifact(...)

# We can print each table individually
for table in a.as_table():
    print(table)

# Or print them all at once
print(*(a.as_table())) # this is equivalent to calling `print(a)`

# We can use the parameters of `as_table` to customize the table:
tables = a.as_table(max_depth=0) # don't recurse into nested models

# We can consume the generator by passing it to a list
tables = list(a.as_table())
tables = tables[:2]
for table in tables:
    print(table)
```
