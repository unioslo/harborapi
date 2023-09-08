# Code Generation

The application relies on code generation to generate models for the Harbor API. Some of these model definitions are not entirely correct, however, and this is where we have to do some extra work to fix them.

Furthermore, the API is constantly evolving, and this is a way to ensure we always have up-to-date models for the API (and if it's not backwards-compatible, blame Harbor for not caring about proper versioning and deprecation of their API).

## What is happening here?

The steps to generate code for the application is as follows:

1. Download the Swagger v2.0 API specification from the Harbor API repository.
2. Convert the spec to OpenAPI v3.0 with the [Swagger converter API](https://converter.swagger.io/)
3. Generate the models with [datamodel-code-generator](https://github.com/koxudaxi/datamodel-code-generator)
4. Modify the generated models to fix inconsistencies and errors in the API spec, as well as add new fields and methods.
5. Format the generated code with [black](https://github.com/psf/black) and [reorder-python-imports](https://github.com/asottile/reorder-python-imports).


## Why AST manipulation instead of modifying the YAML spec?

Basically, because we already need to manipulat the AST to add new methods and have our Root models use custom base classes. It's easier to just do everything in the AST manipulation step instead of adding/modifying behavior in two different places.


## How do I generate code?

It's all orchestrated by the `generate.sh` script:

```
USAGE: generate.sh [main|scanner] [--nocodegen]
```

The script takes two arguments, the first being the name of the module to generate code for, and the second being an optional flag to skip fetching new API definitions and running `datamodel-codegen`, and instead only run the AST manipulation and formatting steps.

### Scanner?

Yeah, for some reason Harbor has a separate ["pluggable scanner API spec"](https://github.com/goharbor/pluggable-scanner-spec), which they actually use in their API without it being fully documented in the main API spec. So, we have to generate code for that as well.

However, in the last year (2023), they have actually starting adding some of it into the main API spec, so now it's just a bit of a mess. Either way, for now we have to generate models for both specs.

It's understandable that they want to provide an API spec for 3rd party scanners to use, but it would be nice if one of two things could happen:

1. Parity between main spec and scanner spec
2. Include scanner spec in main spec

Because right now we have divergent definitions for things like `Artifact`, `VulnerabilityItem` and `Scanner` in both API specs.

## AST Manipulation

In order to add new fields, change certain field type annotations, add or modify class docstrings, and more, we use AST manipulation. The file `ast/parser.py` includes the code for parsing and modifying the AST, as well as certain in-line definitions of the classes to change.


Inline code changes use special classes to signify what to change:

```py
models = {
    "main": {
        "Artifact": [
            # Add new docstring
            Docstring("This is the new docstring for Artifact"),
            # Add new field
            Field("new_field", "str", default="some default", description="field description here"),
            # Change type annotation of an existing field
            Annotation("existing_field", "Optional[str]")
            # Add PEP 257 attribute docstring
            AttrDocstring("some_attr", "This is the new docstring for some_attr"),
        ]
    }
}
```

All inline changes are documented in `ast/parser.py`.

The inline changes should be reserved for small changes. For larger changes, we use "fragments" of the classes to change, which are then inserted into the AST at the appropriate places. The directories `ast/fragments/{main,scanner}` contain fragments for the main and scanner models. A class fragment can look like this:

```py
from typing import Iterable
from pydantic import Field

class Foo(BaseModel):
    gux: float = Field(0.0, description="This is a gux")

    def count(self) -> Iterable[int]:
        for i in range(5):
            yield i
```

While the code we want to modify looks like this:


```py
from pydantic import BaseModel
from pydantic import Field

class Foo(BaseModel):
    bar: str = Field(..., description="This is a bar")
    baz: int = Field(..., description="This is a baz")
```

The `Foo` class in the fragment will be inserted into the AST at the appropriate place, and the result will look like this:

```py
from typing import Iterable

from pydantic import BaseModel
from pydantic import Field

class Foo(BaseModel):
    bar: str = Field(..., description="This is a bar")
    baz: int = Field(..., description="This is a baz")
    gux: float = Field(0.0, description="This is a gux")

    def count(self) -> Iterable[int]:
        for i in range(5):
            yield i
```

The new import (`from typing import Iterable`) from the fragment has been added, along with the new field `gux` and the method `count`.

## TODO

- [ ] Replace fields in original models with fields from fragments
