"""Base module for models that defines a base Pydantic model class
that adds shared functionality and capabilities to all models.

Support for printing the models as Rich tables is added through the
use of the special `__rich_console__` method. See the Rich documentation
for more information: <https://rich.readthedocs.io/en/latest/protocol.html#console-render/>.
"""

from __future__ import annotations

from typing import Any
from typing import Generator
from typing import Iterable
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple
from typing import Type
from typing import TypeVar

from pydantic import BaseModel as PydanticBaseModel
from pydantic import ConfigDict
from pydantic import RootModel as PydanticRootModel

# fmt: off
try:
    from rich.console import Console
    from rich.console import ConsoleOptions
    from rich.console import Group
    from rich.console import RenderResult
    from rich.panel import Panel
    from rich.table import Column
    from rich.table import Table
    rich_installed = True
except ImportError:
    rich_installed = False
# fmt: on


BaseModelType = TypeVar("BaseModelType", bound="BaseModel")


DEPTH_TITLE_COLORS = {
    0: "magenta",
    1: "cyan",
    2: "blue",
    3: "green",
    4: "yellow",
    5: "red",
}


T = TypeVar("T")


class RootModel(PydanticRootModel[T]):
    model_config = ConfigDict(validate_assignment=True)

    root: T

    def __bool__(self) -> bool:
        return bool(self.root)

    def __iter__(self) -> Generator[Tuple[Any, Any], None, None]:
        # TODO: fix API spec so root  types can never be none, only
        # the empty container. That way we can always iterate and access
        # without checking for None.
        if isinstance(self.root, Iterable):
            yield from iter(self.root)  # pyright: ignore[reportUnknownArgumentType, reportUnknownMemberType]
        else:
            yield from iter([])

    def __getitem__(self, key: Any) -> Any:
        if isinstance(self.root, (Mapping, Sequence)):
            return self.root[key]  # pyright: ignore[reportUnknownVariableType, reportUnknownMemberType]
        return None

    # Enables dot access to dict keys for backwards compatibility
    def __getattr__(self, attr: str) -> T:
        try:
            return self.root[attr]  # pyright: ignore[reportUnknownVariableType, reportIndexIssue]
        except (KeyError, TypeError, IndexError):
            raise AttributeError(f"{self.__class__.__name__} has no attribute {attr}")


class BaseModel(PydanticBaseModel):
    model_config = ConfigDict(extra="allow", validate_assignment=True, strict=False)

    # Validators

    # The __rich* properties are only used by methods defined when Rich
    # is installed, but they are defined here, so that static typing works
    # when overriding the properties in subclasses.
    @property
    def __rich_table_title__(self) -> str:
        """The title to use for the table representation of the model.
        By default, the model's class name is be used.
        """
        try:
            title = self.__name__
            assert isinstance(title, str)
        except (AttributeError, AssertionError):
            title = self.__class__.__name__
        return title

    @property
    def __rich_panel_title__(self) -> Optional[str]:
        """Title of the panel that wraps the table representation of the model."""
        return None

    def convert_to(
        self, model: Type[BaseModelType], extra: bool = False
    ) -> BaseModelType:
        """Converts the model to a different model type.

        By default, only fields that are defined in the destination model
        are included in the converted model.

        Parameters
        ----------
        model : Type[BaseModelType]
            The model type to convert to.
        extra : bool
            Whether to include fields that are not defined in the destination model.

        Returns
        -------
        BaseModelType
            The converted model.
        """
        # TODO: include mapping of source fields to destination fields
        # e.g. Project.name -> ProjectReq.project_name
        # pass in mapping: {"name": "project_name"}
        if extra:
            include = None
        else:
            include = model.get_model_fields()
        return model.model_validate(self.model_dump(include=include))

    @classmethod
    def get_model_fields(cls) -> Set[str]:
        """Get a list of the names of the model's fields.

        Returns
        -------
        List[str]
            The names of the model's fields.
        """
        return set(cls.model_fields)

    if rich_installed:

        def __rich_console__(
            self, console: Console, options: ConsoleOptions
        ) -> RenderResult:
            """Rich console representation of the model.
            Returns a panel containing tables representing the model's
            fields and values.
            If the model has a nested model, the nested model's table representation
            is printed after the main table.

            See: https://rich.readthedocs.io/en/latest/protocol.html#console-render
            """
            yield self.as_panel(with_description=False)

        def as_panel(self, title: Optional[str] = None, **kwargs: Any) -> Panel:
            """Returns table representation of model wrapped in a Panel.
            Passes all keyword arguments to `as_table`.

            Returns
            -------
            Panel
                A Rich panel containing the table representation of the model.
            """
            title = title or self.__rich_panel_title__
            return Panel(Group(*self.as_table(**kwargs)), title=title)

        def as_table(
            self,
            with_description: bool = False,
            max_depth: Optional[int] = None,
            parent_field: Optional[str] = None,
            _depth: int = 1,
        ) -> Iterable[Table]:
            """Returns a Rich table representation of the model, and any nested models.

            Parameters
            ----------
            with_description : bool
                Whether to include the description of the model fields.
            max_depth : Optional[int]
                The maximum depth to print nested models.
                `None` means no limit.
            parent_field : Optional[str]
                The title of the parent field that contains this model.
                Used when printing submodels.
            _depth : int
                DO NOT SET THIS.
                This is used internally to track the current depth level.

            Returns
            -------
            Iterable[Table]
                A generator of Rich tables representing the model and any nested models.
            """
            # VOCABULARY:
            # "field" -> a field in the model spec
            # "field name" -> the name of the field in the model spec
            # "submodel" -> a nested model
            # "submodel table" -> the table representation of a nested model

            # None and n <= 0 means no limit to recursion depth
            if max_depth is not None and max_depth <= 0:
                max_depth = None

            # TODO: add list index indicator for list fields
            if not parent_field:
                title = type(self).__qualname__
            else:
                title = f"{parent_field}"

            columns = [
                Column(
                    header="Field", justify="left", style="green", header_style="bold"
                ),
                Column(header="Value", style="blue", justify="left", overflow="fold"),
            ]
            if with_description:
                columns.append(
                    Column(header="Description", style="yellow", justify="left"),
                )

            table = Table(
                title=f"[bold]{title}[/bold]",
                title_style=DEPTH_TITLE_COLORS.get(_depth, "magenta"),
                title_justify="left",
                expand=True,
                *columns,
            )

            subtables = []  # type: list[Iterable[Table]]

            def add_submodel_table(field_title: str, submodel: "BaseModel") -> str:
                """Adds a submodel table to the subtables list."""
                if parent_field:
                    pfield = f"{parent_field}.{field_title}"
                else:
                    pfield = f"{type(self).__qualname__}.{field_title}"
                submodel_table = submodel.as_table(
                    with_description=with_description,
                    max_depth=max_depth,
                    _depth=_depth + 1,
                    parent_field=pfield,
                )
                subtables.append(submodel_table)
                return pfield

            # Iterate over self to get model fields + extra fields
            for field_name, value in super(BaseModel, self).__iter__():
                # Prioritize getting field info from __fields__ dict
                # since this dict contains more metadata for the field
                field = self.model_fields.get(field_name)
                if field is not None:
                    # Try to use field title if available
                    field_title = str(field.title or field_name)
                    # Get the field value
                    value = getattr(self, field_name)
                    description = str(field.description) or ""
                else:
                    field_title = field_name
                    description = ""

                submodels = []  # type: Iterable[BaseModel]
                if isinstance(value, BaseModel):
                    submodels = [value]
                elif isinstance(value, Iterable):
                    if all(isinstance(v, BaseModel) for v in value):
                        submodels = value

                # Only print the submodel table if we are not at the max depth
                # If we don't enter this, we print the string representation of the
                # submodel(s) in the main table.
                if submodels and (max_depth is None or _depth < max_depth):
                    # consume iterable immediately so we can get table title
                    # It's likely this is NOT a generator, but we don't want to
                    # assume that.
                    submodels = list(submodels)
                    table_title = ""
                    for submodel in submodels:
                        table_title = add_submodel_table(field_title, submodel)
                    value = f"[bold]See below ({table_title})[/bold]"

                row = [field_title, str(value)]
                if with_description:
                    row.append(description)
                table.add_row(*row)

            # TODO: sort table rows by field name

            yield table
            for subtable in subtables:
                yield from subtable
