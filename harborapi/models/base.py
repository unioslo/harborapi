"""Base module for models that defines a base Pydantic model class
that adds shared functionality and capabilities to all models.

Support for printing the models as Rich tables is added through the
use of the special `__rich_console__` method. See the Rich documentation
for more information: <https://rich.readthedocs.io/en/latest/protocol.html#console-render/>.
"""

from typing import Any, Iterable, List, Optional, Type, TypeVar

from pydantic import BaseModel as PydanticBaseModel
from pydantic import validator
from pydantic.fields import ModelField

# fmt: off
try:
    from rich.console import Console, ConsoleOptions, Group, RenderResult
    from rich.panel import Panel
    from rich.table import Column, Table
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

_strbool_field_phrases = ['"true"', '"false"']


def convert_bool_to_lower_str_field(
    cls: Type["BaseModel"],
    value: Any,
    field: ModelField,
) -> Any:
    """Harbor API has some models where the accepted values are 'true' and 'false',
    for fields that have a string type. This validator converts bool arguments
    to the correct string values.

    Pydantic has built-in conversion from bool to str, but it yields
    'True' and 'False' instead of 'true' and 'false'.

    Furthermore, this validator only converts the values if the field
    description contains the phrases '"true"' and '"false"' (with quotes).
    """
    # NOTE: we can restrict this validator to a subset of models if needed.
    # For now, we apply it to all models in case the API changes in the future.

    if field.field_info.description is None:
        return value

    # We can only convert bools
    if not isinstance(value, bool):
        return value

    # NOTE: change to any()?
    if all(phrase in field.field_info.description for phrase in _strbool_field_phrases):
        return str(value).lower()
    return value


class BaseModel(PydanticBaseModel):
    class Config:
        # Account for additions to the spec
        # These fields will not be validated however
        extra = "allow"
        validate_assignment = True

    # Validators
    _bool_converter = validator("*", pre=True, allow_reuse=True)(
        convert_bool_to_lower_str_field
    )

    # The __rich* properties are only used by methods defined when Rich
    # is installed, but they are defined here, so that static typing works
    # when overriding the properties in subclasses.
    @property
    def __rich_table_title__(self) -> str:
        """The title to use for the table representation of the model.
        By default, the model's class name is be used.
        """
        try:
            title = self.__name__  # type: ignore # this is populated by Pydantic
            assert isinstance(title, str)
        except (AttributeError, AssertionError):
            title = self.__class__.__name__
        return title  # type: ignore # not sure why mypy complains after assert

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
            include = model.__fields__.keys()
        return model.parse_obj(self.dict(include=include))

    @classmethod
    def get_model_fields(cls) -> List[str]:
        """Get a list of the names of the model's fields.

        Returns
        -------
        List[str]
            The names of the model's fields.
        """
        return list(cls.__fields__.keys())

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

            # Iterate over __dict__, but try to get the field values from the
            # __fields__ dict since it contains more metadata.
            # We iterate over __dict__ to account for fields that are not
            # defined in the model, but are added dynamically ("extra" fields).
            # Extra fields do not show up in __fields__, hence we use __dict__.
            for field_name, value in self.__dict__.items():
                # Prioritize getting field info from __fields__ dict
                # since this dict contains more metadata for the field
                field = self.__fields__.get(field_name)
                if field is not None:
                    # Try to use field title if available
                    field_title = str(field.field_info.title or field_name)
                    # Get the field value
                    value = getattr(self, field_name)
                    description = str(field.field_info.description) or ""
                else:
                    # If the field was not found in __fields__, then it is an
                    # "extra" field that is not a part of the model spec.
                    # We still want to print it, but we don't have any metadata
                    # for it, so we just print the field name and value.
                    # We can never have a description for these fields.
                    field_title = field_name
                    description = ""

                submodels = []  # type: Iterable[BaseModel]

                # Check if we are dealing with a nested model or list of nested models
                # In that case, we need to recurse and fetch the nested model table(s).
                # We don't print them right away, but instead store them in the subtables
                # list, which we yield at the end (after the main table).
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
