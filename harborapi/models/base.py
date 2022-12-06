"""Base module for models that defines a base Pydantic model class
that adds shared functionality and capabilities to all models.

Special support for printing the models as Rich tables is added through the
use of the special __rich_console__ method. See the Rich documentation
for more information: https://rich.readthedocs.io/en/latest/protocol.html#console-render.

Other functionality in the future will be added here as well.
"""

from typing import TYPE_CHECKING

from pydantic import BaseModel as PydanticBaseModel

try:
    import rich
    from rich.console import Console, ConsoleOptions, RenderResult
    from rich.table import Column, Table
except ImportError:
    rich = None


class BaseModel(PydanticBaseModel):
    if rich is not None:

        def __rich_console__(
            self, console: Console, options: ConsoleOptions
        ) -> RenderResult:
            """Rich console representation of the model.
            Returns a table with the model's fields and values.
            If the model has a nested model, the nested model's table representation
            is printed after the main table. Should support multiple levels of
            nested models, but not tested.
            See: https://rich.readthedocs.io/en/latest/protocol.html#console-render
            """
            try:
                name = self.__name__  # type: ignore # this is populated by Pydantic
            except AttributeError:
                name = self.__class__.__name__
            table = Table(
                Column(
                    header="Setting", justify="left", style="green", header_style="bold"
                ),
                Column(header="Value", style="blue", justify="left"),
                Column(header="Description", style="yellow", justify="left"),
                title=f"[bold]{name}[/bold]",
                title_style="magenta",
                title_justify="left",
            )
            subtables = []
            for field_name, field in self.__fields__.items():
                # Try to use field title if available
                field_title = field.field_info.title or field_name

                attr = getattr(self, field_name)
                try:
                    # issubclass is prone to TypeError, so we use try/except
                    if issubclass(field.type_, BaseModel) and attr is not None:
                        if isinstance(attr, (list, set)):
                            subtables.extend(attr)
                        else:
                            subtables.append(attr)
                        continue
                except:
                    pass
                table.add_row(field_title, str(attr), field.field_info.description)

            if table.rows:
                yield table
            yield from subtables

    class Config:
        # Account for additions to the spec
        # These fields will not be validated however
        extra = "allow"
