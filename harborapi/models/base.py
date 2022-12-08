"""Base module for models that defines a base Pydantic model class
that adds shared functionality and capabilities to all models.

Special support for printing the models as Rich tables is added through the
use of the special __rich_console__ method. See the Rich documentation
for more information: https://rich.readthedocs.io/en/latest/protocol.html#console-render.

Other functionality in the future will be added here as well.
"""

from typing import Iterable

from pydantic import BaseModel as PydanticBaseModel

try:
    import rich
    from rich.console import Console, ConsoleOptions, RenderResult
    from rich.table import Column, Table
except ImportError:
    rich = None


NESTING_TITLE_COLORS = {
    0: "magenta",
    1: "cyan",
    2: "blue",
    3: "green",
    4: "yellow",
    5: "red",
}


class BaseModel(PydanticBaseModel):
    class Config:
        # Account for additions to the spec
        # These fields will not be validated however
        extra = "allow"

    @property
    def _table_title(self) -> str:
        """The title to use for the table representation of the model.
        By default, the model's class name is be used.
        """
        try:
            title = self.__name__  # type: ignore # this is populated by Pydantic
        except AttributeError:
            title = self.__class__.__name__
        return title

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
            return self.as_table(with_description=False)

        def as_table(
            self, nesting: int = 0, with_description: bool = False
        ) -> Iterable[Table]:
            """Returns a Rich table representation of the model, and any nested models.

            Parameters
            ----------
            model : BaseModel
                The model to represent as a table.
            nesting : int, optional
                The current nesting level, by default 0
            with_description : bool, optional
                Whether to include the description of the model fields, by default False

            Returns
            -------
            Table
                The table representation of the model.
            """
            title = self._table_title

            columns = [
                Column(
                    header="Setting", justify="left", style="green", header_style="bold"
                ),
                Column(header="Value", style="blue", justify="left"),
            ]
            if with_description:
                columns.append(
                    Column(header="Description", style="yellow", justify="left"),
                )

            depth_indicator = "." * nesting
            table = Table(
                title=f"[bold]{depth_indicator}{title}[/bold]",
                title_style=NESTING_TITLE_COLORS.get(nesting, "magenta"),
                title_justify="left",
                expand=True,
                *columns,
            )

            subtables = []  # type: list[Iterable[Table]]
            for field_name, field in self.__fields__.items():
                # Try to use field title if available
                field_title = field.field_info.title or field_name

                attr = getattr(self, field_name)
                try:
                    # issubclass is prone to TypeError, so we use try/except
                    if issubclass(field.type_, BaseModel) and attr is not None:
                        if isinstance(attr, (list, set)):
                            subtables.extend(
                                a.as_table(nesting=nesting + 1) for a in attr
                            )
                        else:
                            subtables.append(attr.as_table(nesting=nesting + 1))
                        # TODO: only add see below if we actually added a subtable
                        attr = f"[bold]See below[/bold]"
                except:
                    pass
                row = [field_title, str(attr)]
                if with_description:
                    row.append(field.field_info.description)
                table.add_row(*row)

            # TODO: sort table rows by field name

            yield table
            for subtable in subtables:
                yield from subtable
