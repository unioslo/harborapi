from __future__ import annotations

from typing import Any
from typing import Optional
from typing import Type as PyType
from typing import Union

from pydantic import Field
from pydantic import ValidationInfo
from pydantic import field_validator


class ProjectMetadata(BaseModel):
    retention_id: Optional[Union[str, int]] = Field(
        default=None, description="The ID of the tag retention policy for the project"
    )

    @field_validator("*", mode="before")
    @classmethod
    def _validate_strbool(
        cls: PyType["BaseModel"],
        v: Any,
        info: ValidationInfo,
    ) -> Any:
        """The project metadata model spec specifies that all fields are
        strings, but their valid values are 'true' and 'false'.

        Pydantic has built-in conversion from bool to str, but it yields
        'True' and 'False' instead of 'true' and 'false'. This validator
        converts bools to the strings 'true' and 'false' instead.

        This validator only converts the values if the field
        description contains the word '"true"' (with double quotes).
        """
        if not isinstance(v, bool):
            return v
        if not info.field_name:
            raise ValueError("Validator is not attached to a field.")
        field = cls.model_fields[info.field_name]

        if not field.description or '"true"' not in field.description:
            return v
        return str(v).lower()
