# In the future, it would maybe be better to use a metaclass
# to override specific attributes on model fields, but that's
# a bit too complicated for now.
# Alternatively, we could add some sort of _fields_override field to each model,
# where we could specify the fields that need to be overridden. But how to
# specify WHAT to override could be very complicated. Overriding field values
# is one thing, but changing the type of the field is another thing entirely.
# To override field values, look at the optional_field function below, but this
# only gives us a new FieldInfo object, and does nothing to the actual field type
# that Pydantic uses.
#
# If we want to make the process of overriding fields more dynamic and
# less error prone, we need to look at how we can override the
# field type itself.


from typing import Any, Type

from pydantic import Field
from pydantic.fields import FieldInfo

from .base import BaseModel


def _field_info(model: Type[BaseModel], field: str) -> FieldInfo:
    return model.__fields__[field].field_info


def optional_field(model: Type[BaseModel], field: str, **kwargs: Any) -> FieldInfo:
    kwargs.update(default=None)
    return override_field(model, field, **kwargs)


def override_field(model: Type[BaseModel], field: str, **kwargs: Any) -> FieldInfo:
    finfo = _field_info(model, field)
    field_kwargs = dict(
        allow_mutation=finfo.allow_mutation,
        alias=finfo.alias,
        const=finfo.const,
        decimal_places=finfo.decimal_places,
        default=finfo.default,
        default_factory=finfo.default_factory,
        description=finfo.description,
        discriminator=finfo.discriminator,
        exclude=finfo.exclude,
        ge=finfo.ge,
        gt=finfo.gt,
        include=finfo.include,
        le=finfo.le,
        lt=finfo.lt,
        max_digits=finfo.max_digits,
        max_items=finfo.max_items,
        max_length=finfo.max_length,
        min_items=finfo.min_items,
        min_length=finfo.min_length,
        multiple_of=finfo.multiple_of,
        regex=finfo.regex,
        title=finfo.title,
        unique_items=finfo.unique_items,
    )

    # extra is the name of the extra kwargs passed to the Field constructor
    # (such as examples)
    # Pop it from kwargs, and update it with the extra kwargs from the
    # original field
    extra = kwargs.pop("extra", {})
    field_extra = finfo.extra or {}
    extra.update(field_extra)

    # Use remaining kwargs to update the field kwargs
    field_kwargs.update(kwargs)

    # pydantic.Field has Any as type, but it seems to return FieldInfo (?)
    return Field(  # type: ignore
        **field_kwargs,
        **extra,
    )
