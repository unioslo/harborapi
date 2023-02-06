from enum import Enum
from typing import Any, Optional, Sequence, Type, Union

from pydantic import BaseModel

from harborapi.models.base import BaseModel as HarborAPIBaseModel


def _override_class_check(
    modified: BaseModel, generated: BaseModel, check_bases: bool = True
) -> None:
    assert modified.__module__ != generated.__module__
    assert modified.__class__ != generated.__class__
    if check_bases:
        assert generated.__class__ in modified.__class__.__bases__


def _override_compat_check(modified: BaseModel, generated: BaseModel) -> None:
    """Tests that the superclass (generated) is compatible with the subclass (modified).

    When the definition for a field is expanded to be more lenient, this
    test should generally pass. In cases where the field type is changed
    in a non-compatible way, this test will fail and should not be invoked."""
    # we need to serialize by alias, since we can't populate by alias
    m = modified.parse_obj(generated.dict(by_alias=True))
    assert m == generated


def _override_field_check(
    modified: BaseModel,
    generated: BaseModel,
    field: str,
    attr_ignore: Optional[Union[str, Sequence[str]]] = None,
    attr_add: Optional[Union[str, Sequence[str]]] = None,
) -> None:
    attrs = {
        "allow_mutation",
        "alias",
        "const",
        "decimal_places",
        "default_factory",
        "description",
        "discriminator",
        "exclude",
        "extra",
        "ge",
        "gt",
        "include",
        "le",
        "lt",
        "max_digits",
        "max_items",
        "max_length",
        "min_items",
        "min_length",
        "multiple_of",
        "regex",
        "title",
        "unique_items",
    }
    if isinstance(attr_add, str):
        attr_add = [attr_add]
    if isinstance(attr_ignore, str):
        attr_ignore = [attr_ignore]
    # Guaranteed to be an iterable of strings (but not a string)

    if attr_ignore is not None:
        for attr in attr_ignore:
            if attr in attrs:
                attrs.remove(attr)

    if attr_add is not None:
        attrs.update(attr_add)

    for attr in attrs:
        assert getattr(modified.__fields__[field].field_info, attr) == getattr(
            generated.__fields__[field].field_info, attr
        ), f"Field {field} attribute {attr} does not match"


def _enum_members_check(modified: Type[Enum], generated: Type[Enum]) -> None:
    # We can expand the enum, but not shrink it
    for member in generated:
        assert modified(member.value), f"Enum member {member} not in modified enum"


def _no_references_check(
    module: Any, no_references: Sequence[Type[HarborAPIBaseModel]]
) -> None:
    """We assume these models are not referenced by other models when
    overriding them. In order to verify this assumption, we check all
    fields of all models and ensure that they do not reference the models
    in the `no_references` list.

    This test ensures that spec updates do not introduce new references
    to these models undetected. Should any of these models be referenced
    by other models, this test will fail.

    When we add a more dynamic way to override the models, this test will be
    obsolete.

    Parameters
    ----------
    module : Any
        The module containing the models to check
    no_references : List[BaseModel]
        The list of models that we do not expect to be referenced by other
        models.
    """

    # List of models we have updated that we believe are not referenced
    # by any other models
    # no_references = [Repository, Artifact, LdapConf]

    for model in module.__all__:
        assert model in dir(module)
        m = getattr(module, model)
        try:
            # some of the models are enums,
            if not issubclass(m, BaseModel):
                continue
        except:
            continue
        for field in m.__fields__.values():
            assert field.type_ not in no_references
