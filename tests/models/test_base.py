from typing import Optional

from pydantic import Field

from harborapi.models.base import BaseModel


def test_bool_converter() -> None:
    class TestModel(BaseModel):
        foo: str = Field("", description='Valid values are "true" and "false"')

    assert TestModel(foo=True).foo == "true"
    assert TestModel(foo=False).foo == "false"
    assert TestModel().foo is ""


def test_bool_converter_optional() -> None:
    class TestModel(BaseModel):
        foo: Optional[str] = Field(
            None, description='Valid values are "true" and "false"'
        )

    assert TestModel(foo=True).foo == "true"
    assert TestModel(foo=False).foo == "false"
    assert TestModel().foo is None
