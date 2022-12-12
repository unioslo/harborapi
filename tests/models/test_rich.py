"""Tests for rich rendering of models."""

from typing import Union

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_mock import MockerFixture
from rich.console import Console

from harborapi.ext.api import ArtifactInfo
from harborapi.ext.report import ArtifactReport
from harborapi.models import Artifact, HarborVulnerabilityReport, Tag
from harborapi.models.base import BaseModel

from ..strategies.artifact import artifact_strategy, get_hbv_strategy
from ..strategies.ext import artifact_info_strategy, artifact_report_strategy

# Ideally we should test all models here, but that's a lot of work.
# We'll just test a few for now.


@given(
    st.one_of(
        artifact_strategy,
        get_hbv_strategy(),
        artifact_info_strategy,
        artifact_report_strategy,
    )
)
@settings(
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow]
)
def test_rich_console_protocol(
    mocker: MockerFixture,
    model: Union[Artifact, HarborVulnerabilityReport, ArtifactInfo, ArtifactReport],
) -> None:
    """Test that rich console protocol is implemented."""
    console = Console()

    assert model.__rich_console__ is not None
    spy = mocker.spy(model, "__rich_console__")

    console.print(model)
    spy.assert_called()


def test_as_table() -> None:
    a = Artifact(
        digest="sha256:123",
    )
    assert a.as_table() is not None
    assert len(list(a.as_table())) == 1

    # Test that adding a tag increases the number of tables
    a.tags = [Tag(name="latest")]
    assert len(list(a.as_table())) == 2
    # Test recursion limit (max_depth)
    assert len(list(a.as_table(max_depth=0))) == 1
    assert len(list(a.as_table(max_depth=1))) == 2

    # Test custom nested model not part of the spec
    class CustomModel(BaseModel):
        foo: str = "foo"

    # Artifact + tag + custom
    a.custom = CustomModel()
    assert len(list(a.as_table())) == 3

    class CustomNestedModel(BaseModel):
        bar: str = "bar"
        custom: CustomModel = CustomModel()

    # Artifact + tag + customnested + custom
    a.custom = CustomNestedModel()
    assert len(list(a.as_table())) == 4

    # Test list of custom models
    # Artifact + tag + custom + custom
    a.custom = [CustomModel(), CustomModel()]
    assert len(list(a.as_table())) == 4

    # Test list of custom nested models
    # Artifact + tag + customnested + customnested + custom + custom
    a.custom = [CustomNestedModel(), CustomNestedModel()]
    assert len(list(a.as_table())) == 6

    # Test recursion limit with nested models

    # Artifact
    assert len(list(a.as_table(max_depth=0))) == 1
    # Artifact + tag + customnested + customnested
    assert len(list(a.as_table(max_depth=1))) == 4
    # Artifact + tag + customnested + customnested + custom + custom
    assert len(list(a.as_table(max_depth=2))) == 6
