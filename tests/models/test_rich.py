"""Tests for rich rendering of models."""

from datetime import timedelta
from typing import Union

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_mock import MockerFixture
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table

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
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
    # Printing extremely large tables can be slow
    # To rectify this, we could limit the size of the generated examples,
    # but we just limit the number of examples for now
    deadline=timedelta(milliseconds=500),
    max_examples=10,
)
def test_rich_console_protocol(
    mocker: MockerFixture,
    model: Union[Artifact, HarborVulnerabilityReport, ArtifactInfo, ArtifactReport],
) -> None:
    """Test that rich console protocol is implemented."""
    console = Console()

    assert model.__rich_console__ is not None
    proto_spy = mocker.spy(model, "__rich_console__")
    panel_spy = mocker.spy(model, "as_panel")
    console.print(model)
    proto_spy.assert_called()
    panel_spy.assert_called()


def test_as_table_artifact() -> None:
    """Tests the as_table method of the Artifact model (and by extension all models)

    This should be representative of all models, but it is not guaranteed yet."""
    a = Artifact(
        digest="sha256:123",
    )
    assert a.as_table() is not None
    assert len(list(a.as_table())) == 1

    # Test that adding a tag increases the number of tables
    a.tags = [Tag(name="latest")]
    assert len(list(a.as_table())) == 2
    # Test recursion limit (max_depth)
    assert len(list(a.as_table(max_depth=1))) == 1
    assert len(list(a.as_table(max_depth=2))) == 2

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
    assert len(list(a.as_table(max_depth=1))) == 1
    # Artifact + tag + customnested + customnested
    assert len(list(a.as_table(max_depth=2))) == 4
    # Artifact + tag + customnested + customnested + custom + custom
    assert len(list(a.as_table(max_depth=3))) == 6
    assert len(list(a.as_table(max_depth=0))) == 6
    assert len(list(a.as_table(max_depth=-1))) == 6
    assert len(list(a.as_table(max_depth=0))) == len(list(a.as_table(max_depth=None)))


def test_as_table_long_value() -> None:
    """Tests that the value of a cell is not cut off if it is very long."""
    digest = "extremelylongdigest" * 100
    a = Artifact(digest=digest)
    t = list(a.as_table())[0]
    digest_idx = t.columns[0]._cells.index("digest")
    value = t.columns[1]._cells[digest_idx]
    assert value == digest


@given(
    st.one_of(
        artifact_strategy,
        get_hbv_strategy(),
        artifact_info_strategy,
        artifact_report_strategy,
    )
)
@settings(
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
    max_examples=10,  # large models are slow, see `test_rich_console_protocol`
)
def test_model_as_panel(
    model: Union[Artifact, HarborVulnerabilityReport, ArtifactInfo, ArtifactReport]
) -> None:
    """Test that the as_panel method on various models works."""
    # TODO: test kwargs

    # Get panel
    panel = model.as_panel()
    assert isinstance(panel, Panel)

    # Panel should contain a Group of Tables
    r = panel.renderable
    assert r is not None
    assert isinstance(r, Group)
    assert all(isinstance(t, Table) for t in r.renderables)
