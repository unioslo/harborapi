"""Tests for rich rendering of models."""

from typing import Union

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_mock import MockerFixture
from rich.console import Console

from harborapi.ext.api import ArtifactInfo
from harborapi.ext.report import ArtifactReport
from harborapi.models import Artifact, HarborVulnerabilityReport

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
