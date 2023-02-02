import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel

from harborapi.models._models import ChartMetadata as ChartMetadataGenerated
from harborapi.models._models import ReplicationFilter as ReplicationFilterGenerated
from harborapi.models._models import ScannerRegistration as ScannerRegistrationGenerated
from harborapi.models.models import (
    ChartMetadata,
    ReplicationFilter,
    ScannerRegistration,
    VulnerabilitySummary,
)

from .utils import _override_class_check, _override_compat_check, _override_field_check


@given(st.builds(ChartMetadata), st.builds(ChartMetadataGenerated))
def test_chartmetadata_override(
    modified: ChartMetadata, generated: ChartMetadataGenerated
) -> None:
    fields = [
        "name",
        "version",
        "engine",
        "icon",
        "api_version",
        "app_version",
    ]
    for field in fields:
        _override_field_check(modified, generated, field)
    _override_class_check(modified, generated)
    _override_compat_check(modified, generated)


@given(st.builds(ScannerRegistration), st.builds(ScannerRegistrationGenerated))
def test_scannerregistration_override(
    modified: ScannerRegistration, generated: ScannerRegistrationGenerated
) -> None:
    fields = ["url"]
    for field in fields:
        _override_field_check(modified, generated, field)
    _override_class_check(modified, generated)
    _override_compat_check(modified, generated)


@given(st.builds(ReplicationFilter), st.builds(ReplicationFilterGenerated))
def test_replicationfilter_override(
    modified: ReplicationFilter, generated: ReplicationFilterGenerated
) -> None:
    fields = ["value"]
    for field in fields:
        _override_field_check(modified, generated, field)
    _override_class_check(modified, generated)
    _override_compat_check(modified, generated)


@pytest.mark.parametrize("uppercase", [True, False])
def test_vulnerabilitysummary_override(uppercase: bool) -> None:
    # This model is not backwards compatible with the generated model
    # since we add the fields "low", "medium", "high" and "critical"

    # the keys of the summary dict have been observed to have the first
    # letter capitalized, so we test both cases.
    summary = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
    }
    if uppercase:
        summary = {k.title(): v for k, v in summary.items()}

    values = {
        "summary": summary,
        "total": 10,
        "fixable": 5,
    }
    v = VulnerabilitySummary(**values)
    assert v.low == 1
    assert v.medium == 2
    assert v.high == 3
    assert v.critical == 4
    assert v.total == 10
    assert v.fixable == 5
    # NOTE: not testing with Low, Medium, High, Critical aliases
    # which should actually be the keys in the summary dict
