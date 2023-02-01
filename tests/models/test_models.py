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


def _override_class_check(modified: BaseModel, generated: BaseModel) -> None:
    assert modified.__module__ != generated.__module__
    assert modified.__class__ != generated.__class__
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
    modified: BaseModel, generated: BaseModel, field: str
) -> None:
    attrs = [
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
    ]
    for attr in attrs:
        assert getattr(modified.__fields__[field].field_info, attr) == getattr(
            generated.__fields__[field].field_info, attr
        )


@given(st.builds(ChartMetadata), st.builds(ChartMetadataGenerated))
def test_chart_metadata(
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
def test_scanner_registration(
    modified: ChartMetadata, generated: ChartMetadataGenerated
) -> None:
    fields = ["url"]
    for field in fields:
        _override_field_check(modified, generated, field)
    _override_class_check(modified, generated)
    _override_compat_check(modified, generated)


@given(st.builds(ReplicationFilter), st.builds(ReplicationFilterGenerated))
def test_replication_filter(
    modified: ReplicationFilter, generated: ReplicationFilterGenerated
) -> None:
    fields = ["value"]
    for field in fields:
        _override_field_check(modified, generated, field)
    _override_class_check(modified, generated)
    _override_compat_check(modified, generated)


def test_vulnerability_summary() -> None:
    # This model is not backwards compatible with the generated model
    # since we add the fields "low", "medium", "high" and "critical"
    summary = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4,
        "total": 10,
        "fixable": 5,
    }
    v = VulnerabilitySummary(**summary)
    assert v.low == 1
    assert v.medium == 2
    assert v.high == 3
    assert v.critical == 4
    assert v.total == 10
    assert v.fixable == 5
    # NOTE: not testing with Low, Medium, High, Critical aliases
    # which should actually be the keys in the summary dict
