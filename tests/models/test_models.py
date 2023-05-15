"""Test module that test overrides of broken and/or missing models.

Tests mostly ensure that the fields """

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from harborapi.models._models import ReplicationFilter as ReplicationFilterGenerated
from harborapi.models.models import (
    Artifact,
    ExecHistory,
    GCHistory,
    LdapConf,
    NativeReportSummary,
    ReplicationFilter,
    Repository,
    Schedule,
    ScheduleObj,
    Type,
    VulnerabilitySummary,
)
from harborapi.models.scanner import Severity

from .utils import (
    _no_references_check,
    _override_class_check,
    _override_compat_check,
    _override_field_check,
)

# FIXME: Remove use of .utils helper functions:
# Tests that use `_override_*` and `_no_references_check` probably dont't
# need to anymore. We use normal subclassing now, and thus we shouldn't have to
# test if we are able to inject the fields as expected. We should still test that models
# are compatible with the base models, but we can do that in a simpler way now.


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


def test_vulnerabilitysummary_summary_none() -> None:
    # Test that the summary field can be None
    values = {
        "summary": None,
        "total": 0,
        "fixable": 0,
    }
    v = VulnerabilitySummary(**values)
    assert v.low == 0
    assert v.medium == 0
    assert v.high == 0
    assert v.critical == 0
    assert v.total == 0
    assert v.fixable == 0


# FIXME: I'm not even sure if this is needed anymore?
def test_no_references() -> None:
    """We assume these models are not referenced by other models when
    overriding them. In order to verify this assumption, we check all
    fields of all models and ensure that they do not reference the models
    in the `no_references` list.

    This test ensures that spec updates do not introduce new references
    to these models undetected. Should any of these models be referenced
    by other models, this test will fail.

    When we add a more dynamic way to override the models, this test will be
    obsolete.
    """
    from harborapi.models import models

    # List of models we have updated that we believe are not referenced
    # by any other models
    no_references = [Repository, Artifact, LdapConf]
    _no_references_check(models, no_references)


# Only pass valid enum values to the severity field
@given(
    st.builds(
        NativeReportSummary, severity=st.sampled_from([s.value for s in Severity])
    )
)
def test_nativereportsummary_severity_enum(report: NativeReportSummary) -> None:
    """Test that the severity enum is correctly parsed from the string"""
    assert isinstance(report.severity_enum, Severity) or report.severity is None


# Strategy for testing the overriden ScheduleObj model and the models that
# reference it
schedule_enum_values = list(
    set([s.value for s in Type] + ["Schedule"])
)  # explicitly make sure "Schedule" is included


type_strategy = st.sampled_from(schedule_enum_values)
schedule_strategy = st.builds(ScheduleObj, type=type_strategy)


@given(schedule_strategy)
def test_scheduleobj_override(schedule: ScheduleObj) -> None:
    """Test the overriding of the ScheduleObj model"""
    assert isinstance(schedule.type, Type)
    assume(schedule.type == Type.schedule)
    assert schedule.type == Type.schedule


@given(st.builds(GCHistory, schedule=schedule_strategy))
def test_gchistory_override(history: GCHistory) -> None:
    """Test the overriding of the GCHistory model"""
    assert isinstance(history.schedule.type, Type)
    assume(history.schedule.type == Type.schedule)
    assert history.schedule.type == Type.schedule


@given(st.builds(ExecHistory, schedule=schedule_strategy))
def test_exechistory_override(history: ExecHistory) -> None:
    """Test the overriding of the ExecHistory model"""
    assert isinstance(history.schedule.type, Type)
    assume(history.schedule.type == Type.schedule)
    assert history.schedule.type == Type.schedule


@given(st.builds(Schedule, schedule=schedule_strategy))
def test_schedule_override(history: Schedule) -> None:
    """Test the overriding of the Schedule model"""
    assert isinstance(history.schedule.type, Type)
    assume(history.schedule.type == Type.schedule)
    assert history.schedule.type == Type.schedule


@given(st.builds(Repository))
def test_repository_new_methods(repository: Repository) -> None:
    repository.name = "myproject/myrepo"
    assert repository.project_name == "myproject"
    assert repository.base_name == "myrepo"
    assert repository.split_name() == ("myproject", "myrepo")


scan_overview_nonnative_strategy = st.fixed_dictionaries(
    {
        # Bogus keys, we don't know what a non-native report looks like
        # TODO: add a strategy for non-native reports
        "artifact_count": st.integers(min_value=0),
        "severity": st.sampled_from([s.value for s in Severity]),
    }
)

native_report_summary_strategy = st.builds(
    NativeReportSummary,
    severity=st.none(),  # just to ensure this strategy is different from the one above
    report_id=st.text(min_size=1),
)

scan_overview_native_strategy = st.fixed_dictionaries(
    {
        "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0": native_report_summary_strategy,
        "application/vnd.security.vulnerability.report; version=1.1": native_report_summary_strategy,
    }
)


@given(st.builds(Artifact, scan_overview=scan_overview_nonnative_strategy))
def test_artifact_nonnative_scanoverview(artifact: Artifact) -> None:
    """Test that a scan overview with unknown mime types is parsed correctly
    (i.e. values passed to NativeReportSummary)"""
    assume(artifact.scan_overview is not None)
    assert artifact.scan_overview is not None
    assert isinstance(artifact.scan_overview, NativeReportSummary)
    artifact.scan_overview.severity is not None  # assigned from the strategy


@given(st.builds(Artifact, scan_overview=scan_overview_native_strategy))
def test_artifact_nativereportsummary(artifact: Artifact) -> None:
    """Tests that a NativeReportSummary is constructed correctly
    from the dict passed to the scan_overview field."""
    assume(artifact.scan_overview is not None)
    assert isinstance(artifact.scan_overview, NativeReportSummary)
    assert artifact.scan_overview.severity is None  # assigned from the strategy
    assert artifact.scan_overview.report_id is not None
    assert len(artifact.scan_overview.report_id) >= 1
