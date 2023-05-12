from datetime import datetime
from typing import Any, Optional, Type

import pytest
from pydantic import Field

from harborapi.models import (
    CVEAllowlist,
    CVEAllowlistItem,
    Project,
    ProjectMetadata,
    ProjectReq,
)
from harborapi.models.base import BaseModel


def test_bool_converter() -> None:
    class TestModel(BaseModel):
        foo: str = Field("", description='Valid values are "true" and "false"')

    assert TestModel(foo=True).foo == "true"
    assert TestModel(foo=False).foo == "false"
    assert TestModel().foo == ""


def test_bool_converter_optional() -> None:
    class TestModel(BaseModel):
        foo: Optional[str] = Field(
            None, description='Valid values are "true" and "false"'
        )

    assert TestModel(foo=True).foo == "true"
    assert TestModel(foo=False).foo == "false"
    assert TestModel().foo is None


@pytest.mark.parametrize("field_type", [str, Optional[str]])
def test_bool_converter_assignment(field_type: Type[Any]) -> None:
    class TestModel(BaseModel):
        foo: field_type = Field("", description='Valid values are "true" and "false"')

    t = TestModel(foo=True)
    t.foo = False
    assert t.foo == "false"

    t = TestModel(foo=False)
    t.foo = True
    assert t.foo == "true"

    if field_type == Optional[str]:
        t = TestModel(foo=True)
        t.foo = None
        assert t.foo is None


@pytest.mark.parametrize("extra", [True, False])
def test_convert_to_req(extra: bool) -> None:
    # TODO: find all analogues in the codebase and test them
    # e.g. Project -> ProjectReq
    #      ScannerRegistration -> ScannerRegistrationReq

    test_date = "2021-01-01T00:00:00"
    test_date_datetime = datetime.fromisoformat(test_date)

    project = Project(
        project_id=1,
        owner_id=2,
        name="test-project",
        registry_id=3,
        creation_time="2021-01-01T00:00:00Z",
        update_time="2021-01-01T00:00:00Z",
        deleted=False,
        owner_name="test-owner",
        togglable=False,
        current_user_role_id=4,
        current_user_role_ids=[4],
        repo_count=5,
        chart_count=6,
        metadata=ProjectMetadata(
            # NOTE: these will be coerced to the strings "true" and "false"
            public=True,
            enable_content_trust=True,
            enable_content_trust_cosign=True,
            prevent_vul=True,
            severity="high",
            auto_scan=False,
            reuse_sys_cve_allowlist=True,
            retention_id="7",
        ),
        cve_allowlist=CVEAllowlist(
            id=8,
            project_id=1,
            expires_at=int(test_date_datetime.timestamp()),
            items=[
                CVEAllowlistItem(
                    cve_id="CVE-2021-1234",
                )
            ],
            creation_time="2021-01-01T00:00:00Z",
            update_time="2021-01-01T00:00:00Z",
        ),
    )

    req = project.convert_to(ProjectReq, extra=extra)
    assert isinstance(req, ProjectReq)

    # This field is called "name" on Project, but "project_name" on ProjectReq
    # so it will not have the value "test-project" after conversion
    assert req.project_name is None

    # Not included in original project
    assert req.storage_limit is None

    # Explicitly test values instead of comparing with original project,
    # so we can make sure the original project was not modified in the process
    assert req.registry_id == 3
    # metadata with coerced bools
    assert req.metadata.public == "true"
    assert req.metadata.enable_content_trust == "true"
    assert req.metadata.enable_content_trust_cosign == "true"
    assert req.metadata.prevent_vul == "true"
    assert req.metadata.severity == "high"
    assert req.metadata.auto_scan == "false"
    assert req.metadata.reuse_sys_cve_allowlist == "true"
    assert req.metadata.retention_id == "7"

    # Deprecated field, handled by metadata.public
    assert req.public is None
