from __future__ import annotations

from datetime import datetime
from typing import Any
from typing import Type

import pytest

from harborapi.models import CVEAllowlist
from harborapi.models import CVEAllowlistItem
from harborapi.models import Project
from harborapi.models import ProjectMetadata
from harborapi.models import ProjectReq
from harborapi.models.base import StrDictRootModel
from harborapi.models.base import StrRootModel


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

    if extra:
        assert req.project_id == 1  # set by the extra argument
    else:
        assert not hasattr(req, "project_id")
    # TODO: test that all extra fields were set/unset


# TODO: test all models without increasing test run time too much
@pytest.mark.parametrize("instantiate", [True, False])
def test_get_model_fields_project(instantiate: bool) -> None:
    if instantiate:
        model = Project()  # instantiate with defaults
    else:
        model = Project
    fields = model.get_model_fields()
    assert isinstance(fields, set)
    for field in fields:
        assert isinstance(field, str)
        if instantiate:  # try to access field on model if instantiated
            getattr(model, field)  # will raise if field does not exist

    # Explicitly test fields
    assert "project_id" in fields
    assert "owner_id" in fields
    assert "name" in fields
    assert "registry_id" in fields
    assert "creation_time" in fields
    assert "update_time" in fields
    assert "deleted" in fields
    assert "owner_name" in fields
    assert "togglable" in fields
    assert "current_user_role_id" in fields
    assert "current_user_role_ids" in fields
    assert "repo_count" in fields
    assert "metadata" in fields
    assert "cve_allowlist" in fields


@pytest.mark.parametrize(
    "type_,input_,expect",
    (
        [int, 0, 0],
        [int, 1, 1],
        [str, "foo", "foo"],
        [str, "bar", "bar"],
        [bool, True, True],
        [bool, False, False],
        [float, 0.0, 0.0],
        [float, 1.0, 1.0],
        # Pydantic conversion rules:
        [int, "1", 1],  # str can be cast to int
        pytest.param(
            str,
            1,
            "1",
            marks=pytest.mark.xfail(strict=True, reason="cannot cast int to str"),
        ),
        [bool, 0, False],
        [bool, 1, True],
    ),
)
@pytest.mark.parametrize(
    "n_keys",
    [1, 2],
)
def test_strdictrootmodel(
    type_: Type[Any], input_: Any, expect: Any, n_keys: int
) -> None:
    class TestModel(StrDictRootModel[type_]):
        pass

    keys = ["foo", "bar"]
    inp = {}
    for key in keys[:n_keys]:
        inp[key] = input_
    model = TestModel(**inp)

    assert len(model.model_fields) == 1

    for i in range(n_keys):
        key = keys[i]
        # builtin RootModel root dict access
        assert model.root[key] == expect

        # __getitem__ override
        assert model[key] == expect

        # __getattr__ override
        assert getattr(model, key) == expect

        # Explictly test dot access for the first key
        if i == 0:
            assert model.foo == expect

    # non-existent keys
    with pytest.raises(KeyError):
        model["baz"]
    with pytest.raises(AttributeError):
        getattr(model, "baz")
    with pytest.raises(AttributeError):
        model.baz


@pytest.mark.parametrize(
    "input_,",
    (
        "foo",
        "bar",
        pytest.param(
            1,
            marks=pytest.mark.xfail(
                strict=True, reason="StrRootModel only accepts str"
            ),
        ),
    ),
)
def test_strrootmodel(input_: Any) -> None:
    class TestModel(StrRootModel):
        pass

    model = TestModel(root=input_)
    assert model.root == input_
