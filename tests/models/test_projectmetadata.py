"""The ProjectMetadata model spec specifies that all fields are strings,
but their valid values are 'true' and 'false'.

This module tests our validator that converts bools to the strings 'true'
and 'false' instead of 'True' and 'False'.
"""
from __future__ import annotations

from harborapi.models import ProjectMetadata


def test_project_metadata_bool_converter() -> None:
    p = ProjectMetadata(
        public=True,
        enable_content_trust=True,
        enable_content_trust_cosign=True,
        prevent_vul=True,
        severity="high",
        auto_scan=False,
        reuse_sys_cve_allowlist=True,
        retention_id="7",
    )

    assert p.public == "true"
    assert p.enable_content_trust == "true"
    assert p.enable_content_trust_cosign == "true"
    assert p.prevent_vul == "true"
    assert p.severity == "high"
    assert p.auto_scan == "false"
    assert p.reuse_sys_cve_allowlist == "true"
    assert p.retention_id == "7"


def test_project_metadata_bool_converter_none() -> None:
    p = ProjectMetadata()
    assert p.public is None
    assert p.enable_content_trust is None
    assert p.enable_content_trust_cosign is None
    assert p.prevent_vul is None
    assert p.severity is None
    assert p.auto_scan is None
    assert p.reuse_sys_cve_allowlist is None
    assert p.retention_id is None


def test_project_metadata_bool_converter_assignment() -> None:
    p = ProjectMetadata()
    assert p.public is None
    p.public = False
    assert p.public == "false"

    t = ProjectMetadata(public=False)
    assert p.public == "false"
    t.public = True
    assert t.public == "true"
