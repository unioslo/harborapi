import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from harborapi.auth import HarborAuthFile, load_harbor_auth_file, save_authfile
from harborapi.models.models import Access, RobotPermission


def test_load_harbor_auth_file(credentials_file: Path):
    auth_file = load_harbor_auth_file(credentials_file)
    assert auth_file.id == 1
    assert auth_file.level == "system"
    assert auth_file.description == "Some description"
    assert auth_file.duration == 30
    assert auth_file.editable is True
    assert auth_file.expires_at == 1659273646
    assert auth_file.secret == "bad-password"

    assert auth_file.permissions == [
        RobotPermission(
            access=[
                Access(action="list", resource="repository"),
                Access(action="pull", resource="repository"),
            ],
            kind="project",
            namespace="*",
        ),
    ]
    assert auth_file.creation_time == datetime(
        2022, 7, 1, 13, 20, 46, 230000, tzinfo=timezone.utc
    )
    assert auth_file.update_time == datetime(
        2022, 7, 6, 13, 26, 45, 360000, tzinfo=timezone.utc
    )


@pytest.mark.parametrize("field", ["name", "secret"])
def test_load_harbor_auth_file_exceptions(
    field: str, tmp_path: Path, credentials_dict: dict
):
    # Remove a field from the credentials_dict
    credentials_file = tmp_path / "credentials.json"
    del credentials_dict[field]
    credentials_file.write_text(json.dumps(credentials_dict))

    # Assert the missing field is caught
    with pytest.raises(ValueError) as exc_info:
        load_harbor_auth_file(credentials_file)
    assert str(exc_info.value.args[0]) == f"Field '{field}' is required"


@given(st.builds(HarborAuthFile))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_save_authfile(tmp_path: Path, auth_file: HarborAuthFile):
    # make sure auth_file has name and secret
    auth_file.name = "test"
    auth_file.secret = "test"
    fpath = tmp_path / "credentials.json"
    save_authfile(fpath, auth_file, overwrite=True)
    assert fpath.read_text() == auth_file.json(indent=4)  # potentially flaky
    assert load_harbor_auth_file(fpath) == auth_file

    with pytest.raises(FileExistsError) as exc_info:
        save_authfile(fpath, auth_file, overwrite=False)
    assert str(exc_info.value.args[0]) == f"File {fpath} already exists"
