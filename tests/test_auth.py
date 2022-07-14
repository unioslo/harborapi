from datetime import datetime, timezone
from pathlib import Path

from harborapi.auth import load_harbor_auth_file
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
