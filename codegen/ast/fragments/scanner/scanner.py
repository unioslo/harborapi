from __future__ import annotations

from ..version import get_semver
from ..version import SemVer


class Scanner(BaseModel):
    @property
    def semver(self) -> SemVer:
        return get_semver(self.version)
