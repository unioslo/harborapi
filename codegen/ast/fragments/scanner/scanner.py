from __future__ import annotations

from ..version import SemVer
from ..version import get_semver


class Scanner(BaseModel):
    @property
    def semver(self) -> SemVer:
        return get_semver(self.version)
