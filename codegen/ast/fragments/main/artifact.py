from __future__ import annotations


class Artifact(BaseModel):
    @property
    def scan(self) -> Optional[NativeReportSummary]:
        """Returns the first scan overview found for the Artifact,
        or None if there are none.

        In most cases an Artifact will only have one scan overview, and
        in those cases, this is a shortcut to access it.
        """
        if self.scan_overview and self.scan_overview.root:
            return self.scan_overview.root[next(iter(self.scan_overview))]
        return None
