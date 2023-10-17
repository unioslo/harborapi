from __future__ import annotations


class Artifact(BaseModel):
    @property
    def scan(self) -> Optional[NativeReportSummary]:
        """
        Returns the first scan overview found for the Artifact,
        or None if there are none.

        Artifacts are typically scanned in a single format, represented
        by its MIME type. Thus, most Artifacts will have only one
        scan overview. This property provides a quick access to it.
        """
        if self.scan_overview and self.scan_overview.root:
            return self.scan_overview.root[next(iter(self.scan_overview))]
        return None
