from __future__ import annotations


class Artifact(BaseModel):
    # @model_validator(mode="before")
    # @classmethod
    # def _get_native_report_summary(cls, values: Dict[str, Any]) -> Dict[str, Any]:
    #     """Constructs a scan overview from a dict of `mime_type:scan_overview`
    #     and populates the `native_report_summary` field with it.

    #     The API spec does not specify the contents of the scan overview, but from
    #     investigating the behavior of the API, it seems to return a dict that looks like this:

    #     ```py
    #     {
    #         "application/vnd.security.vulnerability.report; version=1.1": {
    #             # dict that conforms to NativeReportSummary spec
    #             ...
    #         }
    #     }
    #     ```
    #     """
    #     mime_types = (
    #         "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0",
    #         "application/vnd.security.vulnerability.report; version=1.1",
    #     )
    #     overview = values.get("scan_overview")
    #     if not overview:
    #         return values

    #     if isinstance(overview, PydanticBaseModel):
    #         overview = overview.model_dump()

    #     # At this point we require that scan_overview is a dict
    #     if not isinstance(overview, dict):
    #         raise TypeError(
    #             f"scan_overview must be a dict, not {type(overview).__name__}"
    #         )

    #     # Extract overview for the first mime type that we recognize
    #     for k, v in overview.items():
    #         if k in mime_types:
    #             values["scan_overview"] = v
    #             break
    #     return values

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
