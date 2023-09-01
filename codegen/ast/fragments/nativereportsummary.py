class NativeReportSummary(BaseModel):
    @property
    def severity_enum(self) -> Optional[Severity]:
        """The severity of the vulnerability

        Returns
        -------
        Optional[Severity]
            The severity of the vulnerability
        """
        if self.severity:
            return Severity(self.severity)
        return None
