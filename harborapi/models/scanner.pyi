from typing import List, Literal, Optional, overload

from pydantic import BaseModel

class HarborVulnerabilityReport(BaseModel):
    @overload
    def get_cvss_scores(self, ignore_none: Literal[True]) -> List[float]: ...
    @overload
    def get_cvss_scores(self, ignore_none: Literal[False]) -> List[Optional[float]]: ...
    @overload
    def get_cvss_scores(self) -> List[float]: ...
