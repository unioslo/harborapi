from __future__ import annotations

from .base import BaseModel


class OIDCTestReq(BaseModel):
    url: str
    verify_cert: bool
