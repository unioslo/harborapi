from __future__ import annotations

from typing import Optional

import httpx


class FileResponse:
    """A response object for a file download."""

    def __init__(self, response: httpx.Response) -> None:
        self.response = response

    @property
    def content(self) -> bytes:
        return self.response.content

    @property
    def encoding(self) -> Optional[str]:
        return self.response.encoding

    @property
    def content_type(self) -> Optional[str]:
        return self.response.headers.get("content-type", None)

    @property
    def headers(self) -> httpx.Headers:
        return self.response.headers

    def __bytes__(self) -> bytes:
        return self.content
