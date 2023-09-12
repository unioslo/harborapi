from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Deque
from typing import Iterator
from typing import NamedTuple
from typing import Optional

from httpx import URL


class ResponseLogEntry(NamedTuple):
    """A log entry for an HTTP response."""

    url: URL
    """An httpx.URL object representing the URL of the request. Can be cast to string using `str()`."""
    method: str
    """The HTTP method used for the request."""
    status_code: int
    """The HTTP status code of the response."""
    duration: float
    """The duration of the full request/response cycle in seconds."""
    response_size: int
    """The size of the response body in bytes."""

    def __repr__(self) -> str:
        return f"<ResponseLogEntry [{self.method} {self.url} {self.status_code}]>"


# NOTE: Could we do the same by subclassing deque?
# We are re-implementing a lot of sequence methods here.
@dataclass
class ResponseLog:
    """A log of HTTP responses."""

    entries: Deque[ResponseLogEntry]

    def __init__(self, max_logs: Optional[int] = None) -> None:
        """Initialize the log."""
        self.entries = deque(maxlen=max_logs)

    def add(self, entry: ResponseLogEntry) -> None:
        """Add a new entry to the log."""
        self.entries.append(entry)

    def resize(self, max_logs: int) -> None:
        """Resize the log to the specified maximum number of entries."""
        self.entries = deque(self.entries, maxlen=max_logs)

    def clear(self) -> None:
        """Clear the log."""
        self.entries.clear()

    def __iter__(self) -> Iterator[ResponseLogEntry]:
        """Return an iterator over the entries in the log."""
        return iter(self.entries)

    def __getitem__(self, index: int) -> ResponseLogEntry:
        """Return the entry at the specified index."""
        return self.entries[index]

    def __len__(self) -> int:
        """Return the number of entries in the log."""
        return len(self.entries)
