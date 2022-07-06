import asyncio
import inspect
from typing import Any

from .client import HarborAsyncClient


class HarborClient(HarborAsyncClient):
    """Extremely hacky non-async client implementation."""

    def __init__(self, loop, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.loop = loop
        asyncio.set_event_loop(loop)

    def __getattribute__(self, name: str) -> Any:
        attr = super().__getattribute__(name)
        name = name.lower()
        if name.startswith("_") or any(
            name == http_method
            for http_method in ("get", "post", "put", "patch", "delete")
        ):
            return attr
        if inspect.iscoroutinefunction(attr):
            return self._wrap_coro(attr)
        return attr

    def _wrap_coro(self, coro: Any) -> Any:
        def wrapper(*args, **kwargs):
            return self.loop.run_until_complete(coro(*args, **kwargs))

        return wrapper
