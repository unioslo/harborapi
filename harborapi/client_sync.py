import asyncio
import inspect
from typing import Any, Callable

from .client import HarborAsyncClient


class HarborClient(HarborAsyncClient):
    """Extremely hacky non-async client implementation."""

    def __init__(self, loop: asyncio.AbstractEventLoop, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.loop = loop
        asyncio.set_event_loop(loop)

    def __getattribute__(self, name: str) -> Any:
        """Overrides the `__getattribute__` method to wrap coroutine functions

        Intercepts attribute access and wraps coroutine functions with `_wrap_coro`.

        Internal methods are not wrapped in order to run them normally in
        an asynchronous manner within the event loop.
        """
        attr = super().__getattribute__(name)
        name = name.lower()

        # Filter out internal methods
        if name.startswith("_") or any(
            name == http_method
            for http_method in (
                "get",
                "get_text",  # get for text/plain (hack)
                "post",
                "put",
                "patch",
                "delete",
            )
        ):
            return attr

        if inspect.iscoroutinefunction(attr):
            return self._wrap_coro(attr)

        return attr

    def _wrap_coro(self, coro: Any) -> Callable[[Any], Any]:
        """Wraps a coroutine function in an `AbstractEventLoop.run_until_complete()`
        call that runs the coroutine in the event loop.

        This is a hacky way to make the client behave like a synchronous client.

        Parameters
        ----------
        coro : Any
            The coroutine function to wrap.

        Returns
        -------
        Callable[[Any], Any]
            A function that runs the coroutine in the event loop.
        """

        def wrapper(*args, **kwargs):
            return self.loop.run_until_complete(coro(*args, **kwargs))

        return wrapper
