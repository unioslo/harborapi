import functools
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    Optional,
    Tuple,
    Type,
    TypeVar,
)

import backoff
from backoff._typing import _WaitGenerator
from httpx import NetworkError, TimeoutException
from pydantic import BaseModel, validator

if TYPE_CHECKING:
    from .client import HarborAsyncClient

from typing_extensions import ParamSpec

RETRY_ERRORS = (
    TimeoutException,
    NetworkError,
)


ExceptionType = Type[Exception]


class RetrySettings(BaseModel):
    enabled: bool = True
    # Required arguments for backoff.on_exception
    wait_gen: _WaitGenerator = backoff.expo
    exception: Tuple[Type[Exception], ...] = RETRY_ERRORS

    # Optional arguments for backoff.on_exception
    max_retries: Optional[int] = None
    max_time: Optional[float] = 60
    # Arguments passed to wait_gen through **kwargs
    wait_gen_base: float = 2
    wait_gen_factor: float = 1
    wait_gen_max_value: Optional[float] = 120
    # Override wait_gen_kwargs with a different set of kwargs
    # if specified, the above three arguments are ignored
    wait_gen_kwargs_override: Optional[Dict[str, Any]] = None

    @validator("exception", pre=True)
    def _validate_exception(cls, v: Any) -> Tuple[Type[Exception], ...]:
        if isinstance(v, type):
            return (v,)
        if isinstance(v, Iterable):
            return tuple(v)
        raise ValueError(
            "Expected an exception type or an iterable for exception types"
        )

    @property
    def wait_gen_kwargs(self) -> Dict[str, Optional[float]]:
        if self.wait_gen_kwargs_override:
            return self.wait_gen_kwargs_override
        return {
            "base": self.wait_gen_base,
            "factor": self.wait_gen_factor,
            "max_value": self.wait_gen_max_value,
        }


def get_backoff_kwargs(client: "HarborAsyncClient") -> Dict[str, Any]:
    retry_settings = client.retry

    if not retry_settings or not retry_settings.enabled:
        return {}

    return dict(
        wait_gen=retry_settings.wait_gen,
        exception=retry_settings.exception,
        max_tries=retry_settings.max_retries,
        max_time=retry_settings.max_time,
        **retry_settings.wait_gen_kwargs,
    )


P = ParamSpec("P")
T = TypeVar("T")


def retry() -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Adds retry logic to a method, where the retry settings are taken
    from the client's retry settings."""

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            if not args:
                raise ValueError("Must be applied on a method, not a function.")
            client = args[0]  # type: HarborAsyncClient # type: ignore
            if not client.retry or not client.retry.enabled:
                return func(*args, **kwargs)

            return backoff.on_exception(**get_backoff_kwargs(client))(func)(
                *args, **kwargs
            )

        return wrapper

    return decorator
