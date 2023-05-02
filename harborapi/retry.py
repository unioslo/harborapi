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
    Union,
)

import backoff
from backoff._typing import _Handler, _Jitterer, _Predicate, _WaitGenerator
from httpx import NetworkError, TimeoutException
from pydantic import BaseModel, Extra, validator

if TYPE_CHECKING:
    from .client import HarborAsyncClient

from typing_extensions import ParamSpec

RETRY_ERRORS = (
    TimeoutException,
    NetworkError,
)


ExceptionType = Type[Exception]


def DEFAULT_PREDICATE(e: Exception) -> bool:
    return False


class RetrySettings(BaseModel, extra=Extra.allow):
    enabled: bool = True
    # Required arguments for backoff.on_exception
    exception: Tuple[Type[Exception], ...] = RETRY_ERRORS

    # Optional arguments for backoff.on_exception
    max_retries: Optional[int] = None
    max_time: Optional[float] = 60
    # Arguments passed to wait_gen
    wait_gen: _WaitGenerator = backoff.expo
    # wait_gen_kwargs: Optional[Dict[str, Any]] = None
    jitter: Union[_Jitterer, None] = backoff.full_jitter
    giveup: _Predicate[Exception] = DEFAULT_PREDICATE
    on_success: Union[_Handler, Iterable[_Handler], None] = None
    on_backoff: Union[_Handler, Iterable[_Handler], None] = None
    on_giveup: Union[_Handler, Iterable[_Handler], None] = None
    raise_on_giveup: bool = True

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
    def wait_gen_kwargs(self) -> Dict[str, Any]:
        fields = self.__fields__.keys()
        return {key: value for key, value in self.__dict__.items() if key not in fields}


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
