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
from pydantic import BaseModel, Extra

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


class RetrySettings(BaseModel):
    enabled: bool = True
    # Required argument for backoff.on_exception
    exception: Union[Type[Exception], Tuple[Type[Exception], ...]] = RETRY_ERRORS

    # Optional arguments for backoff.on_exception
    max_tries: Optional[int] = None
    max_time: Optional[float] = 60
    wait_gen: _WaitGenerator = backoff.expo
    jitter: Union[_Jitterer, None] = backoff.full_jitter
    giveup: _Predicate[Exception] = DEFAULT_PREDICATE
    on_success: Union[_Handler, Iterable[_Handler], None] = None
    on_backoff: Union[_Handler, Iterable[_Handler], None] = None
    on_giveup: Union[_Handler, Iterable[_Handler], None] = None
    raise_on_giveup: bool = True

    class Config:
        extra = Extra.allow
        validate_assignment = True

    @property
    def wait_gen_kwargs(self) -> Dict[str, Any]:
        """Dict of extra model fields."""
        fields = self.__fields__.keys()
        return {key: value for key, value in self.__dict__.items() if key not in fields}


def get_backoff_kwargs(client: "HarborAsyncClient") -> Dict[str, Any]:
    retry_settings = client.retry

    if not retry_settings or not retry_settings.enabled:
        return {}

    return dict(
        exception=retry_settings.exception,
        max_tries=retry_settings.max_tries,
        max_time=retry_settings.max_time,
        wait_gen=retry_settings.wait_gen,
        jitter=retry_settings.jitter,
        giveup=retry_settings.giveup,
        on_success=retry_settings.on_success,
        on_backoff=retry_settings.on_backoff,
        on_giveup=retry_settings.on_giveup,
        raise_on_giveup=retry_settings.raise_on_giveup,
        # extra model fields become **wait_gen_kwargs
        **retry_settings.wait_gen_kwargs,
    )


P = ParamSpec("P")
T = TypeVar("T")


def retry() -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Adds retry functionality to a HarborAsyncClient method.

    NOTE: will fail if applied to any other class.
    """

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
