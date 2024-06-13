from __future__ import annotations

import functools
from typing import TYPE_CHECKING
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import Optional
from typing import Tuple
from typing import Type
from typing import TypeVar
from typing import Union

import backoff
from backoff._typing import _Handler
from backoff._typing import _Jitterer
from backoff._typing import _Predicate
from backoff._typing import _WaitGenerator
from httpx import NetworkError
from httpx import TimeoutException
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

if TYPE_CHECKING:
    from .client import HarborAsyncClient

from typing_extensions import ParamSpec

RETRY_ERRORS = (
    TimeoutException,
    NetworkError,
)


def DEFAULT_PREDICATE(e: Exception) -> bool:
    """Predicate function that always returns False."""
    return False


class RetrySettings(BaseModel):
    enabled: bool = Field(True, description="Whether to retry requests.")
    # Required argument for backoff.on_exception
    exception: Union[Type[Exception], Tuple[Type[Exception], ...]] = Field(
        RETRY_ERRORS,
        description="Exception(s) to catch and retry on.",
    )

    # Optional arguments for backoff.on_exception
    max_tries: Optional[int] = Field(
        default=None,
        gt=0,
        description="Maximum number of tries before giving up.",
    )
    max_time: Optional[float] = Field(
        default=60,
        ge=0,
        description="Maximum number of seconds to retry for.",
    )
    wait_gen: _WaitGenerator = Field(
        default=backoff.expo,
        description="Function that generates wait times.",
    )
    jitter: Union[_Jitterer, None] = Field(
        default=backoff.full_jitter,
        description="Function that jitters wait times.",
    )
    giveup: _Predicate[Exception] = Field(
        default=DEFAULT_PREDICATE,
        description="Predicate function that determines if we should give up.",
    )
    on_success: Union[_Handler, Iterable[_Handler], None] = Field(
        default=None,
        description="Function(s) to call on success.",
    )
    on_backoff: Union[_Handler, Iterable[_Handler], None] = Field(
        default=None,
        description="Function(s) to call when backing off.",
    )
    on_giveup: Union[_Handler, Iterable[_Handler], None] = Field(
        default=None,
        description="Function(s) to call when giving up.",
    )
    raise_on_giveup: bool = Field(
        default=True,
        description="Whether to raise the exception when giving up.",
    )
    model_config = ConfigDict(extra="allow", validate_assignment=True)

    @property
    def wait_gen_kwargs(self) -> Dict[str, Any]:
        """Dict of extra model fields."""
        fields = self.model_fields.keys()
        return {
            key: value for key, value in self.model_dump().items() if key not in fields
        }


def get_backoff_kwargs(client: "HarborAsyncClient") -> Dict[str, Any]:
    retry_settings = client.retry

    # We should never get here, but just in case...
    assert retry_settings is not None, "Client has no retry settings."

    # Ignore RetrySettings.enabled, since we're already here.
    # Callers should have checked that already.

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


@functools.lru_cache()
def _get_client_type() -> Type["HarborAsyncClient"]:
    """Cached client type lazy-import getter."""
    from .client import HarborAsyncClient

    return HarborAsyncClient


P = ParamSpec("P")
T = TypeVar("T")


def retry() -> Callable[[Callable[P, T]], Callable[P, T]]:
    """Adds retry functionality to a HarborAsyncClient method.

    NOTE: will fail if applied to any other class than HarborAsyncClient.
    """

    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            if not args or not isinstance(args[0], _get_client_type()):
                raise TypeError(
                    "retry decorator must be applied on a HarborAsyncClient method."
                )
            client = args[0]
            if not client.retry or not client.retry.enabled:
                return func(*args, **kwargs)

            return backoff.on_exception(**get_backoff_kwargs(client))(func)(
                *args, **kwargs
            )

        return wrapper

    return decorator
