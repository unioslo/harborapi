from __future__ import annotations

import warnings
from typing import Any
from typing import List
from typing import Optional

from httpx import HTTPStatusError
from httpx import Response

from .log import logger
from .models import Error
from .models import Errors


class HarborAPIException(Exception):
    pass


class StatusError(HarborAPIException):
    def __init__(
        self,
        *args: Any,
        errors: Optional[Errors] = None,
        **kwargs: Any,
    ):
        """Initialize a StatusError.

        Parameters
        ----------
        *args : Any
            Positional arguments to pass to the base Exception class.
        errors : Optional[Errors]
            A list of errors returned by the Harbor API.
        **kwargs : Any
            Keyword arguments to pass to the base Exception class.
        """
        super().__init__(*args, **kwargs)

        self.__cause__: Optional[HTTPStatusError] = None
        """The underlying HTTPX exception that caused this exception.
        Automatically assigned when raised from a HTTPX exception."""

        self.errors: List[Error] = []
        """A list of errors returned by the Harbor API."""
        if isinstance(errors, Errors) and errors.errors:
            self.errors = errors.errors

    def __str__(self) -> str:
        """Return a string representation of this exception."""
        # HTTPX exceptions are not very informative, and it is hard to debug
        # failing tests without knowing the response text. So, we append the
        # response text to the exception message.

        # An HTTPX exception will have a single arg that looks like this:
        # "Server error '500 INTERNAL SERVER ERROR' for url 'http://localhost:61656/api/v2.0/foo'\nFor more information check: https://httpstatuses.com/500"
        # We only want the first part, so we partition on the newline
        original_message = super().__str__().partition("\n")[0]
        response_text = self.response.text if self.response else ""
        return f"{original_message}: {response_text}"

    @property
    def response(self) -> Optional[Response]:
        try:
            return self.__cause__.response  # type: ignore
        except AttributeError:
            return None

    @property
    def status_code(self) -> int:
        """The status code of the underlying HTTPX exception.

        Returns
        -------
        Optional[int]
            The status code of the underlying HTTPX exception.
            Returns 0 if no response is available.
        """
        # should always return int, but we can't guarantee it
        if self.response:
            return self.response.status_code
        return 0


class BadRequest(StatusError):
    pass


class Unauthorized(StatusError):
    pass


class Forbidden(StatusError):
    pass


class NotFound(StatusError):
    pass


class MethodNotAllowed(StatusError):
    pass


class Conflict(StatusError):
    pass


class PreconditionFailed(StatusError):
    pass


class UnsupportedMediaType(StatusError):
    pass


class UnprocessableEntity(StatusError):
    pass


class InternalServerError(StatusError):
    pass


EXCEPTIONS_MAP = {
    400: BadRequest,
    401: Unauthorized,
    403: Forbidden,
    404: NotFound,
    405: MethodNotAllowed,
    409: Conflict,
    412: PreconditionFailed,
    415: UnsupportedMediaType,
    422: UnprocessableEntity,
    500: InternalServerError,
}


# NOTE: should this function be async?
def check_response_status(
    response: Response, missing_ok: Optional[bool] = None
) -> None:
    """Raises an exception if the response status is not 2xx.

    Exceptions are wrapped in a `StatusError` if the response contains errors.

    Parameters
    ----------
    response : Response
        The response to check.
    missing_ok : Optional[bool]
        DEPRECATED: If `True`, do not raise an exception if the status is 404.
    """
    if missing_ok is not None:
        warnings.warn(
            "The 'missing_ok' parameter is deprecated and will be removed in version 1.0.0",
            DeprecationWarning,
        )

    try:
        response.raise_for_status()
    except HTTPStatusError as e:
        status_code = response.status_code
        # TODO: remove in v1.0.0
        if missing_ok and status_code == 404:
            logger.warning("%s not found", response.request.url)
            return
        errors = try_parse_errors(response)
        logger.error(
            "Harbor API returned status code %s for %s",
            response.status_code,
            response.url,
        )
        exc = EXCEPTIONS_MAP.get(status_code, StatusError)
        raise exc(*e.args, errors=errors) from e


def try_parse_errors(response: Response) -> Optional[Errors]:
    """Attempts to return the errors from a response.

    See: `models.Errors`

    Parameters
    ----------
    response : Response

    Returns
    -------
    Optional[Errors]
        The errors from the response.
    """
    from .utils import is_json  # avoid circular import

    if is_json(response):
        try:
            return Errors(**response.json())
        except Exception as e:
            logger.error(
                "Failed to parse error response from %s as JSON: %s", response.url, e
            )
    return None
