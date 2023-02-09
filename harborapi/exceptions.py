from typing import Any, List, Optional

from httpx import HTTPStatusError, NetworkError, Response, TimeoutException
from loguru import logger

from harborapi.utils import is_json

from .models import Error, Errors

# NOTE: this should probably be configurable somehow
# However, backoff.on_retry needs to receive a TUPLE of exception types
# (despite claiming it can be a sequence), so it can't be a list
RETRY_ERRORS = (
    TimeoutException,
    NetworkError,
)


class HarborAPIException(Exception):
    pass


class StatusError(HarborAPIException):
    def __init__(self, errors: Optional[Errors] = None, *args: Any, **kwargs: Any):
        """Initialize a StatusError.

        Parameters
        ----------
        errors : Optional[Errors]
            A list of errors returned by the Harbor API.
        """
        super().__init__(*args, **kwargs)

        self.__cause__: Optional[HTTPStatusError] = None
        """The underlying HTTPX exception that caused this exception.
        Automatically assigned when raised from a HTTPX exception."""

        self.errors: List[Error] = []
        """A list of errors returned by the Harbor API."""

        if isinstance(errors, Errors) and errors.errors:
            self.errors = errors.errors

    @property
    def status_code(self) -> Optional[int]:
        """The status code of the underlying HTTPX exception.

        Returns
        -------
        Optional[int]
            The status code of the underlying HTTPX exception, or None if
            this exception was not raised from an HTTPX exception.
        """
        # should always return int, but we can't guarantee it
        try:
            return self.__cause__.response.status_code  # type: ignore
        except:
            return None


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


class InternalServerError(StatusError):
    pass


# NOTE: should this function be async?
def check_response_status(response: Response, missing_ok: bool = False) -> None:
    """Raises an exception if the response status is not 2xx.

    Exceptions are wrapped in a `StatusError` if the response contains errors.

    Parameters
    ----------
    response : Response
        The response to check.
    missing_ok : bool
        If `True`, do not raise an exception if the status is 404.
    """
    try:
        response.raise_for_status()
    except HTTPStatusError as e:
        status_code = response.status_code
        if missing_ok and status_code == 404:
            logger.debug("{} not found", response.request.url)
            return
        errors = try_parse_errors(response)
        logger.bind(httpx_err=e, errors=errors).error(
            "Harbor API returned status code {} for {}",
            response.status_code,
            response.url,
        )
        exceptions = {
            400: BadRequest,
            401: Unauthorized,
            403: Forbidden,
            404: NotFound,
            405: MethodNotAllowed,
            409: Conflict,
            412: PreconditionFailed,
            415: UnsupportedMediaType,
            500: InternalServerError,
        }
        exc = exceptions.get(status_code, StatusError)
        raise exc(errors, *e.args) from e


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
    if is_json(response):
        try:
            return Errors(**response.json())
        except Exception as e:
            logger.bind(error=e).error(
                "Failed to parse error response from {} as JSON", response.url
            )
    return None
