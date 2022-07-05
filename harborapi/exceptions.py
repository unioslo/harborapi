from typing import Optional

from httpx import HTTPStatusError, InvalidURL, Response
from loguru import logger

from harborapi.utils import is_json

from .models import Errors


class HarborAPIException(Exception):
    pass


# FIXME: this SUCKS
class StatusError(HarborAPIException):
    def __init__(self, errors: Optional[Errors] = None, *args, **kwargs):
        self.errors = None
        if isinstance(errors, Errors):
            self.errors = errors
        super().__init__(*args, **kwargs)


# NOTE: should this function be async?
def check_response_status(response: Response, missing_ok: bool = False) -> None:
    """Raises an exception if the response status is not 2xx.

    Exceptions are wrapped in a `StatusError` if the response contains errors.

    """
    try:
        response.raise_for_status()
    except HTTPStatusError as e:
        if missing_ok and response.status_code == 404:
            logger.debug("{} not found", response.request.url)
            return
        errors = try_parse_errors(response)
        logger.bind(httpx_err=e, errors=errors).error(
            "Harbor API returned status code {} for {}",
            response.status_code,
            response.url,
        )
        # TODO: add error handling for different status codes
        raise StatusError(errors) from e


def try_parse_errors(response: Response) -> Optional[Errors]:
    """Attempts to return the errors from a response.

    See: `models.Errors`

    Parameters
    ----------
    response : Response
        The httpx response to parse.

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
