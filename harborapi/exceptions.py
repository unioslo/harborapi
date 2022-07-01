from typing import Optional

from httpx import HTTPStatusError, Response
from loguru import logger

from harborapi.utils import is_json

from .model import Errors


class HarborAPIException(Exception):
    pass


# FIXME: this SUCKS
class StatusError(HarborAPIException):
    def __init__(self, errors: Optional[Errors], *args, **kwargs):
        self.errors = None
        if isinstance(errors, Errors):
            self.errors = errors
        super().__init__(*args, **kwargs)


# NOTE: should this function be async?
def check_response_status(response: Response) -> None:
    try:
        response.raise_for_status()
    except HTTPStatusError as e:
        errors = try_parse_errors(response)
        logger.bind(httpx_err=e, errors=errors).error(
            "Harbor API returned status code {} for {}",
            response.url,
            response.status_code,
        )
        raise StatusError(errors)


def try_parse_errors(response: Response) -> Optional[Errors]:
    if is_json(response):
        try:
            return Errors(**response.json())
        except Exception as e:
            logger.bind(error=e).error(
                "Failed to parse error response from {} as JSON", response.url
            )
    return None
