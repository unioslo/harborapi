import warnings as warnings_stdlib

from . import _types, auth, client, client_sync, exceptions, utils, version, warnings
from .__about__ import __version__ as __version__
from .client import HarborAsyncClient
from .client_sync import HarborClient

# Import after everything else to avoid circular imports
from . import ext  # isort: skip


warnings_stdlib.filterwarnings(
    "default", category=DeprecationWarning, module="harborapi"
)


__all__ = [
    "HarborAsyncClient",
    "HarborClient",
    "auth",
    "client",
    "client_sync",
    "exceptions",
    "ext",
    "_types",
    "utils",
    "version",
    "warnings",
]
