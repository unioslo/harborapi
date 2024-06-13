from __future__ import annotations

from hypothesis import strategies as st
from hypothesis.provisional import urls
from pydantic import AnyUrl

from .artifact import artifact_strategy
from .artifact import get_hbv_strategy
from .artifact import get_vulnerability_item_strategy
from .artifact import scanner_strategy
from .cveallowlist import cveallowlist_strategy
from .cveallowlist import cveallowlistitem_strategy
from .errors import error_strategy
from .errors import errors_strategy

# TODO: make sure we generate None for Optional fields as well!


def init_strategies() -> None:
    st.register_type_strategy(AnyUrl, urls())
