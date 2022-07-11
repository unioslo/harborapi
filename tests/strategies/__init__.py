from hypothesis import strategies as st
from hypothesis.provisional import urls
from pydantic import AnyUrl

from .artifact import (
    artifact_strategy,
    get_hbv_strategy,
    get_vulnerability_item_strategy,
    scanner_strategy,
)
from .cveallowlist import cveallowlist_strategy, cveallowlistitem_strategy
from .errors import error_strategy, errors_strategy

# TODO: make sure we generate None for Optional fields as well!


def init_strategies():
    st.register_type_strategy(AnyUrl, urls())
