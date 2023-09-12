from __future__ import annotations

from hypothesis import strategies as st

from harborapi.models import CVEAllowlist
from harborapi.models import CVEAllowlistItem

cveallowlistitem_strategy = st.builds(
    CVEAllowlistItem,
    # TODO: make a that generates plausible CVE IDs
    cve_id=st.text(),
)


cveallowlist_strategy = st.builds(
    CVEAllowlist,
    id=st.integers(),
    expires_at=st.one_of(st.integers(0, 2147483647), st.none()),
    items=st.lists(cveallowlistitem_strategy),
    creation_time=st.none(),
    update_time=st.none(),
    # creation_time=st.datetimes(),
    # update_time=st.datetimes(),
)
