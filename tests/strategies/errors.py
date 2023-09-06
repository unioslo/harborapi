from __future__ import annotations

from hypothesis import strategies as st

from harborapi.models import Error
from harborapi.models import Errors

error_strategy = st.builds(
    Error,
    code=st.text(),
    message=st.text(),
)
errors_strategy = st.builds(Errors, errors=st.lists(error_strategy))
