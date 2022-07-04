from hypothesis import strategies as st

from harborapi.models import Error, Errors

error_strategy = st.builds(
    Error, code=st.integers(min_value=0, max_value=599), message=st.text()
)
errors_strategy = st.builds(Errors, errors=st.lists(error_strategy))
