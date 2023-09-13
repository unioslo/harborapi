class HarborAPIWarning(UserWarning):
    """Base warning class for warnings emitted by the application."""


class APIURLWarning(HarborAPIWarning):
    """User passed in a URL for the Harbor API server that does not contain /api/v2.0."""
