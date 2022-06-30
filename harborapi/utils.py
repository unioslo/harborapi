from httpx import Response


def is_json(response: Response) -> bool:
    """Return True if the response body is JSON-encoded."""
    return response.headers.get("content-type", "").startswith("application/json")
