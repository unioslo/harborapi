import httpx

from harborapi.models.file import FileResponse


def test_file_response() -> None:
    response = httpx.Response(
        200,
        content=b"Hello, World!",
        headers={"content-type": "text/plain"},
        default_encoding="utf-8",
    )
    file_response = FileResponse(response)
    assert file_response.content == b"Hello, World!"
    assert file_response.encoding == "utf-8"
    assert file_response.content_type == "text/plain"
    assert file_response.headers == {
        "content-type": "text/plain",
        "content-length": "13",  # added by httpx
    }
    assert bytes(file_response) == b"Hello, World!"
