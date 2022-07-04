import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pytest_httpserver import HTTPServer

from harborapi.client import HarborAsyncClient
from harborapi.models import (
    ScannerAdapterMetadata,
    ScannerRegistration,
    ScannerRegistrationReq,
)


@pytest.mark.asyncio
# @given(st.builds(ScannerRegistrationReq))
# @settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_create_scanner_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    # scanner: ScannerRegistrationReq,
):
    # TODO: find out why Hypothesis has no pydantic.networks.AnyUrl strategy
    scanner = ScannerRegistrationReq(
        name="test-scanner",
        description="test scanner",
        url="http://localhost:8080/api/v2.0/scanner",
    )
    httpserver.expect_request("/api/v2.0/scanners", method="POST").respond_with_data(
        status=201, headers={"Location": "/scanners/1234"}
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    location = await async_client.create_scanner(scanner)
    assert location == "/scanners/1234"


@pytest.mark.asyncio
@given(st.builds(ScannerRegistration), st.builds(ScannerRegistration))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_scanners_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    scanner1: ScannerRegistration,
    scanner2: ScannerRegistration,
):
    # TODO: use st.lists(st.builds(ScannerRegistration)) to generate a list of scanners
    httpserver.expect_request("/api/v2.0/scanners").respond_with_json(
        [scanner1.dict(), scanner2.dict()]
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    scanners = await async_client.get_scanners()
    assert len(scanners) == 2
    assert scanners[0] == scanner1
    assert scanners[1] == scanner2


@pytest.mark.asyncio
@given(st.builds(ScannerRegistration))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_scanner_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    scanner: ScannerRegistration,
):
    httpserver.expect_request("/api/v2.0/scanners/1234").respond_with_json(
        scanner.dict()
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    scanner_rtn = await async_client.get_scanner(registration_id=1234)
    assert scanner_rtn == scanner


@pytest.mark.asyncio
@given(st.builds(ScannerAdapterMetadata))
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_get_scanner_metadata_mock(
    async_client: HarborAsyncClient,
    httpserver: HTTPServer,
    scannermeta: ScannerAdapterMetadata,
):
    httpserver.expect_request("/api/v2.0/scanners/1234/metadata").respond_with_json(
        scannermeta.dict()
    )
    async_client.url = httpserver.url_for("/api/v2.0")
    scannermeta_rtn = await async_client.get_scanner_metadata(registration_id=1234)
    assert scannermeta_rtn == scannermeta
