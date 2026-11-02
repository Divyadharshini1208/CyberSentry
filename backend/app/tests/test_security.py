"""SentinelX Security Unit Tests
Validates authentication, SSRF prevention, and access controls.
"""

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from backend.app.core.config import settings
from backend.app.core.exceptions import SSRFViolationError
from backend.app.security.auth import verify_api_key
from backend.app.security.ssrf_guard import validate_url_for_outbound


def test_auth_missing_credentials():
    with pytest.raises(HTTPException) as exc_info:
        verify_api_key(x_sentinelx_key=None, auth_credentials=None)
    assert exc_info.value.status_code == 401
    assert "Missing required authentication" in exc_info.value.detail


def test_auth_invalid_key():
    with pytest.raises(HTTPException) as exc_info:
        verify_api_key(x_sentinelx_key="invalid-untrusted-key", auth_credentials=None)
    assert exc_info.value.status_code == 401
    assert "Invalid SentinelX API key" in exc_info.value.detail


def test_auth_valid_api_key_header():
    client_identity = verify_api_key(x_sentinelx_key=settings.SENTINELX_API_KEY, auth_credentials=None)
    assert client_identity == "authenticated-client"


def test_auth_valid_bearer_token():
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=settings.SENTINELX_API_KEY)
    client_identity = verify_api_key(x_sentinelx_key=None, auth_credentials=creds)
    assert client_identity == "authenticated-client"


def test_ssrf_blocks_loopback():
    with pytest.raises(SSRFViolationError):
        validate_url_for_outbound("http://127.0.0.1/admin")

    with pytest.raises(SSRFViolationError):
        validate_url_for_outbound("http://localhost:8080/metrics")


def test_ssrf_blocks_private_networks():
    with pytest.raises(SSRFViolationError):
        validate_url_for_outbound("http://192.168.1.1/router")

    with pytest.raises(SSRFViolationError):
        validate_url_for_outbound("http://10.0.0.5:9000/internal")


def test_ssrf_blocks_cloud_metadata():
    with pytest.raises(SSRFViolationError):
        validate_url_for_outbound("http://169.254.169.254/latest/meta-data/")


def test_ssrf_allows_public_urls():
    url = "https://example.com/valid/path"
    validated = validate_url_for_outbound(url)
    assert validated == url
