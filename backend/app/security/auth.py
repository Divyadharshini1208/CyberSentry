"""SentinelX Authentication & Security Dependencies
Constant-time API key verification and Bearer token parsing.
"""

import hmac
from typing import Optional
from fastapi import Header, HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from backend.app.core.config import settings
from backend.app.core.exceptions import AuthenticationError

security_bearer = HTTPBearer(auto_error=False)


def verify_api_key(
    x_sentinelx_key: Optional[str] = Header(None, alias="X-SentinelX-Key"),
    x_cybersentry_key: Optional[str] = Header(None, alias="X-CyberSentry-Key"),
    auth_credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> str:
    """Verifies that the incoming request has a valid CyberSentry/SentinelX API key.
    Accepts 'X-CyberSentry-Key', 'X-SentinelX-Key', or 'Authorization: Bearer <key>'.
    Uses constant-time comparison to prevent timing side-channel attacks.
    """
    provided_key = None

    if isinstance(x_cybersentry_key, str) and x_cybersentry_key.strip():
        provided_key = x_cybersentry_key.strip()
    elif isinstance(x_sentinelx_key, str) and x_sentinelx_key.strip():
        provided_key = x_sentinelx_key.strip()
    elif auth_credentials and auth_credentials.credentials:
        provided_key = auth_credentials.credentials.strip()

    if not provided_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required authentication credentials (X-SentinelX-Key or Bearer token)",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Constant-time comparison
    is_valid = hmac.compare_digest(
        provided_key.encode("utf-8"),
        settings.SENTINELX_API_KEY.encode("utf-8")
    )

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid SentinelX API key",
            headers={"WWW-Authenticate": "Bearer"}
        )

    return "authenticated-client"
