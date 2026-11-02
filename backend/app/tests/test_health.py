"""SentinelX Health Check Unit Tests
"""

import pytest
from backend.app.api.v1.health import health_check
from backend.app.core.config import settings


@pytest.mark.asyncio
async def test_health_check_payload():
    res = await health_check()
    assert res["status"] == "healthy"
    assert res["service"] == settings.APP_NAME
    assert res["version"] == settings.APP_VERSION
    assert "timestamp" in res
