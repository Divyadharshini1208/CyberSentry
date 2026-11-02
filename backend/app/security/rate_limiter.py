"""SentinelX Rate Limiter
In-memory sliding-window rate limiter per client IP or key.
"""

import time
from collections import defaultdict
from typing import Dict, List
from fastapi import Request, HTTPException, status
from backend.app.core.config import settings


class SlidingWindowRateLimiter:
    def __init__(self, limit_per_minute: int = 120):
        self.limit = limit_per_minute
        self.requests: Dict[str, List[float]] = defaultdict(list)

    def is_allowed(self, client_key: str) -> bool:
        now = time.time()
        window_start = now - 60.0

        # Filter out timestamps older than 60 seconds
        recent = [t for t in self.requests[client_key] if t > window_start]
        self.requests[client_key] = recent

        if len(recent) >= self.limit:
            return False

        self.requests[client_key].append(now)
        return True


rate_limiter = SlidingWindowRateLimiter(limit_per_minute=settings.RATE_LIMIT_PER_MINUTE)


def check_rate_limit(request: Request) -> None:
    """Dependency that enforces rate limits."""
    client_ip = request.client.host if request.client else "unknown"
    auth_header = request.headers.get("X-SentinelX-Key", "")
    client_key = f"{client_ip}:{auth_header[:8]}" if auth_header else client_ip

    if not rate_limiter.is_allowed(client_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Maximum 120 requests per minute allowed."
        )
