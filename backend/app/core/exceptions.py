"""SentinelX Core Exceptions
"""

from typing import Any, Optional


class SentinelXException(Exception):
    """Base exception for all SentinelX backend errors."""
    def __init__(self, message: str, status_code: int = 500, details: Optional[Any] = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class AuthenticationError(SentinelXException):
    def __init__(self, message: str = "Invalid or missing API credentials"):
        super().__init__(message=message, status_code=401)


class AuthorizationError(SentinelXException):
    def __init__(self, message: str = "Access forbidden to requested resource"):
        super().__init__(message=message, status_code=403)


class NotFoundError(SentinelXException):
    def __init__(self, resource: str, identifier: str):
        super().__init__(message=f"{resource} with id '{identifier}' not found", status_code=404)


class ValidationError(SentinelXException):
    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(message=message, status_code=422, details=details)


class RateLimitExceededError(SentinelXException):
    def __init__(self, message: str = "Rate limit exceeded. Please try again later."):
        super().__init__(message=message, status_code=429)


class SSRFViolationError(SentinelXException):
    def __init__(self, message: str = "Destination IP/URL is blocked by security policy (SSRF Protection)."):
        super().__init__(message=message, status_code=400)


class ThreatIntelError(SentinelXException):
    def __init__(self, provider: str, message: str):
        super().__init__(message=f"Threat intelligence error [{provider}]: {message}", status_code=502)
