"""SentinelX Pytest Configuration
Provides pure coroutine execution for async test functions without requiring IOCP loopback sockets.
"""

import inspect
import os
import pytest

# Set test environment
os.environ["ENVIRONMENT"] = "testing"
os.environ["SENTINELX_API_KEY"] = "test-sentinelx-key"


def run_coro(coro):
    """Executes a coroutine synchronously by stepping through its generator."""
    try:
        while True:
            coro.send(None)
    except StopIteration as e:
        return e.value


def pytest_pyfunc_call(pyfuncitem):
    """Intercepts coroutine test functions and drives them without IOCP sockets."""
    if inspect.iscoroutinefunction(pyfuncitem.obj):
        testargs = {
            arg: pyfuncitem.funcargs[arg]
            for arg in pyfuncitem._fixtureinfo.argnames
        }
        run_coro(pyfuncitem.obj(**testargs))
        return True
