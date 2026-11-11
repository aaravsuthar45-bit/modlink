"""
app/rate_limiter.py — High-precision in-memory rate limiter for ModLink.
Enforces a 1/10th second (100ms) rate limit per user/client key across:
- Login (/auth/discord/login)
- OAuth registration (/register)
- OAuth authorization (/authorize)
- OAuth token exchange (/token)
- MCP Gateway requests (/mcp)

If a request arrives within 100ms of the previous request from the same entity,
it is immediately rejected with HTTP 429 ("Try again in 1/10 of a sec").
"""
from __future__ import annotations

import time
from threading import Lock
from typing import Dict, Tuple


class RateLimiter:
    def __init__(self, window_seconds: float = 0.10):
        self.window = window_seconds
        self._last_request: Dict[str, float] = {}
        self._lock = Lock()
        self._last_cleanup = time.monotonic()

    def check(self, key: str) -> Tuple[bool, float]:
        """
        Check if request is allowed for given key.
        Returns (is_allowed, retry_after_seconds).
        """
        now = time.monotonic()
        with self._lock:
            # Periodic cleanup every 60 seconds
            if now - self._last_cleanup > 60.0:
                self._prune(now)
                self._last_cleanup = now

            last = self._last_request.get(key)
            if last is not None:
                elapsed = now - last
                if elapsed < self.window:
                    retry_after = round(self.window - elapsed, 3)
                    return False, max(retry_after, 0.05)

            self._last_request[key] = now
            return True, 0.0

    def _prune(self, now: float) -> None:
        expiry = now - (self.window * 10)
        stale_keys = [k for k, t in self._last_request.items() if t < expiry]
        for k in stale_keys:
            self._last_request.pop(k, None)


# Global rate limiter instance (1/10 second window)
global_rate_limiter = RateLimiter(window_seconds=0.10)
