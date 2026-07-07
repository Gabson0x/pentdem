"""
Rate Limiter — Token bucket, shared across all hunt classes.

Single ceiling for the entire hunt phase, not per-class.
Prevents WAF bans and respects scope safety.
"""

import asyncio
import time


class RateLimiter:
    """
    Token bucket rate limiter.

    All hunt classes share one limiter, so max_requests_per_sec
    is a real ceiling, not a per-class suggestion.
    """

    def __init__(self, max_per_sec: int = 15, burst: int = 30):
        self.max_per_sec = max_per_sec
        self.burst = burst
        self._tokens = burst
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._total_requests = 0
        self._waited_time = 0.0

    async def acquire(self):
        """Wait until a token is available, then consume it."""
        async with self._lock:
            self._refill()

            while self._tokens < 1:
                # Calculate wait time for next token
                wait_time = (1 - self._tokens) / self.max_per_sec
                self._waited_time += wait_time
                await asyncio.sleep(wait_time)
                self._refill()

            self._tokens -= 1
            self._total_requests += 1

    def _refill(self):
        """Refill tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        new_tokens = elapsed * self.max_per_sec
        self._tokens = min(self.burst, self._tokens + new_tokens)
        self._last_refill = now

    def stats(self) -> dict:
        return {
            "total_requests": self._total_requests,
            "total_waited_sec": round(self._waited_time, 2),
            "max_per_sec": self.max_per_sec,
            "burst": self.burst,
        }
