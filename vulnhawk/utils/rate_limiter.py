"""Rate limiter — controls request throughput to avoid overwhelming targets."""

import asyncio
import time


class RateLimiter:
    """
    Token-bucket rate limiter for respectful scanning.

    Ensures VulnHawk does not accidentally DoS the target by capping
    the number of requests per second across all scanner modules.
    """

    def __init__(self, requests_per_second: float = 10.0):
        self.rps = requests_per_second
        self._tokens = requests_per_second  # Start full
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a request token is available."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            # Refill tokens based on elapsed time
            self._tokens = min(self.rps, self._tokens + elapsed * self.rps)
            self._last_refill = now

            if self._tokens < 1:
                # Wait for a token to become available
                wait_time = (1 - self._tokens) / self.rps
                await asyncio.sleep(wait_time)
                self._tokens = 0
            else:
                self._tokens -= 1

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, *_):
        pass


# Default shared rate limiter (10 req/s — respectful but fast)
_default_limiter = RateLimiter(requests_per_second=10.0)


def get_default_limiter() -> RateLimiter:
    """Get the shared default rate limiter."""
    return _default_limiter
