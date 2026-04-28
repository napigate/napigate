from __future__ import annotations

import logging
import pickle
import threading
import time
import uuid
from collections import deque
from typing import Any, Protocol, runtime_checkable

LOGGER = logging.getLogger("gateway.cache")

_RATE_LIMIT_LUA = """
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local member = ARGV[1] .. ':' .. ARGV[4]
local cutoff = now - window
redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
local count = redis.call('ZCARD', key)
if count < limit then
    redis.call('ZADD', key, now, member)
    redis.call('EXPIRE', key, math.ceil(window) + 1)
    return {0, 0}
end
local oldest      = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local retry_after = math.ceil(tonumber(oldest[2]) + window - now)
if retry_after < 1 then retry_after = 1 end
return {1, retry_after}
"""


@runtime_checkable
class CacheBackend(Protocol):
    def get(self, key: str) -> Any | None: ...
    def set(self, key: str, value: Any, ttl: float) -> None: ...
    def clear(self) -> None: ...


@runtime_checkable
class RateLimitBackend(Protocol):
    def check_and_record(self, key: str, limit: int, window_seconds: float) -> tuple[bool, int]:
        """Return ``(allowed, retry_after_seconds)``. ``retry_after`` is 0 when allowed."""
        ...


# ---------------------------------------------------------------------------
# In-memory backends
# ---------------------------------------------------------------------------


class MemoryCacheBackend:
    def __init__(self) -> None:
        self._store: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._store.get(key)
        if entry is None or entry[0] <= time.time():
            return None
        return entry[1]

    def set(self, key: str, value: Any, ttl: float) -> None:
        with self._lock:
            self._store[key] = (time.time() + ttl, value)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


class MemoryRateLimitBackend:
    def __init__(self) -> None:
        self._buckets: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check_and_record(self, key: str, limit: int, window_seconds: float) -> tuple[bool, int]:
        now = time.time()
        with self._lock:
            bucket = self._buckets.setdefault(key, deque())
            cutoff = now - window_seconds
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, int(bucket[0] + window_seconds - now))
                return False, retry_after
            bucket.append(now)
        return True, 0


# ---------------------------------------------------------------------------
# Redis backends
# ---------------------------------------------------------------------------


class RedisCacheBackend:
    _PREFIX = "napigate:cache:"

    def __init__(self, client: Any) -> None:
        self._redis = client

    def get(self, key: str) -> Any | None:
        try:
            raw = self._redis.get(self._PREFIX + key)
        except Exception:
            LOGGER.warning("Redis GET failed for cache key %r", key, exc_info=True)
            return None
        if raw is None:
            return None
        try:
            return pickle.loads(raw)  # noqa: S301
        except Exception:
            LOGGER.warning("Cache deserialization failed for key %r", key, exc_info=True)
            return None

    def set(self, key: str, value: Any, ttl: float) -> None:
        try:
            raw = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
            self._redis.setex(self._PREFIX + key, max(1, int(ttl)), raw)
        except Exception:
            LOGGER.warning("Redis SET failed for cache key %r", key, exc_info=True)

    def clear(self) -> None:
        try:
            cursor = 0
            while True:
                cursor, keys = self._redis.scan(cursor, match=f"{self._PREFIX}*", count=200)
                if keys:
                    self._redis.delete(*keys)
                if cursor == 0:
                    break
        except Exception:
            LOGGER.warning("Redis cache CLEAR failed", exc_info=True)


class RedisRateLimitBackend:
    _PREFIX = "napigate:rl:"

    def __init__(self, client: Any) -> None:
        self._redis = client
        self._script = client.register_script(_RATE_LIMIT_LUA)

    def check_and_record(self, key: str, limit: int, window_seconds: float) -> tuple[bool, int]:
        now = time.time()
        uid = str(uuid.uuid4())
        try:
            result = self._script(
                keys=[self._PREFIX + key],
                args=[now, window_seconds, limit, uid],
            )
            denied, retry_after = int(result[0]), int(result[1])
            return denied == 0, retry_after
        except Exception:
            LOGGER.warning(
                "Redis rate-limit check failed for key %r; allowing request", key, exc_info=True
            )
            return True, 0


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def make_backends(redis_url: str = "") -> tuple[CacheBackend, RateLimitBackend]:
    if redis_url:
        try:
            import redis as redis_lib  # noqa: PLC0415

            client = redis_lib.from_url(
                redis_url,
                socket_connect_timeout=2,
                socket_timeout=2,
                decode_responses=False,
            )
            client.ping()
            LOGGER.info("Redis connected at %s — distributed cache and rate limiting active.", redis_url)
            return RedisCacheBackend(client), RedisRateLimitBackend(client)
        except ImportError:
            LOGGER.warning("redis package not installed; falling back to in-memory backends.")
        except Exception:
            LOGGER.warning(
                "Cannot connect to Redis at %s; falling back to in-memory backends.",
                redis_url,
                exc_info=True,
            )

    LOGGER.info("Using in-memory cache and rate limiting.")
    return MemoryCacheBackend(), MemoryRateLimitBackend()
