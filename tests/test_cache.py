import threading
import unittest

from gateway.cache import MemoryCacheBackend, MemoryRateLimitBackend
from gateway.runtime import GatewayRuntime


class CacheMaintenanceTests(unittest.TestCase):
    def test_memory_cache_clear_returns_removed_entry_count(self) -> None:
        cache = MemoryCacheBackend()
        cache.set("resp:one", {"ok": True}, ttl=60)
        cache.set("pre:two", {"token": "abc"}, ttl=60)
        cache.set("auth:three", {"allow": True}, ttl=60)

        self.assertEqual(cache.clear(), 3)
        self.assertIsNone(cache.get("resp:one"))
        self.assertIsNone(cache.get("pre:two"))
        self.assertIsNone(cache.get("auth:three"))

    def test_runtime_cache_clear_does_not_reset_rate_limit_state(self) -> None:
        runtime = GatewayRuntime.__new__(GatewayRuntime)
        runtime._cache = MemoryCacheBackend()
        runtime._lock = threading.RLock()
        rate_limiter = MemoryRateLimitBackend()
        runtime._rate_limiter = rate_limiter

        runtime._cache.set("resp:one", "cached", ttl=60)
        allowed, retry_after = rate_limiter.check_and_record("client:demo", limit=1, window_seconds=60)
        self.assertTrue(allowed)
        self.assertEqual(retry_after, 0)

        self.assertEqual(runtime.clear_cache(), 1)

        allowed, retry_after = rate_limiter.check_and_record("client:demo", limit=1, window_seconds=60)
        self.assertFalse(allowed)
        self.assertGreaterEqual(retry_after, 1)


if __name__ == "__main__":
    unittest.main()
