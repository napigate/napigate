import threading
import unittest

from gateway.cache import MemoryCacheBackend, MemoryRateLimitBackend
from gateway.config import EndpointConfig, ResponseCacheConfig, RouteConfig, ServiceConfig
from gateway.runtime import GatewayRuntime, IncomingRequest, MatchedEndpoint, OutgoingResponse


class CacheMaintenanceTests(unittest.TestCase):
    @staticmethod
    def _cached_route() -> MatchedEndpoint:
        endpoint = EndpointConfig(name="demo", slug="demo", upstream_path="/demo")
        service = ServiceConfig(
            name="demo-service",
            base_url="https://service.example",
            endpoints=[endpoint],
        )
        route = RouteConfig(
            name="demo-route",
            slug="demo-route",
            methods=["GET"],
            gateway_path="/demo",
            response_cache=ResponseCacheConfig(enabled=True, ttl_seconds=60),
        )
        return MatchedEndpoint(route=route, service=service, endpoint=endpoint, path_params={})

    @staticmethod
    def _request(headers: dict[str, str] | None = None) -> IncomingRequest:
        return IncomingRequest(
            method="GET",
            path="/demo",
            query={},
            headers=headers or {},
            body=b"",
            client_ip="127.0.0.1",
            url="http://gateway.example/demo",
            json_body=None,
        )

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

    def test_bypass_header_skips_cached_response_and_refreshes_it(self) -> None:
        runtime = GatewayRuntime.__new__(GatewayRuntime)
        runtime._cache = MemoryCacheBackend()
        matched = self._cached_route()
        normal_request = self._request()
        bypass_request = self._request({"x-bypass-cache": "false"})

        runtime._store_cached_response(
            matched=matched,
            request=normal_request,
            authenticated_client=None,
            response=OutgoingResponse(status_code=200, headers={}, body=b"cached"),
        )

        self.assertIsNotNone(
            runtime._get_cached_response(
                matched=matched,
                request=normal_request,
                authenticated_client=None,
                request_id="normal-request",
            )
        )
        self.assertIsNone(
            runtime._get_cached_response(
                matched=matched,
                request=bypass_request,
                authenticated_client=None,
                request_id="bypass-request",
            )
        )

        runtime._store_cached_response(
            matched=matched,
            request=bypass_request,
            authenticated_client=None,
            response=OutgoingResponse(status_code=200, headers={}, body=b"fresh"),
        )
        refreshed = runtime._get_cached_response(
            matched=matched,
            request=normal_request,
            authenticated_client=None,
            request_id="refreshed-request",
        )

        self.assertIsNotNone(refreshed)
        self.assertEqual(refreshed.body, b"fresh")

    def test_bypass_header_is_forwarded_to_upstream(self) -> None:
        runtime = GatewayRuntime.__new__(GatewayRuntime)

        outgoing = runtime._prepare_request_headers(
            incoming_headers={"Host": "gateway.example", "X-Bypass-Cache": "1"},
            service_headers={},
            endpoint_headers={},
            authenticated_client=None,
            forwarded_auth=None,
            forward_napigate_headers=True,
            request_id="request-id",
        )

        self.assertEqual(outgoing["X-Bypass-Cache"], "1")


if __name__ == "__main__":
    unittest.main()
