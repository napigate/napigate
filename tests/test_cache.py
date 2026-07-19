from concurrent.futures import ThreadPoolExecutor
import threading
import time
import unittest
from unittest.mock import patch

from gateway.cache import MemoryCacheBackend, MemoryRateLimitBackend
from gateway.config import (
    EndpointConfig,
    OutputProfileConfig,
    ResponseCacheConfig,
    RouteConfig,
    ServiceConfig,
)
from gateway.runtime import (
    GatewayError,
    GatewayRuntime,
    IncomingRequest,
    MatchedEndpoint,
    OutgoingResponse,
    TargetExecutionResult,
)


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


class ResponseCoalescingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runtime = GatewayRuntime.__new__(GatewayRuntime)
        self.runtime._cache = MemoryCacheBackend()
        self.runtime._lock = threading.RLock()
        self.runtime._inflight_lock = threading.Lock()
        self.runtime._inflight_requests = {}
        self.runtime.output_profiles = {}
        self.matched = CacheMaintenanceTests._cached_route()
        self.request = CacheMaintenanceTests._request()

    def _wait_for_waiters(self, expected: int, timeout: float = 2.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.runtime._inflight_lock:
                entries = list(self.runtime._inflight_requests.values())
                waiter_count = entries[0].waiter_count if entries else 0
            if waiter_count >= expected:
                return
            time.sleep(0.005)
        self.fail(f"Expected {expected} coalesced waiters, found {waiter_count}.")

    def test_identical_concurrent_cache_misses_execute_route_once(self) -> None:
        participant_count = 6
        call_count = 0
        call_count_lock = threading.Lock()
        leader_started = threading.Event()
        release_leader = threading.Event()

        def execute_route(**kwargs) -> TargetExecutionResult:
            nonlocal call_count
            with call_count_lock:
                call_count += 1
            leader_started.set()
            if not release_leader.wait(timeout=5):
                raise TimeoutError("Test leader was not released.")
            response = OutgoingResponse(
                status_code=200,
                headers={"X-Request-ID": kwargs["request_id"]},
                body=b"fresh",
            )
            self.runtime._store_cached_response(
                matched=self.matched,
                request=self.request,
                authenticated_client=None,
                response=response,
            )
            return TargetExecutionResult(
                matched=self.matched,
                response=response,
                upstream_url="https://service.example/demo",
                upstream_curl="curl https://service.example/demo",
                response_source="upstream",
            )

        def invoke(index: int) -> TargetExecutionResult:
            return self.runtime._execute_route_with_coalescing(
                matched=self.matched,
                request=self.request,
                authenticated_client=None,
                forwarded_auth=None,
                request_id=f"request-{index}",
            )

        executor = ThreadPoolExecutor(max_workers=participant_count)
        try:
            with patch.object(self.runtime, "_execute_route", side_effect=execute_route):
                futures = [executor.submit(invoke, index) for index in range(participant_count)]
                self.assertTrue(leader_started.wait(timeout=2))
                self._wait_for_waiters(participant_count - 1)
                release_leader.set()
                results = [future.result(timeout=2) for future in futures]
        finally:
            release_leader.set()
            executor.shutdown(wait=True, cancel_futures=True)

        self.assertEqual(call_count, 1)
        self.assertEqual(self.runtime._inflight_requests, {})
        self.assertEqual({result.response.body for result in results}, {b"fresh"})
        self.assertEqual(
            {result.response.headers["X-Request-ID"] for result in results},
            {f"request-{index}" for index in range(participant_count)},
        )
        coalesced = [
            result
            for result in results
            if result.response.headers.get("X-NapiGate-Coalesced") == "true"
        ]
        self.assertEqual(len(coalesced), participant_count - 1)
        self.assertTrue(all(result.upstream_url == "coalesce://response" for result in coalesced))
        self.assertTrue(all(result.response_source == "coalesced" for result in coalesced))

    def test_concurrent_failure_is_shared_and_inflight_entry_is_removed(self) -> None:
        participant_count = 4
        call_count = 0
        call_count_lock = threading.Lock()
        leader_started = threading.Event()
        release_leader = threading.Event()

        def execute_route(**_kwargs) -> TargetExecutionResult:
            nonlocal call_count
            with call_count_lock:
                call_count += 1
            leader_started.set()
            if not release_leader.wait(timeout=5):
                raise TimeoutError("Test leader was not released.")
            raise GatewayError(
                504,
                "Upstream timed out.",
                matched=self.matched,
                upstream_url="https://service.example/demo",
            )

        def invoke(index: int) -> TargetExecutionResult:
            return self.runtime._execute_route_with_coalescing(
                matched=self.matched,
                request=self.request,
                authenticated_client=None,
                forwarded_auth=None,
                request_id=f"failure-{index}",
            )

        executor = ThreadPoolExecutor(max_workers=participant_count)
        try:
            with patch.object(self.runtime, "_execute_route", side_effect=execute_route):
                futures = [executor.submit(invoke, index) for index in range(participant_count)]
                self.assertTrue(leader_started.wait(timeout=2))
                self._wait_for_waiters(participant_count - 1)
                release_leader.set()
                errors = []
                for future in futures:
                    with self.assertRaises(GatewayError) as raised:
                        future.result(timeout=2)
                    errors.append(raised.exception)
        finally:
            release_leader.set()
            executor.shutdown(wait=True, cancel_futures=True)

        self.assertEqual(call_count, 1)
        self.assertEqual(self.runtime._inflight_requests, {})
        self.assertTrue(all(error.status_code == 504 for error in errors))
        self.assertTrue(all(error.detail == "Upstream timed out." for error in errors))
        self.assertEqual(
            sum(error.upstream_url == "coalesce://error" for error in errors),
            participant_count - 1,
        )
        coalesced_errors = [
            error for error in errors if error.upstream_url == "coalesce://error"
        ]
        self.assertTrue(
            all(error.headers.get("X-NapiGate-Coalesced") == "true" for error in coalesced_errors)
        )
        coalesced_request_ids = {
            error.headers.get("X-Request-ID") for error in coalesced_errors
        }
        self.assertEqual(len(coalesced_request_ids), participant_count - 1)
        self.assertTrue(
            coalesced_request_ids
            <= {f"failure-{index}" for index in range(participant_count)}
        )

    def test_bypass_cache_requests_do_not_coalesce(self) -> None:
        bypass_request = CacheMaintenanceTests._request({"X-Bypass-Cache": "false"})

        def execute_route(**kwargs) -> TargetExecutionResult:
            return TargetExecutionResult(
                matched=self.matched,
                response=OutgoingResponse(
                    status_code=200,
                    headers={"X-Request-ID": kwargs["request_id"]},
                    body=b"fresh",
                ),
                upstream_url="https://service.example/demo",
                upstream_curl="",
                response_source="upstream",
            )

        with patch.object(self.runtime, "_execute_route", side_effect=execute_route) as execute:
            results = [
                self.runtime._execute_route_with_coalescing(
                    matched=self.matched,
                    request=bypass_request,
                    authenticated_client=None,
                    forwarded_auth=None,
                    request_id=f"bypass-{index}",
                )
                for index in range(2)
            ]

        self.assertEqual(execute.call_count, 2)
        self.assertTrue(
            all("X-NapiGate-Coalesced" not in result.response.headers for result in results)
        )

    def test_cache_and_coalescing_keys_include_request_body_digest(self) -> None:
        self.matched.route.methods = ["POST"]
        self.matched.route.response_cache.methods = ["POST"]
        first_request = IncomingRequest(
            method="POST",
            path="/demo",
            query={},
            headers={"Content-Type": "application/json"},
            body=b'{"value":1}',
            client_ip="127.0.0.1",
            url="http://gateway.example/demo",
            json_body={"value": 1},
        )
        second_request = IncomingRequest(
            method="POST",
            path="/demo",
            query={},
            headers={"Content-Type": "application/json"},
            body=b'{"value":2}',
            client_ip="127.0.0.1",
            url="http://gateway.example/demo",
            json_body={"value": 2},
        )

        first_key = self.runtime._request_coalescing_key(
            matched=self.matched,
            request=first_request,
            authenticated_client=None,
            forwarded_auth=None,
        )
        second_key = self.runtime._request_coalescing_key(
            matched=self.matched,
            request=second_request,
            authenticated_client=None,
            forwarded_auth=None,
        )

        self.assertIsNotNone(first_key)
        self.assertIsNotNone(second_key)
        self.assertNotEqual(first_key, second_key)
        self.assertIn("body-sha256=", first_key)
        self.assertNotIn('{"value":1}', first_key)

    def test_buffered_get_without_response_cache_is_eligible_for_coalescing(self) -> None:
        self.matched.route.response_cache = ResponseCacheConfig()
        self.matched.endpoint.output_profile = "buffered"
        self.runtime.output_profiles = {
            "buffered": OutputProfileConfig(
                slug="buffered",
                title="Buffered envelope",
                type="json_envelope",
            )
        }

        first_key = self.runtime._request_coalescing_key(
            matched=self.matched,
            request=self.request,
            authenticated_client=None,
            forwarded_auth=None,
        )
        second_key = self.runtime._request_coalescing_key(
            matched=self.matched,
            request=self.request,
            authenticated_client=None,
            forwarded_auth=None,
        )

        self.assertIsNotNone(first_key)
        self.assertEqual(first_key, second_key)
        self.assertTrue(first_key.startswith("request:"))
        self.assertNotIn(self.request.url, first_key)

    def test_streaming_get_without_response_cache_is_not_coalesced(self) -> None:
        self.matched.route.response_cache = ResponseCacheConfig()

        key = self.runtime._request_coalescing_key(
            matched=self.matched,
            request=self.request,
            authenticated_client=None,
            forwarded_auth=None,
        )

        self.assertIsNone(key)

    def test_uncached_post_is_not_coalesced_even_when_buffered(self) -> None:
        self.matched.route.methods = ["POST"]
        self.matched.route.response_cache = ResponseCacheConfig()
        self.matched.endpoint.output_profile = "buffered"
        self.runtime.output_profiles = {
            "buffered": OutputProfileConfig(
                slug="buffered",
                title="Buffered envelope",
                type="json_envelope",
            )
        }
        request = IncomingRequest(
            method="POST",
            path=self.request.path,
            query=self.request.query,
            headers=self.request.headers,
            body=b'[{"action":"create"}]',
            client_ip=self.request.client_ip,
            url=self.request.url,
            json_body=[{"action": "create"}],
        )

        key = self.runtime._request_coalescing_key(
            matched=self.matched,
            request=request,
            authenticated_client=None,
            forwarded_auth=None,
        )

        self.assertIsNone(key)

    def test_leader_rechecks_cache_before_calling_upstream(self) -> None:
        self.runtime._store_cached_response(
            matched=self.matched,
            request=self.request,
            authenticated_client=None,
            response=OutgoingResponse(status_code=200, headers={}, body=b"cached"),
        )

        with patch.object(self.runtime, "_execute_route") as execute:
            result = self.runtime._execute_route_with_coalescing(
                matched=self.matched,
                request=self.request,
                authenticated_client=None,
                forwarded_auth=None,
                request_id="cache-race",
            )

        execute.assert_not_called()
        self.assertEqual(result.response.body, b"cached")
        self.assertEqual(result.response.headers["X-NapiGate-Cache"], "HIT")
        self.assertEqual(result.response.headers["X-Request-ID"], "cache-race")
        self.assertEqual(result.upstream_url, "cache://response")


if __name__ == "__main__":
    unittest.main()
