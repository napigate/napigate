from __future__ import annotations

from collections.abc import Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.cookies import SimpleCookie
import ipaddress
from dataclasses import dataclass, field
from datetime import UTC, datetime
import base64
import hmac
import json
import logging
from pathlib import Path
import re
import shlex
import threading
import time
from typing import Any
import uuid

import requests

from gateway.cache import CacheBackend, RateLimitBackend, make_backends
from gateway.config import (
    AuthMethodConfig,
    ClientConfig,
    DEFAULT_TRUSTED_PROXY_IPS,
    EndpointConfig,
    GatewayResponseConfig,
    OutputProfileConfig,
    PreCallConfig,
    RUNTIME_IMPLEMENTED_ROUTE_PROTOCOLS,
    RUNTIME_IMPLEMENTED_SERVICE_PROTOCOLS,
    ResponseCacheConfig,
    RouteConfig,
    ServiceConfig,
    SuccessHookConfig,
    StaticResponseConfig,
    get_config_revision,
    get_config_source_label,
    load_gateway_config,
)
from gateway.grpc_support import GrpcTransportError, invoke_grpc_unary
from gateway.integrations import IntegrationDispatcher
from gateway.logging_utils import configure_log_retention_hours
from gateway.monitoring import LogEntry, RequestLogStore
from gateway.output_sandbox import execute_custom_output_code


LOGGER = logging.getLogger("gateway.runtime")
FILTERED_RESPONSE_HEADERS = {
    "content-length",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
FILTERED_REQUEST_HEADERS = {
    "host",
    "content-length",
    "connection",
}
TEMPLATE_PATTERN = re.compile(r"{{\s*([^{}]+?)\s*}}")
DATA_FIELD_TEMPLATE_PATTERN = re.compile(
    r"\$\{\s*([^{}]+?)\s*\}|\{\{\s*([^{}]+?)\s*\}\}"
)


class GatewayError(Exception):
    def __init__(
        self,
        status_code: int,
        detail: str,
        *,
        headers: Mapping[str, Any] | None = None,
        matched: MatchedEndpoint | None = None,
        upstream_url: str = "",
        upstream_curl: str = "",
    ) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.headers = {str(key): str(value) for key, value in (headers or {}).items()}
        self.matched = matched
        self.upstream_url = upstream_url
        self.upstream_curl = upstream_curl


@dataclass(slots=True)
class IncomingRequest:
    method: str
    path: str
    query: dict[str, Any]
    headers: dict[str, Any]
    body: bytes
    client_ip: str
    url: str
    json_body: Any


@dataclass(slots=True)
class OutgoingResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes
    body_iter: Iterator[bytes] | None = field(default=None)


@dataclass(slots=True)
class MatchedEndpoint:
    route: RouteConfig
    service: ServiceConfig
    endpoint: EndpointConfig
    path_params: dict[str, str]


@dataclass(slots=True)
class TargetExecutionResult:
    matched: MatchedEndpoint
    response: OutgoingResponse
    upstream_url: str
    upstream_curl: str
    response_source: str


@dataclass(slots=True)
class AuthenticatedClient:
    client_slug: str
    client_code: str
    client_title: str
    auth_method_code: str
    auth_method_title: str
    auth_type: str
    source: str
    metadata: dict[str, Any]
    consumed_headers: set[str]
    consumed_query_params: set[str]
    consumed_cookie_names: set[str]


class GatewayRuntime:
    def __init__(
        self,
        config_path: Path | str = "config/services.yaml",
        redis_url: str = "",
    ) -> None:
        self.config_path = Path(config_path)
        self.services: list[ServiceConfig] = []
        self.routes: list[RouteConfig] = []
        self.clients: dict[str, ClientConfig] = {}
        self.output_profiles: dict[str, OutputProfileConfig] = {}
        self.gateway_responses = GatewayResponseConfig()
        self.trusted_proxy_ips: list[str] = list(DEFAULT_TRUSTED_PROXY_IPS)
        self.log_store = RequestLogStore()
        self._cache: CacheBackend
        self._rate_limiter: RateLimitBackend
        self._cache, self._rate_limiter = make_backends(redis_url)
        self._config_signature: Any = None
        self._route_round_robin: dict[str, int] = {}
        self._lock = threading.RLock()
        self.dispatcher = IntegrationDispatcher()

    def load(self) -> None:
        gateway_config = load_gateway_config(self.config_path)
        services = gateway_config.services
        routes = gateway_config.routes
        clients = gateway_config.clients
        output_profiles = gateway_config.output_profiles
        gateway_responses = gateway_config.gateway_responses
        signature = get_config_revision(self.config_path)
        with self._lock:
            self.services = services
            self.routes = routes
            self.clients = clients
            self.output_profiles = output_profiles
            self.gateway_responses = gateway_responses
            self.trusted_proxy_ips = list(gateway_config.trusted_proxy_ips)
            self._cache.clear()
            self._route_round_robin.clear()
            self._config_signature = signature
        self.dispatcher.configure(log_aggregators=gateway_config.log_aggregators)
        self.log_store.configure_retention_hours(gateway_config.log_retention_hours)
        configure_log_retention_hours(gateway_config.log_retention_hours)
        LOGGER.info(
            "Loaded %s services, %s routes, %s gateway clients, and %s output profiles from %s",
            len(services),
            len(routes),
            len(clients),
            len(output_profiles),
            get_config_source_label(self.config_path),
        )

    def maybe_reload(self) -> None:
        current_signature = get_config_revision(self.config_path)
        with self._lock:
            known_signature = self._config_signature
        if current_signature == known_signature:
            return
        try:
            self.load()
        except Exception:  # noqa: BLE001
            LOGGER.exception("Failed to reload gateway config from %s", get_config_source_label(self.config_path))
            with self._lock:
                self._config_signature = known_signature

    def close(self) -> None:
        self.log_store.close()
        self.dispatcher.close()

    def match(self, method: str, path: str) -> MatchedEndpoint | None:
        method_upper = method.upper()
        with self._lock:
            routes = list(self.routes)

        for route in routes:
            if method_upper not in route.methods:
                continue
            match = route.compiled_pattern.match(path) if route.compiled_pattern else None
            if not match:
                continue
            selected = self._select_route_target(route)
            if selected is None:
                continue
            service, endpoint = selected
            return MatchedEndpoint(
                route=route,
                service=service,
                endpoint=endpoint,
                path_params=match.groupdict(),
            )
        return None

    def match_any(self, path: str) -> MatchedEndpoint | None:
        with self._lock:
            routes = list(self.routes)

        for route in routes:
            match = route.compiled_pattern.match(path) if route.compiled_pattern else None
            if not match:
                continue
            selected = self._first_route_target(route)
            if selected is None:
                continue
            service, endpoint = selected
            return MatchedEndpoint(
                route=route,
                service=service,
                endpoint=endpoint,
                path_params=match.groupdict(),
            )
        return None

    def _endpoint_lookup(self) -> dict[tuple[str, str], tuple[ServiceConfig, EndpointConfig]]:
        lookup: dict[tuple[str, str], tuple[ServiceConfig, EndpointConfig]] = {}
        for service in self.services:
            for endpoint in service.endpoints:
                lookup[(service.name, endpoint.name)] = (service, endpoint)
                lookup[(service.name, endpoint.slug)] = (service, endpoint)
        return lookup

    def _route_targets(self, route: RouteConfig) -> list[tuple[ServiceConfig, EndpointConfig]]:
        with self._lock:
            lookup = self._endpoint_lookup()
        targets: list[tuple[ServiceConfig, EndpointConfig]] = []
        for target in route.targets:
            resolved = lookup.get((target.service, target.endpoint))
            if resolved is not None:
                targets.append(resolved)
        return targets

    def _first_route_target(self, route: RouteConfig) -> tuple[ServiceConfig, EndpointConfig] | None:
        targets = self._route_targets(route)
        return targets[0] if targets else None

    def _select_route_target(self, route: RouteConfig) -> tuple[ServiceConfig, EndpointConfig] | None:
        targets = self._route_targets(route)
        if not targets:
            return None
        if route.strategy != "round_robin" or len(targets) == 1:
            return targets[0]

        with self._lock:
            index = self._route_round_robin.get(route.slug, 0)
            self._route_round_robin[route.slug] = index + 1
        return targets[index % len(targets)]

    def _target_matches_for_route(self, matched: MatchedEndpoint) -> list[MatchedEndpoint]:
        return [
            MatchedEndpoint(
                route=matched.route,
                service=service,
                endpoint=endpoint,
                path_params=dict(matched.path_params),
            )
            for service, endpoint in self._route_targets(matched.route)
        ]

    def handle_options(self, request: IncomingRequest) -> OutgoingResponse | None:
        matched = self.match_any(request.path)
        if matched is None or not matched.service.cors.enabled:
            return None

        request_id = str(uuid.uuid4())
        started_at = time.perf_counter()
        status_code = 204
        error_message = ""
        upstream_url = "local://cors-preflight"
        response_body = ""

        try:
            headers = self._build_cors_headers(matched, request, preflight=True)
            if self._get_header(request.headers, "Origin") and "Access-Control-Allow-Origin" not in headers:
                raise GatewayError(403, "Origin is not allowed for this service.")
            headers["X-Request-ID"] = request_id
            return OutgoingResponse(status_code=204, headers=headers, body=b"")
        except GatewayError as exc:
            status_code = exc.status_code
            error_message = exc.detail
            response_body = self._error_response_body(exc.status_code, exc.detail, request)
            raise
        finally:
            duration_us = max(0, int(round((time.perf_counter() - started_at) * 1_000_000)))
            duration_ms = round(duration_us / 1000, 3)
            self._write_log(
                request_id=request_id,
                request=request,
                matched=matched,
                upstream_url=upstream_url,
                upstream_curl="",
                status_code=status_code,
                duration_ms=duration_ms,
                duration_us=duration_us,
                error_message=error_message,
                response_body=response_body,
            )

    def handle_proxy(self, request: IncomingRequest) -> OutgoingResponse:
        matched = self.match(request.method, request.path)
        if matched is None:
            raise GatewayError(404, "No route matched this request.")
        self._ensure_transport_supported(matched)

        request_id = str(uuid.uuid4())
        started_at = time.perf_counter()
        status_code = 500
        error_message = ""
        upstream_url = ""
        upstream_curl = ""
        response_body = ""
        log_matched = matched
        authenticated_client: AuthenticatedClient | None = None
        forwarded_auth: AuthenticatedClient | None = None

        try:
            authenticated_client = self._authenticate_client(matched=matched, request=request)
            forwarded_auth = authenticated_client or self._detect_forwarded_auth_credentials(
                matched=matched,
                request=request,
            )
            self._enforce_rate_limit(
                matched=matched,
                request=request,
                authenticated_client=authenticated_client,
            )
            cached_response = self._get_cached_response(
                matched=matched,
                request=request,
                authenticated_client=authenticated_client,
                request_id=request_id,
            )
            if cached_response is not None:
                upstream_url = "cache://response"
                cached_response.headers = self.merge_response_headers(
                    cached_response.headers,
                    self._build_cors_headers(matched, request),
                )
                status_code = cached_response.status_code
                response_body = self._response_body_for_log(cached_response)
                self._emit_success_hook(
                    matched=matched,
                    request=request,
                    authenticated_client=authenticated_client,
                    response=cached_response,
                    request_id=request_id,
                    response_source="cache",
                )
                return cached_response

            result = self._execute_route(
                matched=matched,
                request=request,
                authenticated_client=authenticated_client,
                forwarded_auth=forwarded_auth,
                request_id=request_id,
            )
            log_matched = result.matched
            upstream_url = result.upstream_url
            upstream_curl = result.upstream_curl

            result.response.headers = self.merge_response_headers(
                result.response.headers,
                self._build_cors_headers(result.matched, request),
            )
            status_code = result.response.status_code
            response_body = self._response_body_for_log(result.response)
            self._emit_success_hook(
                matched=result.matched,
                request=request,
                authenticated_client=authenticated_client,
                response=result.response,
                request_id=request_id,
                response_source=result.response_source,
            )
            return result.response
        except GatewayError as exc:
            status_code = exc.status_code
            error_message = (
                str(exc.__cause__)
                if exc.upstream_url and exc.__cause__ is not None
                else exc.detail
            )
            if exc.matched is not None:
                log_matched = exc.matched
            if exc.upstream_url:
                upstream_url = exc.upstream_url
            if exc.upstream_curl:
                upstream_curl = exc.upstream_curl
            response_body = self._error_response_body(exc.status_code, exc.detail, request)
            raise
        except requests.RequestException as exc:
            status_code = 502
            error_message = str(exc)
            response_body = self._error_response_body(502, "Upstream request failed.", request)
            LOGGER.exception("Upstream HTTP error for %s", request.path)
            raise GatewayError(502, "Upstream request failed.") from exc
        except Exception as exc:  # noqa: BLE001
            status_code = 500
            error_message = str(exc)
            response_body = self._error_response_body(500, "Gateway internal error.", request)
            LOGGER.exception("Unhandled gateway error for %s", request.path)
            raise GatewayError(500, "Gateway internal error.") from exc
        finally:
            duration_us = max(0, int(round((time.perf_counter() - started_at) * 1_000_000)))
            duration_ms = round(duration_us / 1000, 3)
            self._write_log(
                request_id=request_id,
                request=request,
                matched=log_matched,
                upstream_url=upstream_url,
                upstream_curl=upstream_curl,
                status_code=status_code,
                duration_ms=duration_ms,
                duration_us=duration_us,
                error_message=error_message,
                response_body=response_body,
            )

    def _ensure_transport_supported(self, matched: MatchedEndpoint) -> None:
        route_protocol = str(matched.route.protocol or "http").strip().lower() or "http"
        service_protocol = str(matched.service.protocol or "http").strip().lower() or "http"
        if route_protocol not in RUNTIME_IMPLEMENTED_ROUTE_PROTOCOLS:
            raise GatewayError(
                501,
                (
                    f"Route protocol '{route_protocol}' is declared for route "
                    f"'{matched.route.slug}' but is not implemented in this NapiGate runtime yet."
                ),
                matched=matched,
            )
        if service_protocol not in RUNTIME_IMPLEMENTED_SERVICE_PROTOCOLS:
            raise GatewayError(
                501,
                (
                    f"Service protocol '{service_protocol}' is declared for service "
                    f"'{matched.service.name}' but is not implemented in this NapiGate runtime yet."
                ),
                matched=matched,
            )

    def _execute_route(
        self,
        *,
        matched: MatchedEndpoint,
        request: IncomingRequest,
        authenticated_client: AuthenticatedClient | None,
        forwarded_auth: AuthenticatedClient | None,
        request_id: str,
    ) -> TargetExecutionResult:
        if matched.route.strategy in {"single", "round_robin"}:
            return self._execute_target(
                matched=matched,
                request=request,
                authenticated_client=authenticated_client,
                forwarded_auth=forwarded_auth,
                request_id=request_id,
            )

        targets = self._target_matches_for_route(matched)
        if not targets:
            raise GatewayError(502, f"Route '{matched.route.name}' has no usable targets.")

        if matched.route.strategy == "parallel_race":
            return self._execute_parallel_race(
                targets=targets,
                request=request,
                authenticated_client=authenticated_client,
                forwarded_auth=forwarded_auth,
                request_id=request_id,
            )

        return self._execute_failover(
            targets=targets,
            request=request,
            authenticated_client=authenticated_client,
            forwarded_auth=forwarded_auth,
            request_id=request_id,
        )

    def _execute_failover(
        self,
        *,
        targets: list[MatchedEndpoint],
        request: IncomingRequest,
        authenticated_client: AuthenticatedClient | None,
        forwarded_auth: AuthenticatedClient | None,
        request_id: str,
    ) -> TargetExecutionResult:
        last_response: TargetExecutionResult | None = None
        last_error: Exception | None = None
        for target in targets:
            try:
                result = self._execute_target(
                    matched=target,
                    request=request,
                    authenticated_client=authenticated_client,
                    forwarded_auth=forwarded_auth,
                    request_id=request_id,
                )
                if result.response.status_code < 500:
                    return result
                last_response = result
            except GatewayError as exc:
                if exc.status_code < 500:
                    raise
                last_error = exc
                LOGGER.warning(
                    "Route target failed: route=%s service=%s endpoint=%s status=%s detail=%s",
                    target.route.slug,
                    target.service.name,
                    target.endpoint.name,
                    exc.status_code,
                    exc.detail,
                )
            except requests.RequestException as exc:
                last_error = exc
                LOGGER.warning(
                    "Route target HTTP error: route=%s service=%s endpoint=%s error=%s",
                    target.route.slug,
                    target.service.name,
                    target.endpoint.name,
                    exc,
                )

        if last_response is not None:
            return last_response
        if isinstance(last_error, GatewayError):
            raise last_error
        if last_error is not None:
            raise GatewayError(502, "All route targets failed.") from last_error
        raise GatewayError(502, "All route targets failed.")

    def _execute_parallel_race(
        self,
        *,
        targets: list[MatchedEndpoint],
        request: IncomingRequest,
        authenticated_client: AuthenticatedClient | None,
        forwarded_auth: AuthenticatedClient | None,
        request_id: str,
    ) -> TargetExecutionResult:
        last_response: TargetExecutionResult | None = None
        last_error: Exception | None = None
        worker_count = max(1, min(len(targets), 8))
        executor = ThreadPoolExecutor(max_workers=worker_count)
        futures = [
            executor.submit(
                self._execute_target,
                matched=target,
                request=request,
                authenticated_client=authenticated_client,
                forwarded_auth=forwarded_auth,
                request_id=request_id,
            )
            for target in targets
        ]
        try:
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result.response.status_code < 500:
                        executor.shutdown(wait=False, cancel_futures=True)
                        return result
                    last_response = result
                except GatewayError as exc:
                    if exc.status_code < 500:
                        raise
                    last_error = exc
                except requests.RequestException as exc:
                    last_error = exc
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

        if last_response is not None:
            return last_response
        if isinstance(last_error, GatewayError):
            raise last_error
        if last_error is not None:
            raise GatewayError(502, "All parallel route targets failed.") from last_error
        raise GatewayError(502, "All parallel route targets failed.")

    def _execute_target(
        self,
        *,
        matched: MatchedEndpoint,
        request: IncomingRequest,
        authenticated_client: AuthenticatedClient | None,
        forwarded_auth: AuthenticatedClient | None,
        request_id: str,
    ) -> TargetExecutionResult:
        variables = dict(matched.service.variables)
        context = self._build_template_context(
            matched=matched,
            request=request,
            variables=variables,
            authenticated_client=authenticated_client,
        )

        pre_call_steps = (
            (matched.service.pre_call, f"service:{matched.service.name}"),
            (matched.route.pre_call, f"route:{matched.route.slug}"),
            (matched.endpoint.pre_call, f"{matched.service.name}:{matched.endpoint.name}"),
        )
        for pre_call, default_cache_key in pre_call_steps:
            if not pre_call:
                continue
            self._run_pre_call(
                matched=matched,
                request=request,
                context=context,
                variables=variables,
                pre_call=pre_call,
                default_cache_key=default_cache_key,
            )
            context = self._build_template_context(
                matched=matched,
                request=request,
                variables=variables,
                authenticated_client=authenticated_client,
            )

        context = self._build_template_context(
            matched=matched,
            request=request,
            variables=variables,
            authenticated_client=authenticated_client,
        )

        if matched.endpoint.response is not None:
            upstream_url = "local://response"
            direct_response = self._build_static_response(
                response_config=matched.endpoint.response,
                context=context,
                request_id=request_id,
            )
            direct_response = self._apply_output_profile(
                matched=matched,
                request=request,
                response=direct_response,
            )
            direct_response = self._tag_route_response(matched=matched, response=direct_response)
            self._store_cached_response(
                matched=matched,
                request=request,
                authenticated_client=authenticated_client,
                response=direct_response,
            )
            return TargetExecutionResult(
                matched=matched,
                response=direct_response,
                upstream_url=upstream_url,
                upstream_curl="",
                response_source="local",
            )

        rendered_service_headers = self._render_header_mapping(matched.service.headers, context)
        rendered_endpoint_headers = self._render_header_mapping(matched.endpoint.headers, context)
        request_headers = self._prepare_request_headers(
            incoming_headers=request.headers,
            service_headers=rendered_service_headers,
            endpoint_headers=rendered_endpoint_headers,
            authenticated_client=authenticated_client,
            forwarded_auth=forwarded_auth,
            forward_napigate_headers=matched.service.forward_napigate_headers,
            request_id=request_id,
        )
        if matched.service.forward_napigate_headers:
            request_headers["X-NapiGate-Endpoint-Slug"] = matched.endpoint.slug
            request_headers["X-NapiGate-Route-Slug"] = matched.route.slug

        if matched.service.protocol == "grpc":
            try:
                grpc_result = self._execute_grpc_request(
                    matched=matched,
                    request=request,
                    context=context,
                    request_headers=request_headers,
                )
            except GrpcTransportError as exc:
                raise GatewayError(
                    exc.status_code,
                    exc.detail,
                    matched=matched,
                    upstream_url=exc.upstream_url,
                    upstream_curl=exc.upstream_curl,
                ) from exc
            outgoing_response = OutgoingResponse(
                status_code=grpc_result.status_code,
                headers=self.merge_response_headers(grpc_result.headers, {"X-Request-ID": request_id}),
                body=grpc_result.body,
            )
            outgoing_response = self._apply_output_profile(
                matched=matched,
                request=request,
                response=outgoing_response,
            )
            outgoing_response = self._tag_route_response(matched=matched, response=outgoing_response)
            self._store_cached_response(
                matched=matched,
                request=request,
                authenticated_client=authenticated_client,
                response=outgoing_response,
            )
            return TargetExecutionResult(
                matched=matched,
                response=outgoing_response,
                upstream_url=grpc_result.upstream_url,
                upstream_curl=grpc_result.upstream_curl,
                response_source="upstream",
            )

        upstream_path = self.render_template(matched.endpoint.upstream_path, context)
        upstream_url = self._join_url(matched.service.base_url, str(upstream_path))

        rendered_query = self.render_data(matched.endpoint.query, context)
        final_query = self._merge_query_params(
            request.query,
            rendered_query,
            authenticated_client=authenticated_client,
        )

        _request_kwargs = dict(
            headers=request_headers,
            params=final_query,
            data=request.body or None,
            timeout=matched.service.timeout_seconds,
            verify=matched.service.verify_ssl,
            allow_redirects=False,
        )

        if self._should_stream_response(matched):
            try:
                response, _session, prepared_request = self._send_request_streaming(
                    matched.service, request.method, upstream_url, **_request_kwargs
                )
            except requests.RequestException as exc:
                prepared_request = getattr(exc, "napigate_prepared_request", None)
                upstream_curl = (
                    self._build_upstream_curl(
                        prepared_request=prepared_request,
                        timeout_seconds=matched.service.timeout_seconds,
                        verify_ssl=matched.service.verify_ssl,
                        allow_redirects=False,
                    )
                    if prepared_request is not None
                    else ""
                )
                raise GatewayError(
                    502,
                    "Upstream request failed.",
                    matched=matched,
                    upstream_url=upstream_url,
                    upstream_curl=upstream_curl,
                ) from exc
            upstream_curl = self._build_upstream_curl(
                prepared_request=prepared_request,
                timeout_seconds=matched.service.timeout_seconds,
                verify_ssl=matched.service.verify_ssl,
                allow_redirects=False,
            )

            def _body_iter() -> Iterator[bytes]:
                try:
                    yield from response.iter_content(8192)
                finally:
                    _session.close()

            outgoing_response = OutgoingResponse(
                status_code=response.status_code,
                headers=self._prepare_response_headers(response.headers, request_id),
                body=b"",
                body_iter=_body_iter(),
            )
            # Passthrough profiles only modify headers, safe to apply on streaming responses
            outgoing_response = self._apply_output_profile(
                matched=matched,
                request=request,
                response=outgoing_response,
            )
            outgoing_response = self._tag_route_response(matched=matched, response=outgoing_response)
            return TargetExecutionResult(
                matched=matched,
                response=outgoing_response,
                upstream_url=upstream_url,
                upstream_curl=upstream_curl,
                response_source="upstream",
            )

        try:
            response, prepared_request = self._send_request(
                matched.service, request.method, upstream_url, **_request_kwargs
            )
        except requests.RequestException as exc:
            prepared_request = getattr(exc, "napigate_prepared_request", None)
            upstream_curl = (
                self._build_upstream_curl(
                    prepared_request=prepared_request,
                    timeout_seconds=matched.service.timeout_seconds,
                    verify_ssl=matched.service.verify_ssl,
                    allow_redirects=False,
                )
                if prepared_request is not None
                else ""
            )
            raise GatewayError(
                502,
                "Upstream request failed.",
                matched=matched,
                upstream_url=upstream_url,
                upstream_curl=upstream_curl,
            ) from exc
        upstream_curl = self._build_upstream_curl(
            prepared_request=prepared_request,
            timeout_seconds=matched.service.timeout_seconds,
            verify_ssl=matched.service.verify_ssl,
            allow_redirects=False,
        )

        outgoing_response = OutgoingResponse(
            status_code=response.status_code,
            headers=self._prepare_response_headers(response.headers, request_id),
            body=response.content,
        )
        outgoing_response = self._apply_output_profile(
            matched=matched,
            request=request,
            response=outgoing_response,
        )
        outgoing_response = self._tag_route_response(matched=matched, response=outgoing_response)
        self._store_cached_response(
            matched=matched,
            request=request,
            authenticated_client=authenticated_client,
            response=outgoing_response,
        )
        return TargetExecutionResult(
            matched=matched,
            response=outgoing_response,
            upstream_url=upstream_url,
            upstream_curl=upstream_curl,
            response_source="upstream",
        )

    def _execute_grpc_request(
        self,
        *,
        matched: MatchedEndpoint,
        request: IncomingRequest,
        context: dict[str, Any],
        request_headers: dict[str, str],
    ):
        grpc_config = matched.service.grpc
        grpc_method = matched.endpoint.grpc
        if grpc_config is None:
            raise GrpcTransportError(
                f"Service '{matched.service.name}' is configured for grpc but grpc settings are missing.",
                status_code=500,
            )
        full_method = (
            self.render_template(grpc_method.full_method, context)
            if grpc_method is not None
            else self.render_template(matched.endpoint.upstream_path, context)
        )
        if not full_method:
            raise GrpcTransportError(
                f"Endpoint '{matched.endpoint.name}' in service '{matched.service.name}' is missing a grpc full method.",
                status_code=500,
            )
        payload = self._grpc_request_payload(
            matched=matched,
            request=request,
            context=context,
        )
        return invoke_grpc_unary(
            target=self._service_target(matched.service),
            full_method=str(full_method),
            payload=payload,
            metadata=self._grpc_request_metadata(request_headers),
            timeout_seconds=matched.service.timeout_seconds,
            use_tls=grpc_config.use_tls,
            authority=grpc_config.authority,
            root_certificates_path=self._resolve_config_reference(grpc_config.root_certificates_path),
            descriptor_set_path=self._resolve_config_reference(grpc_config.descriptor_set_path),
            use_reflection=grpc_config.use_reflection,
        )

    def _grpc_request_payload(
        self,
        *,
        matched: MatchedEndpoint,
        request: IncomingRequest,
        context: dict[str, Any],
    ) -> Any:
        grpc_method = matched.endpoint.grpc
        if grpc_method is not None and grpc_method.request_body is not None:
            return self.render_data(grpc_method.request_body, context)
        if request.json_body is not None:
            return request.json_body
        if request.body:
            raise GrpcTransportError(
                "gRPC targets require a JSON request body or grpc.request_body mapping.",
                status_code=400,
            )
        return {}

    def _grpc_request_metadata(self, request_headers: dict[str, str]) -> list[tuple[str, str]]:
        metadata: list[tuple[str, str]] = []
        filtered = {
            "host",
            "content-length",
            "connection",
            "content-type",
        }
        for name, value in request_headers.items():
            lowered = str(name).strip().lower()
            if not lowered or lowered in filtered:
                continue
            metadata.append((lowered, str(value)))
        return metadata

    def _service_target(self, service: ServiceConfig) -> str:
        return str(service.target or service.base_url).strip()

    def _resolve_config_reference(self, value: str | None) -> str | None:
        if not value:
            return None
        path = Path(value)
        if path.is_absolute():
            return str(path)
        return str((self.config_path.parent / path).resolve())

    def list_logs(self, limit: int = 200) -> list[dict[str, Any]]:
        return self.log_store.recent(limit=limit)

    def service_count(self) -> int:
        with self._lock:
            return len(self.services)

    def client_count(self) -> int:
        with self._lock:
            return len(self.clients)

    def route_count(self) -> int:
        with self._lock:
            return len(self.routes)

    def output_profile_count(self) -> int:
        with self._lock:
            return len(self.output_profiles)

    def trusted_proxy_allowlist(self) -> list[str]:
        with self._lock:
            return list(self.trusted_proxy_ips)

    def _route_response_cache_config(self, matched: MatchedEndpoint) -> ResponseCacheConfig:
        for cache_config in (
            matched.endpoint.response_cache,
            matched.service.response_cache,
            matched.route.response_cache,
        ):
            if cache_config.enabled and cache_config.ttl_seconds > 0:
                return cache_config
        if matched.route.legacy_endpoint_config:
            return matched.endpoint.response_cache
        return matched.route.response_cache

    def _output_profile_slugs(self, matched: MatchedEndpoint) -> list[str]:
        slugs: list[str] = []
        for slug in (matched.endpoint.output_profile, matched.route.output_profile):
            if not slug or slug in slugs:
                continue
            slugs.append(slug)
        return slugs

    def _route_success_hook(self, matched: MatchedEndpoint) -> SuccessHookConfig | None:
        if matched.route.success_hook is not None:
            return matched.route.success_hook
        if matched.route.legacy_endpoint_config:
            return matched.endpoint.success_hook
        return None

    def _tag_route_response(
        self,
        *,
        matched: MatchedEndpoint,
        response: OutgoingResponse,
    ) -> OutgoingResponse:
        response.headers = self.merge_response_headers(
            response.headers,
            {
                "X-NapiGate-Route-Slug": matched.route.slug,
                "X-NapiGate-Route-Strategy": matched.route.strategy,
                "X-NapiGate-Target": f"{matched.service.name}.{matched.endpoint.name}",
            },
        )
        return response

    def _get_cached_response(
        self,
        *,
        matched: MatchedEndpoint,
        request: IncomingRequest,
        authenticated_client: AuthenticatedClient | None,
        request_id: str,
    ) -> OutgoingResponse | None:
        cache_config = self._route_response_cache_config(matched)
        if (
            not cache_config.enabled
            or cache_config.ttl_seconds <= 0
            or request.method.upper() not in cache_config.methods
        ):
            return None

        cache_key = self._response_cache_key(
            matched=matched,
            request=request,
            authenticated_client=authenticated_client,
        )
        cached_response = self._cache.get(f"resp:{cache_key}")
        if cached_response is None:
            return None
        headers = self.merge_response_headers(
            cached_response.headers,
            {
                "X-Request-ID": request_id,
                "X-NapiGate-Cache": "HIT",
            },
        )
        return OutgoingResponse(
            status_code=cached_response.status_code,
            headers=headers,
            body=bytes(cached_response.body),
        )

    def _store_cached_response(
        self,
        *,
        matched: MatchedEndpoint,
        request: IncomingRequest,
        authenticated_client: AuthenticatedClient | None,
        response: OutgoingResponse,
    ) -> None:
        cache_config = self._route_response_cache_config(matched)
        if (
            not cache_config.enabled
            or cache_config.ttl_seconds <= 0
            or request.method.upper() not in cache_config.methods
            or response.status_code >= 400
        ):
            return

        cache_key = self._response_cache_key(
            matched=matched,
            request=request,
            authenticated_client=authenticated_client,
        )
        stored_headers = {
            key: value
            for key, value in response.headers.items()
            if key.lower() not in {"x-request-id", "x-napigate-cache"}
        }
        self._cache.set(
            f"resp:{cache_key}",
            OutgoingResponse(
                status_code=response.status_code,
                headers=stored_headers,
                body=bytes(response.body),
            ),
            cache_config.ttl_seconds,
        )

    def _response_cache_key(
        self,
        *,
        matched: MatchedEndpoint,
        request: IncomingRequest,
        authenticated_client: AuthenticatedClient | None,
    ) -> str:
        cache_config = self._route_response_cache_config(matched)
        parts = [
            matched.route.slug,
            matched.route.gateway_path,
            request.method.upper(),
            request.path,
        ]
        if cache_config.vary_by_client:
            parts.append(
                f"client={authenticated_client.client_slug if authenticated_client else 'anonymous'}"
            )
        for key in sorted(request.query):
            parts.append(f"query:{key}={request.query[key]}")
        for header_name in cache_config.vary_headers:
            parts.append(
                f"header:{header_name.lower()}={self._get_header(request.headers, header_name) or ''}"
            )
        return "|".join(parts)

    def _apply_output_profile(
        self,
        *,
        matched: MatchedEndpoint,
        request: IncomingRequest,
        response: OutgoingResponse,
    ) -> OutgoingResponse:
        profile_slugs = self._output_profile_slugs(matched)
        if not profile_slugs:
            return response

        with self._lock:
            profiles = [self.output_profiles.get(profile_slug) for profile_slug in profile_slugs]
        for profile in profiles:
            if profile is None or not profile.enabled:
                continue
            response = self._apply_output_profile_config(
                profile=profile,
                request=request,
                response=response,
            )
        return response

    def _apply_output_profile_config(
        self,
        *,
        profile: OutputProfileConfig,
        request: IncomingRequest | None,
        response: OutgoingResponse,
        detail: str = "",
    ) -> OutgoingResponse:
        if profile.type == "passthrough":
            response.headers = self.merge_response_headers(response.headers, profile.headers)
            return response

        content_type = self._response_content_type(response.headers)
        parsed_body = self._parse_response_body(response.body, content_type=content_type)

        if profile.type == "jsonp":
            callback_raw = str(
                (request.query.get(profile.jsonp_callback_param) if request is not None else None)
                or profile.jsonp_default_callback
                or "callback"
            )
            callback = re.sub(r"[^a-zA-Z0-9_.$]", "", callback_raw) or "callback"
            body = f"{callback}({json.dumps(parsed_body, ensure_ascii=False)});".encode("utf-8")
            headers = dict(response.headers)
            headers["Content-Type"] = "application/javascript; charset=utf-8"
            headers = self.merge_response_headers(headers, profile.headers)
            return OutgoingResponse(status_code=response.status_code, headers=headers, body=body)

        if content_type.startswith("image/") or content_type == "application/octet-stream":
            response.headers = self.merge_response_headers(response.headers, profile.headers)
            return response

        if profile.type == "custom":
            validation = self._custom_validation_state(
                profile=profile,
                payload=parsed_body,
                response=response,
                detail=detail,
            )
            transformed = execute_custom_output_code(
                profile.transform_code or "",
                payload=parsed_body,
                status_code=response.status_code,
                detail=(detail or str(validation.get("error", "")))
                if not validation.get("ok", True)
                else detail,
                validation=validation,
                empty_value=profile.empty_value,
                content_type=content_type,
                headers=response.headers,
                query=request.query if request is not None else {},
            )
            body = json.dumps(transformed, ensure_ascii=False).encode("utf-8")
            headers = dict(response.headers)
            headers["Content-Type"] = "application/json; charset=utf-8"
            headers = self.merge_response_headers(headers, profile.headers)
            return OutgoingResponse(status_code=response.status_code, headers=headers, body=body)

        if self._is_existing_output_envelope(parsed_body, profile):
            envelope = parsed_body
        else:
            if profile.source_success_key:
                success_source_value = self._payload_path_value_or_default(
                    parsed_body,
                    profile.source_success_key,
                    profile.empty_value,
                )
                success = self._success_flag(success_source_value)
                success_value = success
            else:
                success_value = self._payload_value_or_default(
                    parsed_body,
                    profile.success_key,
                    response.status_code < 400,
                )
                success = self._success_flag(success_value)

            if profile.message_source_keys:
                message = self._first_payload_path_value_or_default(
                    parsed_body,
                    profile.message_source_keys,
                    profile.empty_value,
                )
            else:
                message = self._payload_value_or_default(
                    parsed_body,
                    profile.message_key,
                    self._output_message_from_payload(parsed_body),
                )

            if profile.data_fields:
                data_value = {
                    field_name: self._resolve_output_data_field_value(
                        parsed_body,
                        source_path,
                        profile.empty_value,
                    )
                    for field_name, source_path in profile.data_fields.items()
                }
            else:
                data_default = parsed_body if success else None
                data_value = self._payload_value_or_default(
                    parsed_body,
                    profile.data_key,
                    data_default,
                )

            error_default = (
                parsed_body
                if not success and parsed_body not in (None, "")
                else message or f"HTTP {response.status_code}"
            )
            envelope = {
                profile.success_key: success_value,
                profile.message_key: message,
                profile.data_key: data_value,
            }
            if not success:
                if profile.error_source_keys:
                    error_value = self._first_payload_path_value_or_default(
                        parsed_body,
                        profile.error_source_keys,
                        profile.empty_value,
                    )
                else:
                    error_value = self._payload_value_or_default(
                        parsed_body,
                        profile.error_key,
                        error_default,
                    )
                envelope[profile.error_key] = error_value

        body = json.dumps(envelope, ensure_ascii=False).encode("utf-8")
        headers = dict(response.headers)
        headers["Content-Type"] = "application/json; charset=utf-8"
        headers = self.merge_response_headers(headers, profile.headers)
        return OutgoingResponse(status_code=response.status_code, headers=headers, body=body)

    def _response_content_type(self, headers: Mapping[str, Any]) -> str:
        return str(self._get_header(headers, "Content-Type") or "").split(";", 1)[0].strip().lower()

    def _parse_response_body(self, body: bytes, *, content_type: str) -> Any:
        if not body:
            return None
        if content_type in {
            "application/json",
            "application/problem+json",
            "text/json",
        }:
            try:
                return json.loads(body.decode("utf-8"))
            except Exception:  # noqa: BLE001
                return body.decode("utf-8", errors="ignore")
        return body.decode("utf-8", errors="ignore")

    def _custom_validation_state(
        self,
        *,
        profile: OutputProfileConfig,
        payload: Any,
        response: OutgoingResponse,
        detail: str,
    ) -> dict[str, Any]:
        config = profile.custom_validation
        fallback_error = detail or f"HTTP {response.status_code}"
        error_text = self._first_payload_path_value_or_default(
            payload,
            config.error_source_keys,
            "",
        )
        if config.mode == "payload_key":
            missing = object()
            actual = self._payload_path_value_or_default(payload, config.source_key or "", missing)
            ok = actual is not missing and self._validation_value_matches(actual, config.expected_value)
            if not ok and not error_text:
                expected_text = self._stringify_output_data_field_value(config.expected_value)
                actual_text = (
                    "<missing>"
                    if actual is missing
                    else self._stringify_output_data_field_value(actual)
                )
                error_text = (
                    f"Payload key '{config.source_key or ''}' did not match the expected value "
                    f"({expected_text}). Actual: {actual_text}."
                )
            return {
                "mode": config.mode,
                "key": config.source_key or "",
                "expected": config.expected_value,
                "actual": None if actual is missing else actual,
                "ok": ok,
                "error": str(error_text or fallback_error if not ok else ""),
                "status_code": response.status_code,
            }

        ok = response.status_code < 400
        return {
            "mode": config.mode,
            "key": "",
            "expected": "<400",
            "actual": response.status_code,
            "ok": ok,
            "error": str(error_text or fallback_error if not ok else ""),
            "status_code": response.status_code,
        }

    def _validation_value_matches(self, actual: Any, expected: Any) -> bool:
        if isinstance(expected, bool):
            return self._success_flag(actual) == expected
        return actual == expected

    def _is_existing_output_envelope(
        self,
        payload: Any,
        profile: OutputProfileConfig,
    ) -> bool:
        if not isinstance(payload, Mapping):
            return False
        required_keys = profile.passthrough_keys or [profile.success_key, profile.data_key]
        return all(key in payload for key in required_keys)

    def _payload_value_or_default(self, payload: Any, key: str, default: Any) -> Any:
        if isinstance(payload, Mapping) and key in payload and payload[key] not in (None, ""):
            return payload[key]
        return default

    def _payload_path_value_or_default(self, payload: Any, path: str, default: Any) -> Any:
        current: Any = payload
        for part in path.split("."):
            if isinstance(current, Mapping) and part in current:
                current = current[part]
            else:
                return default
        if current in (None, ""):
            return default
        return current

    def _first_payload_path_value_or_default(
        self,
        payload: Any,
        paths: list[str],
        default: Any,
    ) -> Any:
        for path in paths:
            value = self._payload_path_value_or_default(payload, path, None)
            if value not in (None, ""):
                return value
        return default

    def _resolve_output_data_field_value(self, payload: Any, expression: str, default: Any) -> Any:
        template = str(expression or "").strip()
        if not template:
            return default
        match = DATA_FIELD_TEMPLATE_PATTERN.fullmatch(template)
        if match:
            return self._payload_path_value_or_default(
                payload,
                self._data_field_placeholder_path(match),
                default,
            )
        if DATA_FIELD_TEMPLATE_PATTERN.search(template):
            return DATA_FIELD_TEMPLATE_PATTERN.sub(
                lambda item: self._stringify_output_data_field_value(
                    self._payload_path_value_or_default(
                        payload,
                        self._data_field_placeholder_path(item),
                        default,
                    )
                ),
                template,
            )
        return self._payload_path_value_or_default(payload, template, default)

    def _data_field_placeholder_path(self, match: re.Match[str]) -> str:
        return str(match.group(1) or match.group(2) or "").strip()

    def _stringify_output_data_field_value(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        return json.dumps(value, ensure_ascii=False)

    def _success_flag(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"false", "0", "no", "failed", "error"}:
                return False
            if normalized in {"true", "1", "yes", "ok", "success"}:
                return True
        return bool(value)

    def _output_message_from_payload(self, payload: Any) -> str:
        if isinstance(payload, Mapping):
            for key in ("message", "detail", "error"):
                value = payload.get(key)
                if value not in (None, ""):
                    return str(value)
        if isinstance(payload, str):
            return payload
        return ""

    def _emit_success_hook(
        self,
        *,
        matched: MatchedEndpoint,
        request: IncomingRequest,
        authenticated_client: AuthenticatedClient | None,
        response: OutgoingResponse,
        request_id: str,
        response_source: str,
    ) -> None:
        success_hook = self._route_success_hook(matched)
        if success_hook is None or not success_hook.enabled or response.status_code >= 400:
            return

        payload: dict[str, Any] = {
            "event_type": success_hook.event_type,
            "request_id": request_id,
            "response_source": response_source,
            "route": {
                "name": matched.route.name,
                "slug": matched.route.slug,
                "gateway_path": matched.route.gateway_path,
                "strategy": matched.route.strategy,
            },
            "service": {
                "name": matched.service.name,
            },
            "endpoint": {
                "name": matched.endpoint.name,
                "slug": matched.endpoint.slug,
            },
            "client": (
                {
                    "slug": authenticated_client.client_slug,
                    "code": authenticated_client.client_code,
                    "title": authenticated_client.client_title,
                    "auth_method_code": authenticated_client.auth_method_code,
                    "auth_method_type": authenticated_client.auth_type,
                }
                if authenticated_client is not None
                else None
            ),
            "request": {
                "method": request.method,
                "path": request.path,
                "client_ip": request.client_ip,
                "query": request.query,
                "headers": request.headers,
            },
            "response": {
                "status_code": response.status_code,
                "headers": response.headers,
            },
            "created_at": datetime.now(UTC).isoformat(),
        }
        if success_hook.include_request_body:
            payload["request"]["body_text"] = request.body.decode("utf-8", errors="ignore")
        if success_hook.include_response_body:
            payload["response"]["body_text"] = response.body.decode("utf-8", errors="ignore")
        self.dispatcher.enqueue_success_hook(success_hook=success_hook, payload=payload)

    def issue_oauth_token(
        self,
        *,
        client_id: str,
        client_secret: str,
        client_ip: str | None = None,
    ) -> tuple[str, int, str, str]:
        with self._lock:
            clients = list(self.clients.values())

        for client in clients:
            if not client.enabled:
                continue
            for method in client.auth_methods:
                if not method.enabled or method.type != "oauth_client_credentials":
                    continue
                if not hmac.compare_digest(method.client_id or "", client_id):
                    continue
                if not hmac.compare_digest(method.client_secret or "", client_secret):
                    continue
                if client_ip and client.ip_allowlist and not self._ip_allowed(client_ip, client.ip_allowlist):
                    raise GatewayError(
                        403,
                        f"Client '{client.code}' is not allowed from IP '{client_ip}'.",
                    )
                issued_at = int(time.time())
                expires_at = issued_at + max(1, int(method.token_ttl_seconds or 3600))
                token = self._build_oauth_access_token(client, method, expires_at)
                return token, expires_at - issued_at, client.code, method.code

        raise GatewayError(401, "OAuth client authentication failed.")

    def _run_pre_call(
        self,
        *,
        matched: MatchedEndpoint,
        request: IncomingRequest,
        context: dict[str, Any],
        variables: dict[str, Any],
        pre_call: PreCallConfig,
        default_cache_key: str,
    ) -> None:
        raw_cache_key = pre_call.cache_key or default_cache_key
        rendered_cache_key = self.render_template(raw_cache_key, context)
        cache_key = str(rendered_cache_key or default_cache_key)
        now = time.time()
        cached_vars = self._cache.get(f"pre_call:{cache_key}")
        if cached_vars is not None:
            variables.update(cached_vars)
            return

        def call(method: str, url: str, **kwargs: Any) -> requests.Response:
            call_context = self._build_template_context(
                matched=matched,
                request=request,
                variables=variables,
            )
            rendered_url = self.render_template(url, call_context)
            final_url = self._join_url(matched.service.base_url, str(rendered_url))
            rendered_kwargs = self.render_data(kwargs, call_context)
            rendered_kwargs.setdefault("timeout", matched.service.timeout_seconds)
            rendered_kwargs.setdefault("verify", matched.service.verify_ssl)
            rendered_kwargs.setdefault("allow_redirects", False)
            response, _prepared_request = self._send_request(
                matched.service,
                method.upper(),
                final_url,
                **rendered_kwargs,
            )
            return response

        def set_var(name: str, value: Any) -> None:
            variables[name] = value

        def get_var(name: str, default: Any = None) -> Any:
            return variables.get(name, default)

        exec_globals: dict[str, Any] = {
            "__builtins__": __builtins__,
            "call": call,
            "set_var": set_var,
            "get_var": get_var,
            "vars": variables,
            "service": {
                "name": matched.service.name,
                "base_url": matched.service.base_url,
                "timeout_seconds": matched.service.timeout_seconds,
                "verify_ssl": matched.service.verify_ssl,
                "trust_env_proxy": matched.service.trust_env_proxy,
                "variables": matched.service.variables,
            },
            "endpoint": {
                "name": matched.endpoint.name,
                "methods": matched.endpoint.methods,
                "gateway_path": matched.route.gateway_path,
                "upstream_path": matched.endpoint.upstream_path,
                "response": (
                    {
                        "status_code": matched.endpoint.response.status_code,
                        "content_type": matched.endpoint.response.content_type,
                        "headers": matched.endpoint.response.headers,
                        "body": matched.endpoint.response.body,
                    }
                    if matched.endpoint.response is not None
                    else None
                ),
            },
            "request_ctx": context["request"],
            "path": context["path"],
            "query": context["query"],
            "headers": context["headers"],
            "json": json,
            "time": time,
            "datetime": datetime,
            "base64": __import__("base64"),
            "hashlib": __import__("hashlib"),
        }
        exec_locals: dict[str, Any] = {}

        snippet = "def __user_pre_call__():\n"
        for line in pre_call.code.splitlines():
            snippet += f"    {line}\n"

        before_variables = dict(variables)
        exec(snippet, exec_globals, exec_locals)
        exec_locals["__user_pre_call__"]()

        if pre_call.cache_ttl_seconds > 0:
            changed_variables = {
                key: value
                for key, value in variables.items()
                if key not in before_variables or before_variables.get(key) != value
            }
            self._cache.set(f"pre_call:{cache_key}", changed_variables, pre_call.cache_ttl_seconds)

    def _build_template_context(
        self,
        *,
        matched: MatchedEndpoint,
        request: IncomingRequest,
        variables: dict[str, Any],
        authenticated_client: AuthenticatedClient | None = None,
    ) -> dict[str, Any]:
        request_ctx = {
            "method": request.method,
            "path": request.path,
            "url": request.url,
            "client_ip": request.client_ip,
            "headers": request.headers,
            "query": request.query,
            "body_bytes": request.body,
            "body_text": request.body.decode("utf-8", errors="ignore"),
            "json": request.json_body,
        }

        base_context: dict[str, Any] = {
            "route": {
                "name": matched.route.name,
                "slug": matched.route.slug,
                "protocol": matched.route.protocol,
                "methods": matched.route.methods,
                "gateway_path": matched.route.gateway_path,
                "strategy": matched.route.strategy,
                "targets": [
                    {"service": target.service, "endpoint": target.endpoint}
                    for target in matched.route.targets
                ],
            },
            "service": {
                "name": matched.service.name,
                "protocol": matched.service.protocol,
                "base_url": matched.service.base_url,
                "target": matched.service.target,
                "timeout_seconds": matched.service.timeout_seconds,
                "verify_ssl": matched.service.verify_ssl,
                "trust_env_proxy": matched.service.trust_env_proxy,
                "variables": matched.service.variables,
                "grpc": (
                    {
                        "use_tls": matched.service.grpc.use_tls,
                        "use_reflection": matched.service.grpc.use_reflection,
                        "descriptor_set_path": matched.service.grpc.descriptor_set_path,
                        "authority": matched.service.grpc.authority,
                        "root_certificates_path": matched.service.grpc.root_certificates_path,
                    }
                    if matched.service.grpc is not None
                    else None
                ),
            },
            "endpoint": {
                "name": matched.endpoint.name,
                "slug": matched.endpoint.slug,
                "gateway_path": matched.route.gateway_path,
                "upstream_path": matched.endpoint.upstream_path,
                "grpc": (
                    {
                        "full_method": matched.endpoint.grpc.full_method,
                        "request_body": matched.endpoint.grpc.request_body,
                    }
                    if matched.endpoint.grpc is not None
                    else None
                ),
                "response": (
                    {
                        "status_code": matched.endpoint.response.status_code,
                        "content_type": matched.endpoint.response.content_type,
                        "headers": matched.endpoint.response.headers,
                        "body": matched.endpoint.response.body,
                    }
                    if matched.endpoint.response is not None
                    else None
                ),
            },
            "auth": {
                "required": matched.route.auth.required,
                "client_slug": authenticated_client.client_slug if authenticated_client else None,
                "client_code": authenticated_client.client_code if authenticated_client else None,
                "client_title": authenticated_client.client_title if authenticated_client else None,
                "method_code": authenticated_client.auth_method_code if authenticated_client else None,
                "method_title": authenticated_client.auth_method_title if authenticated_client else None,
                "method_type": authenticated_client.auth_type if authenticated_client else None,
                "source": authenticated_client.source if authenticated_client else None,
                "metadata": authenticated_client.metadata if authenticated_client else {},
            },
            "client": {
                "slug": authenticated_client.client_slug if authenticated_client else None,
                "code": authenticated_client.client_code if authenticated_client else None,
                "title": authenticated_client.client_title if authenticated_client else None,
                "auth_method_code": authenticated_client.auth_method_code if authenticated_client else None,
                "auth_method_title": authenticated_client.auth_method_title if authenticated_client else None,
                "auth_type": authenticated_client.auth_type if authenticated_client else None,
                "source": authenticated_client.source if authenticated_client else None,
                "metadata": authenticated_client.metadata if authenticated_client else {},
            },
            "request": request_ctx,
            "request_ctx": request_ctx,
            "path": matched.path_params,
            "query": request.query,
            "headers": request.headers,
            "vars": variables,
        }

        for key, value in variables.items():
            if key not in base_context:
                base_context[key] = value

        return base_context

    def render_data(self, value: Any, context: dict[str, Any]) -> Any:
        if isinstance(value, str):
            return self.render_template(value, context)
        if isinstance(value, list):
            return [self.render_data(item, context) for item in value]
        if isinstance(value, Mapping):
            return {
                key: self.render_data(item, context)
                for key, item in value.items()
                if item is not None
            }
        return value

    def _render_header_mapping(
        self,
        headers: Mapping[str, Any],
        context: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            str(key): (None if value is None else self.render_data(value, context))
            for key, value in headers.items()
        }

    def render_template(self, template: str, context: dict[str, Any]) -> Any:
        match = TEMPLATE_PATTERN.fullmatch(template)
        if match:
            return self._resolve_path(match.group(1), context)

        def replace(item: re.Match[str]) -> str:
            resolved = self._resolve_path(item.group(1), context)
            return "" if resolved is None else str(resolved)

        return TEMPLATE_PATTERN.sub(replace, template)

    def _resolve_path(self, expression: str, context: dict[str, Any]) -> Any:
        current: Any = context
        for part in expression.split("."):
            if isinstance(current, Mapping):
                current = current.get(part)
            else:
                current = getattr(current, part, None)
            if current is None:
                return None
        return current

    def _prepare_request_headers(
        self,
        *,
        incoming_headers: dict[str, Any],
        service_headers: dict[str, Any],
        endpoint_headers: dict[str, Any],
        authenticated_client: AuthenticatedClient | None,
        forwarded_auth: AuthenticatedClient | None,
        forward_napigate_headers: bool,
        request_id: str,
    ) -> dict[str, str]:
        filtered_headers = set(FILTERED_REQUEST_HEADERS)
        strip_auth = forwarded_auth or authenticated_client
        if strip_auth is not None:
            filtered_headers.update(item.lower() for item in strip_auth.consumed_headers)

        outgoing = {
            key: value
            for key, value in incoming_headers.items()
            if key.lower() not in filtered_headers
        }

        if strip_auth is not None and strip_auth.consumed_cookie_names:
            cookie_header = self._remove_cookie_names(
                str(incoming_headers.get("Cookie", incoming_headers.get("cookie", ""))),
                strip_auth.consumed_cookie_names,
            )
            if cookie_header:
                outgoing["Cookie"] = cookie_header
            else:
                outgoing.pop("Cookie", None)
                outgoing.pop("cookie", None)

        def apply_header_overrides(headers: Mapping[str, Any]) -> None:
            for key, value in headers.items():
                existing_key = next(
                    (candidate for candidate in outgoing if candidate.lower() == key.lower()),
                    None,
                )
                if value in (None, ""):
                    if existing_key is not None:
                        outgoing.pop(existing_key, None)
                    continue
                outgoing[existing_key or key] = str(value)

        apply_header_overrides(service_headers)
        apply_header_overrides(endpoint_headers)
        outgoing["X-Request-ID"] = request_id
        if authenticated_client is not None and forward_napigate_headers:
            outgoing["X-NapiGate-Client-Slug"] = authenticated_client.client_slug
            outgoing["X-NapiGate-Client-Code"] = authenticated_client.client_code
            outgoing["X-NapiGate-Client-Title"] = authenticated_client.client_title
            outgoing["X-NapiGate-Auth-Method-Code"] = authenticated_client.auth_method_code
            outgoing["X-NapiGate-Auth-Method-Type"] = authenticated_client.auth_type
            outgoing["X-NapiGate-Auth-Source"] = authenticated_client.source
        return outgoing

    def _prepare_response_headers(
        self,
        response_headers: Mapping[str, str],
        request_id: str,
    ) -> dict[str, str]:
        headers = {
            key: value
            for key, value in response_headers.items()
            if key.lower() not in FILTERED_RESPONSE_HEADERS
        }
        headers["X-Request-ID"] = request_id
        return headers

    def merge_response_headers(
        self,
        headers: Mapping[str, Any],
        extra_headers: Mapping[str, Any],
    ) -> dict[str, str]:
        merged = {str(key): str(value) for key, value in headers.items()}
        for key, value in extra_headers.items():
            existing_key = next(
                (candidate for candidate in merged if candidate.lower() == key.lower()),
                None,
            )
            if key.lower() == "vary" and existing_key is not None:
                current_values = [
                    item.strip() for item in merged[existing_key].split(",") if item.strip()
                ]
                new_values = [item.strip() for item in str(value).split(",") if item.strip()]
                merged[existing_key] = ", ".join(dict.fromkeys(current_values + new_values))
            else:
                merged[existing_key or str(key)] = str(value)
        return merged

    def cors_headers_for_request(
        self,
        request: IncomingRequest,
        *,
        preflight: bool = False,
    ) -> dict[str, str]:
        matched = self.match(request.method, request.path)
        if matched is None and (preflight or request.method.upper() == "OPTIONS"):
            matched = self.match_any(request.path)
        if matched is None:
            return {}
        return self._build_cors_headers(matched, request, preflight=preflight)

    def _build_static_response(
        self,
        *,
        response_config: StaticResponseConfig,
        context: dict[str, Any],
        request_id: str,
    ) -> OutgoingResponse:
        rendered_headers = self.render_data(response_config.headers, context)
        headers = {
            key: str(value)
            for key, value in rendered_headers.items()
            if value is not None and key.lower() not in FILTERED_RESPONSE_HEADERS
        }

        rendered_body = self.render_data(response_config.body, context)
        default_content_type = response_config.content_type

        if isinstance(rendered_body, bytes):
            body = rendered_body
            default_content_type = default_content_type or "application/octet-stream"
        elif isinstance(rendered_body, (dict, list)):
            body = json.dumps(rendered_body, ensure_ascii=False).encode("utf-8")
            default_content_type = default_content_type or "application/json; charset=utf-8"
        elif rendered_body is None:
            body = b""
            default_content_type = default_content_type or "text/plain; charset=utf-8"
        else:
            body = str(rendered_body).encode("utf-8")
            default_content_type = default_content_type or "text/plain; charset=utf-8"

        if default_content_type and not any(key.lower() == "content-type" for key in headers):
            headers["Content-Type"] = default_content_type
        headers["X-Request-ID"] = request_id
        return OutgoingResponse(
            status_code=response_config.status_code,
            headers=headers,
            body=body,
        )

    def _build_cors_headers(
        self,
        matched: MatchedEndpoint,
        request: IncomingRequest,
        *,
        preflight: bool = False,
    ) -> dict[str, str]:
        cors = matched.service.cors
        if not cors.enabled:
            return {}

        origin = self._get_header(request.headers, "Origin")
        allowed_origin = self._allowed_cors_origin(
            origin=origin,
            allow_origins=cors.allow_origins,
            allow_credentials=cors.allow_credentials,
        )
        if origin and allowed_origin is None:
            return {}

        headers: dict[str, str] = {}
        vary_values: list[str] = []

        if allowed_origin is not None:
            headers["Access-Control-Allow-Origin"] = allowed_origin
            if allowed_origin != "*":
                vary_values.append("Origin")

        if cors.allow_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"

        if cors.expose_headers and not preflight:
            headers["Access-Control-Expose-Headers"] = ", ".join(cors.expose_headers)

        if preflight:
            allow_methods = cors.allow_methods or list(
                dict.fromkeys([*matched.route.methods, "OPTIONS"])
            )
            request_headers = [
                item.strip()
                for item in str(
                    self._get_header(request.headers, "Access-Control-Request-Headers") or ""
                ).split(",")
                if item.strip()
            ]
            allow_headers = cors.allow_headers or request_headers or [
                "Authorization",
                "Content-Type",
            ]
            headers["Access-Control-Allow-Methods"] = ", ".join(allow_methods)
            headers["Access-Control-Allow-Headers"] = ", ".join(allow_headers)
            headers["Access-Control-Max-Age"] = str(cors.max_age_seconds)
            if request_headers and not cors.allow_headers:
                vary_values.append("Access-Control-Request-Headers")

        if vary_values:
            headers["Vary"] = ", ".join(dict.fromkeys(vary_values))

        return headers

    def _allowed_cors_origin(
        self,
        *,
        origin: str | None,
        allow_origins: list[str],
        allow_credentials: bool,
    ) -> str | None:
        if not allow_origins:
            return None
        if "*" in allow_origins:
            if allow_credentials:
                return origin
            return "*"
        if origin and origin in allow_origins:
            return origin
        return None

    def _merge_query_params(
        self,
        incoming_query: dict[str, Any],
        configured_query: dict[str, Any],
        authenticated_client: AuthenticatedClient | None = None,
    ) -> dict[str, Any]:
        merged = dict(incoming_query)
        if authenticated_client is not None:
            for key in authenticated_client.consumed_query_params:
                merged.pop(key, None)
        for key, value in configured_query.items():
            if value is None:
                continue
            merged[key] = value
        return merged

    def _join_url(self, base_url: str, path_or_url: str) -> str:
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            return path_or_url
        return f"{base_url.rstrip('/')}/{str(path_or_url).lstrip('/')}"

    def _send_request(
        self,
        service: ServiceConfig,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> tuple[requests.Response, requests.PreparedRequest]:
        request_kwargs: dict[str, Any] = {}
        send_kwargs = dict(kwargs)
        for key in ("headers", "files", "data", "json", "params", "cookies", "auth"):
            if key in send_kwargs:
                request_kwargs[key] = send_kwargs.pop(key)
        verify = send_kwargs.pop("verify", None)
        stream = send_kwargs.pop("stream", None)
        cert = send_kwargs.pop("cert", None)
        proxies = send_kwargs.pop("proxies", None)
        with requests.Session() as session:
            session.trust_env = service.trust_env_proxy
            prepared_request = session.prepare_request(
                requests.Request(method.upper(), url, **request_kwargs)
            )
            merged_settings = session.merge_environment_settings(
                prepared_request.url,
                proxies=proxies,
                stream=stream,
                verify=verify,
                cert=cert,
            )
            send_kwargs = {
                **merged_settings,
                **send_kwargs,
            }
            try:
                response = session.send(prepared_request, **send_kwargs)
            except requests.RequestException as exc:
                setattr(exc, "napigate_prepared_request", prepared_request)
                raise
            return response, prepared_request

    def _send_request_streaming(
        self,
        service: ServiceConfig,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> tuple[requests.Response, requests.Session, requests.PreparedRequest]:
        """Open a streaming upstream request. Caller must close session after consuming body."""
        request_kwargs: dict[str, Any] = {}
        send_kwargs = dict(kwargs)
        for key in ("headers", "files", "data", "json", "params", "cookies", "auth"):
            if key in send_kwargs:
                request_kwargs[key] = send_kwargs.pop(key)
        verify = send_kwargs.pop("verify", None)
        send_kwargs.pop("stream", None)
        cert = send_kwargs.pop("cert", None)
        proxies = send_kwargs.pop("proxies", None)
        session = requests.Session()
        session.trust_env = service.trust_env_proxy
        try:
            prepared_request = session.prepare_request(
                requests.Request(method.upper(), url, **request_kwargs)
            )
            merged_settings = session.merge_environment_settings(
                prepared_request.url,
                proxies=proxies,
                stream=True,
                verify=verify,
                cert=cert,
            )
            send_kwargs = {**merged_settings, **send_kwargs}
            response = session.send(prepared_request, **send_kwargs)
        except requests.RequestException as exc:
            session.close()
            setattr(exc, "napigate_prepared_request", locals().get("prepared_request"))
            raise
        return response, session, prepared_request

    def _should_stream_response(self, matched: MatchedEndpoint) -> bool:
        """Return True when the response can be streamed without buffering."""
        if matched.service.protocol != "http":
            return False
        for profile_slug in self._output_profile_slugs(matched):
            profile = self.output_profiles.get(profile_slug)
            if profile and profile.enabled and profile.type != "passthrough":
                return False
        cache_config = self._route_response_cache_config(matched)
        if cache_config.enabled and cache_config.ttl_seconds > 0:
            return False
        return True

    def _build_upstream_curl(
        self,
        *,
        prepared_request: requests.PreparedRequest,
        timeout_seconds: int | float | None,
        verify_ssl: bool,
        allow_redirects: bool,
    ) -> str:
        command = [
            "curl",
            f"-X {shlex.quote(prepared_request.method or 'GET')}",
        ]
        if not verify_ssl:
            command.append("-k")
        if allow_redirects:
            command.append("-L")
        if timeout_seconds is not None:
            timeout_value = (
                int(timeout_seconds)
                if isinstance(timeout_seconds, (int, float)) and float(timeout_seconds).is_integer()
                else timeout_seconds
            )
            command.append(f"--max-time {shlex.quote(str(timeout_value))}")

        for header_name, header_value in prepared_request.headers.items():
            command.append(
                f"-H {shlex.quote(f'{header_name}: {header_value}')}"
            )

        body_prefix = ""
        prepared_body = prepared_request.body
        if prepared_body not in (None, b"", ""):
            if isinstance(prepared_body, bytes):
                try:
                    body_text = prepared_body.decode("utf-8")
                except UnicodeDecodeError:
                    escaped_bytes = "".join(f"\\x{byte:02x}" for byte in prepared_body)
                    body_prefix = f"printf '%b' {shlex.quote(escaped_bytes)} | "
                    command.append("--data-binary @-")
                else:
                    command.append(f"--data-binary {shlex.quote(body_text)}")
            else:
                command.append(f"--data-binary {shlex.quote(str(prepared_body))}")

        command.append(shlex.quote(prepared_request.url or ""))
        rendered = " \\\n  ".join(command)
        return f"{body_prefix}{rendered}" if body_prefix else rendered

    def _response_body_for_log(self, response: OutgoingResponse) -> str:
        if response.body_iter is not None:
            return "<streaming>"
        if not response.body:
            return ""
        content_type = str(response.headers.get("Content-Type", "") or "")
        parsed_body = self._parse_response_body(response.body, content_type=content_type)
        if parsed_body in (None, ""):
            return ""
        if isinstance(parsed_body, (dict, list)):
            text = json.dumps(parsed_body, ensure_ascii=False)
        else:
            text = str(parsed_body)
        if len(text) > 12000:
            trimmed = len(text) - 12000
            return f"{text[:12000]}\n...[truncated {trimmed} chars]"
        return text

    def _inline_gateway_error_payload(self, detail: str) -> dict[str, Any]:
        config = self.gateway_responses
        message = detail or config.empty_value
        error = detail or config.empty_value
        return {
            config.success_key: False,
            config.data_key: config.empty_value,
            config.message_key: message,
            config.error_key: error,
        }

    def _gateway_error_seed_payload(self, status_code: int, detail: str) -> dict[str, Any]:
        return {
            "detail": detail,
            "message": detail,
            "error": detail,
            "status_code": status_code,
            "status": status_code,
        }

    def _shape_gateway_error_response(
        self,
        *,
        status_code: int,
        detail: str,
        request: IncomingRequest | None = None,
    ) -> OutgoingResponse:
        config = self.gateway_responses
        if config.mode == "profile" and config.output_profile:
            with self._lock:
                profile = self.output_profiles.get(config.output_profile)
            if profile is None:
                LOGGER.warning(
                    "Gateway response output profile '%s' was not found. Falling back to default detail shape.",
                    config.output_profile,
                )
            else:
                try:
                    seed_response = OutgoingResponse(
                        status_code=status_code,
                        headers={"Content-Type": "application/json; charset=utf-8"},
                        body=json.dumps(
                            self._gateway_error_seed_payload(status_code, detail),
                            ensure_ascii=False,
                        ).encode("utf-8"),
                    )
                    return self._apply_output_profile_config(
                        profile=profile,
                        request=request,
                        response=seed_response,
                        detail=detail,
                    )
                except Exception:  # noqa: BLE001
                    LOGGER.exception(
                        "Gateway response output profile '%s' failed. Falling back to default detail shape.",
                        config.output_profile,
                    )
        if config.mode == "inline":
            payload = self._inline_gateway_error_payload(detail)
        else:
            payload = {"detail": detail}
        return OutgoingResponse(
            status_code=status_code,
            headers={"Content-Type": "application/json; charset=utf-8"},
            body=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        )

    def _error_response_body(
        self,
        status_code: int,
        detail: str,
        request: IncomingRequest | None = None,
    ) -> str:
        shaped = self._shape_gateway_error_response(
            status_code=status_code,
            detail=detail,
            request=request,
        )
        return shaped.body.decode("utf-8", errors="ignore")

    def build_gateway_error_response(
        self,
        *,
        status_code: int,
        detail: str,
        request: IncomingRequest | None = None,
        preflight: bool = False,
        extra_headers: Mapping[str, Any] | None = None,
        include_body: bool = True,
    ) -> OutgoingResponse:
        shaped = self._shape_gateway_error_response(
            status_code=status_code,
            detail=detail,
            request=request,
        )
        headers: dict[str, Any] = dict(shaped.headers)
        if request is not None:
            headers = self.merge_response_headers(
                headers,
                self.cors_headers_for_request(request, preflight=preflight),
            )
        headers = self.merge_response_headers(headers, self.gateway_responses.headers)
        headers = self.merge_response_headers(headers, extra_headers or {})
        return OutgoingResponse(
            status_code=status_code,
            headers=headers,
            body=shaped.body if include_body else b"",
        )

    def _write_log(
        self,
        *,
        request_id: str,
        request: IncomingRequest,
        matched: MatchedEndpoint,
        upstream_url: str,
        upstream_curl: str,
        status_code: int,
        duration_ms: float,
        duration_us: int,
        error_message: str,
        response_body: str,
    ) -> None:
        created_at = datetime.now(UTC).isoformat()
        entry = LogEntry(
            request_id=request_id,
            method=request.method,
            gateway_path=request.path,
            service_name=matched.service.name,
            endpoint_name=matched.endpoint.name,
            upstream_url=upstream_url,
            upstream_curl=upstream_curl,
            status_code=status_code,
            duration_ms=duration_ms,
            duration_us=duration_us,
            client_ip=request.client_ip,
            error=error_message,
            response_body=response_body,
            created_at=created_at,
        )
        self.log_store.write(entry)
        self.dispatcher.emit_request_log(
            {
                "request_id": request_id,
                "method": request.method,
                "gateway_path": request.path,
                "route_name": matched.route.name,
                "route_slug": matched.route.slug,
                "route_strategy": matched.route.strategy,
                "service_name": matched.service.name,
                "endpoint_name": matched.endpoint.name,
                "endpoint_slug": matched.endpoint.slug,
                "upstream_url": upstream_url,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "duration_us": duration_us,
                "client_ip": request.client_ip,
                "error": error_message,
                "created_at": created_at,
            }
        )
        LOGGER.info(
            "request_id=%s method=%s path=%s route=%s service=%s endpoint=%s status=%s duration_ms=%s duration_us=%s upstream=%s error=%s",
            request_id,
            request.method,
            request.path,
            matched.route.slug,
            matched.service.name,
            matched.endpoint.name,
            status_code,
            duration_ms,
            duration_us,
            upstream_url,
            error_message or "-",
        )

    def _enforce_rate_limit(
        self,
        *,
        matched: MatchedEndpoint,
        request: IncomingRequest,
        authenticated_client: AuthenticatedClient | None,
    ) -> None:
        rate_limit = matched.service.rate_limit
        if not rate_limit.enabled:
            return

        subject = self._rate_limit_subject(
            scope=rate_limit.scope,
            request=request,
            authenticated_client=authenticated_client,
        )
        bucket_key = f"{matched.service.name}:{rate_limit.scope}:{subject}"
        allowed, retry_after = self._rate_limiter.check_and_record(
            bucket_key, rate_limit.requests, rate_limit.window_seconds
        )
        if not allowed:
            raise GatewayError(
                429,
                f"Rate limit exceeded for service '{matched.service.name}'.",
                headers={"Retry-After": str(retry_after)},
            )

    def _rate_limit_subject(
        self,
        *,
        scope: str,
        request: IncomingRequest,
        authenticated_client: AuthenticatedClient | None,
    ) -> str:
        if scope == "client":
            return authenticated_client.client_code if authenticated_client else "anonymous"
        if scope == "ip":
            return request.client_ip or "unknown"
        return authenticated_client.client_code if authenticated_client else (request.client_ip or "anonymous")

    def _authenticate_client(
        self,
        *,
        matched: MatchedEndpoint,
        request: IncomingRequest,
    ) -> AuthenticatedClient | None:
        if not matched.route.auth.required:
            return None

        return self._match_scoped_client_credentials(
            targets=self._target_matches_for_route(matched),
            request=request,
            require_success=True,
            enforce_ip_allowlist=True,
        )

    def _detect_forwarded_auth_credentials(
        self,
        *,
        matched: MatchedEndpoint,
        request: IncomingRequest,
    ) -> AuthenticatedClient | None:
        targets = self._target_matches_for_route(matched)
        if not targets:
            return None

        return self._match_scoped_client_credentials(
            targets=targets,
            request=request,
            require_success=False,
            enforce_ip_allowlist=False,
        )

    def _match_scoped_client_credentials(
        self,
        *,
        targets: list[MatchedEndpoint],
        request: IncomingRequest,
        require_success: bool,
        enforce_ip_allowlist: bool,
    ) -> AuthenticatedClient | None:
        if not targets:
            return None

        with self._lock:
            eligible_clients = [
                client
                for client in self.clients.values()
                if client.enabled
                and any(
                    self._client_scope_applies(client, matched=target)
                    for target in targets
                )
            ]

        if not eligible_clients:
            if require_success:
                raise GatewayError(401, "Client authentication failed.")
            return None

        for client in eligible_clients:
            for method in client.auth_methods:
                if not method.enabled:
                    continue
                for auth_match in targets:
                    if not self._client_scope_applies(client, matched=auth_match):
                        continue
                    matched_client = self._match_auth_method(
                        client=client,
                        method=method,
                        matched=auth_match,
                        request=request,
                    )
                    if matched_client is None:
                        continue
                    if client.ip_allowlist and not self._ip_allowed(request.client_ip, client.ip_allowlist):
                        if require_success and enforce_ip_allowlist:
                            raise GatewayError(
                                403,
                                f"Client '{client.code}' is not allowed from IP '{request.client_ip}'.",
                            )
                        continue
                    return matched_client

        if require_success:
            raise GatewayError(401, "Client authentication failed.")
        return None

    def _client_scope_applies(
        self,
        client: ClientConfig,
        *,
        matched: MatchedEndpoint,
    ) -> bool:
        if client.access.mode == "all":
            return True
        if client.access.mode == "services":
            return matched.service.name in client.access.services
        return any(
            target.service == matched.service.name
            and target.endpoint in {matched.endpoint.name, matched.endpoint.slug}
            for target in client.access.endpoints
        )

    def _match_auth_method(
        self,
        client: ClientConfig,
        method: AuthMethodConfig,
        matched: MatchedEndpoint,
        request: IncomingRequest,
    ) -> AuthenticatedClient | None:
        cookies = self._parse_cookies(request.headers)

        if method.type == "api_key":
            for header_name in method.header_names:
                value = self._get_header(request.headers, header_name)
                if value is not None and hmac.compare_digest(value, method.secret or ""):
                    return AuthenticatedClient(
                        client_slug=client.slug,
                        client_code=client.code,
                        client_title=client.title,
                        auth_method_code=method.code,
                        auth_method_title=method.title,
                        auth_type=method.type,
                        source=f"header:{header_name}",
                        metadata={},
                        consumed_headers={header_name},
                        consumed_query_params=set(),
                        consumed_cookie_names=set(),
                    )
            for query_name in method.query_params:
                value = request.query.get(query_name)
                if value is not None and hmac.compare_digest(str(value), method.secret or ""):
                    return AuthenticatedClient(
                        client_slug=client.slug,
                        client_code=client.code,
                        client_title=client.title,
                        auth_method_code=method.code,
                        auth_method_title=method.title,
                        auth_type=method.type,
                        source=f"query:{query_name}",
                        metadata={},
                        consumed_headers=set(),
                        consumed_query_params={query_name},
                        consumed_cookie_names=set(),
                    )
            for cookie_name in method.cookie_names:
                value = cookies.get(cookie_name)
                if value is not None and hmac.compare_digest(value, method.secret or ""):
                    return AuthenticatedClient(
                        client_slug=client.slug,
                        client_code=client.code,
                        client_title=client.title,
                        auth_method_code=method.code,
                        auth_method_title=method.title,
                        auth_type=method.type,
                        source=f"cookie:{cookie_name}",
                        metadata={},
                        consumed_headers={"Cookie"},
                        consumed_query_params=set(),
                        consumed_cookie_names={cookie_name},
                    )
            return None

        if method.type == "bearer":
            if method.allow_authorization_header:
                token = self._extract_bearer_token(request.headers)
                if token is not None and hmac.compare_digest(token, method.token or ""):
                    return AuthenticatedClient(
                        client_slug=client.slug,
                        client_code=client.code,
                        client_title=client.title,
                        auth_method_code=method.code,
                        auth_method_title=method.title,
                        auth_type=method.type,
                        source="authorization:bearer",
                        metadata={},
                        consumed_headers={"Authorization"},
                        consumed_query_params=set(),
                        consumed_cookie_names=set(),
                    )
            for header_name in method.header_names:
                value = self._get_header(request.headers, header_name)
                if value is not None and hmac.compare_digest(value, method.token or ""):
                    return AuthenticatedClient(
                        client_slug=client.slug,
                        client_code=client.code,
                        client_title=client.title,
                        auth_method_code=method.code,
                        auth_method_title=method.title,
                        auth_type=method.type,
                        source=f"header:{header_name}",
                        metadata={},
                        consumed_headers={header_name},
                        consumed_query_params=set(),
                        consumed_cookie_names=set(),
                    )
            for query_name in method.query_params:
                value = request.query.get(query_name)
                if value is not None and hmac.compare_digest(str(value), method.token or ""):
                    return AuthenticatedClient(
                        client_slug=client.slug,
                        client_code=client.code,
                        client_title=client.title,
                        auth_method_code=method.code,
                        auth_method_title=method.title,
                        auth_type=method.type,
                        source=f"query:{query_name}",
                        metadata={},
                        consumed_headers=set(),
                        consumed_query_params={query_name},
                        consumed_cookie_names=set(),
                    )
            for cookie_name in method.cookie_names:
                value = cookies.get(cookie_name)
                if value is not None and hmac.compare_digest(value, method.token or ""):
                    return AuthenticatedClient(
                        client_slug=client.slug,
                        client_code=client.code,
                        client_title=client.title,
                        auth_method_code=method.code,
                        auth_method_title=method.title,
                        auth_type=method.type,
                        source=f"cookie:{cookie_name}",
                        metadata={},
                        consumed_headers={"Cookie"},
                        consumed_query_params=set(),
                        consumed_cookie_names={cookie_name},
                    )
            return None

        if method.type == "basic":
            parsed = self._extract_basic_credentials(request.headers)
            if parsed is None:
                return None
            username, password = parsed
            if hmac.compare_digest(username, method.username or "") and hmac.compare_digest(
                password, method.password or ""
            ):
                return AuthenticatedClient(
                    client_slug=client.slug,
                    client_code=client.code,
                    client_title=client.title,
                    auth_method_code=method.code,
                    auth_method_title=method.title,
                    auth_type=method.type,
                    source="authorization:basic",
                    metadata={},
                    consumed_headers={"Authorization"},
                    consumed_query_params=set(),
                    consumed_cookie_names=set(),
                )
            return None

        if method.type == "header_key":
            header_name = method.header_name or ""
            value = self._get_header(request.headers, header_name)
            if value is not None and hmac.compare_digest(value, method.secret or ""):
                return AuthenticatedClient(
                    client_slug=client.slug,
                    client_code=client.code,
                    client_title=client.title,
                    auth_method_code=method.code,
                    auth_method_title=method.title,
                    auth_type=method.type,
                    source=f"header:{header_name}",
                    metadata={},
                    consumed_headers={header_name},
                    consumed_query_params=set(),
                    consumed_cookie_names=set(),
                )
            return None

        if method.type == "oauth_client_credentials":
            token = self._extract_bearer_token(request.headers)
            if token is None:
                return None
            if self._verify_oauth_access_token(client, method, token):
                return AuthenticatedClient(
                    client_slug=client.slug,
                    client_code=client.code,
                    client_title=client.title,
                    auth_method_code=method.code,
                    auth_method_title=method.title,
                    auth_type=method.type,
                    source="authorization:bearer",
                    metadata={},
                    consumed_headers={"Authorization"},
                    consumed_query_params=set(),
                    consumed_cookie_names=set(),
                )
            return None

        if method.type == "external_service":
            return self._match_external_service_auth(
                client=client,
                method=method,
                matched=matched,
                request=request,
            )

        return None

    def _match_external_service_auth(
        self,
        *,
        client: ClientConfig,
        method: AuthMethodConfig,
        matched: MatchedEndpoint,
        request: IncomingRequest,
    ) -> AuthenticatedClient | None:
        request_ctx = {
            "method": request.method,
            "path": request.path,
            "url": request.url,
            "client_ip": request.client_ip,
            "headers": request.headers,
            "query": request.query,
            "body_bytes": request.body,
            "body_text": request.body.decode("utf-8", errors="ignore"),
            "json": request.json_body,
        }
        context = {
            "client": {
                "slug": client.slug,
                "code": client.code,
                "title": client.title,
            },
            "auth": {
                "client_slug": client.slug,
                "client_code": client.code,
                "client_title": client.title,
                "method_code": method.code,
                "method_title": method.title,
                "method_type": method.type,
            },
            "auth_method": {
                "code": method.code,
                "title": method.title,
                "type": method.type,
            },
            "service": {
                "name": matched.service.name,
                "base_url": matched.service.base_url,
            },
            "route": {
                "name": matched.route.name,
                "slug": matched.route.slug,
                "gateway_path": matched.route.gateway_path,
                "strategy": matched.route.strategy,
            },
            "endpoint": {
                "name": matched.endpoint.name,
                "slug": matched.endpoint.slug,
                "gateway_path": matched.route.gateway_path,
                "upstream_path": matched.endpoint.upstream_path,
            },
            "request": request_ctx,
            "request_ctx": request_ctx,
            "path": matched.path_params,
            "query": request.query,
            "headers": request.headers,
        }

        cache_key: str | None = None
        if method.cache_ttl_seconds > 0 and method.cache_key:
            rendered_cache_key = self.render_template(method.cache_key, context)
            cache_key = f"{client.code}:{method.code}:{rendered_cache_key}"
            cached_auth = self._cache.get(f"auth:{cache_key}")
            if cached_auth is not None:
                return cached_auth

        decision: dict[str, Any] = {"result": None}

        def call(http_method: str, url: str, **kwargs: Any) -> requests.Response:
            rendered_url = self.render_template(url, context)
            final_url = str(rendered_url)
            if not final_url.startswith(("http://", "https://")):
                raise ValueError("external_service call() requires an absolute URL.")
            rendered_kwargs = self.render_data(kwargs, context)
            rendered_kwargs.setdefault("timeout", matched.service.timeout_seconds)
            rendered_kwargs.setdefault("allow_redirects", False)
            with requests.Session() as session:
                session.trust_env = matched.service.trust_env_proxy
                return session.request(http_method.upper(), final_url, **rendered_kwargs)

        def allow(
            *,
            source: str = "external_service",
            consumed_headers: list[str] | None = None,
            consumed_query_params: list[str] | None = None,
            consumed_cookie_names: list[str] | None = None,
            metadata: dict[str, Any] | None = None,
        ) -> None:
            decision["result"] = AuthenticatedClient(
                client_slug=client.slug,
                client_code=client.code,
                client_title=client.title,
                auth_method_code=method.code,
                auth_method_title=method.title,
                auth_type=method.type,
                source=source,
                metadata=dict(metadata or {}),
                consumed_headers=set(consumed_headers or []),
                consumed_query_params=set(consumed_query_params or []),
                consumed_cookie_names=set(consumed_cookie_names or []),
            )

        def skip() -> None:
            decision["result"] = None

        def deny(detail: str = "Client authentication failed.", *, status_code: int = 401) -> None:
            raise GatewayError(status_code, detail)

        exec_globals: dict[str, Any] = {
            "__builtins__": __builtins__,
            "call": call,
            "allow": allow,
            "skip": skip,
            "deny": deny,
            "client": context["client"],
            "auth_method": context["auth_method"],
            "service": context["service"],
            "endpoint": context["endpoint"],
            "request_ctx": request_ctx,
            "path": context["path"],
            "query": context["query"],
            "headers": context["headers"],
            "json": json,
            "time": time,
            "datetime": datetime,
            "base64": __import__("base64"),
            "hashlib": __import__("hashlib"),
        }
        exec_locals: dict[str, Any] = {}
        snippet = "def __user_external_auth__():\n"
        for line in (method.script or "").splitlines():
            snippet += f"    {line}\n"
        exec(snippet, exec_globals, exec_locals)
        exec_locals["__user_external_auth__"]()

        result = decision["result"]
        if result is not None and cache_key and method.cache_ttl_seconds > 0:
            self._cache.set(f"auth:{cache_key}", result, method.cache_ttl_seconds)
        return result

    def _extract_bearer_token(self, headers: Mapping[str, Any]) -> str | None:
        header = self._get_header(headers, "Authorization")
        if not header:
            return None
        parts = header.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        return parts[1].strip() or None

    def _extract_basic_credentials(self, headers: Mapping[str, Any]) -> tuple[str, str] | None:
        header = self._get_header(headers, "Authorization")
        if not header:
            return None
        parts = header.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "basic":
            return None
        try:
            decoded = base64.b64decode(parts[1].encode("ascii")).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:  # noqa: BLE001
            return None
        return username, password

    def _get_header(self, headers: Mapping[str, Any], name: str) -> str | None:
        expected = name.lower()
        for key, value in headers.items():
            if key.lower() == expected:
                return str(value)
        return None

    def _parse_cookies(self, headers: Mapping[str, Any]) -> dict[str, str]:
        raw_cookie = self._get_header(headers, "Cookie")
        if not raw_cookie:
            return {}
        cookie = SimpleCookie()
        cookie.load(raw_cookie)
        return {key: morsel.value for key, morsel in cookie.items()}

    def _file_signature(self, path: Path) -> tuple[int, int] | None:
        try:
            stat = path.stat()
        except FileNotFoundError:
            return None
        return stat.st_mtime_ns, stat.st_size

    def _remove_cookie_names(self, raw_cookie: str, names: set[str]) -> str:
        if not raw_cookie:
            return ""
        cookie = SimpleCookie()
        cookie.load(raw_cookie)
        for name in names:
            cookie.pop(name, None)
        parts = [f"{key}={morsel.value}" for key, morsel in cookie.items()]
        return "; ".join(parts)

    def _ip_allowed(self, client_ip: str, allowlist: list[str]) -> bool:
        try:
            address = ipaddress.ip_address(client_ip)
        except ValueError:
            return False

        for entry in allowlist:
            if address in ipaddress.ip_network(entry, strict=False):
                return True
        return False

    def _build_oauth_access_token(
        self,
        client: ClientConfig,
        method: AuthMethodConfig,
        expires_at: int,
    ) -> str:
        if method.type != "oauth_client_credentials":
            raise ValueError("OAuth tokens can only be issued for oauth_client_credentials clients.")

        payload = {
            "type": "oauth_client_credentials",
            "client_code": client.code,
            "auth_method_code": method.code,
            "client_id": method.client_id,
            "exp": expires_at,
        }
        payload_raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload_encoded = self._base64url_encode(payload_raw)
        signature = hmac.new(
            (method.client_secret or "").encode("utf-8"),
            payload_encoded.encode("ascii"),
            "sha256",
        ).digest()
        return f"{payload_encoded}.{self._base64url_encode(signature)}"

    def _verify_oauth_access_token(
        self,
        client: ClientConfig,
        method: AuthMethodConfig,
        token: str,
    ) -> bool:
        if method.type != "oauth_client_credentials":
            return False
        try:
            payload_encoded, signature_encoded = token.split(".", 1)
            payload_raw = self._base64url_decode(payload_encoded)
            payload = json.loads(payload_raw.decode("utf-8"))
            expected_signature = hmac.new(
                (method.client_secret or "").encode("utf-8"),
                payload_encoded.encode("ascii"),
                "sha256",
            ).digest()
        except Exception:  # noqa: BLE001
            return False

        if not hmac.compare_digest(
            self._base64url_encode(expected_signature),
            signature_encoded,
        ):
            return False
        if payload.get("type") != "oauth_client_credentials":
            return False
        if payload.get("client_code") != client.code:
            return False
        if payload.get("auth_method_code") != method.code:
            return False
        if payload.get("client_id") != method.client_id:
            return False
        try:
            expires_at = int(payload.get("exp", 0))
        except (TypeError, ValueError):
            return False
        return expires_at > int(time.time())

    def _base64url_encode(self, value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    def _base64url_decode(self, value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
