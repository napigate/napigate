# AGENTS.md (Project Knowledge Base)

This file stores the working knowledge for the `NapiGate` project so future sessions do not need to rebuild technical context from scratch before making changes.

## 1) Project Scope

- Project path: repo root
- Purpose: a lightweight, config-driven Python API gateway
- Current goals:
  - route incoming gateway paths to one or more configured endpoint targets
  - keep gateway routes separate from upstream endpoint definitions
  - support route strategies for `single`, `round_robin`, `failover`, and `parallel_race`
  - authenticate incoming gateway clients against protected services
  - support multiple auth methods per client
  - scope each client to all services, selected services, or selected endpoints
  - support service-level CORS for browser clients
  - support service-level rate limiting for safer public use
  - support `pre_call` hooks for downstream preparation
  - support `external_service` auth scripts for upstream client validation
  - support reusable output profiles for passthrough, JSON envelope, and JSONP responses
  - support route-level response caching
  - support route-level async success hooks for financial/accounting style callbacks
  - support async request-log forwarding to HTTP JSON sinks or Loki
  - expose simple request monitoring through an HTML table and a JSON endpoint
  - hot-reload config and security files without process restarts
  - rotate file logs daily

## 2) Architecture Decisions

- This project intentionally stays on `stdlib + requests + PyYAML`.
- The HTTP server runs on `ThreadingHTTPServer`.
- Services and endpoints remain config-driven.
- Public gateway exposure is now top-level route-driven:
  - `routes[].gateway_path`
  - `routes[].methods`
  - `routes[].strategy`
  - `routes[].targets[]`
- Endpoints are target definitions only: upstream path, headers, query, `pre_call`, or local `response`.
- Legacy endpoint-local `gateway_path`, `output_profile`, `response_cache`, and `success_hook` are still loaded as single-target routes for migration, but new config and admin saves should write these fields under `routes[]`.
- Client auth is now top-level and cleanly separated:
  - `client`
  - `client.access`
  - `client.auth_methods[]`
- Compatibility for old service-local clients and endpoint auth is intentionally removed.
- `gateway/config.py` raises validation errors if an old config shape is used.

## 3) Important Files

- `gateway/main.py`
  - server entrypoint
  - HTTP handler
  - OAuth token endpoint
  - admin/monitor route dispatch
- `gateway/admin_ops.py`
  - config and security persistence logic used by admin routes
  - keeps mutation logic separate from HTTP parsing/response handling
- `gateway/admin_state.py`
  - serializes config and security data into the admin UI view-model
  - keeps page state assembly separate from template rendering
- `gateway/runtime.py`
  - top-level route matching
  - route target strategy execution
  - client scope resolution
  - multi-method auth matching
  - config hot reload
  - OAuth token issuance and verification
  - `external_service` auth execution
  - output profile transforms
  - response caching
  - async success hooks
  - async log forwarding
  - CORS preflight and response headers
  - rate limiting
  - `pre_call` execution
  - local configured responses
  - upstream proxying
- `gateway/integrations.py`
  - async dispatcher for success hooks and log aggregators
- `gateway/config.py`
  - config loading and validation
  - exposes `GatewayConfig` for single-pass typed loading
  - rejects deprecated config shapes
  - validates client scopes against real services/endpoints
- `gateway/security.py`
  - file-backed users and roles
- `gateway/settings.py`
  - `.env` loading
- `gateway/monitoring.py`
  - SQLite monitor storage
  - hourly retention cleanup when configured
- `gateway/logging_utils.py`
  - daily rotating file logs
  - hourly retention cleanup for rotated files when configured
- `config/services.example.yaml`
  - canonical sample for the current architecture
- `config/services.yaml`
  - local runtime config
  - gitignored
- `config/security.example.yaml`
  - canonical security sample
- `config/security.yaml`
  - local runtime security config
  - gitignored
- `.env.example`
  - Docker and runtime env template
- `.env`
  - local env
  - gitignored

## 4) Security Contract

Main structure:

- `roles.<role_name>.permissions[]`
- `users.<username>.roles[]`
- `users.<username>.enabled`
- `users.<username>.password_hash`

Current permissions:

- `monitor_access`
- `admin_access`
- `services_manage`
- `security_manage`

## 5) Config Contract

Top-level structure:

- `clients[]`
- `routes[]`
- `output_profiles.<profile_slug>`
- `gateway_responses`
- `observability.log_retention_hours`
- `observability.log_aggregators.<sink_code>`
- `services.<service_name>`

### Client Fields

- `slug`
- `code`
- `title`
- `enabled`
- `ip_allowlist[]`
- `access.mode`
- `access.services[]`
- `access.endpoints[]`
- `auth_methods[]`

### Access Modes

- `all`
- `services`
- `endpoints`
- `services` and `endpoints` can temporarily hold empty selections after dependency cleanup; those clients simply match no protected targets until reassigned.

### Endpoint Scope Item

- `service`
- `endpoint`

### Auth Method Fields

Common:

- `code`
- `title`
- `type`
- `enabled`

`api_key`:

- `secret`
- `header_names[]`
- `query_params[]`
- `cookie_names[]`

`bearer`:

- `token`
- `allow_authorization_header`
- `header_names[]`
- `query_params[]`
- `cookie_names[]`

`basic`:

- `username`
- `password`

`header_key`:

- `header_name`
- `secret`

`oauth_client_credentials`:

- `client_id`
- `client_secret`
- `token_ttl_seconds`

`external_service`:

- `script`
- `cache_ttl_seconds`
- `cache_key`

### Service Fields

- `base_url`
- `timeout_seconds`
- `verify_ssl`
- `trust_env_proxy`
- `forward_napigate_headers`
- `variables`
- `headers`
- `pre_call`
- `auth.required`
- `cors`
- `rate_limit`
- `endpoints[]`

### Endpoint Fields

- `name`
- `slug`
- `upstream_path`
- `response`
- `headers`
- `query`
- `pre_call`

- `headers` can also blank out inherited incoming headers for an upstream target by setting a header value to an empty string.

### Route Fields

- `name`
- `slug`
- `methods`
- `gateway_path`
- `strategy`
- `targets[]`
- `pre_call`
- `output_profile`
- `response_cache`
- `success_hook`

### Gateway Response Fields

- `enabled`
- `success_key`
- `data_key`
- `message_key`
- `error_key`
- `empty_value`
- `headers`

### Route Target Fields

- `service`
- `endpoint`

### Route Strategies

- `single`
- `round_robin`
- `failover`
- `parallel_race`
- Routes can temporarily keep an empty `targets[]` list after dependency cleanup; they remain editable in admin but do not match traffic until a target is attached again.

### Output Profile Fields

- `title`
- `enabled`
- `type`
- `success_key`
- `data_key`
- `message_key`
- `error_key`
- `passthrough_keys[]`
- `source_success_key`
- `message_source_keys[]`
- `error_source_keys[]`
- `data_fields`
- `empty_value`
- `jsonp_callback_param`
- `jsonp_default_callback`
- `headers`

### Response Cache Fields

- `enabled`
- `ttl_seconds`
- `vary_by_client`
- `vary_headers[]`
- `methods[]`

### Success Hook Fields

- `enabled`
- `url`
- `timeout_seconds`
- `headers`
- `include_response_body`
- `include_request_body`
- `event_type`

### Log Aggregator Fields

- `type`
- `enabled`
- `url`
- `headers`
- `timeout_seconds`
- `labels`

### Local Response Fields

- `status_code`
- `content_type`
- `body`
- `headers`

### CORS Fields

- `enabled`
- `allow_origins[]`
- `allow_methods[]`
- `allow_headers[]`
- `expose_headers[]`
- `allow_credentials`
- `max_age_seconds`

### Rate Limit Fields

- `enabled`
- `requests`
- `window_seconds`
- `scope`

## 6) `pre_call` Behavior

- `pre_call.code` is trusted Python.
- It can be configured on a service, route, or endpoint.
- Execution order is service `pre_call`, then route `pre_call`, then endpoint `pre_call`.
- Each `pre_call` runs synchronously before proxying or returning a local response.
- Helpers available:
  - `call(method, url, **kwargs)`
  - `set_var(name, value)`
  - `get_var(name, default=None)`
  - `vars`
  - `service`
  - `endpoint`
  - `request_ctx`
  - `path`
  - `query`
  - `headers`
  - `json`
  - `time`
  - `datetime`
  - `base64`
  - `hashlib`
- `pre_call.cache_ttl_seconds` enables in-memory caching of variables changed by that hook.
- `pre_call.cache_key` can override the default key.
- Default cache keys are service-scoped, route-scoped, or endpoint-scoped based on where the hook is configured.

## 6.5) Local Response Behavior

- `response` lets an endpoint return a direct response from NapiGate without calling an upstream.
- If `response` is defined, it is returned after auth and `pre_call`, but before upstream proxying.
- `upstream_path` becomes optional for response-only endpoints.
- `response.body` can be plain text or structured data.
- Structured response bodies are serialized as JSON unless `content_type` overrides that behavior.

## 6.6) CORS Behavior

- `cors` is configured at the service level.
- When enabled, NapiGate adds CORS headers to matching responses.
- Matching `OPTIONS` requests are answered directly by the gateway as preflight responses.
- If `allow_headers` is empty, requested preflight headers are reflected back.
- `allow_credentials: true` should be paired with explicit origins instead of a broad wildcard policy.

## 6.7) Rate Limit Behavior

- `rate_limit` is configured at the service level.
- It uses an in-memory sliding window.
- `scope` can be:
  - `client_or_ip`
  - `client`
  - `ip`
- Rate-limit violations return `429` and include `Retry-After`.

## 6.8) Output Profile Behavior

- `output_profiles` are reusable top-level response contracts.
- Routes opt in through `output_profile`.
- Supported types:
  - `passthrough`
  - `json_envelope`
  - `jsonp`
- `passthrough` returns the upstream or local response body unchanged, while still allowing profile headers to be merged.
- `json_envelope` does not double-wrap payloads that already contain the configured `passthrough_keys`.
- When `json_envelope` builds an envelope, it uses existing response values such as `success`, `data`, `message`, and `error` when present, and falls back to HTTP status, the raw body, inferred messages, or generated errors when they are missing.
- `json_envelope` can also map upstream keys into the standard envelope through `source_success_key`, `message_source_keys`, `error_source_keys`, and `data_fields`; missing or null mapped values become `empty_value`.
- Image and opaque binary responses should usually stay on `passthrough`.
- Deleting a referenced output profile clears dependent route or legacy endpoint `output_profile` values instead of blocking the delete.

## 6.9) Response Cache Behavior

- `response_cache` is configured at the route level.
- It uses an in-memory TTL cache.
- Only successful responses are cached.
- Cache keys include method, path, query, configured vary headers, and optionally the authenticated client slug.

## 6.10) Success Hook Behavior

- `success_hook` is configured at the route level.
- It runs asynchronously after successful responses only.
- It is intended for downstream accounting, billing, metering, or audit callbacks.
- Current implementation uses an in-process async queue worker rather than durable persistence.

## 6.11) Log Aggregator Behavior

- `observability.log_retention_hours` controls log retention when set.
- Leave `observability.log_retention_hours` unset for unlimited retention.
- When set, request log rows in `data/monitor.db` and rotated files under `logs/` older than that many hours are deleted by an hourly cleanup worker.
- Daily file rotation stays enabled regardless of retention.
- `observability.log_aggregators` is top-level.
- Supported sink types:
  - `http_json`
  - `loki`
- Request log delivery is asynchronous and best-effort.

## 6.12) Route Strategy Behavior

- `single` calls exactly one target.
- `round_robin` rotates through targets in memory for each matched request.
- `failover` tries targets in order and moves to the next target when a target is unreachable or returns HTTP 5xx.
- `parallel_race` sends the request to all targets concurrently and returns the first healthy response under HTTP 500.
- Route strategy state is in-process and resets on config reload or process restart.

## 6.13) Gateway Response Behavior

- `gateway_responses` is top-level.
- It shapes public runtime errors generated by NapiGate itself, such as 401, 403, 404, 429, and 5xx responses.
- When disabled, gateway runtime errors keep the default body shape: `{"detail": "..."}`
- When enabled, runtime errors use the configured `success_key`, `data_key`, `message_key`, `error_key`, and `empty_value`.
- `gateway_responses.headers` are merged into those public runtime error responses after the JSON body is rendered.
- Admin and monitor APIs keep their existing JSON contracts and are not affected by this setting.

## 7) Incoming Client Auth Behavior

- Service auth is now only `required: true|false`.
- A protected service accepts any enabled client whose scope matches the current endpoint.
- A client can expose multiple enabled auth methods.
- Supported auth types:
  - `api_key`
  - `bearer`
  - `basic`
  - `header_key`
  - `oauth_client_credentials`
  - `external_service`
- `ip_allowlist` is client-wide.
- Consumed credentials are stripped before upstream forwarding.
- On public routes, if the incoming request still matches a scoped client auth method, those consumed credential headers/query params/cookies are stripped from the upstream request even though client auth is not enforced for access control.
- Runtime injects these headers only when the target service keeps `forward_napigate_headers: true`:
  - `X-NapiGate-Client-Slug`
  - `X-NapiGate-Client-Code`
  - `X-NapiGate-Client-Title`
  - `X-NapiGate-Auth-Method-Code`
  - `X-NapiGate-Auth-Method-Type`
  - `X-NapiGate-Auth-Source`
  - `X-NapiGate-Route-Slug`
  - `X-NapiGate-Endpoint-Slug`

## 8) `external_service` Auth Behavior

- This is trusted Python for validating an incoming request against an external auth service.
- Helpers available:
  - `call(method, url, **kwargs)`
  - `allow(...)`
  - `skip()`
  - `deny(detail, status_code=401)`
  - `client`
  - `auth_method`
  - `service`
  - `endpoint`
  - `request_ctx`
  - `path`
  - `query`
  - `headers`
  - `json`
  - `time`
  - `datetime`
  - `base64`
  - `hashlib`
- `call()` requires an absolute URL.
- `allow()` can attach:
  - `source`
  - `consumed_headers`
  - `consumed_query_params`
  - `consumed_cookie_names`
  - `metadata`
- If the script neither calls `allow()` nor `deny()`, the method behaves like a non-match.

## 9) Template Rendering

- Templates use `{{ ... }}`.
- Useful auth keys:
  - `{{ auth.client_slug }}`
  - `{{ auth.client_code }}`
  - `{{ auth.client_title }}`
  - `{{ auth.method_code }}`
  - `{{ auth.method_title }}`
  - `{{ auth.method_type }}`
  - `{{ auth.source }}`
  - `{{ auth.metadata.subject }}`
- Other common keys:
  - `{{ route.slug }}`
  - `{{ route.gateway_path }}`
  - `{{ route.strategy }}`
  - `{{ endpoint.slug }}`
  - `{{ client.slug }}`
  - `{{ path.id }}`
  - `{{ request.method }}`
  - `{{ vars.access_token }}`

## 10) Monitoring And Logging

- HTML monitor:
  - `GET /__monitor`
- JSON monitor:
  - `GET /__monitor/logs`
- Live stream:
  - `GET /__monitor/stream`
  - when proxied through Nginx or similar reverse proxies, SSE buffering must stay disabled so the live monitor does not remain stuck in a connecting state
- OAuth token endpoint:
  - `POST /__oauth/token`
- Admin config API:
  - `GET /__admin/api/config`
  - `PUT /__admin/api/config`
- Admin client APIs:
  - `GET /__admin/api/clients`
  - `POST /__admin/api/clients`
  - `GET /__admin/api/clients/{slug}`
  - `PUT /__admin/api/clients/{slug}`
  - `DELETE /__admin/api/clients/{slug}`
- Admin output profile APIs:
  - `GET /__admin/api/output-profiles`
  - `POST /__admin/api/output-profiles`
  - `GET /__admin/api/output-profiles/{slug}`
  - `PUT /__admin/api/output-profiles/{slug}`
  - `DELETE /__admin/api/output-profiles/{slug}`
- Admin route form endpoints:
  - `POST /__admin/route/save`
  - `POST /__admin/route/delete`
- Health endpoint:
  - `GET /__health`
- SQLite DB:
  - `data/monitor.db`
- File log:
  - `logs/napigate.log`
- rotation:
  - daily
- retention:
  - unlimited when `observability.log_retention_hours` is unset
  - hourly cleanup of rows and rotated files when `observability.log_retention_hours` is set
- proxied request capture:
  - monitor rows now also persist the final upstream URL and rendered `curl` command after templating, auth stripping, and header/query injection
  - monitor rows also persist the final outgoing response body text shown to the client when it can be decoded as text

## 11) Admin UI Notes

- UI language is English.
- Admin tabs:
  - `Live`
  - `Config`
  - `Services`
  - `Routes`
  - `Output`
  - `Clients`
  - `Users`
  - `Roles`
  - `Logout`
- Live is the first tab.
- Admin tabs update the URL hash, for example `/__admin#output`, without reloading the page.
- Admin modal save/delete actions use AJAX when JavaScript is available, refresh the in-page admin state, and preserve the active tab instead of returning to Live.
- Inactive tabs are dark with white text by design.
- Monitor and admin Live tables now show `Status` plus a `Response` column for each request row.
- Monitor and admin Live views now expose the final upstream URL plus a copyable rendered `cURL` for proxied requests.
- Client forms support:
  - slug, title, and code
  - title and code
  - enabled toggle
  - IP allowlist
  - minimal checkbox-based service/endpoint scope selection
  - multiple auth methods
  - generated credentials from the UI
- OAuth methods can request live tokens from the UI.
- Services and endpoints remain modal-based CRUD.
- Routes have their own tab and modal CRUD.
- Config has its own tab for gateway-wide operational settings.
- Config now also exposes gateway-generated response envelope settings for public runtime errors.
- Route and endpoint `Copy cURL` actions open a modal first so the admin can generate a request without auth or choose a client plus auth method before copying the command.
- Endpoint forms define target behavior only; gateway path, method exposure, output profile, response cache, and success hook are configured from route forms.
- Output profiles now have their own tab and modal CRUD.
- Output profile forms show response shaping as pseudo-code instead of raw success/data/message/error key inputs; `passthrough` is the raw unmodified-output mode.
- Admin forms now include inline tooltip help and examples for the visible input fields.
- Admin modal forms include client-side validation for required fields, numbers, URLs, identifiers, obvious browser-markup injection, JSONP callback names, and output-profile pseudo-code key safety; server-side validation also rejects unsafe output envelope keys and JSONP callback values.
- Endpoint forms now also expose:
  - slug
- Endpoint forms still preserve existing local `response` blocks, but direct-response editing remains config-first rather than fully modeled in the admin form.

## 12) Running The Project

Main command:

```bash
cp config/services.example.yaml config/services.yaml
cp config/security.example.yaml config/security.yaml
python3 -m gateway.main --host 0.0.0.0 --port 8000 --config config/services.yaml
```

Docker:

```bash
cp .env.example .env
cp config/services.example.yaml config/services.yaml
cp config/security.example.yaml config/security.yaml
docker compose pull
docker compose up -d
```

- `docker-compose.yml` runs `NAPIGATE_IMAGE` and does not build during normal startup.
- `docker-compose.build.yml` is the explicit local build/publish override.
- Manual Docker Hub publish:
  - `docker login`
  - `NAPIGATE_IMAGE=your-dockerhub-username/napigate:0.1.0 docker compose -f docker-compose.yml -f docker-compose.build.yml build app`
  - `NAPIGATE_IMAGE=your-dockerhub-username/napigate:0.1.0 docker compose -f docker-compose.yml -f docker-compose.build.yml push app`
- GitHub Actions workflow `.github/workflows/docker-image.yml` publishes `napigate/napigate:latest` from `main` and semantic version tags from `v*.*.*` tags when `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` secrets are configured; change workflow `IMAGE_NAME` if the Docker Hub namespace is different.
- Compose mounts:
  - `./config:/code/config`
  - `./data:/code/data`
  - `./logs:/code/logs`
- Runtime and security config changes are hot-reloaded from those mounted files without restarting the container.

If dependencies are missing:

```bash
pip install requests pyyaml
```

## 13) Important Operational Notes

- `trust_env_proxy` defaults to `false`.
- `config/services.yaml` must stay local.
- `.env` must stay local.
- `NAPIGATE_IMAGE` selects the runtime image for Compose.
- `NAPIGATE_PULL_POLICY` controls whether Compose pulls the runtime image.
- `observability.log_retention_hours` controls hourly cleanup of monitor rows and rotated file logs; leave it unset for unlimited retention.
- `forward_napigate_headers` defaults to `true`.
- `gateway_responses` defaults to the disabled `{"detail": ...}` runtime error shape until enabled in config.
- Shared template changes go to `config/services.example.yaml`.
- `config/services.yaml` and `config/security.yaml` are reloaded automatically when their on-disk contents change.
- Container runtime user settings come from `.env`:
  - `UID`
  - `GID`
  - `CURRENT_USER`
  - `CURRENT_GROUP`
- Container image build user settings come from `.env` when using `docker-compose.build.yml`:
  - `NAPIGATE_IMAGE_UID`
  - `NAPIGATE_IMAGE_GID`
  - `NAPIGATE_IMAGE_USER`
  - `NAPIGATE_IMAGE_GROUP`
- `NAPIGATE_ADMIN_USERNAME` and `NAPIGATE_ADMIN_PASSWORD` protect both monitor and admin pages.
- `NAPIGATE_ADMIN_ACCESS_WHITELIST_IPS` restricts `/__admin` UI and admin API requests to comma-separated IP/CIDR ranges when set.
- `NAPIGATE_SECURITY_CONFIG` can override the default security file path.
- Default mirrors:
  - `DEBIAN_MIRROR_URL=https://deb.debian.org/debian`
  - `DEBIAN_SECURITY_MIRROR_URL=https://security.debian.org/debian-security`
  - `PIP_INDEX_URL=https://pypi.org/simple`
- Request and response bodies are still buffered in memory.
- YAML remains appropriate for gateway config objects, but it is not meant to be an application end-user database.

## 14) Current State And Verification

- 2026-04-23: initial gateway implementation was created.
- 2026-04-23: Dockerfile and docker-compose were added and runtime user settings became configurable through `.env`.
- 2026-04-23: monitor became live, admin/monitor auth was added through `.env`, and an admin UI for managing services/endpoints was added.
- 2026-04-25: admin UI was upgraded to a tabbed layout with tables and modal CRUD.
- 2026-04-25: client auth was redesigned around:
  - top-level client list
  - `title` and `code`
  - `access` scope
  - multiple auth methods
  - `external_service`
  - OAuth token issuance
- 2026-04-25: code structure was standardized further:
  - `gateway/config.py` now exposes `GatewayConfig` and performs single-pass config loading
  - `gateway/admin_ops.py` now owns admin-side config/security mutations
  - package metadata now includes a console script entrypoint: `napigate`
- 2026-04-26: endpoints gained an optional `response` block for direct local replies such as plain `ok` health/status samples.
- 2026-04-26: services gained:
  - hot-reloaded config/security files
  - service-level `cors`
  - service-level `rate_limit`
  - admin input tooltips with examples
- 2026-04-26: gateway config and admin APIs gained:
  - client `slug`
  - endpoint `slug`
  - top-level `output_profiles`
  - endpoint `response_cache`
  - endpoint `success_hook`
  - top-level `observability.log_aggregators`
  - `/__admin/api/config`
  - `/__admin/api/clients/{slug}`
  - `/__admin/api/output-profiles/{slug}`
  - `NAPIGATE_ADMIN_ACCESS_WHITELIST_IPS`
- 2026-04-26: gateway routes were separated from endpoint targets:
  - top-level `routes[]`
  - route targets connected to service endpoints
  - route strategies for `single`, `round_robin`, `failover`, and `parallel_race`
  - route-level `output_profile`
  - route-level `response_cache`
  - route-level `success_hook`
  - admin `Routes` tab
- 2026-04-27: Docker runtime and image publishing were separated:
  - `docker-compose.yml` now runs `NAPIGATE_IMAGE`
  - `docker-compose.build.yml` owns local image builds
  - `.github/workflows/docker-image.yml` publishes to Docker Hub when Docker Hub secrets are configured
- 2026-04-27: `json_envelope` output profiles gained source-key mapping for upstream payloads:
  - `source_success_key`
  - `message_source_keys`
  - `error_source_keys`
  - `data_fields`
  - `empty_value`
- 2026-04-27: `pre_call` became available at service, route, and endpoint levels and now runs in that order.
- 2026-04-28: admin deletes now clear dependent client scopes, route targets, and output-profile references instead of failing on those dependencies; empty scoped clients or targetless routes are preserved until reassigned.
- 2026-04-28: admin and monitor log tables gained a `Response` column backed by the final outgoing response body, and the admin panel gained a `Config` tab with `observability.log_retention_hours` so monitor rows and rotated file logs can be kept indefinitely or cleaned hourly after a configured number of hours.
- 2026-04-28: monitor storage and Live views now capture the final outgoing upstream `curl` command, including rendered URL, headers, and request body when a proxied call is actually sent.
- 2026-04-28: gateway-wide `gateway_responses` settings were added under Config so public runtime errors can keep the default detail shape or switch to a configurable JSON envelope with custom keys, empty values, and headers.
- Verified locally:
  - `python3 -m compileall gateway`
  - `python3 -m py_compile gateway/*.py`
  - `docker compose config`
  - config load for `config/services.example.yaml`
  - config load for `config/services.yaml`
  - runtime smoke test for:
    - CORS preflight
    - `api_key`
    - `bearer`
    - `header_key`
    - `oauth_client_credentials`
    - `external_service`
    - direct `response` endpoints
    - rate limiting
    - config hot reload
    - client scope filtering
    - output profile envelope rendering
    - response cache hit behavior
    - output profile source-key mapping behavior
    - route config loading from `config/services.example.yaml`
    - route strategy smoke test for `single`, `round_robin`, `failover`, and `parallel_race`

## 15) Maintenance Rule For Future Sessions

- Read this file before making changes.
- If architecture, config contract, monitor endpoints, logging behavior, Docker defaults, auth model, or `pre_call` behavior changes, update this file in the same task.
- Core design principles:
  - service definitions stay in config
  - clients are top-level and explicit
  - auth methods stay attached to the client
  - custom trusted hooks stay inside `pre_call.code` or `external_service.script`
  - runtime stays lightweight and dependency-minimal
