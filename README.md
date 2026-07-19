# NapiGate

NapiGate is a lightweight, config-driven Python API gateway built for small and mid-sized internal integrations. It keeps the stack intentionally small, routes HTTP requests to HTTP or gRPC upstream services, authenticates gateway clients, supports trusted inline hooks, and exposes a simple built-in admin and monitoring UI.

## Highlights

- YAML-defined services, endpoint targets, and gateway routes
- HTTP ingress with an APISIX-inspired protocol catalog; HTTP ingress plus HTTP and gRPC unary upstream execution are supported today
- route strategies for `single`, `round_robin`, `failover`, and `parallel_race`
- reusable output profiles for passthrough, JSON envelope, and JSONP responses — selectable at route or endpoint level
- Top-level client model with scoped access
- stable client and endpoint slugs for admin APIs and external automation
- Multiple auth methods per client
- Trusted `pre_call` hooks for downstream preparation
- Trusted `external_service` auth scripts for custom validation
- route response caching and async success hooks
- optional structured request-log forwarding to HTTP JSON sinks or Loki
- Built-in monitor UI, JSON logs endpoint, and live stream
- file-backed or Postgres-backed config and security state with in-memory runtime snapshots
- Daily rotating file logs with optional hourly retention cleanup
- Bounded thread pool (`NAPIGATE_MAX_WORKERS`) instead of unbounded per-connection threads
- Streaming proxy for responses that need no body transformation — memory footprint stays flat for large payloads
- Optional Redis backend for distributed rate limiting and response caching; falls back to in-memory automatically
- Minimal dependency footprint: `stdlib + requests + PyYAML` with optional extras for Redis, PostgreSQL, and gRPC

## Why This Project

NapiGate is designed for teams that need an API gateway without adopting a large platform or a complex control plane. The project favors:

- explicit configuration over convention-heavy abstractions
- predictable runtime behavior over plugin sprawl
- easy local deployment over cluster-first assumptions
- readable Python over framework lock-in

## Architecture

The codebase is split into a few focused modules:

- [`gateway/config.py`](gateway/config.py): typed config loading, validation, and route compilation
- [`gateway/runtime.py`](gateway/runtime.py): request matching, client auth, rate limiting, CORS handling, token issuance, output transforms, response caching, async success hooks, config hot-reload, and upstream execution
- [`gateway/grpc_support.py`](gateway/grpc_support.py): optional dynamic gRPC invocation through server reflection or descriptor-set files
- [`gateway/cache.py`](gateway/cache.py): pluggable cache and rate-limit backends — in-memory (default) or Redis
- [`gateway/admin_ops.py`](gateway/admin_ops.py): config and security mutations used by the admin UI
- [`gateway/state_store.py`](gateway/state_store.py): file or Postgres-backed config/security persistence plus admin audit logs
- [`gateway/security.py`](gateway/security.py): users, roles, password hashing, and authorization checks
- [`gateway/monitoring.py`](gateway/monitoring.py): SQLite-backed request log storage and retention cleanup
- [`gateway/logging_utils.py`](gateway/logging_utils.py): daily rotating file logging and retention cleanup
- [`gateway/settings.py`](gateway/settings.py): `.env` loading and runtime settings
- [`gateway/main.py`](gateway/main.py): HTTP server, admin/monitor endpoints, and CLI entrypoint

Runtime and security state are always served from memory. In file mode the process watches local YAML revisions. In Postgres mode the process loads config and security documents into RAM, persists admin mutations transactionally into dedicated tables for services, endpoints, routes, clients, output profiles, users, and roles, and refreshes only when the stored revision changes. Request handling never reads config from the database on the hot path.

The runtime uses a bounded thread pool (`PooledHTTPServer`) and keeps the gateway model intentionally simple:

1. Match the incoming request to a configured endpoint.
2. Enforce service protection and client scope.
3. Authenticate the client using one of its enabled auth methods.
4. Enforce service-level rate limits when configured.
5. Check endpoint response cache when configured.
6. Run `pre_call` if defined.
7. Render templates, optionally return a local configured response, otherwise execute the configured upstream transport.
8. Apply output shaping, response caching, async success hooks, CORS headers, and monitoring/logging records.

## Project Layout

```text
.
├── config/
│   ├── security.example.yaml
│   └── services.example.yaml
├── gateway/
│   ├── admin_ops.py
│   ├── cache.py
│   ├── config.py
│   ├── logging_utils.py
│   ├── main.py
│   ├── monitoring.py
│   ├── runtime.py
│   ├── security.py
│   ├── state_store.py
│   └── settings.py
├── Dockerfile
├── docker-compose.build.yml
├── docker-compose.yml
├── .github/workflows/docker-image.yml
└── pyproject.toml
```

## Requirements

- Python `3.12+`
- `requests`
- `PyYAML`

Install locally:

```bash
pip install .
```

To enable Redis-backed rate limiting and caching, install the optional extra:

```bash
pip install ".[redis]"
```

To enable the optional Postgres-backed state store:

```bash
pip install ".[postgres]"
```

To enable gRPC upstream support outside the Docker image:

```bash
pip install ".[grpc]"
```

Or install dependencies without packaging:

```bash
pip install requests pyyaml
# optional Redis support:
pip install "redis[hiredis]"
# optional Postgres state store:
pip install "psycopg[binary]"
# optional gRPC upstream support:
pip install grpcio grpcio-reflection protobuf
```

The package also exposes a console entrypoint after installation:

```bash
napigate --host 0.0.0.0 --port 8000 --admin-port 8001 --config config/services.yaml --security-config config/security.yaml
```

## Quick Start

1. Create local runtime files:

```bash
cp config/services.example.yaml config/services.yaml
cp config/security.example.yaml config/security.yaml
```

2. Run the gateway:

```bash
python3 -m gateway.main \
  --host 0.0.0.0 \
  --port 8000 \
  --admin-host 0.0.0.0 \
  --admin-port 8001 \
  --config config/services.yaml \
  --security-config config/security.yaml
```

3. Open the built-in surfaces:

- Public health: `http://127.0.0.1:8000/__health`
- Public OAuth token endpoint: `http://127.0.0.1:8000/__oauth/token`
- Admin login: `http://127.0.0.1:8001/__login`
- Admin UI: `http://127.0.0.1:8001/__admin`
- Monitor HTML: `http://127.0.0.1:8001/__monitor`
- Monitor JSON: `http://127.0.0.1:8001/__monitor/logs`
- Monitor 24h report JSON: `http://127.0.0.1:8001/__monitor/report?hours=24&bucket_minutes=60&timezone_offset_minutes=210`
- Live stream: `http://127.0.0.1:8001/__monitor/stream`

`/__login`, `/__admin`, `/__monitor`, and `/__logout` are intentionally unavailable on the public listener so they can be isolated with firewall rules or a separate reverse-proxy policy.

## gRPC Upstreams

NapiGate keeps HTTP on the ingress side, then executes the matched target through the service transport. For gRPC, set the service `protocol` to `grpc`, point `target` at the upstream authority, and define each endpoint method through `grpc.full_method` or the existing `upstream_path` field.

```yaml
routes:
  - name: hello_grpc
    slug: hello-grpc
    methods: [POST]
    gateway_path: /demo/grpc/hello
    strategy: single
    targets:
      - service: greeter_grpc
        endpoint: say_hello

services:
  greeter_grpc:
    protocol: grpc
    target: localhost:50051
    grpc:
      use_tls: false
      use_reflection: true
    endpoints:
      - name: say_hello
        slug: say-hello
        grpc:
          full_method: /helloworld.Greeter/SayHello
          request_body:
            name: "{{ request.json.name }}"
```

Then call the public route with normal HTTP JSON:

```bash
curl -X POST http://127.0.0.1:8000/demo/grpc/hello \
  -H 'Content-Type: application/json' \
  -d '{"name":"Mohsen"}'
```

Notes:

- `service.grpc.use_reflection: true` works when the upstream gRPC server exposes reflection.
- If reflection is disabled, set `service.grpc.descriptor_set_path` to a compiled `.protoset` file that is reachable from the gateway container or process.
- If `endpoint.grpc.request_body` is omitted, NapiGate forwards the incoming JSON body as the protobuf request message.
- Service and endpoint header mappings become gRPC metadata after template rendering and auth stripping.

## Protocol Catalog

NapiGate now keeps protocol types explicit on both services and routes so the config and admin UI can describe more than plain HTTP.

- Service protocol choices: `http`, `grpc`, `websocket`, `grpc_web`, `http3`, `tcp`, `udp`
- Route protocol choices: `http`, `websocket`, `grpc`, `grpc_web`, `http3`
- Runtime implemented today:
  - route `http` -> service `http`
  - route `http` -> service `grpc`
- Declared but not executed yet:
  - `websocket`
  - `grpc` ingress
  - `grpc_web`
  - `http3`
  - `tcp`
  - `udp`

When a declared-but-unimplemented protocol is matched, NapiGate returns `501` with a direct message instead of silently falling back to HTTP behavior.

### Nginx Reverse Proxy

If you proxy NapiGate through Nginx, keep SSE buffering disabled for `__monitor/stream`, otherwise the live monitor can appear stuck in a connecting state even though direct access works. With the default listener split, public traffic points at port `8000` and admin/monitor traffic points at port `8001`.

If you want the request monitor and audit log to show the real client IP instead of the proxy/container IP, add those Nginx or ingress addresses to `observability.trusted_proxy_ips` in `config/services.yaml`.

Example:

```nginx
server {
    listen 80;
    server_name gateway.example.com;

    location /__monitor/stream {
        proxy_pass http://127.0.0.1:8001/__monitor/stream;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1h;
        chunked_transfer_encoding off;
    }

    location /__monitor/ {
        proxy_pass http://127.0.0.1:8001;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_read_timeout 300s;
    }

    location /__admin {
        proxy_pass http://127.0.0.1:8001;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_read_timeout 300s;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
        proxy_read_timeout 300s;
    }
}
```

## Docker

1. Prepare local files:

```bash
cp .env.example .env
cp config/services.example.yaml config/services.yaml
cp config/security.example.yaml config/security.yaml
```

2. Start the container:

```bash
docker compose pull
docker compose up -d
```

The default listener ports are controlled by `APP_PORT` and `ADMIN_PORT` in `.env`.
`docker-compose.yml` runs the published image from `NAPIGATE_IMAGE` and does not build from the local Dockerfile during normal startup.
The public listener uses `APP_PORT` and the separate admin/monitor listener uses `ADMIN_PORT`.
The published Docker image already includes the optional Redis, Postgres, and gRPC dependencies.

Compose mounts `config/`, `data/`, and `logs/` into the container. Changes to `config/services.yaml` and `config/security.yaml` are detected automatically by the running process, so Docker restart cycles are not required for routine config edits.

To bring up the optional Postgres sidecar as well:

```bash
docker compose --profile postgres up -d
```

Then switch the app to the Postgres state store in `.env`:

```dotenv
NAPIGATE_STATE_STORE=postgres
NAPIGATE_POSTGRES_DSN=postgresql://napigate:napigate@postgres:5432/napigate
```

### Docker Hub Image

The default image is `napigate/napigate:latest`. Override it in `.env` when publishing under another Docker Hub namespace or when pinning a release:

```dotenv
NAPIGATE_IMAGE=your-dockerhub-username/napigate:0.1.2
NAPIGATE_PULL_POLICY=missing
```

Build and push a release image explicitly with the build override:

```bash
docker login
NAPIGATE_IMAGE=your-dockerhub-username/napigate:0.1.2 docker compose -f docker-compose.yml -f docker-compose.build.yml build app
NAPIGATE_IMAGE=your-dockerhub-username/napigate:0.1.2 docker compose -f docker-compose.yml -f docker-compose.build.yml push app
```

For automated publishing, configure the GitHub repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. The workflow in `.github/workflows/docker-image.yml` pushes `napigate/napigate:latest` from `main` and version tags from `v*.*.*` tags; change `IMAGE_NAME` in that workflow if the Docker Hub namespace is different.

### Important `.env` Variables

See [`.env.example`](.env.example) for the full template.

- `NAPIGATE_IMAGE`
- `NAPIGATE_PULL_POLICY`
- `NAPIGATE_IMAGE_USER`
- `NAPIGATE_IMAGE_GROUP`
- `NAPIGATE_IMAGE_UID`
- `NAPIGATE_IMAGE_GID`
- `APP_PORT`
- `ADMIN_PORT`
- `APP_TIMEZONE`
- `NAPIGATE_CONFIG`
- `NAPIGATE_SECURITY_CONFIG`
- `NAPIGATE_STATE_STORE`
- `NAPIGATE_POSTGRES_DSN`
- `NAPIGATE_STATE_SYNC_INTERVAL_SECONDS`
- `NAPIGATE_ADMIN_USERNAME`
- `NAPIGATE_ADMIN_PASSWORD`
- `NAPIGATE_ADMIN_ACCESS_WHITELIST_IPS`
- `NAPIGATE_REDIS_URL`
- `NAPIGATE_MAX_WORKERS`
- `POSTGRES_DB`
- `POSTGRES_USER`
- `POSTGRES_PASSWORD`
- `UID`
- `GID`
- `CURRENT_USER`
- `CURRENT_GROUP`
- `DEBIAN_MIRROR_URL`
- `DEBIAN_SECURITY_MIRROR_URL`
- `PIP_INDEX_URL`

## Configuration Model

Sample files:

- Services: [`config/services.example.yaml`](config/services.example.yaml)
- Security: [`config/security.example.yaml`](config/security.example.yaml)

Runtime-local files are intentionally gitignored:

- `config/services.yaml`
- `config/security.yaml`
- `.env`

### Top-Level Shape

```yaml
clients:
  - ...

output_profiles:
  profile_slug:
    ...

gateway_responses:
  mode: profile
  output_profile: custom_contract
  headers:
    Cache-Control: no-store

routes:
  - ...

observability:
  log_retention_hours: 168
  log_aggregators:
    sink_code:
      ...

services:
  service_name:
    ...
```

### Clients

Clients are top-level and define both authentication and access scope.

```yaml
clients:
  - slug: demo-portal
    code: demo_portal
    title: Demo Portal
    enabled: true
    ip_allowlist:
      - 127.0.0.1/32
    access:
      mode: services
      services:
        - protected_httpbin
    auth_methods:
      - code: portal_api_key
        title: Primary API Key
        type: api_key
        secret: demo-api-key
        header_names:
          - X-API-Key
```

Client fields:

- `slug`
- `code`
- `title`
- `enabled`
- `ip_allowlist[]`
- `access.mode`
- `access.services[]`
- `access.endpoints[]`
- `auth_methods[]`

Access modes:

- `all`
- `services`
- `endpoints`

`services` and `endpoints` scopes may be left empty after admin-side dependency cleanup. In that state the client remains saved, but it will not match protected targets until you assign new scope entries.

### Supported Auth Methods

- `api_key`
- `bearer`
- `basic`
- `header_key`
- `oauth_client_credentials`
- `external_service`

Method-specific fields:

- `api_key`: `secret`, `header_names[]`, `query_params[]`, `cookie_names[]`
- `bearer`: `token`, `allow_authorization_header`, `header_names[]`, `query_params[]`, `cookie_names[]`
- `basic`: `username`, `password`
- `header_key`: `header_name`, `secret`
- `oauth_client_credentials`: `client_id`, `client_secret`, `token_ttl_seconds`
- `external_service`: `script`, `cache_ttl_seconds`, `cache_key`

### Services, Endpoints, And Routes

Services remain fully config-driven:

- `base_url`
- `timeout_seconds`
- `verify_ssl`
- `trust_env_proxy`
- `forward_napigate_headers`
- `variables`
- `headers`
- `pre_call`
- `cors`
- `rate_limit`
- `response_cache`
- `endpoints[]`

Endpoint fields:

- `name`
- `slug`
- `upstream_path`
- `response`
- `headers`
- `query`
- `pre_call`
- `output_profile`
- `response_cache`

Route fields:

- `name`
- `slug`
- `methods`
- `gateway_path`
- `strategy`
- `targets[]`
- `auth.required`
- `pre_call`
- `output_profile`
- `response_cache`
- `success_hook`

Route strategies:

- `single`
- `round_robin`
- `failover`
- `parallel_race`

Routes may temporarily keep an empty `targets[]` list after admin-side cleanup. Those routes stay editable in the admin UI, but they will not match traffic until a target is attached again.

`response` can be used for direct gateway replies without an upstream call:

```yaml
routes:
  - name: status_ok
    slug: status-ok
    methods: [GET]
    gateway_path: /demo/status
    strategy: single
    targets:
      - service: status
        endpoint: status_ok

services:
  status:
    base_url: https://example.invalid
    endpoints:
      - name: status_ok
        response:
          status_code: 200
          content_type: text/plain; charset=utf-8
          body: ok
```

`response` fields:

- `status_code`
- `content_type`
- `body`
- `headers`

Important contract notes:

- `auth.required` is route-level.
- If `response` is defined, NapiGate returns it before any upstream proxy call.
- `output_profile` can be set at route level or endpoint level. Endpoint output is shaped first, then the route output profile runs on that result when a route profile is set.
- `response_cache` can be configured at endpoint, service, or route level. Runtime checks endpoint first, then service, then route, and only stores successful responses for configured methods.
- `success_hook` is route-level, async, and fires only after successful responses.
- Legacy endpoint-local `gateway_path` and `success_hook` still load as single-target routes for migration, but new config should use `routes[]`.
- Old service-local clients are rejected during validation.
- Old endpoint-level auth is rejected during validation.
- Existing service-level auth flags still act as a fallback for older route definitions until those routes are resaved with explicit route auth.
- Protected routes must be reachable by at least one enabled client scope.

### Output Profiles

Output profiles are top-level reusable response contracts. Routes can opt into one profile by slug.

Supported profile types:

- `passthrough`
- `json_envelope`
- `jsonp`
- `custom`

Common output profile fields:

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
- `transform_code`
- `custom_validation.mode`
- `custom_validation.source_key`
- `custom_validation.expected_value`
- `custom_validation.error_source_keys[]`
- `headers`

`json_envelope` behavior:

- If the upstream JSON already contains the configured `passthrough_keys`, NapiGate does not wrap it again.
- Otherwise, the payload is placed into `data_key`.
- `source_success_key`, `message_source_keys`, `error_source_keys`, and `data_fields` can map an upstream response into a stable envelope such as `success`, `message`, `data`, and `error`.
- `data_fields` values can be plain source paths such as `payload.user` or `{{field}}` templates such as `{{Name}} {{family}}`.
- Missing or null mapped values use `empty_value`.
- Non-JSON binary/image responses should normally stay on `passthrough`.

`custom` behavior:

- `transform_code` is a safe Python-like snippet that must assign the final response body to `result`.
- `custom_validation` can declare whether success is detected from `status_code` or from a payload key such as `IsSuccessful`, what value should count as success, and which payload keys should be checked for an error message such as `ErrorDesc`.
- Available input names are `payload`, `status_code`, `detail`, `validation`, `empty_value`, `content_type`, `headers`, and `query`.
- `validation` is a mapping with `mode`, `key`, `expected`, `actual`, `ok`, `error`, and `status_code`, computed before your custom code runs.
- Safe helpers include `pick()`, `pick_first()`, `exists()`, `success()`, `text()`, `len()`, `bool()`, `int()`, `float()`, and `str()`.
- Allowed syntax is intentionally narrow: assignments, `if/else`, literals, indexing, boolean/comparison expressions, and safe helper calls.
- Imports, arbitrary builtins, attribute access, and unsafe calls are rejected during validation.

Example custom profile:

```yaml
output_profiles:
  custom_contract:
    title: Custom Safe Transform
    enabled: true
    type: custom
    custom_validation:
      mode: payload_key
      source_key: IsSuccessful
      expected_value: true
      error_source_keys:
        - ErrorDesc
        - WarningDesc
    transform_code: |
      if not validation["ok"]:
          result = {
              "success": False,
              "message": "",
              "data": empty_value,
              "error": validation["error"],
          }
      else:
          result = {
              "success": True,
              "message": "",
              "data": {
                  "name": text(pick("Name")) + " " + text(pick("LastName")),
              },
              "error": "",
          }
```

Admin workflow:

1. Open `Output` in the admin UI.
2. Create or edit a profile and set `Profile Type` to `custom`.
3. Write `transform_code` so the final body is assigned to `result`.
4. Save the profile, then attach it to a route or select it from `Config > Gateway Response Output`.

### Gateway-Generated Error Responses

`gateway_responses` controls the JSON body used when NapiGate itself generates a public runtime error such as:

- `401` client authentication failure
- `403` gateway-side access or origin denial
- `404` no matching route
- `429` rate limit rejection
- `5xx` internal or upstream gateway failures

Example:

```yaml
gateway_responses:
  mode: profile
  output_profile: custom_contract
  enabled: true
  headers:
    Cache-Control: no-store
```

Behavior:

- `mode: default` keeps the default body shape: `{"detail": "..."}`
- `mode: inline` uses the legacy inline envelope fields in `gateway_responses`, such as `success_key`, `data_key`, `message_key`, `error_key`, and `empty_value`
- `mode: profile` builds a gateway error payload with `detail`, `message`, `error`, `status_code`, and `status`, then runs the selected `output_profile` against that payload
- when `mode: profile`, `output_profile` must reference an existing top-level output profile
- `headers` are merged into gateway-generated public error responses after the JSON body is rendered
- this setting is for public runtime responses, not admin or monitor API endpoints

Recommended admin flow:

1. Open `Output` and create the reusable profile first. A `custom` profile is the best fit when you want a fully controlled contract.
2. Open `Config > Gateway Response Output`.
3. Set `Gateway Response Mode` to `selected output profile`.
4. Choose the profile from `Gateway Error Output Profile`.
5. Save settings. From that point on, gateway-generated public errors will pass through the selected profile.

### Response Caching

Response caching can be configured on an endpoint, a service, or a route. Runtime resolves it in that order: endpoint, then service, then route. The cache uses a TTL store — in-memory by default, Redis when `NAPIGATE_REDIS_URL` is set. The Redis backend uses `SETEX` with pickle serialization and the key prefix `napigate:cache:`. Rate-limit state uses `napigate:rl:`. Both namespaces are isolated from any other keys in the same Redis instance. Admins with `services_manage` can clear all gateway cache entries from `__admin#config`; this clears response, pre-call, and external-auth cache entries, but does not reset rate-limit state.

When an incoming request contains the `X-Bypass-Cache` header, NapiGate skips the response-cache lookup and executes the configured target. The header name is case-insensitive and its value is ignored. NapiGate forwards the header to the upstream, and a successful fresh response is stored normally so it refreshes the matching cache entry.

```yaml
response_cache:
  enabled: true
  ttl_seconds: 60
  vary_by_client: true
  vary_headers:
    - Accept-Language
  methods:
    - GET
```

`response_cache` fields:

- `enabled`
- `ttl_seconds`
- `vary_by_client`
- `vary_headers[]`
- `methods[]`

### Async Success Hooks

Routes can publish a best-effort async event after successful responses:

```yaml
success_hook:
  enabled: true
  url: https://billing.example.com/hooks/usage
  timeout_seconds: 5
  event_type: financial
  headers:
    X-NapiGate-Signature: demo
```

`success_hook` fields:

- `enabled`
- `url`
- `timeout_seconds`
- `event_type`
- `headers`
- `include_request_body`
- `include_response_body`

### Log Aggregators

`observability` can hold both log retention and async forwarding settings.

`log_retention_hours` behavior:

- leave it unset or blank for unlimited retention
- when set, request log rows in `data/monitor.db` and rotated file logs under `logs/` older than that many hours are deleted by an hourly cleanup worker
- daily file rotation stays enabled regardless of retention

Request logs can also be forwarded asynchronously through `observability.log_aggregators`.

Supported sink types:

- `http_json`
- `loki`

### CORS

Service-level CORS enables browser access and automatic preflight responses:

```yaml
cors:
  enabled: true
  allow_origins:
    - https://app.example.com
  allow_methods:
    - GET
    - POST
  allow_headers:
    - Authorization
    - Content-Type
  expose_headers:
    - X-Request-ID
  allow_credentials: true
  max_age_seconds: 600
```

`cors` fields:

- `enabled`
- `allow_origins`
- `allow_methods`
- `allow_headers`
- `expose_headers`
- `allow_credentials`
- `max_age_seconds`

### Rate Limiting

Service-level rate limiting uses a sliding window. With no Redis configured it runs in-memory; set `NAPIGATE_REDIS_URL` to share state across multiple instances using a Redis sorted-set Lua script:

```yaml
rate_limit:
  enabled: true
  requests: 120
  window_seconds: 60
  scope: client_or_ip
```

`rate_limit` fields:

- `enabled`
- `requests`
- `window_seconds`
- `scope`

Allowed `scope` values:

- `client_or_ip`
- `client`
- `ip`

## Trusted Hook Model

### `pre_call`

`pre_call.code` is trusted Python executed synchronously before the upstream request. It can be defined on a service, route, or endpoint, and NapiGate runs those hooks in service, route, endpoint order.

Helpers available:

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

Caching:

- `pre_call.cache_ttl_seconds`
- `pre_call.cache_key`

The cache stores variables changed by that specific hook. If `cache_key` is omitted, NapiGate uses a default key scoped to the service, route, or endpoint that owns the hook.

Admin delete actions clear dependent client scopes, route targets, and output-profile references instead of blocking the delete on those cross-references.

### `external_service`

`external_service.script` is trusted Python for custom client validation.

Helpers available:

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

If the script neither calls `allow()` nor `deny()`, the auth method behaves like a non-match.

## Template Rendering

Templates use `{{ ... }}` and can be used in upstream paths, headers, query params, and other config-driven values.

Common variables:

- `{{ auth.client_code }}`
- `{{ auth.client_title }}`
- `{{ auth.method_code }}`
- `{{ auth.method_title }}`
- `{{ auth.method_type }}`
- `{{ auth.source }}`
- `{{ auth.metadata.subject }}`
- `{{ path.id }}`
- `{{ request.method }}`
- `{{ vars.access_token }}`

## Security Model

Security is file-backed and defined in [`config/security.example.yaml`](config/security.example.yaml).

Main shape:

- `roles.<role_name>.permissions[]`
- `users.<username>.roles[]`
- `users.<username>.enabled`
- `users.<username>.password_hash`

Current permissions:

- `monitor_access`
- `admin_access`
- `services_manage`
- `security_manage`

The control-plane now uses a built-in login page and a signed session cookie instead of browser HTTP Basic Auth prompts. If `NAPIGATE_ADMIN_USERNAME` and `NAPIGATE_ADMIN_PASSWORD` are set, that bootstrap admin from `.env` can sign in immediately and manage file-backed users and roles from the admin UI.

If `NAPIGATE_ADMIN_ACCESS_WHITELIST_IPS` is empty, admin routes accept requests from any IP. If it contains comma-separated IPs or CIDRs, every `/__admin` page and admin API request must originate from one of those ranges.

If NapiGate sits behind Docker, Nginx, Traefik, HAProxy, or another reverse proxy, set `observability.trusted_proxy_ips` to the IPs or CIDRs of only those proxies. When the direct peer matches that allowlist, NapiGate resolves the request IP from `X-Forwarded-For`, `Forwarded`, or `X-Real-IP` and stores the end-user IP in monitor/audit logs. If the peer is not trusted, those headers are ignored to avoid spoofing.

## Monitoring And Logs

- SQLite request log DB: `data/monitor.db`
- File log: `logs/napigate.log`
- Rotation: daily
- Retention: unlimited by default, or `observability.log_retention_hours` with hourly cleanup when set

The request monitor exposes:

- HTML table view
- JSON log list
- 24-hour summary/report JSON with hourly buckets aligned to the optional `timezone_offset_minutes` offset; the Admin chart sends the browser offset automatically
- server-sent events live stream
- incoming request cURL capture, used on cache hits so query parameters, headers, and request bodies remain inspectable even when no upstream call runs

Structured request logs can also be forwarded to configured HTTP JSON or Loki sinks through the async dispatcher.

## Admin APIs

NapiGate now exposes machine-oriented admin endpoints under `/__admin/api`.

Examples:

- `GET /__admin/api/config`
- `PUT /__admin/api/config`
- `POST /__admin/api/cache/clear`
- `GET /__admin/api/backup?scope=full&format=yaml`
- `POST /__admin/api/import?scope=services`
- `GET /__admin/api/clients`
- `POST /__admin/api/clients`
- `GET /__admin/api/clients/{client_slug}`
- `PUT /__admin/api/clients/{client_slug}`
- `DELETE /__admin/api/clients/{client_slug}`
- `GET /__admin/api/output-profiles`
- `POST /__admin/api/output-profiles`
- `GET /__admin/api/output-profiles/{profile_slug}`
- `PUT /__admin/api/output-profiles/{profile_slug}`
- `DELETE /__admin/api/output-profiles/{profile_slug}`

Notes:

- These routes require an authenticated admin session plus the normal `services_manage` permission.
- Backup/import scopes that touch security data require `security_manage`; the full snapshot scope requires both `services_manage` and `security_manage`.
- Full config replacement accepts JSON or YAML request bodies.
- The Config tab can now export or import either a full snapshot (`config` + `security`) or an individual section such as `services`, `routes`, `clients`, `output_profiles`, `observability`, `roles`, or `users`.
- The Config tab can clear the active gateway cache backend for response, pre-call, and external-auth cache entries; rate-limit counters are not cleared.
- Client automation should use `slug`, not the display title.

## Example Requests

Public route:

```bash
curl http://127.0.0.1:8000/demo/ip
```

OAuth client credentials token:

```bash
curl -u demo-client-id:demo-client-secret \
  -X POST \
  http://127.0.0.1:8000/__oauth/token
```

Protected request with API key:

```bash
curl \
  -H 'X-API-Key: demo-api-key' \
  http://127.0.0.1:8000/demo/headers
```

## Development Notes

- The project intentionally avoids heavyweight frameworks.
- Runtime and admin config validation happen before persisted changes are accepted.
- Request bodies are buffered in memory. Response bodies stream through without buffering when the endpoint-plus-route output-profile chain has no transforming profile and response caching is disabled; otherwise they are buffered to allow envelope wrapping or cache storage.
- If you proxy NapiGate through Nginx and want streaming responses to reach the client without buffering, set `proxy_buffering off` in the relevant location block.
- Rate-limiter sliding-window state is not cleared on config hot-reload or manual cache clearing; only the response/pre-call/auth caches are cleared.
- `trust_env_proxy` defaults to `false`.
- `forward_napigate_headers` defaults to `true`.
- `gateway_responses` defaults to `mode: default`, which keeps the runtime error shape as `{"detail": ...}` until you switch to `inline` or `profile`.
- `config/services.yaml` and `config/security.yaml` are hot-reloaded when their file contents change on disk.
- Admin forms include inline help tooltips with behavior notes and quick examples for each major field.
- Shared example updates should go into `config/services.example.yaml` and `config/security.example.yaml`.
- YAML remains the control plane for gateway config objects. It is appropriate for gateway services, clients, profiles, and roles, but it is not intended to be an application user database for hundreds of thousands of end users.

## Verification

Useful checks while developing:

```bash
python3 -m compileall gateway
python3 -m py_compile gateway/*.py
docker compose config
```

## Repository Readiness Checklist

Before publishing, confirm:

- `config/services.yaml`, `config/security.yaml`, and `.env` stay local
- admin credentials in `.env` are not default values
- example YAML files reflect the current public contract
- Docker defaults match your expected deployment environment
- README examples match real runtime behavior

## License

No license file is included yet. Add one before publishing publicly if you intend to allow reuse.
