# NapiGate

NapiGate is a lightweight, config-driven Python API gateway built for small and mid-sized internal integrations. It keeps the stack intentionally small, routes requests to upstream services, authenticates gateway clients, supports trusted inline hooks, and exposes a simple built-in admin and monitoring UI.

## Highlights

- YAML-defined services and endpoints
- reusable output profiles for passthrough, JSON envelope, and JSONP responses
- Top-level client model with scoped access
- stable client and endpoint slugs for admin APIs and external automation
- Multiple auth methods per client
- Trusted `pre_call` hooks for downstream preparation
- Trusted `external_service` auth scripts for custom validation
- endpoint response caching and async success hooks
- optional structured request-log forwarding to HTTP JSON sinks or Loki
- Built-in monitor UI, JSON logs endpoint, and live stream
- File-backed users and roles for admin access
- Daily rotating file logs
- Minimal dependency footprint: `stdlib + requests + PyYAML`

## Why This Project

NapiGate is designed for teams that need an API gateway without adopting a large platform or a complex control plane. The project favors:

- explicit configuration over convention-heavy abstractions
- predictable runtime behavior over plugin sprawl
- easy local deployment over cluster-first assumptions
- readable Python over framework lock-in

## Architecture

The codebase is split into a few focused modules:

- [`gateway/config.py`](gateway/config.py): typed config loading, validation, and route compilation
- [`gateway/runtime.py`](gateway/runtime.py): request matching, client auth, rate limiting, CORS handling, token issuance, output transforms, response caching, async success hooks, config hot-reload, and upstream proxying
- [`gateway/admin_ops.py`](gateway/admin_ops.py): config and security mutations used by the admin UI
- [`gateway/security.py`](gateway/security.py): users, roles, password hashing, and authorization checks
- [`gateway/monitoring.py`](gateway/monitoring.py): SQLite-backed request log storage
- [`gateway/logging_utils.py`](gateway/logging_utils.py): daily rotating file logging
- [`gateway/settings.py`](gateway/settings.py): `.env` loading and runtime settings
- [`gateway/main.py`](gateway/main.py): HTTP server, admin/monitor endpoints, and CLI entrypoint

The runtime uses `ThreadingHTTPServer` and keeps the gateway model intentionally simple:

1. Match the incoming request to a configured endpoint.
2. Enforce service protection and client scope.
3. Authenticate the client using one of its enabled auth methods.
4. Enforce service-level rate limits when configured.
5. Check endpoint response cache when configured.
6. Run `pre_call` if defined.
7. Render templates, optionally return a local configured response, otherwise forward the request upstream.
8. Apply output shaping, response caching, async success hooks, CORS headers, and monitoring/logging records.

## Project Layout

```text
.
├── config/
│   ├── security.example.yaml
│   └── services.example.yaml
├── gateway/
│   ├── admin_ops.py
│   ├── config.py
│   ├── logging_utils.py
│   ├── main.py
│   ├── monitoring.py
│   ├── runtime.py
│   ├── security.py
│   └── settings.py
├── Dockerfile
├── docker-compose.yml
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

Or install dependencies without packaging:

```bash
pip install requests pyyaml
```

The package also exposes a console entrypoint after installation:

```bash
napigate --host 0.0.0.0 --port 8000 --config config/services.yaml
```

## Quick Start

1. Create local runtime files:

```bash
cp config/services.example.yaml config/services.yaml
cp config/security.example.yaml config/security.yaml
```

2. Run the gateway:

```bash
python3 -m gateway.main --host 0.0.0.0 --port 8000 --config config/services.yaml
```

3. Open the built-in surfaces:

- Monitor HTML: `http://127.0.0.1:8000/__monitor`
- Monitor JSON: `http://127.0.0.1:8000/__monitor/logs`
- Live stream: `http://127.0.0.1:8000/__monitor/stream`
- Admin UI: `http://127.0.0.1:8000/__admin`
- Health: `http://127.0.0.1:8000/__health`
- OAuth token endpoint: `POST /__oauth/token`

## Docker

1. Prepare local files:

```bash
cp .env.example .env
cp config/services.example.yaml config/services.yaml
cp config/security.example.yaml config/security.yaml
```

2. Start the container:

```bash
docker compose up -d --build
```

The default container port is controlled by `APP_PORT` in `.env`.

Compose mounts `config/`, `data/`, and `logs/` into the container. Changes to `config/services.yaml` and `config/security.yaml` are detected automatically by the running process, so Docker restart cycles are not required for routine config edits.

### Important `.env` Variables

See [`.env.example`](.env.example) for the full template.

- `APP_PORT`
- `APP_TIMEZONE`
- `NAPIGATE_CONFIG`
- `NAPIGATE_SECURITY_CONFIG`
- `NAPIGATE_ADMIN_USERNAME`
- `NAPIGATE_ADMIN_PASSWORD`
- `NAPIGATE_ADMIN_ACCESS_WHITELIST_IPS`
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

observability:
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

### Services And Endpoints

Services remain fully config-driven:

- `base_url`
- `timeout_seconds`
- `verify_ssl`
- `trust_env_proxy`
- `variables`
- `headers`
- `auth.required`
- `cors`
- `rate_limit`
- `endpoints[]`

Endpoint fields:

- `name`
- `slug`
- `methods`
- `gateway_path`
- `upstream_path`
- `response`
- `output_profile`
- `response_cache`
- `success_hook`
- `headers`
- `query`
- `pre_call`

`response` can be used for direct gateway replies without an upstream call:

```yaml
services:
  status:
    base_url: https://example.invalid
    auth:
      required: false
    endpoints:
      - name: status_ok
        methods: [GET]
        gateway_path: /demo/status
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

- `auth.required` is service-level only.
- If `response` is defined, NapiGate returns it before any upstream proxy call.
- `output_profile` applies after local responses or upstream responses are built.
- `response_cache` only stores successful responses for configured methods.
- `success_hook` is async and fires only after successful responses.
- Old service-local clients are rejected during validation.
- Old endpoint-level auth is rejected during validation.
- Protected endpoints must be reachable by at least one enabled client scope.

### Output Profiles

Output profiles are top-level reusable response contracts. Endpoints can opt into one profile by slug.

Supported profile types:

- `passthrough`
- `json_envelope`
- `jsonp`

Common output profile fields:

- `title`
- `enabled`
- `type`
- `success_key`
- `data_key`
- `message_key`
- `error_key`
- `passthrough_keys[]`
- `jsonp_callback_param`
- `jsonp_default_callback`
- `headers`

`json_envelope` behavior:

- If the upstream JSON already contains the configured `passthrough_keys`, NapiGate does not wrap it again.
- Otherwise, the payload is placed into `data_key`.
- Non-JSON binary/image responses should normally stay on `passthrough`.

### Response Caching

Endpoint-level response caching uses in-memory TTL storage:

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

Endpoints can publish a best-effort async event after successful responses:

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

Request logs can be forwarded asynchronously through `observability.log_aggregators`.

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

Service-level rate limiting uses an in-memory sliding window:

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

`pre_call.code` is trusted Python executed synchronously before the upstream request.

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

If `NAPIGATE_ADMIN_USERNAME` and `NAPIGATE_ADMIN_PASSWORD` are set, admin and monitor routes also require HTTP Basic Auth. The bootstrap admin from `.env` can then manage file-backed users and roles from the admin UI.

If `NAPIGATE_ADMIN_ACCESS_WHITELIST_IPS` is empty, admin routes accept requests from any IP. If it contains comma-separated IPs or CIDRs, every `/__admin` page and admin API request must originate from one of those ranges.

## Monitoring And Logs

- SQLite request log DB: `data/monitor.db`
- File log: `logs/napigate.log`
- Rotation: daily
- Retention: `14` rotated log files

The request monitor exposes:

- HTML table view
- JSON log list
- server-sent events live stream

Structured request logs can also be forwarded to configured HTTP JSON or Loki sinks through the async dispatcher.

## Admin APIs

NapiGate now exposes machine-oriented admin endpoints under `/__admin/api`.

Examples:

- `GET /__admin/api/config`
- `PUT /__admin/api/config`
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

- These routes require HTTP Basic Auth plus the normal `services_manage` permission.
- Full config replacement accepts JSON or YAML request bodies.
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
- Request and response bodies are currently buffered in memory.
- `trust_env_proxy` defaults to `false`.
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
