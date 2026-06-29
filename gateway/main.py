from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
import hashlib
from html import escape
import hmac
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
from pathlib import Path
import secrets
import threading
import time
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

import yaml

from gateway.admin_ops import (
    backup_scope_definition,
    build_status_query,
    delete_client,
    delete_endpoint,
    delete_output_profile,
    delete_role,
    delete_route,
    delete_service,
    delete_user,
    export_backup_scope,
    import_backup_scope,
    save_client,
    save_endpoint,
    save_gateway_settings,
    save_output_profile,
    save_role,
    save_route,
    save_service,
    save_user,
)
from gateway.admin_state import build_admin_page_state
from gateway.config import (
    ROUTE_PROTOCOL_CHOICES,
    SERVICE_PROTOCOL_CHOICES,
    configure_config_document_io,
    get_config_source_label,
    load_config_document,
    save_config_document,
)
from gateway.logging_utils import setup_logging, shutdown_logging
from gateway.output_sandbox import validate_custom_output_code
from gateway.runtime import GatewayError, GatewayRuntime, IncomingRequest, OutgoingResponse
from gateway.security import (
    AuthenticatedPrincipal,
    SECURITY_CONFIG_PATH,
    SecurityManager,
    configure_security_document_io,
    get_security_source_label,
)
from gateway.settings import get_env, load_env_file, load_settings
from gateway.state_store import build_state_store


load_env_file()
setup_logging()
LOGGER = logging.getLogger("gateway.main")
SETTINGS = load_settings()
runtime: GatewayRuntime
security: SecurityManager
state_store: Any
ADMIN_SESSION_COOKIE = "napigate_admin_session"
# Cookie path matching requires either an exact prefix ending with "/"
# or a boundary slash in the request path after the prefix. Admin routes
# are "/__admin", "/__monitor", and "/__login", so "/__" would not match
# them reliably. Use "/" so the session survives redirects across the
# whole control-plane surface on the admin listener.
ADMIN_SESSION_PATH = "/"
ADMIN_SESSION_TTL_SECONDS = 12 * 60 * 60
_ADMIN_SESSION_SECRET: bytes | None = None
_PRINCIPAL_CACHE_EMPTY = object()


def _config_path_arg_default() -> str:
    return get_env("NAPIGATE_CONFIG", "APIGATE_CONFIG", default="config/services.yaml")


def _security_path_default() -> str:
    return get_env(
        "NAPIGATE_SECURITY_CONFIG",
        "APIGATE_SECURITY_CONFIG",
        default=str(SECURITY_CONFIG_PATH),
    )


def normalize_request_target(target: str) -> str:
    """Repair request targets that http.server decoded from raw UTF-8 bytes as latin-1."""
    if not target:
        return target
    try:
        return target.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return target


def configure_application(*, config_path: Path | str, security_path: Path | str) -> None:
    global runtime
    global security
    global state_store

    state_store = build_state_store(
        mode=SETTINGS.state_store_mode,
        config_path=config_path,
        security_path=security_path,
        postgres_dsn=SETTINGS.postgres_dsn,
        sync_interval_seconds=SETTINGS.state_sync_interval_seconds,
    )
    configure_config_document_io(
        loader=lambda _path: state_store.load_config_document(),
        saver=lambda _path, document: state_store.save_config_document(document),
        revision_provider=lambda _path: state_store.config_revision(),
        source_label_provider=lambda _path: state_store.config_source_label,
    )
    configure_security_document_io(
        loader=lambda _path: state_store.load_security_document(),
        saver=lambda _path, document: state_store.save_security_document(document),
        revision_provider=lambda _path: state_store.security_revision(),
        source_label_provider=lambda _path: state_store.security_source_label,
    )
    runtime = GatewayRuntime(config_path=Path(config_path), redis_url=SETTINGS.redis_url)
    security = SecurityManager(config_path=Path(security_path))


def _admin_session_secret() -> bytes:
    global _ADMIN_SESSION_SECRET
    if _ADMIN_SESSION_SECRET is not None:
        return _ADMIN_SESSION_SECRET

    configured = get_env("NAPIGATE_ADMIN_SESSION_SECRET", "APIGATE_ADMIN_SESSION_SECRET").strip()
    if configured:
        _ADMIN_SESSION_SECRET = configured.encode("utf-8")
        return _ADMIN_SESSION_SECRET

    if SETTINGS.admin_auth.enabled:
        seed = (
            f"{SETTINGS.admin_auth.username}\0"
            f"{SETTINGS.admin_auth.password}\0"
            f"{SETTINGS.admin_auth.realm}"
        ).encode("utf-8")
        _ADMIN_SESSION_SECRET = hashlib.sha256(seed).digest()
        return _ADMIN_SESSION_SECRET

    _ADMIN_SESSION_SECRET = secrets.token_bytes(32)
    LOGGER.warning(
        "Admin session secret is ephemeral because neither "
        "NAPIGATE_ADMIN_SESSION_SECRET nor bootstrap admin credentials are configured."
    )
    return _ADMIN_SESSION_SECRET


def _urlsafe_b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _urlsafe_b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(f"{value}{padding}".encode("ascii"))


def render_login_page(*, error: str = "", message: str = "", next_path: str = "/__admin", username: str = "") -> str:
    error_html = (
        f'<div class="notice error">{escape(error)}</div>'
        if error
        else ""
    )
    message_html = (
        f'<div class="notice ok">{escape(message)}</div>'
        if message and not error
        else ""
    )
    return f"""
    <!doctype html>
    <html lang="en" dir="ltr">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>NapiGate Login</title>
      <style>
        :root {{
          color-scheme: light;
          --bg: #f4f7fb;
          --panel: #ffffff;
          --ink: #18202a;
          --muted: #5f6b7a;
          --line: #dbe3ee;
          --blue: #1f6feb;
          --blue-strong: #1148a8;
          --danger: #c62828;
          --danger-bg: #fff1f1;
          --ok: #166534;
          --ok-bg: #eefbf2;
          --shadow: 0 18px 60px rgba(26, 40, 58, 0.12);
          font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        }}
        * {{ box-sizing: border-box; }}
        body {{
          margin: 0;
          min-height: 100vh;
          background:
            radial-gradient(circle at top left, rgba(31, 111, 235, 0.16), transparent 28%),
            radial-gradient(circle at right 18%, rgba(15, 118, 110, 0.12), transparent 22%),
            var(--bg);
          color: var(--ink);
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 28px 16px;
        }}
        .shell {{
          width: min(100%, 980px);
          display: grid;
          grid-template-columns: minmax(260px, 1fr) minmax(320px, 430px);
          gap: 20px;
          align-items: stretch;
        }}
        .intro,
        .card {{
          background: rgba(255,255,255,0.94);
          border: 1px solid var(--line);
          border-radius: 28px;
          box-shadow: var(--shadow);
        }}
        .intro {{
          padding: 30px;
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          gap: 18px;
        }}
        .brand {{
          display: flex;
          align-items: center;
          gap: 12px;
        }}
        .mark {{
          display: grid;
          grid-template-columns: repeat(2, 12px);
          gap: 4px;
          padding: 4px;
          border-radius: 12px;
          background: #fff;
          border: 1px solid var(--line);
        }}
        .mark span {{
          width: 12px;
          height: 12px;
          border-radius: 4px;
          display: block;
        }}
        .mark .a {{ background: #1f6feb; }}
        .mark .b {{ background: #159957; }}
        .mark .c {{ background: #f59e0b; }}
        .mark .d {{ background: #dc2626; }}
        .intro h1 {{
          margin: 0;
          font-size: clamp(2.1rem, 4vw, 3.2rem);
          line-height: 1.02;
          letter-spacing: -0.04em;
        }}
        .intro p,
        .intro li,
        .card p {{
          color: var(--muted);
          line-height: 1.72;
        }}
        .eyebrow {{
          margin: 0 0 12px;
          color: var(--blue);
          font-size: 0.83rem;
          letter-spacing: 0.14em;
          text-transform: uppercase;
          font-weight: 700;
        }}
        .bullets {{
          margin: 0;
          padding-left: 18px;
        }}
        .bullets li + li {{
          margin-top: 8px;
        }}
        .card {{
          padding: 26px;
        }}
        .card h2 {{
          margin: 0 0 6px;
          font-size: 1.35rem;
        }}
        .notice {{
          margin-bottom: 14px;
          padding: 11px 13px;
          border-radius: 14px;
          font-size: 0.94rem;
        }}
        .notice.error {{
          color: var(--danger);
          background: var(--danger-bg);
          border: 1px solid rgba(198, 40, 40, 0.16);
        }}
        .notice.ok {{
          color: var(--ok);
          background: var(--ok-bg);
          border: 1px solid rgba(22, 101, 52, 0.12);
        }}
        form {{
          margin-top: 18px;
          display: grid;
          gap: 14px;
        }}
        label {{
          display: grid;
          gap: 8px;
          font-size: 0.92rem;
          font-weight: 600;
        }}
        input {{
          width: 100%;
          min-height: 46px;
          padding: 0 14px;
          border-radius: 14px;
          border: 1px solid var(--line);
          background: #fff;
          color: var(--ink);
          font: inherit;
        }}
        input:focus {{
          outline: 2px solid rgba(31, 111, 235, 0.18);
          border-color: rgba(31, 111, 235, 0.34);
        }}
        button {{
          min-height: 48px;
          border: 0;
          border-radius: 14px;
          background: linear-gradient(180deg, var(--blue) 0%, var(--blue-strong) 100%);
          color: #fff;
          font: inherit;
          font-weight: 700;
          cursor: pointer;
          box-shadow: 0 12px 28px rgba(31, 111, 235, 0.22);
        }}
        .meta {{
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
          margin-top: 18px;
        }}
        .chip {{
          display: inline-flex;
          align-items: center;
          min-height: 32px;
          padding: 0 12px;
          border-radius: 999px;
          background: #f6f8fb;
          border: 1px solid var(--line);
          color: var(--muted);
          font-size: 0.85rem;
        }}
        .footnote {{
          margin-top: 14px;
          font-size: 0.86rem;
          color: var(--muted);
        }}
        .mono {{
          font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        }}
        @media (max-width: 880px) {{
          .shell {{
            grid-template-columns: 1fr;
          }}
          .intro {{
            padding: 24px;
          }}
          .card {{
            padding: 22px;
          }}
        }}
      </style>
    </head>
    <body>
      <div class="shell">
        <section class="intro">
          <div>
            <div class="brand">
              <div class="mark">
                <span class="a"></span>
                <span class="b"></span>
                <span class="c"></span>
                <span class="d"></span>
              </div>
              <div>
                <div class="eyebrow">NapiGate Control Plane</div>
                <h1>Sign in to the admin and monitor surface.</h1>
              </div>
            </div>
            <p>
              Public gateway traffic stays on its own listener. Routes, users, output profiles,
              monitor logs, and audit history stay behind the admin listener and a signed session.
            </p>
          </div>
          <div>
            <ul class="bullets">
              <li>Use the bootstrap admin from <span class="mono">.env</span> or any configured user account.</li>
              <li>Roles still decide whether this account can open <span class="mono">/__admin</span>, <span class="mono">/__monitor</span>, or both.</li>
              <li>Logout clears the session cookie so switching users works reliably.</li>
            </ul>
            <div class="meta">
              <span class="chip">Public: /__health and /__oauth/token stay separate</span>
              <span class="chip">Next: <span class="mono">{escape(next_path)}</span></span>
            </div>
          </div>
        </section>

        <section class="card">
          <div class="eyebrow">Login</div>
          <h2>Use your control-plane account</h2>
          <p>The session is stored in a signed cookie. Browser Basic Auth prompts are no longer used for the admin UI.</p>
          {error_html}
          {message_html}
          <form method="post" action="/__login" autocomplete="on">
            <input type="hidden" name="next" value="{escape(next_path)}">
            <label>
              <span>Username</span>
              <input name="username" value="{escape(username)}" autocomplete="username" required>
            </label>
            <label>
              <span>Password</span>
              <input name="password" type="password" autocomplete="current-password" required>
            </label>
            <button type="submit">Sign In</button>
          </form>
          <div class="footnote">
            Accounts with only <span class="mono">monitor_access</span> will be sent to
            <span class="mono">/__monitor</span> after login.
          </div>
        </section>
      </div>
    </body>
    </html>
    """


def render_monitor_page(principal: AuthenticatedPrincipal) -> str:
    initial_rows = json.dumps(runtime.list_logs(limit=200), ensure_ascii=False)
    return f"""
    <!doctype html>
    <html lang="en" dir="ltr">
    <head>
      <meta charset="utf-8">
      <title>NapiGate Monitor</title>
      <style>
        :root {{
          color-scheme: light;
          --bg: #f4f0e8;
          --paper: #fffdf8;
          --ink: #1f2937;
          --line: #d7cbb7;
          --muted: #6b7280;
          --accent: #9a3412;
          --ok: #166534;
          --warn: #b45309;
          --bad: #991b1b;
        }}
        * {{ box-sizing: border-box; }}
        body {{
          margin: 0;
          font-family: "Segoe UI", "Inter", sans-serif;
          background: radial-gradient(circle at top, #fbf6eb 0%, var(--bg) 60%);
          color: var(--ink);
          font-size: 13px;
          line-height: 1.45;
        }}
        .wrap {{
          max-width: 1480px;
          margin: 18px auto;
          padding: 0 16px;
        }}
        .panel {{
          background: var(--paper);
          border: 1px solid var(--line);
          border-radius: 14px;
          overflow: hidden;
          box-shadow: 0 12px 30px rgba(107, 114, 128, 0.08);
        }}
        .head {{
          display: flex;
          justify-content: space-between;
          gap: 12px;
          align-items: center;
          padding: 12px 16px;
          border-bottom: 1px solid var(--line);
        }}
        .title {{
          font-size: 18px;
          font-weight: 700;
          margin: 0;
        }}
        .meta {{
          color: var(--muted);
          font-size: 12px;
        }}
        .toolbar {{
          display: flex;
          gap: 8px;
          align-items: center;
          flex-wrap: wrap;
        }}
        .chip {{
          border: 1px solid var(--line);
          border-radius: 999px;
          padding: 4px 8px;
          background: #fff8ee;
          font-size: 12px;
        }}
        .chip.ok {{ color: var(--ok); }}
        .chip.offline {{ color: var(--bad); }}
        .chip.warn {{ color: var(--warn); }}
        .chip.paused {{
          color: #1d4ed8;
          border-color: #bfdbfe;
          background: #eff6ff;
        }}
        .toolbar-btn {{
          border: 1px solid #e7c9a6;
          border-radius: 10px;
          padding: 6px 10px;
          background: #fff8ee;
          color: var(--ink);
          font: inherit;
          font-size: 12px;
          font-weight: 700;
          cursor: pointer;
        }}
        .toolbar-btn.active {{
          color: #1d4ed8;
          border-color: #93c5fd;
          background: #eff6ff;
        }}
        .toolbar-btn:disabled {{
          opacity: 0.55;
          cursor: default;
        }}
        .links a {{
          color: var(--accent);
          text-decoration: none;
          font-weight: 700;
          margin-inline-start: 8px;
        }}
        .stats {{
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
          gap: 10px;
          padding: 10px 16px;
          border-bottom: 1px solid var(--line);
          background: #fff8ef;
        }}
        .stat {{
          border: 1px solid #eadbc4;
          border-radius: 10px;
          padding: 8px 10px;
          background: #fffdf8;
        }}
        .stat-label {{
          color: var(--muted);
          font-size: 11px;
        }}
        .stat-value {{
          font-size: 19px;
          font-weight: 700;
          margin-top: 2px;
        }}
        .table-wrap {{
          overflow: auto;
          max-height: 80vh;
        }}
        table {{
          width: 100%;
          border-collapse: collapse;
          font-size: 12.5px;
        }}
        th, td {{
          padding: 7px 8px;
          border-bottom: 1px solid #eee4d2;
          text-align: left;
          vertical-align: top;
        }}
        th {{
          background: #f7f0e5;
          position: sticky;
          top: 0;
          font-size: 11.5px;
          z-index: 1;
        }}
        .th-inner {{
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 6px;
        }}
        .filter-btn {{
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 24px;
          height: 24px;
          border: 1px solid transparent;
          border-radius: 8px;
          background: transparent;
          color: var(--muted);
          cursor: pointer;
          flex: 0 0 auto;
        }}
        .filter-btn:hover {{
          color: var(--accent);
          border-color: #eadbc4;
          background: #fff8ee;
        }}
        .filter-btn.active {{
          color: var(--accent);
          border-color: #d6b08b;
          background: #fce7d2;
        }}
        .filter-btn svg {{
          width: 13px;
          height: 13px;
        }}
        tbody tr:nth-child(even) {{
          background: #fffaf2;
        }}
        .status-badge {{
          display: inline-block;
          min-width: 48px;
          text-align: center;
          border-radius: 999px;
          padding: 3px 7px;
          font-size: 11px;
          font-weight: 700;
          background: #fce7d2;
          color: var(--accent);
        }}
        .status-2xx {{ background: #dcfce7; color: var(--ok); }}
        .status-4xx {{ background: #fef3c7; color: var(--warn); }}
        .status-5xx {{ background: #fee2e2; color: var(--bad); }}
        .bool-yes {{ background: #dcfce7; color: var(--ok); }}
        .bool-no {{ background: #fee2e2; color: var(--bad); }}
        .muted {{ color: var(--muted); }}
        .btn-link {{
          border: 0;
          background: transparent;
          color: var(--accent);
          cursor: pointer;
          font: inherit;
          font-weight: 700;
          padding: 0;
        }}
        .upstream-cell {{
          min-width: 260px;
        }}
        .curl-block {{
          margin-top: 6px;
        }}
        .curl-block summary {{
          cursor: pointer;
          color: var(--accent);
          font-weight: 700;
        }}
        .curl-pre {{
          margin-top: 6px;
          padding: 8px;
          border: 1px solid #eadbc4;
          border-radius: 10px;
          background: #fff8ee;
          white-space: pre-wrap;
          word-break: break-word;
        }}
        .response-cell {{
          min-width: 260px;
        }}
        .response-snippet {{
          margin: 0;
          padding: 8px;
          border: 1px solid #eadbc4;
          border-radius: 10px;
          background: #fff8ee;
          white-space: pre-wrap;
          word-break: break-word;
          max-height: 120px;
          overflow: auto;
        }}
        .mono {{
          font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
          font-size: 11px;
          direction: ltr;
          unicode-bidi: plaintext;
        }}
        .overlay {{
          position: fixed;
          inset: 0;
          display: none;
          align-items: center;
          justify-content: center;
          padding: 14px;
          background: rgba(15, 23, 42, 0.42);
          z-index: 1000;
        }}
        .overlay.open {{
          display: flex;
        }}
        .modal {{
          width: min(460px, 100%);
          background: var(--paper);
          border: 1px solid var(--line);
          border-radius: 18px;
          box-shadow: 0 22px 56px rgba(107, 114, 128, 0.22);
          overflow: hidden;
        }}
        .modal-head {{
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
          padding: 12px 14px;
          border-bottom: 1px solid #eadbc4;
        }}
        .modal-title {{
          margin: 0;
          font-size: 16px;
          font-weight: 700;
        }}
        .icon-btn {{
          border: 1px solid #eadbc4;
          background: #fff8ee;
          color: var(--ink);
          width: 34px;
          height: 34px;
          border-radius: 10px;
          font: inherit;
          font-size: 18px;
          cursor: pointer;
        }}
        .modal-body {{
          padding: 14px;
        }}
        .field {{
          display: flex;
          flex-direction: column;
          gap: 8px;
          font-size: 12px;
          font-weight: 700;
        }}
        .field input {{
          width: 100%;
          border: 1px solid #d7cbb7;
          border-radius: 10px;
          padding: 10px 12px;
          background: #fff;
          color: var(--ink);
          font: inherit;
        }}
        .modal-actions {{
          display: flex;
          justify-content: flex-end;
          gap: 8px;
          margin-top: 12px;
        }}
      </style>
    </head>
    <body>
      <div class="wrap">
        <div class="panel">
          <div class="head">
            <div>
              <h1 class="title">NapiGate Monitor</h1>
              <div class="meta">Live request stream for user {escape(principal.username)}</div>
            </div>
            <div class="toolbar">
              <div id="connection-badge" class="chip warn">Connecting...</div>
              <button id="pause-button" class="toolbar-btn" type="button">Pause</button>
              <button id="clear-filters-button" class="toolbar-btn" type="button" disabled>Clear Filters</button>
              <div id="filter-summary" class="chip">Filters: none</div>
              <div class="chip">Config: <span class="mono">{escape(get_config_source_label(runtime.config_path))}</span></div>
              <div class="links">
                <a href="/__monitor/logs">JSON</a>
                <a href="/__admin">Admin</a>
                <a href="/__logout">Logout</a>
              </div>
            </div>
          </div>
          <div class="stats">
            <div class="stat">
              <div class="stat-label">Visible Rows</div>
              <div class="stat-value" id="stat-rows">0</div>
            </div>
            <div class="stat">
              <div class="stat-label">5xx Errors</div>
              <div class="stat-value" id="stat-errors">0</div>
            </div>
            <div class="stat">
              <div class="stat-label">Average Duration</div>
              <div class="stat-value" id="stat-duration">0.000 ms</div>
            </div>
            <div class="stat">
              <div class="stat-label">Latest Visible</div>
              <div class="stat-value" id="stat-updated">-</div>
            </div>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th><div class="th-inner"><span>Time</span><button class="filter-btn" type="button" data-filter-column="created_at" onclick="openFilterModal('created_at')" title="Filter Time" aria-label="Filter Time"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 5h14l-5.5 6.5v4l-3 1v-5z"></path></svg></button></div></th>
                  <th><div class="th-inner"><span>Method</span><button class="filter-btn" type="button" data-filter-column="method" onclick="openFilterModal('method')" title="Filter Method" aria-label="Filter Method"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 5h14l-5.5 6.5v4l-3 1v-5z"></path></svg></button></div></th>
                  <th><div class="th-inner"><span>Gateway Path</span><button class="filter-btn" type="button" data-filter-column="gateway_path" onclick="openFilterModal('gateway_path')" title="Filter Gateway Path" aria-label="Filter Gateway Path"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 5h14l-5.5 6.5v4l-3 1v-5z"></path></svg></button></div></th>
                  <th><div class="th-inner"><span>Service</span><button class="filter-btn" type="button" data-filter-column="service_name" onclick="openFilterModal('service_name')" title="Filter Service" aria-label="Filter Service"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 5h14l-5.5 6.5v4l-3 1v-5z"></path></svg></button></div></th>
                  <th><div class="th-inner"><span>Endpoint</span><button class="filter-btn" type="button" data-filter-column="endpoint_name" onclick="openFilterModal('endpoint_name')" title="Filter Endpoint" aria-label="Filter Endpoint"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 5h14l-5.5 6.5v4l-3 1v-5z"></path></svg></button></div></th>
                  <th><div class="th-inner"><span>Upstream</span><button class="filter-btn" type="button" data-filter-column="upstream" onclick="openFilterModal('upstream')" title="Filter Upstream" aria-label="Filter Upstream"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 5h14l-5.5 6.5v4l-3 1v-5z"></path></svg></button></div></th>
                  <th><div class="th-inner"><span>Status</span><button class="filter-btn" type="button" data-filter-column="status_code" onclick="openFilterModal('status_code')" title="Filter Status" aria-label="Filter Status"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 5h14l-5.5 6.5v4l-3 1v-5z"></path></svg></button></div></th>
                  <th><div class="th-inner"><span>Response</span><button class="filter-btn" type="button" data-filter-column="response" onclick="openFilterModal('response')" title="Filter Response" aria-label="Filter Response"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 5h14l-5.5 6.5v4l-3 1v-5z"></path></svg></button></div></th>
                  <th><div class="th-inner"><span>Duration</span><button class="filter-btn" type="button" data-filter-column="duration_display" onclick="openFilterModal('duration_display')" title="Filter Duration" aria-label="Filter Duration"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 5h14l-5.5 6.5v4l-3 1v-5z"></path></svg></button></div></th>
                  <th><div class="th-inner"><span>IP</span><button class="filter-btn" type="button" data-filter-column="client_ip" onclick="openFilterModal('client_ip')" title="Filter IP" aria-label="Filter IP"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 5h14l-5.5 6.5v4l-3 1v-5z"></path></svg></button></div></th>
                </tr>
              </thead>
              <tbody id="log-rows"></tbody>
            </table>
          </div>
        </div>
      </div>
      <div class="overlay" id="filter-overlay">
        <div class="modal">
          <div class="modal-head">
            <h2 class="modal-title" id="filter-title">Filter</h2>
            <button id="filter-close" class="icon-btn" type="button" aria-label="Close">×</button>
          </div>
          <div class="modal-body">
            <form id="filter-form">
              <label class="field">
                <span>Search text</span>
                <input id="filter-input" type="text" autocomplete="off" placeholder="Type any part of the value">
              </label>
              <div class="modal-actions">
                <button id="filter-clear-button" class="toolbar-btn" type="button">Clear This Filter</button>
                <button id="filter-apply-button" class="toolbar-btn active" type="submit">Apply Filter</button>
              </div>
            </form>
          </div>
        </div>
      </div>
      <script>
        const initialRows = {initial_rows};
        const tbody = document.getElementById("log-rows");
        const badge = document.getElementById("connection-badge");
        const pauseButton = document.getElementById("pause-button");
        const clearFiltersButton = document.getElementById("clear-filters-button");
        const filterSummary = document.getElementById("filter-summary");
        const filterOverlay = document.getElementById("filter-overlay");
        const filterTitle = document.getElementById("filter-title");
        const filterInput = document.getElementById("filter-input");
        const filterForm = document.getElementById("filter-form");
        const filterClose = document.getElementById("filter-close");
        const filterClearButton = document.getElementById("filter-clear-button");
        let allRows = Array.isArray(initialRows) ? initialRows : [];
        let activeFilters = {{}};
        let currentFilterColumn = "";
        let monitorPaused = false;
        let monitorConnectionState = "connecting";
        let source = null;

        const FILTER_FIELDS = {{
          created_at: {{ label: "Time", value: (row) => `${{formatDateTime(row.created_at)}} ${{String(row.created_at || "")}}` }},
          method: {{ label: "Method", value: (row) => String(row.method || "") }},
          gateway_path: {{ label: "Gateway Path", value: (row) => String(row.gateway_path || "") }},
          service_name: {{ label: "Service", value: (row) => String(row.service_name || "") }},
          endpoint_name: {{ label: "Endpoint", value: (row) => String(row.endpoint_name || "") }},
          upstream: {{ label: "Upstream", value: (row) => `${{String(row.upstream_url || "")}} ${{String(row.upstream_curl || "")}} ${{String(responseSource(row) || "")}}` }},
          status_code: {{ label: "Status", value: (row) => String(row.status_code || "") }},
          response: {{ label: "Response", value: (row) => responseText(row) }},
          duration_display: {{ label: "Duration", value: (row) => String(row.duration_display || row.duration_ms || "") }},
          client_ip: {{ label: "IP", value: (row) => String(row.client_ip || "") }},
        }};

        function esc(value) {{
          return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;");
        }}

        function formatDateTime(value) {{
          if (!value) return "-";
          const date = new Date(value);
          if (Number.isNaN(date.getTime())) return String(value);
          return date.toLocaleString();
        }}

        function statusClass(code) {{
          if (code >= 500) return "status-5xx";
          if (code >= 400) return "status-4xx";
          if (code >= 200) return "status-2xx";
          return "";
        }}

        function responseSource(row) {{
          const explicitSource = String(row.response_source || "").trim().toLowerCase();
          if (explicitSource) {{
            return explicitSource;
          }}
          if (row.cached === true) {{
            return "cache";
          }}
          const upstreamUrl = String(row.upstream_url || "").trim();
          if (upstreamUrl === "cache://response") {{
            return "cache";
          }}
          if (upstreamUrl.startsWith("local://")) {{
            return "local";
          }}
          return "upstream";
        }}

        function normalized(value) {{
          return String(value ?? "").toLowerCase().trim();
        }}

        function activeFilterEntries() {{
          return Object.entries(activeFilters).filter(([, value]) => String(value || "").trim());
        }}

        function filterValue(row, column) {{
          const field = FILTER_FIELDS[column];
          return field ? String(field.value(row) || "") : "";
        }}

        function filteredRows() {{
          const entries = activeFilterEntries();
          if (!entries.length) {{
            return allRows;
          }}
          return allRows.filter((row) =>
            entries.every(([column, value]) => normalized(filterValue(row, column)).includes(normalized(value)))
          );
        }}

        function updateFilterButtons() {{
          document.querySelectorAll("[data-filter-column]").forEach((button) => {{
            const column = button.dataset.filterColumn;
            const activeValue = String(activeFilters[column] || "").trim();
            button.classList.toggle("active", Boolean(activeValue));
            button.title = activeValue
              ? `Filter ${{FILTER_FIELDS[column].label}}: ${{activeValue}}`
              : `Filter ${{FILTER_FIELDS[column].label}}`;
          }});
          const activeCount = activeFilterEntries().length;
          clearFiltersButton.disabled = activeCount === 0;
          if (currentFilterColumn) {{
            filterClearButton.disabled = !String(activeFilters[currentFilterColumn] || "").trim();
          }}
        }}

        function connectionBadgeState() {{
          if (monitorPaused) {{
            return {{ label: "Live paused", className: "chip paused" }};
          }}
          if (monitorConnectionState === "online") {{
            return {{ label: "Live connection established", className: "chip ok" }};
          }}
          if (monitorConnectionState === "error") {{
            return {{ label: "Reconnecting...", className: "chip offline" }};
          }}
          return {{ label: "Connecting...", className: "chip warn" }};
        }}

        function renderConnectionBadge() {{
          const state = connectionBadgeState();
          badge.textContent = state.label;
          badge.className = state.className;
          pauseButton.textContent = monitorPaused ? "Resume" : "Pause";
          pauseButton.classList.toggle("active", monitorPaused);
        }}

        async function copyText(text) {{
          if (navigator.clipboard?.writeText) {{
            await navigator.clipboard.writeText(text);
            return;
          }}
          const textarea = document.createElement("textarea");
          textarea.value = text;
          textarea.setAttribute("readonly", "readonly");
          textarea.style.position = "absolute";
          textarea.style.left = "-9999px";
          document.body.appendChild(textarea);
          textarea.select();
          document.execCommand("copy");
          textarea.remove();
        }}

        async function copyCurl(button) {{
          const curl = button.closest(".curl-block")?.querySelector("pre")?.textContent || "";
          if (!curl.trim()) return;
          const originalText = button.dataset.label || button.textContent;
          button.dataset.label = originalText;
          try {{
            await copyText(curl);
            button.textContent = "Copied";
          }} catch (_error) {{
            button.textContent = "Copy failed";
          }}
          window.setTimeout(() => {{
            button.textContent = originalText;
          }}, 1400);
        }}

        function renderUpstreamCell(row) {{
          const source = responseSource(row);
          const upstreamUrl = String(row.upstream_url || "").trim();
          const upstreamCurl = String(row.upstream_curl || "").trim();
          const requestCurl = String(row.request_curl || "").trim();
          if (source === "cache") {{
            return `
              <div class="upstream-cell">
                <div><span class="tag warn">Cache</span></div>
                <div class="muted mono">response cache hit</div>
                ${{
                  requestCurl
                    ? `
                      <details class="curl-block">
                        <summary>Incoming cURL</summary>
                        <div style="margin-top:6px;">
                          <button class="btn-link" type="button" onclick="copyCurl(this)">Copy</button>
                        </div>
                        <pre class="mono curl-pre">${{esc(requestCurl)}}</pre>
                      </details>
                    `
                    : '<div class="muted">Incoming cURL unavailable</div>'
                }}
              </div>
            `;
          }}
          if (source === "local") {{
            return `
              <div class="upstream-cell">
                <div><span class="tag ok">Local</span></div>
                <div class="muted">cURL unavailable</div>
              </div>
            `;
          }}
          if (!upstreamUrl && !upstreamCurl) {{
            return '<span class="muted">-</span>';
          }}
          return `
            <div class="upstream-cell">
              ${{upstreamUrl ? `<div class="mono">${{esc(upstreamUrl)}}</div>` : ""}}
              ${{
                upstreamCurl
                  ? `
                    <details class="curl-block">
                      <summary>cURL</summary>
                      <div style="margin-top:6px;">
                        <button class="btn-link" type="button" onclick="copyCurl(this)">Copy</button>
                      </div>
                      <pre class="mono curl-pre">${{esc(upstreamCurl)}}</pre>
                    </details>
                  `
                  : ""
              }}
            </div>
          `;
        }}

        function responseText(row) {{
          return String(row.response_body || row.error || "").trim();
        }}

        function durationMicros(row) {{
          const direct = Number(row.duration_us || 0);
          if (Number.isFinite(direct) && direct > 0) {{
            return direct;
          }}
          const millis = Number(row.duration_ms || 0);
          if (!Number.isFinite(millis) || millis <= 0) {{
            return 0;
          }}
          return Math.max(0, Math.round(millis * 1000));
        }}

        function formatDuration(row) {{
          const micros = durationMicros(row);
          const millis = micros / 1000;
          return `${{millis.toFixed(3)}} ms`;
        }}

        function renderResponseCell(row) {{
          const text = responseText(row);
          if (!text) {{
            return '<span class="muted">-</span>';
          }}
          return `
            <div class="response-cell">
              <pre class="mono response-snippet">${{esc(text)}}</pre>
            </div>
          `;
        }}

        function render(rows = filteredRows()) {{
          const totalRows = rows.length;
          const total5xx = rows.filter((row) => row.status_code >= 500).length;
          const avgDurationMicros = totalRows
            ? Math.round(rows.reduce((sum, row) => sum + durationMicros(row), 0) / totalRows)
            : 0;
          const activeCount = activeFilterEntries().length;

          document.getElementById("stat-rows").textContent = String(totalRows);
          document.getElementById("stat-errors").textContent = String(total5xx);
          document.getElementById("stat-duration").textContent = `${{(avgDurationMicros / 1000).toFixed(3)}} ms`;
          document.getElementById("stat-updated").textContent = formatDateTime(rows[0]?.created_at);
          filterSummary.textContent = activeCount
            ? `${{totalRows}} / ${{allRows.length}} rows | ${{activeCount}} filter(s)`
            : "Filters: none";

          tbody.innerHTML = rows.length
            ? rows.map((row) => `
                <tr>
                  <td class="mono">${{esc(formatDateTime(row.created_at))}}</td>
                  <td>${{esc(row.method)}}</td>
                  <td class="mono">${{esc(row.gateway_path)}}</td>
                  <td>${{esc(row.service_name)}}</td>
                  <td>${{esc(row.endpoint_name)}}</td>
                  <td>${{renderUpstreamCell(row)}}</td>
                  <td><span class="status-badge ${{statusClass(row.status_code)}}">${{row.status_code}}</span></td>
                  <td>${{renderResponseCell(row)}}</td>
                  <td>${{esc(row.duration_display || formatDuration(row))}}</td>
                  <td class="mono">${{esc(row.client_ip)}}</td>
                </tr>
              `).join("")
            : `<tr><td colspan="10">${{allRows.length ? "No logs match the active filters." : "No logs yet."}}</td></tr>`;
          updateFilterButtons();
          renderConnectionBadge();
        }}

        function openFilterModal(column) {{
          const field = FILTER_FIELDS[column];
          if (!field) {{
            return;
          }}
          currentFilterColumn = column;
          filterTitle.textContent = `Filter ${{field.label}}`;
          filterInput.value = String(activeFilters[column] || "");
          filterClearButton.disabled = !String(activeFilters[column] || "").trim();
          filterOverlay.classList.add("open");
          window.setTimeout(() => {{
            filterInput.focus();
            filterInput.select();
          }}, 0);
        }}

        function closeFilterModal() {{
          filterOverlay.classList.remove("open");
          currentFilterColumn = "";
        }}

        function applyCurrentFilter(value) {{
          if (!currentFilterColumn) {{
            return;
          }}
          const trimmed = String(value || "").trim();
          if (trimmed) {{
            activeFilters[currentFilterColumn] = trimmed;
          }} else {{
            delete activeFilters[currentFilterColumn];
          }}
          closeFilterModal();
          render();
        }}

        function clearCurrentFilter() {{
          if (!currentFilterColumn) {{
            return;
          }}
          delete activeFilters[currentFilterColumn];
          closeFilterModal();
          render();
        }}

        function clearAllFilters() {{
          activeFilters = {{}};
          render();
        }}

        async function fetchLogsSnapshot() {{
          const response = await fetch("/__monitor/logs", {{
            headers: {{ "Accept": "application/json" }},
            cache: "no-store",
          }});
          if (!response.ok) {{
            throw new Error(`HTTP ${{response.status}}`);
          }}
          const payload = await response.json();
          allRows = Array.isArray(payload) ? payload : [];
          render();
        }}

        function disconnectStream() {{
          if (source) {{
            source.close();
            source = null;
          }}
        }}

        function connectStream() {{
          if (monitorPaused || source) {{
            return;
          }}
          monitorConnectionState = "connecting";
          renderConnectionBadge();
          const currentSource = new EventSource("/__monitor/stream");
          source = currentSource;
          currentSource.onopen = () => {{
            if (source !== currentSource || monitorPaused) {{
              return;
            }}
            monitorConnectionState = "online";
            renderConnectionBadge();
          }};
          currentSource.onmessage = (event) => {{
            if (source !== currentSource || monitorPaused) {{
              return;
            }}
            allRows = JSON.parse(event.data);
            monitorConnectionState = "online";
            render();
          }};
          currentSource.onerror = () => {{
            if (source !== currentSource || monitorPaused) {{
              return;
            }}
            monitorConnectionState = "error";
            renderConnectionBadge();
          }};
        }}

        async function toggleMonitorPause() {{
          monitorPaused = !monitorPaused;
          if (monitorPaused) {{
            disconnectStream();
            renderConnectionBadge();
            return;
          }}

          monitorConnectionState = "connecting";
          renderConnectionBadge();
          try {{
            await fetchLogsSnapshot();
          }} catch (_error) {{
            monitorConnectionState = "error";
            renderConnectionBadge();
          }}
          connectStream();
        }}

        pauseButton.addEventListener("click", () => {{
          void toggleMonitorPause();
        }});
        clearFiltersButton.addEventListener("click", clearAllFilters);
        filterClose.addEventListener("click", closeFilterModal);
        filterClearButton.addEventListener("click", clearCurrentFilter);
        filterForm.addEventListener("submit", (event) => {{
          event.preventDefault();
          applyCurrentFilter(filterInput.value);
        }});
        filterOverlay.addEventListener("click", (event) => {{
          if (event.target === filterOverlay) {{
            closeFilterModal();
          }}
        }});
        document.addEventListener("keydown", (event) => {{
          if (event.key === "Escape" && filterOverlay.classList.contains("open")) {{
            closeFilterModal();
          }}
        }});

        render();
        connectStream();
        window.openFilterModal = openFilterModal;
      </script>
    </body>
    </html>
    """


def build_admin_state(
    *,
    principal: AuthenticatedPrincipal,
    document: dict[str, Any],
    public_base_url: str,
    admin_base_url: str,
) -> dict[str, Any]:
    can_view_live = principal.can("monitor_access")
    state = build_admin_page_state(
        principal=principal,
        document=document,
        security_state=security.public_state(),
        services_config_path=get_config_source_label(runtime.config_path),
        security_config_path=get_security_source_label(security.config_path),
        audit_logs=state_store.list_admin_change_logs(limit=200),
        network_state={
            "public_base_url": public_base_url,
            "admin_base_url": admin_base_url,
        },
        store_state={
            "mode": getattr(state_store, "mode", "file"),
            "audit_enabled": bool(getattr(state_store, "audit_enabled", False)),
        },
        live_state={
            "can_view": can_view_live,
            "logs": runtime.list_logs(limit=40) if can_view_live else [],
            "logs_url": f"{admin_base_url}/__monitor/logs",
            "report": runtime.log_report(hours=24, bucket_minutes=60) if can_view_live else {},
            "report_url": f"{admin_base_url}/__monitor/report?hours=24&bucket_minutes=60",
            "monitor_url": f"{admin_base_url}/__monitor",
        },
    )
    state["oauth"]["token_url"] = f"{public_base_url}/__oauth/token"
    return state


def render_admin_page(
    *,
    principal: AuthenticatedPrincipal,
    document: dict[str, Any],
    public_base_url: str,
    admin_base_url: str,
    message: str = "",
    error: str = "",
) -> str:
    state = build_admin_state(
        principal=principal,
        document=document,
        public_base_url=public_base_url,
        admin_base_url=admin_base_url,
    )
    state_json = json.dumps(state, ensure_ascii=False).replace("</", "<\\/")
    flash = ""
    if message:
        flash = f'<div class="flash ok">{escape(message)}</div>'
    elif error:
        flash = f'<div class="flash error">{escape(error)}</div>'

    return f"""
    <!doctype html>
    <html lang="en" dir="ltr">
    <head>
      <meta charset="utf-8">
      <title>NapiGate Admin Panel</title>
      <style>
        :root {{
          color-scheme: light;
          --bg: #f6f8fc;
          --paper: #ffffff;
          --ink: #202124;
          --line: #dde3ea;
          --muted: #5f6368;
          --accent: #1a73e8;
          --accent-2: #174ea6;
          --danger: #d93025;
          --ok: #137333;
          --okbg: #e6f4ea;
          --errbg: #fce8e6;
          --tabbg: #f7faff;
        }}
        * {{ box-sizing: border-box; }}
        body {{
          min-height: 100vh;
          margin: 0;
          font-family: "Google Sans Text", "Segoe UI", sans-serif;
          color: var(--ink);
          font-size: 13px;
          line-height: 1.45;
          background:
            radial-gradient(circle at top right, rgba(26, 115, 232, 0.10), transparent 30%),
            radial-gradient(circle at bottom left, rgba(66, 133, 244, 0.08), transparent 35%),
            var(--bg);
        }}
        body.sidebar-open {{
          overflow: hidden;
        }}
        .app-shell {{
          min-height: 100vh;
        }}
        .sidebar-backdrop {{
          position: fixed;
          inset: 0;
          background: rgba(15, 23, 42, 0.40);
          opacity: 0;
          pointer-events: none;
          transition: opacity 0.22s ease;
          z-index: 40;
          display: none;
        }}
        .sidebar {{
          position: fixed;
          inset: 0 auto 0 0;
          width: min(300px, calc(100vw - 28px));
          height: 100vh;
          display: none;
          flex-direction: column;
          gap: 18px;
          padding: 20px 14px 16px;
          background:
            linear-gradient(180deg, rgba(255, 255, 255, 0.96) 0%, rgba(244, 247, 253, 0.92) 100%),
            rgba(255, 255, 255, 0.94);
          border-right: 1px solid rgba(221, 227, 234, 0.92);
          backdrop-filter: blur(18px);
          flex-shrink: 0;
          z-index: 50;
          transform: translateX(-104%);
          transition: transform 0.22s ease;
          box-shadow: 0 22px 54px rgba(15, 23, 42, 0.24);
        }}
        .sidebar-brand {{
          display: flex;
          flex-direction: column;
          gap: 6px;
          padding: 4px 6px 2px;
        }}
        .sidebar-kicker {{
          color: var(--accent-2);
          font-size: 11px;
          font-weight: 800;
          letter-spacing: 0.08em;
          text-transform: uppercase;
        }}
        .sidebar-title {{
          margin: 0;
          font-size: 26px;
          font-weight: 900;
          line-height: 1;
        }}
        .sidebar-subtitle {{
          color: var(--muted);
          font-size: 12px;
          line-height: 1.55;
        }}
        .sidebar-nav {{
          display: flex;
          flex-direction: column;
          gap: 8px;
        }}
        .main-shell {{
          min-width: 0;
        }}
        .mobile-bar {{
          display: none;
        }}
        .mobile-toggle {{
          width: 42px;
          height: 42px;
          border-radius: 14px;
          border: 1px solid #d7e2f0;
          background: rgba(255, 255, 255, 0.92);
          color: var(--ink);
          font-size: 18px;
          box-shadow: 0 10px 22px rgba(60, 64, 67, 0.10);
        }}
        .wrap {{
          width: 100%;
          max-width: none;
          margin: 0;
          padding: 18px 18px 28px;
        }}
        .hero {{
          display: flex;
          justify-content: space-between;
          gap: 14px;
          align-items: center;
          margin-bottom: 12px;
        }}
        .title {{
          margin: 0;
          font-size: 26px;
          font-weight: 900;
        }}
        .subtitle {{
          margin-top: 5px;
          color: var(--muted);
          line-height: 1.55;
          font-size: 12px;
          max-width: 880px;
        }}
        .meta-box {{
          display: flex;
          flex-wrap: wrap;
          gap: 8px;
        }}
        .sidebar-meta {{
          display: flex;
          flex-direction: column;
          gap: 8px;
        }}
        .chip {{
          display: inline-flex;
          align-items: center;
          gap: 6px;
          max-width: 100%;
          padding: 6px 10px;
          border-radius: 999px;
          background: rgba(255, 255, 255, 0.94);
          border: 1px solid var(--line);
          font-size: 12px;
          box-shadow: 0 8px 18px rgba(60, 64, 67, 0.05);
          overflow-wrap: anywhere;
        }}
        .flash {{
          margin-bottom: 12px;
          padding: 9px 11px;
          border-radius: 10px;
          font-weight: 700;
          font-size: 12px;
        }}
        .flash.ok {{
          background: var(--okbg);
          color: var(--ok);
        }}
        .flash.error {{
          background: var(--errbg);
          color: var(--danger);
        }}
        #admin-flash:not(:empty) {{
          margin-bottom: 12px;
        }}
        .field-error {{
          color: var(--danger);
          font-size: 11px;
          font-weight: 700;
          margin-top: 4px;
        }}
        .form-grid input:invalid,
        .form-grid textarea:invalid,
        .form-grid select:invalid {{
          border-color: #ef9a9a;
          box-shadow: 0 0 0 2px rgba(217, 48, 37, 0.08);
        }}
        .panel {{
          background: rgba(255, 255, 255, 0.82);
          border: 1px solid var(--line);
          border-radius: 18px;
          overflow: visible;
          box-shadow: 0 14px 34px rgba(60, 64, 67, 0.08);
          backdrop-filter: blur(14px);
        }}
        .tabs {{
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
          align-items: center;
          padding: 12px 14px;
          background: var(--tabbg);
          border-bottom: 1px solid var(--line);
        }}
        .desktop-tabs {{
          display: flex;
        }}
        .tab {{
          border: 1px solid #d7e2f0;
          border-radius: 999px;
          background: #fff;
          color: var(--muted);
          padding: 7px 11px;
          font: inherit;
          font-weight: 800;
          font-size: 12px;
          cursor: pointer;
          text-decoration: none;
          line-height: 1.2;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          white-space: nowrap;
          transition: background 0.18s ease, color 0.18s ease, border-color 0.18s ease;
        }}
        .tab:hover {{
          background: #f3f7fd;
          color: var(--ink);
          border-color: #d7e3f3;
        }}
        .tab.active {{
          background: #202124;
          color: white;
          border-color: #202124;
        }}
        .tab.logout {{
          background: #3c4043;
          color: #fff;
          border-color: #3c4043;
        }}
        .sidebar-nav .tab,
        .sidebar-nav .tab.logout {{
          width: 100%;
          justify-content: flex-start;
          padding: 11px 12px;
          border-radius: 14px;
        }}
        .sidebar-nav .tab.logout {{
          margin-top: 6px;
        }}
        .sidebar-nav .tab.active {{
          box-shadow: 0 12px 24px rgba(32, 33, 36, 0.16);
        }}
        .sidebar-nav .tab.logout:hover {{
          color: #fff;
          border-color: #202124;
          background: #202124;
        }}
        .desktop-tabs .tab.logout:hover {{
          color: var(--danger);
          background: #fff;
          border-color: #f2cfcb;
        }}
        .section {{
          display: none;
          padding: 14px;
        }}
        .section.active {{
          display: block;
        }}
        .section-head {{
          display: flex;
          justify-content: space-between;
          gap: 10px;
          align-items: center;
          margin-bottom: 12px;
        }}
        .section-title {{
          margin: 0;
          font-size: 18px;
          font-weight: 800;
        }}
        .section-note {{
          color: var(--muted);
          margin-top: 4px;
          font-size: 12px;
          line-height: 1.45;
        }}
        .card {{
          border: 1px solid #e3e9f1;
          border-radius: 16px;
          padding: 12px;
          background: #fff;
          overflow-x: auto;
        }}
        table {{
          width: 100%;
          min-width: 760px;
          border-collapse: collapse;
          background: white;
          border-radius: 14px;
          overflow: hidden;
          font-size: 12.5px;
        }}
        th, td {{
          padding: 8px 10px;
          border-bottom: 1px solid #edf1f5;
          text-align: left;
          vertical-align: top;
        }}
        th {{
          background: #f8fafd;
          font-size: 11.5px;
        }}
        tr:last-child td {{
          border-bottom: none;
        }}
        .mono {{
          font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
          direction: ltr;
          unicode-bidi: plaintext;
          font-size: 11px;
        }}
        .actions {{
          display: flex;
          flex-wrap: wrap;
          gap: 6px;
        }}
        button,
        .btn {{
          border: none;
          border-radius: 10px;
          background: var(--accent);
          color: white;
          padding: 7px 10px;
          font: inherit;
          font-weight: 700;
          font-size: 12px;
          line-height: 1.2;
          cursor: pointer;
          text-decoration: none;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          white-space: nowrap;
        }}
        .btn.secondary {{
          background: var(--accent-2);
        }}
        .btn.light {{
          background: #fff;
          color: var(--ink);
          border: 1px solid #d2d8e0;
        }}
        .btn.danger {{
          background: var(--danger);
        }}
        .empty {{
          color: var(--muted);
          padding: 12px 2px;
          font-size: 12px;
        }}
        .tag {{
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 3px 7px;
          border-radius: 999px;
          background: #e8f0fe;
          color: #174ea6;
          font-size: 11px;
          margin-inline-end: 4px;
          margin-bottom: 4px;
        }}
        .tag.ok {{
          background: #dcfce7;
          color: #166534;
        }}
        .tag.warn {{
          background: #fef3c7;
          color: #b45309;
        }}
        .live-grid {{
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
          gap: 10px;
          margin-bottom: 12px;
        }}
        .live-report-grid {{
          display: grid;
          grid-template-columns: minmax(0, 1.7fr) minmax(280px, 1fr);
          gap: 12px;
          margin-bottom: 12px;
          align-items: start;
        }}
        .live-report-side {{
          display: grid;
          gap: 12px;
        }}
        .live-stat {{
          border: 1px solid #e3e9f1;
          border-radius: 14px;
          padding: 10px;
          background: #f8fafd;
        }}
        .live-label {{
          color: var(--muted);
          font-size: 11px;
          margin-bottom: 5px;
        }}
        .live-value {{
          font-size: 22px;
          font-weight: 900;
          line-height: 1;
        }}
        .live-subvalue {{
          margin-top: 4px;
          color: var(--muted);
          font-size: 12px;
        }}
        .live-head {{
          display: flex;
          justify-content: space-between;
          gap: 10px;
          align-items: center;
          margin-bottom: 10px;
        }}
        .live-badge {{
          display: inline-flex;
          align-items: center;
          gap: 6px;
          padding: 5px 9px;
          border-radius: 999px;
          border: 1px solid #d6e2fb;
          background: #fff;
          color: var(--muted);
          font-size: 12px;
          font-weight: 700;
        }}
        .live-badge.ok {{
          color: var(--ok);
          background: #f0fbf3;
          border-color: #d1f0db;
        }}
        .live-badge.warn {{
          color: #b45309;
          background: #fff7e8;
          border-color: #f3dfb4;
        }}
        .live-badge.paused {{
          color: #1d4ed8;
          background: #eff6ff;
          border-color: #bfdbfe;
        }}
        .live-dot {{
          width: 8px;
          height: 8px;
          border-radius: 50%;
          background: currentColor;
          box-shadow: 0 0 0 4px rgba(26, 115, 232, 0.10);
        }}
        .live-table-card {{
          border: 1px solid #e3e9f1;
          border-radius: 16px;
          padding: 12px;
          background: #fff;
          overflow-x: auto;
        }}
        .live-chart-card,
        .live-list-card {{
          border: 1px solid #e3e9f1;
          border-radius: 16px;
          padding: 12px;
          background: #fff;
        }}
        .live-card-title {{
          margin: 0 0 4px;
          font-size: 15px;
          font-weight: 800;
        }}
        .live-card-note {{
          color: var(--muted);
          font-size: 12px;
          margin-bottom: 10px;
          line-height: 1.45;
        }}
        .live-chart-wrap {{
          display: grid;
          gap: 10px;
        }}
        .live-chart {{
          width: 100%;
          height: auto;
          display: block;
          border-radius: 12px;
          background: linear-gradient(180deg, #fcfdff 0%, #f6f9fd 100%);
        }}
        .live-chart-grid {{
          stroke: #e6edf5;
          stroke-width: 1;
        }}
        .live-chart-bar {{
          fill: rgba(26, 115, 232, 0.78);
        }}
        .live-chart-bar-guide {{
          display: none;
        }}
        .live-chart-line {{
          fill: none;
          stroke: #d97706;
          stroke-width: 2.5;
          stroke-linecap: round;
          stroke-linejoin: round;
        }}
        .live-chart-line-dot {{
          fill: #d97706;
          stroke: #fff;
          stroke-width: 1.5;
        }}
        .live-chart-label {{
          fill: #6b7280;
          font-size: 11px;
          font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
        }}
        .live-chart-legend {{
          display: flex;
          flex-wrap: wrap;
          gap: 10px 16px;
          color: var(--muted);
          font-size: 12px;
        }}
        .live-chart-legend span {{
          display: inline-flex;
          align-items: center;
          gap: 6px;
        }}
        .live-chart-chip {{
          width: 14px;
          height: 10px;
          border-radius: 999px;
          display: inline-block;
        }}
        .live-chart-chip.requests {{
          background: rgba(26, 115, 232, 0.78);
        }}
        .live-chart-chip.failures {{
          background: #d97706;
        }}
        .live-pill-grid {{
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(90px, 1fr));
          gap: 8px;
        }}
        .live-pill {{
          border: 1px solid #edf1f5;
          border-radius: 12px;
          padding: 8px 9px;
          background: #fafcff;
        }}
        .live-pill strong {{
          display: block;
          font-size: 17px;
          line-height: 1;
        }}
        .live-list {{
          display: grid;
          gap: 8px;
        }}
        .live-list-row {{
          display: grid;
          grid-template-columns: 28px minmax(0, 1fr);
          gap: 8px;
          align-items: start;
          padding: 8px 0;
          border-bottom: 1px solid #edf1f5;
        }}
        .live-list-row:last-child {{
          border-bottom: none;
          padding-bottom: 0;
        }}
        .live-list-rank {{
          width: 24px;
          height: 24px;
          border-radius: 999px;
          background: #eef3fd;
          color: #174ea6;
          font-size: 12px;
          font-weight: 800;
          display: inline-flex;
          align-items: center;
          justify-content: center;
        }}
        .live-list-main {{
          min-width: 0;
        }}
        .live-table-card table {{
          border-radius: 12px;
        }}
        .overlay {{
          position: fixed;
          inset: 0;
          background: rgba(15, 23, 42, 0.45);
          display: none;
          align-items: center;
          justify-content: center;
          padding: 14px;
          z-index: 999;
        }}
        .overlay.open {{
          display: flex;
        }}
        .modal {{
          width: min(980px, 100%);
          max-height: 92vh;
          overflow: hidden;
          background: white;
          border-radius: 18px;
          box-shadow: 0 22px 56px rgba(60, 64, 67, 0.18);
          border: 1px solid #d8e0ea;
          display: flex;
          flex-direction: column;
        }}
        .modal-head {{
          display: flex;
          justify-content: space-between;
          gap: 10px;
          align-items: center;
          padding: 12px 14px;
          border-bottom: 1px solid #e8edf3;
          position: sticky;
          top: 0;
          background: white;
        }}
        .modal-body {{
          padding: 14px;
          overflow: auto;
          max-height: calc(92vh - 62px);
        }}
        .modal-title {{
          margin: 0;
          font-size: 17px;
          font-weight: 800;
        }}
        .icon-btn {{
          background: transparent;
          color: var(--ink);
          border: 1px solid #d6cab8;
          width: 34px;
          height: 34px;
          border-radius: 10px;
          padding: 0;
        }}
        .form-grid {{
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 10px;
        }}
        .form-grid label {{
          display: flex;
          flex-direction: column;
          gap: 6px;
          font-size: 13px;
          font-weight: 700;
        }}
        .help-label {{
          display: inline-flex;
          align-items: center;
          gap: 6px;
          flex-wrap: wrap;
        }}
        .help-tip {{
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 18px;
          height: 18px;
          border-radius: 999px;
          border: 1px solid #c9d6eb;
          background: #f8fbff;
          color: #1a73e8;
          font-size: 10px;
          font-weight: 900;
          cursor: help;
          outline: none;
          flex-shrink: 0;
        }}
        .help-tip:hover,
        .help-tip:focus {{
          border-color: #1a73e8;
          background: #edf4ff;
        }}
        .help-title {{
          display: block;
          font-size: 11px;
          font-weight: 800;
          margin-bottom: 4px;
        }}
        .help-body {{
          display: block;
          color: var(--muted);
          font-size: 11px;
          font-weight: 500;
          line-height: 1.5;
        }}
        .help-example {{
          display: block;
          margin-top: 6px;
          padding-top: 6px;
          border-top: 1px solid #edf2f8;
          color: #334155;
          font-size: 11px;
          font-weight: 600;
        }}
        .help-example code {{
          font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
          font-size: 10px;
        }}
        .floating-help {{
          position: fixed;
          left: 0;
          top: 0;
          width: min(320px, calc(100vw - 24px));
          padding: 10px 12px;
          border-radius: 14px;
          border: 1px solid #d9e4f2;
          background: #fff;
          color: var(--ink);
          box-shadow: 0 20px 38px rgba(60, 64, 67, 0.18);
          text-align: left;
          z-index: 1200;
          opacity: 0;
          transform: translateY(6px);
          pointer-events: none;
          transition: opacity 0.16s ease, transform 0.16s ease;
        }}
        .floating-help.open {{
          opacity: 1;
          transform: translateY(0);
        }}
        .form-grid .full {{
          grid-column: 1 / -1;
        }}
        .form-grid input,
        .form-grid textarea,
        .form-grid select {{
          width: 100%;
          border: 1px solid #d2d8e0;
          border-radius: 10px;
          padding: 8px 10px;
          font: inherit;
          background: #fff;
        }}
        .form-grid textarea {{
          min-height: 78px;
          resize: vertical;
          font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
          font-size: 12px;
        }}
        .check-grid {{
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 8px;
        }}
        .check-item {{
          display: flex;
          gap: 8px;
          align-items: flex-start;
          padding: 8px 10px;
          border-radius: 12px;
          background: #f8fafd;
          border: 1px solid #e3e9f1;
        }}
        .check-item input {{
          width: auto;
          margin-top: 2px;
        }}
        .muted {{
          color: var(--muted);
          font-size: 12px;
          line-height: 1.5;
        }}
        .detail-box {{
          background: #f8fafd;
          border: 1px solid #e4e9f0;
          border-radius: 12px;
          padding: 10px;
        }}
        .detail-box pre {{
          margin: 0;
          white-space: pre-wrap;
          word-break: break-word;
          font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
          font-size: 11px;
        }}
        .output-flow {{
          border: 1px solid #dbe5f2;
          border-radius: 14px;
          background: linear-gradient(180deg, #f8fafd 0%, #fff 100%);
          padding: 12px;
        }}
        .output-flow-head {{
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 10px;
          margin-bottom: 10px;
        }}
        .output-flow-title {{
          font-weight: 800;
          font-size: 13px;
        }}
        .output-flow-subtitle {{
          color: var(--muted);
          font-size: 11px;
          margin-top: 3px;
        }}
        .output-rule {{
          display: none;
        }}
        .output-rule.is-active {{
          display: block;
        }}
        .pseudo-code {{
          margin: 0;
          padding: 10px;
          border-radius: 10px;
          background: #111827;
          color: #e5e7eb;
          border: 1px solid #0f172a;
          font-family: "IBM Plex Mono", "SFMono-Regular", monospace;
          font-size: 11px;
          line-height: 1.55;
          white-space: pre-wrap;
          word-break: break-word;
        }}
        .pseudo-code .keyword {{
          color: #93c5fd;
        }}
        .pseudo-code .value {{
          color: #86efac;
        }}
        .pseudo-code .fallback {{
          color: #fde68a;
        }}
        .output-mode-note {{
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 8px;
          margin-top: 10px;
        }}
        .output-mode-note div {{
          border: 1px solid #e3e9f1;
          border-radius: 10px;
          background: #fff;
          padding: 8px;
          font-size: 11px;
          color: var(--muted);
        }}
        .output-mode-note strong {{
          display: block;
          color: var(--ink);
          font-size: 11px;
          margin-bottom: 3px;
        }}
        .output-config {{
          border: 1px solid #dbe5f2;
          border-radius: 14px;
          background: #f8fafd;
          padding: 12px;
        }}
        .output-config-head {{
          margin-bottom: 10px;
        }}
        .output-config-title {{
          font-size: 13px;
          font-weight: 800;
        }}
        .output-config-note {{
          color: var(--muted);
          font-size: 11px;
          margin-top: 3px;
        }}
        .stack {{
          display: flex;
          flex-direction: column;
          gap: 10px;
        }}
        .auth-method-card {{
          border: 1px solid #dbe5f2;
          border-radius: 14px;
          background: #f8fafd;
          padding: 12px;
        }}
        .auth-method-head {{
          display: flex;
          justify-content: space-between;
          gap: 10px;
          align-items: center;
          margin-bottom: 10px;
        }}
        .scope-grid {{
          display: grid;
          grid-template-columns: repeat(2, minmax(0, 1fr));
          gap: 8px;
        }}
        .mini-check {{
          display: flex;
          gap: 8px;
          align-items: flex-start;
          padding: 8px 10px;
          border: 1px solid #e1e7ef;
          border-radius: 12px;
          background: #fff;
        }}
        .mini-check input {{
          width: auto;
          margin-top: 2px;
        }}
        .route-target-grid {{
          grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
          gap: 6px;
        }}
        .mini-check.compact-target {{
          align-items: center;
          padding: 6px 8px;
          border-radius: 10px;
          line-height: 1.25;
        }}
        .mini-check.compact-target .target-line {{
          display: flex;
          align-items: center;
          gap: 6px;
          min-width: 0;
          font-size: 12px;
        }}
        .mini-check.compact-target .target-service {{
          color: var(--muted);
          white-space: nowrap;
        }}
        .mini-check.compact-target .target-endpoint {{
          font-weight: 700;
          min-width: 0;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }}
        @media (max-width: 1100px) {{
          .hero {{
            flex-direction: column;
            align-items: flex-start;
          }}
          .meta-box {{
            width: 100%;
          }}
        }}
        @media (max-width: 900px) {{
          .sidebar-backdrop {{
            display: block;
          }}
          .sidebar {{
            display: flex;
          }}
          body.sidebar-open .sidebar {{
            transform: translateX(0);
          }}
          body.sidebar-open .sidebar-backdrop {{
            opacity: 1;
            pointer-events: auto;
          }}
          .mobile-bar {{
            position: sticky;
            top: 0;
            z-index: 30;
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 14px 16px;
            background: rgba(246, 248, 252, 0.92);
            border-bottom: 1px solid rgba(221, 227, 234, 0.88);
            backdrop-filter: blur(16px);
          }}
          .mobile-bar-title {{
            font-size: 15px;
            font-weight: 800;
          }}
          .mobile-bar-subtitle {{
            color: var(--muted);
            font-size: 11px;
            margin-top: 2px;
          }}
          .desktop-tabs {{
            display: none;
          }}
          .wrap {{
            padding: 18px 12px 20px;
          }}
          .hero, .section-head {{
            flex-direction: column;
            align-items: flex-start;
          }}
          .form-grid, .check-grid, .scope-grid {{
            grid-template-columns: 1fr;
          }}
          .output-mode-note {{
            grid-template-columns: 1fr;
          }}
          .meta-box {{
            width: 100%;
          }}
          .chip {{
            border-radius: 14px;
            align-items: flex-start;
          }}
          .live-head {{
            flex-direction: column;
            align-items: flex-start;
          }}
          .live-report-grid {{
            grid-template-columns: 1fr;
          }}
          .section {{
            padding: 14px;
          }}
          table {{
            min-width: 640px;
          }}
        }}
      </style>
    </head>
    <body>
      <div class="app-shell">
        <div class="sidebar-backdrop" id="sidebar-backdrop"></div>
        <aside class="sidebar" id="admin-sidebar">
          <div class="sidebar-brand">
            <div class="sidebar-kicker">Gateway Control</div>
            <h1 class="sidebar-title">NapiGate</h1>
            <div class="sidebar-subtitle">Admin panel for routes, clients, output profiles, and security.</div>
          </div>
          <nav class="sidebar-nav" aria-label="Admin sections">
            <button class="tab active" data-tab="live">Live</button>
            <button class="tab" data-tab="config">Config</button>
            <button class="tab" data-tab="audit">Audit</button>
            <button class="tab" data-tab="services">Services</button>
            <button class="tab" data-tab="routes">Routes</button>
            <button class="tab" data-tab="output">Output</button>
            <button class="tab" data-tab="clients">Clients</button>
            <button class="tab" data-tab="users">Users</button>
            <button class="tab" data-tab="roles">Roles</button>
            <a class="tab logout" href="/__logout">Logout</a>
          </nav>
          <div class="sidebar-meta">
            <div class="chip">User: <strong>{escape(principal.username)}</strong></div>
            <div class="chip">Services Config: <span class="mono">{escape(str(state["config_paths"]["services"]))}</span></div>
            <div class="chip">Security Config: <span class="mono">{escape(str(state["config_paths"]["security"]))}</span></div>
            <div class="chip">State Store: <strong>{escape(str(state["store"].get("mode", "file")).upper())}</strong></div>
          </div>
        </aside>

        <main class="main-shell">
          <div class="mobile-bar">
            <button class="mobile-toggle" id="sidebar-toggle" type="button" aria-controls="admin-sidebar" aria-expanded="false">☰</button>
            <div>
              <div class="mobile-bar-title">NapiGate Admin</div>
              <div class="mobile-bar-subtitle">Routes, clients, output profiles, and security.</div>
            </div>
          </div>

          <div class="wrap">
            <div class="hero">
              <div>
                <h1 class="title">NapiGate Admin Panel</h1>
                <div class="subtitle">
                  Manage gateway settings, services, endpoint targets, gateway routes, output profiles, scoped gateway clients, users, and roles
                </div>
              </div>
              <div class="meta-box">
                <div class="chip">User: <strong>{escape(principal.username)}</strong></div>
                <div class="chip">Services Config: <span class="mono">{escape(str(state["config_paths"]["services"]))}</span></div>
                <div class="chip">Security Config: <span class="mono">{escape(str(state["config_paths"]["security"]))}</span></div>
                <div class="chip">State Store: <strong>{escape(str(state["store"].get("mode", "file")).upper())}</strong></div>
              </div>
            </div>
            {flash}
            <div id="admin-flash"></div>
            <div class="panel">
              <nav class="tabs desktop-tabs" aria-label="Admin sections">
                <button class="tab active" data-tab="live">Live</button>
                <button class="tab" data-tab="config">Config</button>
                <button class="tab" data-tab="audit">Audit</button>
                <button class="tab" data-tab="services">Services</button>
                <button class="tab" data-tab="routes">Routes</button>
                <button class="tab" data-tab="output">Output</button>
                <button class="tab" data-tab="clients">Clients</button>
                <button class="tab" data-tab="users">Users</button>
                <button class="tab" data-tab="roles">Roles</button>
                <a class="tab logout" href="/__logout">Logout</a>
              </nav>
              <section class="section active" data-section="live">
            <div class="section-head">
              <div>
                <h2 class="section-title">Live</h2>
                <div class="section-note">See a live operational snapshot before editing services, clients, users, or roles.</div>
              </div>
              <div class="actions" id="live-top-actions"></div>
            </div>
            <div id="live-wrap"></div>
              </section>

              <section class="section" data-section="config">
            <div class="section-head">
              <div>
                <h2 class="section-title">Config</h2>
                <div class="section-note">Keep gateway-wide operational settings here so the runtime and monitor stay aligned.</div>
              </div>
            </div>
            <div id="config-wrap"></div>
              </section>

              <section class="section" data-section="audit">
            <div class="section-head">
              <div>
                <h2 class="section-title">Audit</h2>
                <div class="section-note">Track admin-side config and security mutations with actor, target, listener, and summary details.</div>
              </div>
              <div class="actions" id="audit-top-actions"></div>
            </div>
            <div class="card" id="audit-wrap"></div>
              </section>

              <section class="section" data-section="services">
            <div class="section-head">
              <div>
                <h2 class="section-title">Services</h2>
                <div class="section-note">Review upstream services first, then manage their endpoint targets in a modal table.</div>
              </div>
              <div class="actions" id="services-top-actions"></div>
            </div>
            <div class="card" id="services-table-wrap"></div>
              </section>

              <section class="section" data-section="routes">
            <div class="section-head">
              <div>
                <h2 class="section-title">Routes</h2>
                <div class="section-note">Expose public gateway paths here, then attach them to one or more service endpoints with single, round-robin, failover, or parallel race strategy.</div>
              </div>
              <div class="actions" id="routes-top-actions"></div>
            </div>
            <div class="card" id="routes-table-wrap"></div>
              </section>

              <section class="section" data-section="clients">
            <div class="section-head">
              <div>
                <h2 class="section-title">Clients</h2>
                <div class="section-note">Define each client once, attach one or more auth methods, and choose whether it reaches all services, selected services, or selected endpoints.</div>
              </div>
              <div class="actions" id="clients-top-actions"></div>
            </div>
            <div class="card" id="clients-table-wrap"></div>
              </section>

              <section class="section" data-section="output">
            <div class="section-head">
              <div>
                <h2 class="section-title">Output</h2>
                <div class="section-note">Define reusable output profiles so routes can stay passthrough, use a standard JSON envelope, or publish JSONP safely.</div>
              </div>
              <div class="actions" id="output-top-actions"></div>
            </div>
            <div class="card" id="output-table-wrap"></div>
              </section>

              <section class="section" data-section="users">
            <div class="section-head">
              <div>
                <h2 class="section-title">Users</h2>
                <div class="section-note">Users sign in through the control-plane login page and receive access through assigned roles.</div>
              </div>
              <div class="actions" id="users-top-actions"></div>
            </div>
            <div class="card" id="users-table-wrap"></div>
              </section>

              <section class="section" data-section="roles">
            <div class="section-head">
              <div>
                <h2 class="section-title">Roles</h2>
                <div class="section-note">Each role can define monitor, admin, service-management, and security-management access.</div>
              </div>
              <div class="actions" id="roles-top-actions"></div>
            </div>
            <div class="card" id="roles-table-wrap"></div>
              </section>
            </div>
          </div>
        </main>
      </div>

      <div class="floating-help" id="help-tooltip" hidden></div>

      <div class="overlay" id="modal-overlay">
        <div class="modal">
          <div class="modal-head">
            <h3 class="modal-title" id="modal-title"></h3>
            <button class="icon-btn" id="modal-close" type="button">×</button>
          </div>
          <div class="modal-body" id="modal-body"></div>
        </div>
      </div>

      <script>
        let STATE = {state_json};
        let permissions = new Set(STATE.principal.permissions);
        const overlay = document.getElementById("modal-overlay");
        const modalTitle = document.getElementById("modal-title");
        const modalBody = document.getElementById("modal-body");
        const modalClose = document.getElementById("modal-close");
        const adminFlash = document.getElementById("admin-flash");
        const sidebar = document.getElementById("admin-sidebar");
        const sidebarToggle = document.getElementById("sidebar-toggle");
        const sidebarBackdrop = document.getElementById("sidebar-backdrop");
        const helpTooltip = document.getElementById("help-tooltip");

        function esc(value) {{
          return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;");
        }}

        function jsonText(value) {{
          if (value == null) return "";
          if (Array.isArray(value) && value.length === 0) return "";
          if (typeof value === "object" && Object.keys(value).length === 0) return "";
          return JSON.stringify(value, null, 2);
        }}

        function configValueText(value) {{
          if (value === "") return "";
          if (value == null) return "null";
          if (typeof value === "string") return JSON.stringify(value);
          return JSON.stringify(value, null, 2);
        }}

        function arg(value) {{
          return encodeURIComponent(String(value ?? ""));
        }}

        function has(permission) {{
          return permissions.has(permission);
        }}

        const FIELD_HELP = {{
          service_name: {{ title: "Service Name", text: "A stable internal identifier used in config, logs, scopes, and templates.", example: "billing_api" }},
          service_protocol: {{ title: "Service Protocol", text: "Select the upstream transport family. HTTP and gRPC run today. Other APISIX-inspired types can be declared now and enforced later.", example: "http or grpc" }},
          base_url: {{ title: "Base URL", text: "For HTTP, WebSocket, gRPC-Web, and HTTP/3 services this is the upstream URL or base URL. For gRPC, TCP, and UDP services this field carries the upstream target such as host:port.", example: "https://api.example.com or grpc.internal:50051" }},
          timeout_seconds: {{ title: "Timeout Seconds", text: "Maximum upstream wait time before the gateway aborts the request.", example: "15" }},
          verify_ssl: {{ title: "Verify SSL", text: "Reject upstream TLS certificates that are invalid, expired, or signed by an unknown CA.", example: "On for public HTTPS APIs" }},
          trust_env_proxy: {{ title: "Trust Env Proxy", text: "Allow upstream requests to use HTTP_PROXY or HTTPS_PROXY from the runtime environment.", example: "Enable only when the container must reach APIs through a proxy" }},
          forward_napigate_headers: {{ title: "Forward NapiGate Headers", text: "Send internal X-NapiGate route and client metadata headers to the upstream service when enabled.", example: "Turn off when the upstream should only receive business headers like Token or Cookie" }},
          variables_yaml: {{ title: "Variables", text: "Reusable values injected into templates and pre_call code for this service.", example: '{{ "client_id": "demo-client" }}' }},
          headers_yaml: {{ title: "Headers", text: "Static or templated headers added to every upstream request in this service.", example: '{{ "X-Tenant": "{{ vars.tenant }}" }}' }},
          auth_required: {{ title: "Protect This Route", text: "Require a matching enabled client auth method before this public route can be called.", example: "Turn on for partner or internal APIs" }},
          cors_enabled: {{ title: "Enable CORS", text: "Serve browser-friendly cross-origin headers and automatic OPTIONS preflight responses.", example: "Enable for frontend apps calling the gateway from another domain" }},
          cors_allow_origins: {{ title: "Allowed Origins", text: "Origins allowed to call this service from browsers. Use * only for public, non-credentialed access.", example: "https://app.example.com" }},
          cors_allow_methods: {{ title: "Allowed Methods", text: "Methods exposed to browsers during preflight. Leave blank to use the endpoint methods automatically.", example: "GET, POST, PATCH" }},
          cors_allow_headers: {{ title: "Allowed Headers", text: "Request headers browsers may send. Leave blank to reflect preflight-requested headers.", example: "Authorization, Content-Type, X-Trace-ID" }},
          cors_expose_headers: {{ title: "Expose Headers", text: "Response headers browsers are allowed to read from JavaScript.", example: "X-Request-ID, X-RateLimit-Remaining" }},
          cors_allow_credentials: {{ title: "Allow Credentials", text: "Permit cookies or browser-managed auth headers on cross-origin requests.", example: "Use with explicit origins, not a wildcard frontend" }},
          cors_max_age_seconds: {{ title: "CORS Max Age", text: "How long browsers may cache the preflight result before sending OPTIONS again.", example: "600" }},
          rate_limit_enabled: {{ title: "Enable Rate Limit", text: "Protect this service against bursts and abuse with an in-memory request window.", example: "Useful for public endpoints or expensive upstreams" }},
          rate_limit_requests: {{ title: "Allowed Requests", text: "Maximum number of accepted requests inside one rate-limit window.", example: "120" }},
          rate_limit_window_seconds: {{ title: "Window Seconds", text: "Length of the sliding rate-limit window in seconds.", example: "60" }},
          rate_limit_scope: {{ title: "Rate Limit Scope", text: "Choose whether the bucket is tracked by authenticated client, IP address, or client then IP fallback.", example: "client_or_ip" }},
          endpoint_name: {{ title: "Endpoint Name", text: "A stable internal target name used by routes, scopes, logs, and templates.", example: "user_by_id" }},
          upstream_path: {{ title: "Upstream Path", text: "For HTTP targets this is the upstream path or absolute URL. For gRPC targets this field carries the full method, such as /package.Service/Method. Leave blank only for local response endpoints.", example: "/users/{{ path.id }} or /helloworld.Greeter/SayHello" }},
          endpoint_headers_yaml: {{ title: "Endpoint Headers", text: "Headers added only for this endpoint after template rendering.", example: '{{ "Authorization": "Bearer {{ vars.access_token }}" }}' }},
          query_yaml: {{ title: "Endpoint Query", text: "Query parameters forced or templated by the gateway for this endpoint.", example: '{{ "expand": "profile" }}' }},
          pre_call_cache_ttl_seconds: {{ title: "Pre-call Cache TTL", text: "Cache successful pre_call variable output in memory for this many seconds.", example: "300" }},
          pre_call_cache_key: {{ title: "Pre-call Cache Key", text: "Optional template or literal cache key if the default service:endpoint key is too broad.", example: "{{ path.id }}" }},
          pre_call_code: {{ title: "Pre-call Code", text: "Trusted Python executed before proxying so you can fetch tokens, compute values, or enrich variables.", example: 'set_var("access_token", "demo-token")' }},
          endpoint_slug: {{ title: "Endpoint Slug", text: "Stable machine-friendly identifier for automation, success hooks, downstream mapping, and admin APIs.", example: "user_by_id" }},
          route_name: {{ title: "Route Name", text: "A stable internal name for the public gateway route.", example: "get_user" }},
          route_slug: {{ title: "Route Slug", text: "Machine-friendly route identifier used in logs, headers, and admin state.", example: "get-user" }},
          route_protocol: {{ title: "Route Protocol", text: "Select the incoming route protocol contract. Only HTTP ingress is implemented today. WebSocket, gRPC, gRPC-Web, and HTTP/3 can already be declared explicitly.", example: "http or websocket" }},
          methods: {{ title: "Methods", text: "Comma-separated HTTP methods accepted by this gateway route.", example: "GET, POST" }},
          gateway_path: {{ title: "Gateway Path", text: "The public path exposed by NapiGate. Use path tokens like {{id}} or {{path:path}}.", example: "/v1/users/{{id}}" }},
          route_strategy: {{ title: "Route Strategy", text: "single calls one target, round_robin rotates targets, failover tries the next target on 5xx or connection failure, parallel_race calls targets concurrently and returns the first healthy response.", example: "failover" }},
          route_targets: {{ title: "Route Targets", text: "Select one or more service endpoints that this public route can call.", example: "protected_httpbin / user_by_id" }},
          output_profile: {{ title: "Output Profile", text: "Choose a reusable response-shaping profile for this route. Leave blank to keep the target response untouched.", example: "standard_json" }},
          endpoint_output_profile: {{ title: "Output Profile", text: "Default response-shaping profile for this endpoint. Routes that do not set their own output profile will use this value.", example: "standard_json" }},
          response_cache_ttl_seconds: {{ title: "Response Cache TTL", text: "Cache successful responses at this scope in memory for this many seconds. Runtime checks endpoint cache first, then service, then route.", example: "60" }},
          response_cache_vary_headers: {{ title: "Cache Vary Headers", text: "Header names that should produce separate cache entries for the same request when this scope's cache is enabled.", example: "Accept-Language, X-Tenant" }},
          response_cache_methods: {{ title: "Cache Methods", text: "HTTP methods eligible for response caching when this scope's cache TTL is enabled.", example: "GET, HEAD" }},
          response_cache_vary_by_client: {{ title: "Cache Per Client", text: "Keep a separate cache bucket for each authenticated gateway client when this scope's cache is enabled.", example: "Recommended for scoped partner APIs" }},
          success_hook_url: {{ title: "Success Hook URL", text: "Optional async webhook triggered only after a successful gateway response. Useful for billing or financial systems.", example: "https://billing.example.com/hooks/usage" }},
          success_hook_timeout_seconds: {{ title: "Success Hook Timeout", text: "Maximum wait time for the async success callback worker before it marks the delivery as failed.", example: "5" }},
          success_hook_event_type: {{ title: "Success Hook Event Type", text: "Business label sent to the downstream webhook so it can route or classify the event.", example: "financial" }},
          success_hook_headers_yaml: {{ title: "Success Hook Headers", text: "Static headers sent with the async success callback request.", example: '{{ "X-Signature": "demo" }}' }},
          success_hook_include_response_body: {{ title: "Include Response Body", text: "Attach the rendered response body to the async success event payload.", example: "Enable only when downstream accounting needs the response payload" }},
          success_hook_include_request_body: {{ title: "Include Request Body", text: "Attach the incoming request body to the async success event payload.", example: "Useful for payment confirmation requests" }},
          client_title: {{ title: "Client Title", text: "Readable display name for operators and logs.", example: "Mobile App" }},
          client_slug: {{ title: "Client Slug", text: "Stable automation identifier for admin APIs and external control planes. Use this instead of the display name.", example: "mobile-app" }},
          client_code: {{ title: "Client Code", text: "Stable identifier injected upstream and used in OAuth tokens, scopes, and logs.", example: "mobile_app" }},
          client_enabled: {{ title: "Client Enabled", text: "Disabled clients stay in config but can no longer authenticate.", example: "Temporarily disable a partner without deleting its credentials" }},
          ip_allowlist: {{ title: "IP Allowlist", text: "Optional CIDR ranges allowed to use this client. Leave blank for no IP restriction.", example: "10.0.0.0/24" }},
          access_mode: {{ title: "Access Scope", text: "Choose whether this client can reach all services, selected services, or selected endpoints only.", example: "services" }},
          allowed_services: {{ title: "Allowed Services", text: "Service-level scope grants this client access to every endpoint inside selected services.", example: "protected_httpbin" }},
          allowed_endpoints: {{ title: "Allowed Endpoints", text: "Endpoint-level scope is the most restrictive option and is useful for partners or narrow integrations.", example: "protected_httpbin / protected_headers" }},
          auth_methods: {{ title: "Authentication Methods", text: "A client may expose multiple auth methods so different consumers can use the same scoped identity.", example: "api_key plus oauth_client_credentials" }},
          auth_method_title: {{ title: "Method Title", text: "Readable label shown in admin views.", example: "Primary API Key" }},
          auth_method_code: {{ title: "Method Code", text: "Stable identifier for logs and upstream metadata headers.", example: "portal_api_key" }},
          auth_type: {{ title: "Auth Type", text: "How the gateway validates incoming credentials for this client.", example: "api_key" }},
          auth_method_enabled: {{ title: "Method Enabled", text: "Disabled methods remain saved but are ignored during authentication.", example: "Use this during credential rotation" }},
          api_key_secret: {{ title: "API Key Secret", text: "Shared secret compared against configured headers, query params, or cookies.", example: "key_f8Xn2..." }},
          api_key_header_names: {{ title: "API Key Header Names", text: "Header names that may carry the API key.", example: "X-API-Key, X-App-Key" }},
          api_key_query_params: {{ title: "API Key Query Params", text: "Query-string parameter names that may carry the API key.", example: "api_key" }},
          api_key_cookie_names: {{ title: "API Key Cookie Names", text: "Cookie names that may carry the API key.", example: "api_key_cookie" }},
          bearer_token: {{ title: "Bearer Token", text: "Expected bearer token value for this method.", example: "tok_A1b2..." }},
          bearer_allow_authorization_header: {{ title: "Allow Authorization Header", text: "Accept the standard Authorization: Bearer <token> header for this method.", example: "Recommended for most bearer-token clients" }},
          bearer_header_names: {{ title: "Extra Bearer Headers", text: "Alternative header names that may hold the bearer token.", example: "X-Access-Token" }},
          bearer_query_params: {{ title: "Bearer Query Params", text: "Query-string parameter names that may carry the bearer token.", example: "access_token" }},
          bearer_cookie_names: {{ title: "Bearer Cookie Names", text: "Cookie names that may carry the bearer token.", example: "access_token" }},
          basic_username: {{ title: "Basic Username", text: "Expected username for HTTP Basic authentication.", example: "demo-user" }},
          basic_password: {{ title: "Basic Password", text: "Expected password for HTTP Basic authentication.", example: "pwd_X7..." }},
          header_key_name: {{ title: "Header Name", text: "The custom header used for header_key auth.", example: "X-Partner-Token" }},
          header_key_secret: {{ title: "Header Secret", text: "Expected secret value for the custom header.", example: "hdr_9s..." }},
          oauth_client_id: {{ title: "OAuth Client ID", text: "Client credential identifier accepted by the built-in token endpoint.", example: "cli_public_web" }},
          oauth_client_secret: {{ title: "OAuth Client Secret", text: "Secret paired with the client ID for token issuance.", example: "sec_4J..." }},
          oauth_token_ttl_seconds: {{ title: "Token TTL", text: "Lifetime of issued access tokens in seconds.", example: "3600" }},
          external_auth_script: {{ title: "External Auth Script", text: "Trusted Python that can call another auth service and decide allow, deny, or skip.", example: 'allow(source="external_service")' }},
          external_cache_ttl_seconds: {{ title: "External Auth Cache TTL", text: "Cache positive external auth results in memory for this many seconds.", example: "60" }},
          external_cache_key: {{ title: "External Auth Cache Key", text: "Optional explicit cache key when the default request-based key is not precise enough.", example: "{{ headers.Authorization }}" }},
          role_name: {{ title: "Role Name", text: "Stable role identifier assigned to users.", example: "operator" }},
          role_permissions: {{ title: "Permissions", text: "Choose which admin and monitor capabilities belong to this role.", example: "monitor_access plus services_manage" }},
          username: {{ title: "Username", text: "Login name for admin and monitor access.", example: "ops_admin" }},
          password: {{ title: "Password", text: "Plain password typed here and stored as a PBKDF2 hash in security.yaml.", example: "Leave blank during edit to keep the current password" }},
          user_enabled: {{ title: "User Enabled", text: "Disabled users stay in config but can no longer sign in.", example: "Use to suspend access without deleting history" }},
          user_roles: {{ title: "Roles", text: "Assigned roles define the permissions this user receives after login.", example: "admin, monitor" }},
          profile_slug: {{ title: "Output Profile Slug", text: "Stable machine-friendly identifier used by endpoints to select this profile.", example: "standard_json" }},
          profile_title: {{ title: "Output Profile Title", text: "Readable label shown in the admin UI.", example: "Standard JSON Envelope" }},
          profile_type: {{ title: "Output Profile Type", text: "Choose passthrough, standard JSON envelope wrapping, JSONP callback output, or a safe custom transform rule.", example: "custom" }},
          profile_enabled: {{ title: "Output Profile Enabled", text: "Disabled output profiles stay saved but cannot transform endpoint responses until re-enabled.", example: "Turn off temporarily during a response-contract rollout" }},
          success_key: {{ title: "Success Key", text: "Key name that should contain the boolean success flag in a JSON envelope.", example: "success" }},
          data_key: {{ title: "Data Key", text: "Key name that should contain the upstream payload in a JSON envelope.", example: "data" }},
          message_key: {{ title: "Message Key", text: "Key name used for human-readable response messages.", example: "message" }},
          error_key: {{ title: "Error Key", text: "Key name used for error details when the endpoint fails.", example: "error" }},
          passthrough_keys: {{ title: "Existing Envelope Keys", text: "If the upstream JSON already contains these keys, NapiGate will not wrap it again.", example: "success, data, message" }},
          source_success_key: {{ title: "Success Source Path", text: "Optional dot path read from the upstream payload to compute the envelope success flag.", example: "meta.ok" }},
          message_source_keys: {{ title: "Message Source Paths", text: "Comma-separated dot paths checked in order to populate the envelope message before falling back to the message key.", example: "meta.message, error.message" }},
          error_source_keys: {{ title: "Error Source Paths", text: "Comma-separated dot paths checked in order to populate the envelope error field when the response is not successful.", example: "error.detail, meta.error" }},
          data_fields_yaml: {{ title: "Mapped Data Fields", text: "Optional output field mapping where each key becomes part of the envelope data object. Each value can be either a plain source path or a template string with {{{{field}}}} placeholders read from the upstream payload.", example: '{{ "user": "payload.user", "fullname": "{{{{Name}}}} {{{{family}}}}", "request_id": "{{{{meta.request_id}}}}" }}' }},
          empty_value_yaml: {{ title: "Empty Value", text: "Fallback YAML or JSON value used when a mapped source path is missing or null.", example: "null" }},
          custom_validation_mode: {{ title: "Custom Success Detection", text: "Choose whether custom transform code should treat the upstream input as successful by HTTP status code or by checking a payload key first.", example: "payload_key" }},
          custom_validation_source_key: {{ title: "Validation Source Path", text: "Dot path read from the upstream payload before custom transform code runs when detection mode is payload_key.", example: "IsSuccessful" }},
          custom_validation_expected_value_yaml: {{ title: "Expected Success Value", text: "YAML or JSON scalar that the selected payload key must match for validation to pass. Use true for boolean success flags such as IsSuccessful.", example: "true" }},
          custom_validation_error_source_keys: {{ title: "Validation Error Paths", text: "Comma-separated dot paths checked in order to extract a failure message for custom profiles before the transform code branches on validation.", example: "ErrorDesc, WarningDesc" }},
          transform_code: {{ title: "Custom Transform Code", text: "Safe Python-like code for output shaping. It must assign the final body to result. Only assignments, if/else, literals, indexing, and safe helpers like pick(), pick_first(), exists(), success(), and text() are allowed.", example: 'result = {{ "message": pick("message", detail), "error": pick("error", detail) }}' }},
          jsonp_callback_param: {{ title: "JSONP Callback Param", text: "Query-string parameter name that carries the JavaScript callback function.", example: "callback" }},
          jsonp_default_callback: {{ title: "JSONP Default Callback", text: "Fallback callback name used when the request omits the callback parameter.", example: "callback" }},
          output_headers_yaml: {{ title: "Profile Headers", text: "Headers applied after the output profile transforms the response.", example: '{{ "Cache-Control": "no-store" }}' }},
          log_retention_hours: {{ title: "Log Retention Hours", text: "When set, request log rows and rotated file logs older than this many hours are deleted by an hourly cleanup worker. Leave blank for unlimited retention.", example: "168" }},
          trusted_proxy_ips: {{ title: "Trusted Proxy IPs", text: "Only forwarded headers from these direct proxy IPs or CIDRs are trusted for client IP, host, and scheme detection.", example: "127.0.0.1, 172.24.0.0/12, 192.168.0.0/16, 10.0.0.0/8" }},
          gateway_response_mode: {{ title: "Gateway Response Mode", text: "Choose the default detail-only error body, a selected output profile, or the legacy inline envelope fields below.", example: "profile" }},
          gateway_response_output_profile: {{ title: "Gateway Response Output Profile", text: "When mode is profile, NapiGate first builds a gateway error payload with detail, message, error, status_code, and status, then sends that payload through the selected output profile.", example: "gateway_error_contract" }},
          gateway_response_empty_value: {{ title: "Gateway Empty Value", text: "Fallback value written into empty envelope fields for gateway-generated errors. Blank means an empty string.", example: 'null or ""' }},
          gateway_response_headers: {{ title: "Gateway Response Headers", text: "Extra headers merged into gateway-generated public error responses after the JSON body is rendered.", example: '{{ "Cache-Control": "no-store" }}' }},
        }};

        function helpMarkup(key) {{
          const info = FIELD_HELP[key];
          if (!info) return "";
          return `
            <span
              class="help-tip"
              tabindex="0"
              role="button"
              aria-label="${{esc(info.title)}} help"
              data-help-title="${{esc(info.title)}}"
              data-help-text="${{esc(info.text)}}"
              data-help-example="${{esc(info.example || "")}}"
            >?</span>
          `;
        }}

        let activeHelpAnchor = null;

        function setSidebarOpen(open) {{
          document.body.classList.toggle("sidebar-open", !!open);
          if (sidebarToggle) {{
            sidebarToggle.setAttribute("aria-expanded", open ? "true" : "false");
          }}
        }}

        function hideHelpTooltip() {{
          activeHelpAnchor = null;
          if (!helpTooltip) return;
          helpTooltip.classList.remove("open");
          helpTooltip.hidden = true;
          helpTooltip.innerHTML = "";
        }}

        function positionHelpTooltip(anchor) {{
          if (!helpTooltip || !anchor) return;
          const rect = anchor.getBoundingClientRect();
          const margin = 12;
          helpTooltip.style.left = "0px";
          helpTooltip.style.top = "0px";
          helpTooltip.hidden = false;
          helpTooltip.classList.add("open");
          const tooltipRect = helpTooltip.getBoundingClientRect();
          let left = rect.right - tooltipRect.width;
          if (left < margin) left = margin;
          if (left + tooltipRect.width > window.innerWidth - margin) {{
            left = window.innerWidth - tooltipRect.width - margin;
          }}
          let top = rect.bottom + 10;
          if (top + tooltipRect.height > window.innerHeight - margin) {{
            top = rect.top - tooltipRect.height - 10;
          }}
          if (top < margin) {{
            top = Math.max(margin, window.innerHeight - tooltipRect.height - margin);
          }}
          helpTooltip.style.left = `${{Math.round(left)}}px`;
          helpTooltip.style.top = `${{Math.round(top)}}px`;
        }}

        function showHelpTooltip(anchor) {{
          if (!helpTooltip || !anchor) return;
          activeHelpAnchor = anchor;
          const example = anchor.dataset.helpExample
            ? `<span class="help-example">Example: <code>${{esc(anchor.dataset.helpExample)}}</code></span>`
            : "";
          helpTooltip.innerHTML = `
            <span class="help-title">${{esc(anchor.dataset.helpTitle || "")}}</span>
            <span class="help-body">${{esc(anchor.dataset.helpText || "")}}</span>
            ${{example}}
          `;
          positionHelpTooltip(anchor);
        }}

        function bindHelpTips(root = document) {{
          root.querySelectorAll(".help-tip").forEach((tip) => {{
            if (tip.dataset.helpBound === "1") return;
            tip.dataset.helpBound = "1";
            tip.addEventListener("mouseenter", () => showHelpTooltip(tip));
            tip.addEventListener("focus", () => showHelpTooltip(tip));
            tip.addEventListener("mouseleave", () => {{
              if (activeHelpAnchor === tip) hideHelpTooltip();
            }});
            tip.addEventListener("blur", () => {{
              if (activeHelpAnchor === tip) hideHelpTooltip();
            }});
            tip.addEventListener("click", (event) => {{
              event.preventDefault();
              if (activeHelpAnchor === tip && !helpTooltip.hidden) {{
                hideHelpTooltip();
                return;
              }}
              showHelpTooltip(tip);
            }});
          }});
        }}

        function decorateHelp(root = modalBody) {{
          root.querySelectorAll("[data-help]").forEach((element) => {{
            if (element.querySelector(".help-label")) return;
            const anchor = element.querySelector("[data-help-anchor]") || element.querySelector("span, strong");
            const markup = helpMarkup(element.dataset.help || "");
            if (!anchor || !markup) return;
            const wrapper = document.createElement("span");
            wrapper.className = "help-label";
            wrapper.innerHTML = `${{anchor.outerHTML}}${{markup}}`;
            anchor.replaceWith(wrapper);
          }});
          bindHelpTips(root);
        }}

        let liveRows = Array.isArray(STATE.live?.logs) ? STATE.live.logs : [];
        let liveReport = STATE.live?.report && typeof STATE.live.report === "object" ? STATE.live.report : null;
        let liveConnectionState = STATE.live?.can_view ? "connecting" : "locked";
        let livePollTimer = null;
        let livePaused = false;

        function openModal(title, bodyHtml) {{
          modalTitle.textContent = title;
          modalBody.innerHTML = bodyHtml;
          decorateHelp(modalBody);
          hideHelpTooltip();
          overlay.classList.add("open");
        }}

        function closeModal() {{
          hideHelpTooltip();
          overlay.classList.remove("open");
          modalBody.innerHTML = "";
        }}

        modalClose.addEventListener("click", closeModal);
        overlay.addEventListener("click", (event) => {{
          if (event.target === overlay) closeModal();
        }});
        sidebarToggle?.addEventListener("click", () => {{
          setSidebarOpen(!document.body.classList.contains("sidebar-open"));
        }});
        sidebarBackdrop?.addEventListener("click", () => setSidebarOpen(false));
        document.addEventListener("click", (event) => {{
          if (!event.target.closest(".help-tip")) hideHelpTooltip();
        }});
        window.addEventListener("resize", () => {{
          if (activeHelpAnchor) {{
            positionHelpTooltip(activeHelpAnchor);
          }}
          if (window.innerWidth > 900) {{
            setSidebarOpen(false);
          }}
        }});
        window.addEventListener("scroll", () => {{
          if (activeHelpAnchor) positionHelpTooltip(activeHelpAnchor);
        }}, true);
        document.addEventListener("keydown", (event) => {{
          if (event.key !== "Escape") return;
          if (overlay.classList.contains("open")) {{
            closeModal();
            return;
          }}
          if (document.body.classList.contains("sidebar-open")) {{
            setSidebarOpen(false);
          }}
          hideHelpTooltip();
        }});

        const VALID_TABS = Array.from(new Set(Array.from(document.querySelectorAll(".tab[data-tab]")).map((tab) => tab.dataset.tab)));
        let activeTab = VALID_TABS.includes(window.location.hash.slice(1)) ? window.location.hash.slice(1) : "live";

        function showAdminNotice(message, type = "ok") {{
          if (!adminFlash) return;
          adminFlash.innerHTML = message
            ? `<div class="flash ${{type === "error" ? "error" : "ok"}}">${{esc(message)}}</div>`
            : "";
        }}

        function activateTab(tabName, options = {{ push: false }}) {{
          const target = VALID_TABS.includes(tabName) ? tabName : "live";
          activeTab = target;
          document.querySelectorAll(".tab[data-tab]").forEach((item) => {{
            item.classList.toggle("active", item.dataset.tab === target);
          }});
          document.querySelectorAll(".section").forEach((item) => {{
            item.classList.toggle("active", item.dataset.section === target);
          }});
          if (options.push && window.location.hash.slice(1) !== target) {{
            history.pushState({{ tab: target }}, "", `#${{target}}`);
          }}
          if (window.innerWidth <= 900) {{
            setSidebarOpen(false);
          }}
        }}

        document.querySelectorAll(".tab[data-tab]").forEach((tab) => {{
          tab.addEventListener("click", () => activateTab(tab.dataset.tab, {{ push: true }}));
        }});

        window.addEventListener("popstate", () => activateTab(window.location.hash.slice(1) || "live"));
        window.addEventListener("hashchange", () => activateTab(window.location.hash.slice(1) || "live"));
        activateTab(activeTab, {{ push: false }});

        function applyState(nextState) {{
          if (!nextState) return;
          STATE = nextState;
          permissions = new Set(STATE.principal.permissions);
          liveRows = Array.isArray(STATE.live?.logs) ? STATE.live.logs : liveRows;
          liveReport = STATE.live?.report && typeof STATE.live.report === "object" ? STATE.live.report : liveReport;
          renderServices();
          renderRoutes();
          renderOutputProfiles();
          renderClients();
          renderConfig();
          renderAudit();
          renderUsers();
          renderRoles();
          renderLive();
          activateTab(activeTab, {{ push: false }});
        }}

        function formPayload(form) {{
          return new URLSearchParams(new FormData(form));
        }}

        async function postAdminMutation(action, body) {{
          const response = await fetch(action, {{
            method: "POST",
            headers: {{
              "Accept": "application/json",
              "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
              "X-Requested-With": "XMLHttpRequest",
            }},
            body,
          }});
          const payload = await response.json().catch(() => ({{}}));
          if (!response.ok) {{
            throw new Error(payload.detail || `HTTP ${{response.status}}`);
          }}
          applyState(payload.state);
          showAdminNotice(payload.message || "Saved.");
          return payload;
        }}

        function setFieldError(field, message) {{
          field.setCustomValidity(message || "");
          let error = field.closest("label")?.querySelector(".field-error");
          if (!message) {{
            error?.remove();
            return;
          }}
          if (!error) {{
            error = document.createElement("div");
            error.className = "field-error";
            field.closest("label")?.appendChild(error);
          }}
          error.textContent = message;
        }}

        function clearFormErrors(form) {{
          form.querySelectorAll(".field-error").forEach((node) => node.remove());
          form.querySelectorAll("input, textarea, select").forEach((field) => field.setCustomValidity(""));
        }}

        function hasUnsafeMarkup(value) {{
          return /<\\s*\\/?\\s*script\\b|on(?:error|load|click|mouseover)\\s*=|javascript\\s*:|<\\s*iframe\\b/i.test(String(value || ""));
        }}

        function isSafeIdentifier(value) {{
          return /^[a-zA-Z_][a-zA-Z0-9_-]{{0,63}}$/.test(String(value || ""));
        }}

        function isSafeJsonpCallback(value) {{
          return /^[a-zA-Z_$][a-zA-Z0-9_$]*(\\.[a-zA-Z_$][a-zA-Z0-9_$]*)*$/.test(String(value || ""));
        }}

        function validateAdminForm(form) {{
          clearFormErrors(form);
          let firstInvalid = null;
          const fail = (field, message) => {{
            setFieldError(field, message);
            firstInvalid = firstInvalid || field;
          }};

          form.querySelectorAll("input, textarea, select").forEach((field) => {{
            if (field.disabled || field.type === "hidden" || field.type === "button" || field.type === "submit") return;
            const value = String(field.value || "").trim();
            if (field.required && !value) {{
              fail(field, "Required.");
              return;
            }}
            if (value && hasUnsafeMarkup(value)) {{
              fail(field, "Unsafe browser markup is not allowed here.");
              return;
            }}
            if (field.type === "number" && value) {{
              const numberValue = Number(value);
              const min = field.min === "" ? null : Number(field.min);
              const max = field.max === "" ? null : Number(field.max);
              if (!Number.isFinite(numberValue)) fail(field, "Must be a valid number.");
              if (min !== null && numberValue < min) fail(field, `Must be at least ${{field.min}}.`);
              if (max !== null && numberValue > max) fail(field, `Must be at most ${{field.max}}.`);
            }}
            if (value && field.name === "base_url") {{
              const serviceProtocol = String(form.querySelector('[name="protocol"]')?.value || "http").trim().toLowerCase();
              if (serviceProtocol === "http" && !/^https?:\\/\\//i.test(value)) {{
                fail(field, "Use an absolute http(s) URL.");
              }}
            }}
            if (value && ["service_name", "endpoint_name", "endpoint_slug", "route_name", "route_slug", "client_slug", "client_code", "profile_slug", "role_name", "success_key", "data_key", "message_key", "error_key", "gateway_response_success_key", "gateway_response_data_key", "gateway_response_message_key", "gateway_response_error_key"].includes(field.name)) {{
              if (!isSafeIdentifier(value)) fail(field, "Use letters, numbers, underscore, or dash. Start with a letter or underscore.");
            }}
            if (value && field.name === "username" && !/^[a-zA-Z0-9_.@-]{{1,64}}$/.test(value)) {{
              fail(field, "Use letters, numbers, dot, underscore, dash, or @.");
            }}
          }});

          const profileType = form.querySelector('[name="profile_type"]')?.value;
          if (profileType && !["passthrough", "json_envelope", "jsonp", "custom"].includes(profileType)) {{
            fail(form.querySelector('[name="profile_type"]'), "Invalid output profile mode.");
          }}
          const transformCodeField = form.querySelector('[name="transform_code"]');
          if (profileType === "custom" && transformCodeField && !transformCodeField.value.trim()) {{
            fail(transformCodeField, "Custom transform code is required.");
          }}
          const jsonpCallback = form.querySelector('[name="jsonp_default_callback"]');
          if (profileType === "jsonp" && jsonpCallback?.value && !isSafeJsonpCallback(jsonpCallback.value.trim())) {{
            fail(jsonpCallback, "Use a JavaScript identifier path, for example callback or window.handleResponse.");
          }}
          const passthroughKeysField = form.querySelector('[name="passthrough_keys"]');
          if (passthroughKeysField?.value) {{
            const invalid = splitList(passthroughKeysField.value).find((item) => !isSafeIdentifier(item));
            if (invalid) fail(passthroughKeysField, `Unsafe envelope key: ${{invalid}}.`);
          }}
          const methods = form.querySelector('[name="methods"]');
          if (methods?.value) {{
            const validMethods = new Set(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]);
            const invalid = splitList(methods.value).map((item) => item.toUpperCase()).filter((item) => !validMethods.has(item));
            if (invalid.length) fail(methods, `Invalid method: ${{invalid[0]}}.`);
          }}
          const pathField = form.querySelector('[name="gateway_path"]');
          if (pathField?.value && !pathField.value.trim().startsWith("/")) {{
            fail(pathField, "Gateway path must start with /.");
          }}
          const routeStrategy = form.querySelector('[name="strategy"]')?.value;
          if (routeStrategy && !["single", "round_robin", "failover", "parallel_race"].includes(routeStrategy)) {{
            fail(form.querySelector('[name="strategy"]'), "Invalid route strategy.");
          }}
          const gatewayResponseMode = form.querySelector('[name="gateway_response_mode"]')?.value;
          if (gatewayResponseMode && !["default", "profile", "inline"].includes(gatewayResponseMode)) {{
            fail(form.querySelector('[name="gateway_response_mode"]'), "Invalid gateway response mode.");
          }}
          if (gatewayResponseMode === "profile") {{
            const gatewayResponseProfile = form.querySelector('[name="gateway_response_output_profile"]');
            if (gatewayResponseProfile && !String(gatewayResponseProfile.value || "").trim()) {{
              fail(gatewayResponseProfile, "Select an output profile for gateway-generated errors.");
            }}
          }}
          if (form.action.endsWith("/__admin/route/save")) {{
            const targetInputs = Array.from(form.querySelectorAll("[data-route-target]"));
            const checkedTargets = targetInputs.filter((input) => input.checked);
            const firstTarget = targetInputs[0];
            if (!checkedTargets.length && firstTarget) {{
              fail(firstTarget, "Select at least one route target.");
            }}
            if (routeStrategy === "single" && checkedTargets.length !== 1 && firstTarget) {{
              fail(firstTarget, "Single strategy needs exactly one target.");
            }}
            if (["round_robin", "failover", "parallel_race"].includes(routeStrategy || "") && checkedTargets.length < 2 && firstTarget) {{
              fail(firstTarget, "This strategy needs at least two targets.");
            }}
          }}

          if (firstInvalid) {{
            firstInvalid.reportValidity();
            firstInvalid.focus();
            return false;
          }}
          return true;
        }}

        modalBody.addEventListener("submit", async (event) => {{
          if (event.defaultPrevented) return;
          const form = event.target;
          if (!(form instanceof HTMLFormElement)) return;
          event.preventDefault();
          showAdminNotice("");
          if (form.action.endsWith("/__admin/client/save") && !submitClientForm(form)) return;
          if (!validateAdminForm(form)) return;
          const submitButton = form.querySelector('[type="submit"]');
          submitButton?.setAttribute("disabled", "disabled");
          try {{
            const payload = await postAdminMutation(form.action, formPayload(form));
            closeModal();
            showAdminNotice(payload.message || "Saved.");
          }} catch (error) {{
            showAdminNotice(String(error?.message || error), "error");
          }} finally {{
            submitButton?.removeAttribute("disabled");
          }}
        }});

        async function postDelete(action, fields) {{
          if (!confirm("Are you sure?")) return;
          showAdminNotice("");
          const body = new URLSearchParams();
          Object.entries(fields).forEach(([key, value]) => body.set(key, value));
          try {{
            const payload = await postAdminMutation(action, body);
            showAdminNotice(payload.message || "Deleted.");
          }} catch (error) {{
            showAdminNotice(String(error?.message || error), "error");
          }}
        }}

        function serviceByName(name) {{
          return STATE.services.find((service) => service.name === name);
        }}

        function roleByName(name) {{
          return STATE.security.roles.find((role) => role.name === name);
        }}

        function userByName(username) {{
          return STATE.security.users.find((user) => user.username === username);
        }}

        function clientByCode(code) {{
          return STATE.clients.find((client) => client.code === code);
        }}

        function clientBySlug(slug) {{
          return STATE.clients.find((client) => client.slug === slug);
        }}

        function outputProfileBySlug(slug) {{
          return STATE.output_profiles.find((profile) => profile.slug === slug);
        }}

        function routeBySlug(slug) {{
          return (STATE.routes || []).find((route) => route.slug === slug);
        }}

        function outputProfileRuleSummary(profile) {{
          if (!profile) return "";
          if (profile.type === "passthrough") {{
            return "return response as-is";
          }}
          if (profile.type === "jsonp") {{
            return `callback = query.${{profile.jsonp_callback_param || "callback"}} ?? "${{profile.jsonp_default_callback || "callback"}}"`;
          }}
          if (profile.type === "custom") {{
            const validation = profile.custom_validation || {{}};
            const firstLine = String(profile.transform_code || "")
              .split(/\\r?\\n/)
              .map((line) => line.trim())
              .find(Boolean);
            const validationLabel = validation.mode === "payload_key"
              ? `if payload.${{validation.source_key || "<key>"}} == ${{JSON.stringify(validation.expected_value ?? true)}}`
              : "if status_code < 400";
            return `${{validationLabel}} -> ${{firstLine || "custom result = ..." }}`;
          }}
          const successKey = profile.success_key || "success";
          const dataKey = profile.data_key || "data";
          return `${{successKey}} = response.${{successKey}} ?? status<400; ${{dataKey}} = response.${{dataKey}} ?? body`;
        }}

        function outputProfileListText(values) {{
          return Array.isArray(values) ? values.join(", ") : "";
        }}

        function outputProfileDataFieldsText(value) {{
          if (!value || Array.isArray(value) || typeof value !== "object" || !Object.keys(value).length) {{
            return "";
          }}
          return JSON.stringify(value, null, 2);
        }}

        function outputProfilePreviewConfig(form) {{
          const valueOf = (name, fallback = "") => String(form?.querySelector(`[name="${{name}}"]`)?.value || fallback).trim();
          return {{
            type: valueOf("profile_type", "passthrough") || "passthrough",
            successKey: valueOf("success_key", "success") || "success",
            dataKey: valueOf("data_key", "data") || "data",
            messageKey: valueOf("message_key", "message") || "message",
            errorKey: valueOf("error_key", "error") || "error",
            passthroughKeys: splitList(valueOf("passthrough_keys")),
            sourceSuccessKey: valueOf("source_success_key"),
            messageSourceKeys: splitList(valueOf("message_source_keys")),
            errorSourceKeys: splitList(valueOf("error_source_keys")),
            dataFields: valueOf("data_fields_yaml"),
            emptyValue: valueOf("empty_value_yaml"),
            jsonpParam: valueOf("jsonp_callback_param", "callback") || "callback",
            jsonpDefault: valueOf("jsonp_default_callback", "callback") || "callback",
            customValidationMode: valueOf("custom_validation_mode", "status_code") || "status_code",
            customValidationSourceKey: valueOf("custom_validation_source_key"),
            customValidationExpectedValue: valueOf("custom_validation_expected_value_yaml", "true") || "true",
            customValidationErrorSourceKeys: splitList(valueOf("custom_validation_error_source_keys")),
            transformCode: valueOf("transform_code"),
          }};
        }}

        function outputProfilePseudoCode(config) {{
          if (config.type === "passthrough") {{
            return `<code><span class="keyword">return</span> upstream.response\n\n# No wrapping, no JSON editing, no key rewriting.</code>`;
          }}
          if (config.type === "jsonp") {{
            return `<code>callback = query["${{esc(config.jsonpParam)}}"] ?? <span class="value">"${{esc(config.jsonpDefault)}}"</span>\n\n<span class="keyword">return</span> callback + "(" + json(response.body) + ");"</code>`;
          }}
          if (config.type === "custom") {{
            const validationErrorPaths = config.customValidationErrorSourceKeys.length
              ? config.customValidationErrorSourceKeys.map((item) => `"${{esc(item)}}"`).join(", ")
              : '"ErrorDesc"';
            const validationRule = config.customValidationMode === "payload_key"
              ? `validation = {{\n  "mode": "payload_key",\n  "key": "${{esc(config.customValidationSourceKey || "<path>")}}",\n  "expected": ${{esc(config.customValidationExpectedValue || "true")}},\n  "actual": pick("${{esc(config.customValidationSourceKey || "<path>")}}"),\n  "ok": success(pick("${{esc(config.customValidationSourceKey || "<path>")}}")) == ${{esc(config.customValidationExpectedValue || "true")}},\n  "error": pick_first(${{validationErrorPaths}}, default="")\n}}`
              : `validation = {{\n  "mode": "status_code",\n  "ok": status_code < 400,\n  "actual": status_code,\n  "expected": "<400",\n  "error": pick_first(${{validationErrorPaths}}, default=detail)\n}}`;
            const customCode = esc(config.transformCode || `result = {{
  "success": validation["ok"],
  "message": "",
  "data": payload if validation["ok"] else empty_value,
  "error": "" if validation["ok"] else validation["error"],
}}`);
            return `<code># Validation runs before your transform code.\n${{validationRule}}\n\n# Available names: payload, status_code, detail, validation, headers, query.\n# Safe helpers: pick(), pick_first(), exists(), success(), text().\n# Assign the final shaped body to result.\n\n${{customCode}}</code>`;
          }}
          const guardKeys = config.passthroughKeys.length ? config.passthroughKeys : [config.successKey, config.dataKey];
          const successValue = config.sourceSuccessKey
            ? `bool(payload.${{esc(config.sourceSuccessKey)}} ?? <span class="fallback">${{esc(config.emptyValue || "empty_value")}}</span>)`
            : `response["${{esc(config.successKey)}}"] ?? <span class="fallback">(status &lt; 400)</span>`;
          const messageValue = config.messageSourceKeys.length
            ? `first(payload.${{esc(config.messageSourceKeys.join(", payload."))}}) ?? <span class="fallback">${{esc(config.emptyValue || "empty_value")}}</span>`
            : `response["${{esc(config.messageKey)}}"] ?? <span class="fallback">auto_message(response)</span>`;
          const dataValue = config.dataFields
            ? `<span class="fallback">mapped fields from data_fields using source paths or {{{{field}}}} templates</span>`
            : `response["${{esc(config.dataKey)}}"] ?? <span class="fallback">response.body</span>`;
          const errorValue = config.errorSourceKeys.length
            ? `first(payload.${{esc(config.errorSourceKeys.join(", payload."))}}) ?? <span class="fallback">${{esc(config.emptyValue || "empty_value")}}</span>`
            : `response["${{esc(config.errorKey)}}"] ?? <span class="fallback">auto_error(response)</span>`;
          return `<code>if response has ${{guardKeys.map((key) => `"${{esc(key)}}"`).join(" + ")}}:\n  <span class="keyword">return</span> response\n\n<span class="keyword">return</span> {{\n  "${{esc(config.successKey)}}": ${{successValue}},\n  "${{esc(config.messageKey)}}": ${{messageValue}},\n  "${{esc(config.dataKey)}}": ${{dataValue}},\n  "${{esc(config.errorKey)}}": ${{errorValue}}\n}}</code>`;
        }}

        function syncOutputProfileRules(form) {{
          const select = form?.querySelector('[name="profile_type"]');
          if (!select) return;
          const preview = form.querySelector("[data-output-preview]");
          const sync = () => {{
            form.querySelectorAll("[data-output-rule]").forEach((panel) => {{
              panel.classList.toggle("is-active", panel.dataset.outputRule === select.value);
            }});
            form.querySelectorAll("[data-output-envelope-field]").forEach((field) => {{
              field.hidden = select.value !== "json_envelope";
            }});
            form.querySelectorAll("[data-output-jsonp-field]").forEach((field) => {{
              field.hidden = select.value !== "jsonp";
            }});
            form.querySelectorAll("[data-output-custom-field]").forEach((field) => {{
              field.hidden = select.value !== "custom";
            }});
            const customValidationMode = form.querySelector('[name="custom_validation_mode"]');
            form.querySelectorAll("[data-output-custom-validation-key-field]").forEach((field) => {{
              field.hidden = select.value !== "custom" || customValidationMode?.value !== "payload_key";
            }});
            const customCode = form.querySelector('[name="transform_code"]');
            if (customCode) {{
              customCode.required = select.value === "custom";
            }}
            const customValidationSourceKey = form.querySelector('[name="custom_validation_source_key"]');
            if (customValidationSourceKey) {{
              customValidationSourceKey.required = select.value === "custom" && customValidationMode?.value === "payload_key";
            }}
            if (preview) {{
              preview.innerHTML = outputProfilePseudoCode(outputProfilePreviewConfig(form));
            }}
          }};
          [
            "profile_type",
            "success_key",
            "data_key",
            "message_key",
            "error_key",
            "passthrough_keys",
            "source_success_key",
            "message_source_keys",
            "error_source_keys",
            "data_fields_yaml",
            "empty_value_yaml",
            "jsonp_callback_param",
            "jsonp_default_callback",
            "custom_validation_mode",
            "custom_validation_source_key",
            "custom_validation_expected_value_yaml",
            "custom_validation_error_source_keys",
            "transform_code",
          ].forEach((name) => {{
            form.querySelector(`[name="${{name}}"]`)?.addEventListener("input", sync);
            form.querySelector(`[name="${{name}}"]`)?.addEventListener("change", sync);
          }});
          sync();
        }}

        function gatewayResponsePreviewConfig(form) {{
          const valueOf = (name, fallback = "") => String(form?.querySelector(`[name="${{name}}"]`)?.value || fallback).trim();
          return {{
            mode: valueOf("gateway_response_mode", "default") || "default",
            outputProfile: valueOf("gateway_response_output_profile"),
            successKey: valueOf("gateway_response_success_key", "success") || "success",
            dataKey: valueOf("gateway_response_data_key", "data") || "data",
            messageKey: valueOf("gateway_response_message_key", "message") || "message",
            errorKey: valueOf("gateway_response_error_key", "error") || "error",
          }};
        }}

        function gatewayResponsePseudoCode(config) {{
          if (config.mode === "default") {{
            return `<code><span class="keyword">return</span> {{ "detail": error.detail }}</code>`;
          }}
          if (config.mode === "profile") {{
            const selectedProfile = outputProfileBySlug(config.outputProfile);
            const profileLabel = selectedProfile ? `${{selectedProfile.slug}} (${{selectedProfile.type}})` : "<select-profile>";
            const profileRule = selectedProfile?.type === "custom"
              ? esc(selectedProfile.transform_code || "result = {{ ... }}")
              : esc(outputProfileRuleSummary(selectedProfile) || "select an output profile");
            return `<code>seed = {{\n  "detail": error.detail,\n  "message": error.detail,\n  "error": error.detail,\n  "status_code": status_code,\n  "status": status_code,\n}}\n\n# The selected profile receives payload=seed.\n# In custom mode you also get detail and status_code directly.\n# Selected profile: ${{profileLabel}}\n${{profileRule}}</code>`;
          }}
          return `<code><span class="keyword">return</span> {{\n  "${{esc(config.successKey)}}": <span class="value">false</span>,\n  "${{esc(config.dataKey)}}": <span class="fallback">empty_value</span>,\n  "${{esc(config.messageKey)}}": error.detail ?? <span class="fallback">empty_value</span>,\n  "${{esc(config.errorKey)}}": error.detail ?? <span class="fallback">empty_value</span>\n}}</code>`;
        }}

        function syncGatewayResponseSettings(form) {{
          const modeSelect = form?.querySelector('[name="gateway_response_mode"]');
          const preview = form?.querySelector("[data-gateway-response-preview]");
          if (!modeSelect) return;
          const sync = () => {{
            form.querySelectorAll("[data-gateway-profile-field]").forEach((field) => {{
              field.hidden = modeSelect.value !== "profile";
            }});
            form.querySelectorAll("[data-gateway-inline-field]").forEach((field) => {{
              field.hidden = modeSelect.value !== "inline";
            }});
            if (preview) {{
              preview.innerHTML = gatewayResponsePseudoCode(gatewayResponsePreviewConfig(form));
            }}
          }};
          ["gateway_response_mode", "gateway_response_output_profile", "gateway_response_success_key", "gateway_response_data_key", "gateway_response_message_key", "gateway_response_error_key"].forEach((name) => {{
            form.querySelector(`[name="${{name}}"]`)?.addEventListener("input", sync);
            form.querySelector(`[name="${{name}}"]`)?.addEventListener("change", sync);
          }});
          sync();
        }}

        function serviceOptions() {{
          return STATE.services.map((service) => service.name);
        }}

        function endpointOptions() {{
          return STATE.services.flatMap((service) =>
            service.endpoints.map((endpoint) => ({{
              service: service.name,
              endpoint: endpoint.name,
              slug: endpoint.slug || endpoint.name,
              ref: `${{service.name}}::${{endpoint.name}}`,
              label: `${{service.name}} / ${{endpoint.name}}`,
            }}))
          );
        }}

        function splitList(raw) {{
          return String(raw || "")
            .split(/[\\n,]/)
            .map((item) => item.trim())
            .filter(Boolean)
            .filter((item, index, items) => items.indexOf(item) === index);
        }}

        function listText(values) {{
          return Array.isArray(values) ? values.join(", ") : "";
        }}

        function randomSecret(length = 32) {{
          const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
          const bytes = new Uint8Array(length);
          crypto.getRandomValues(bytes);
          return Array.from(bytes, (byte) => chars[byte % chars.length]).join("");
        }}

        function visibleMethodField(card, fieldName) {{
          const fields = Array.from(card?.querySelectorAll(`[data-field="${{fieldName}}"]`) || []);
          return fields.find((field) => {{
            const holder = field.closest("[data-auth-types]");
            return !holder || holder.style.display !== "none";
          }}) || fields[0] || null;
        }}

        function fillMethodField(button, fieldName, length = 32, prefix = "") {{
          const card = button.closest(".auth-method-card");
          const input = visibleMethodField(card, fieldName);
          if (!input) return;
          input.value = `${{prefix}}${{randomSecret(length)}}`;
        }}

        function fillOauthFields(button) {{
          fillMethodField(button, "client_id", 16, "cli_");
          fillMethodField(button, "client_secret", 40, "sec_");
        }}

        async function issueOauthToken(clientCode, methodCode) {{
          const client = clientByCode(clientCode);
          const method = client?.auth_methods?.find((item) => item.code === methodCode);
          const outputKey = encodeURIComponent(`${{clientCode}}::${{methodCode}}`);
          const output = modalBody.querySelector(`[data-oauth-token-output="${{outputKey}}"]`);
          if (!client || !method || method.type !== "oauth_client_credentials" || !output) return;

          output.textContent = "Requesting access token...";
          try {{
            const body = new URLSearchParams();
            body.set("client_id", method.client_id || "");
            body.set("client_secret", method.client_secret || "");

            const response = await fetch(STATE.oauth.token_url, {{
              method: "POST",
              headers: {{
                "Content-Type": "application/x-www-form-urlencoded",
              }},
              body: body.toString(),
            }});

            const payload = await response.json();
            if (!response.ok) {{
              throw new Error(payload.detail || "OAuth token request failed.");
            }}
            output.textContent = JSON.stringify(payload, null, 2);
          }} catch (error) {{
            output.textContent = String(error?.message || error);
          }}
        }}

        function clientScopeSummary(client) {{
          if (client.access.mode === "all") return "All services";
          if (client.access.mode === "services") {{
            return `${{client.access.services.length}} selected service(s)`;
          }}
          return `${{client.access.endpoints.length}} selected endpoint(s)`;
        }}

        function clientTouchesService(client, serviceName) {{
          if (client.access.mode === "all") return true;
          if (client.access.mode === "services") return client.access.services.includes(serviceName);
          return client.access.endpoints.some((item) => item.service === serviceName);
        }}

        function scopedClientsCount(serviceName) {{
          return STATE.clients.filter((client) => clientTouchesService(client, serviceName)).length;
        }}

        function statusClass(statusCode) {{
          const code = Number(statusCode || 0);
          if (code >= 500) return "warn";
          if (code >= 400) return "warn";
          return "ok";
        }}

        function shellQuote(value) {{
          return `'${{String(value ?? "").replace(/'/g, `'\"'\"'`)}}'`;
        }}

        function sampleGatewayPath(pathValue) {{
          return String(pathValue || "").replace(/\\{{([a-zA-Z_][a-zA-Z0-9_]*)(:path)?\\}}/g, (_match, name, pathMode) => {{
            return pathMode ? `sample-${{name}}/path` : `sample-${{name}}`;
          }});
        }}

        function appendQueryParam(url, key, value) {{
          const separator = url.includes("?") ? "&" : "?";
          return `${{url}}${{separator}}${{encodeURIComponent(key)}}=${{encodeURIComponent(value)}}`;
        }}

        function clientTouchesEndpoint(client, serviceName, endpointRef) {{
          const endpointName = typeof endpointRef === "string" ? endpointRef : String(endpointRef?.name || "");
          const endpointSlug = typeof endpointRef === "string" ? "" : String(endpointRef?.slug || "");
          if (client.access.mode === "all") return true;
          if (client.access.mode === "services") return client.access.services.includes(serviceName);
          return client.access.endpoints.some((item) =>
            item.service === serviceName
            && (item.endpoint === endpointName || (endpointSlug && item.endpoint === endpointSlug))
          );
        }}

        function authPriority(type) {{
          return {{
            api_key: 1,
            bearer: 2,
            header_key: 3,
            basic: 4,
            oauth_client_credentials: 5,
            external_service: 6,
          }}[type] || 99;
        }}

        function emptyAuthSample() {{
          return {{ headers: [], cookies: [], basic: "", query: [] }};
        }}

        function authSampleForMethod(method) {{
          if (!method) return emptyAuthSample();

          if (method.type === "api_key") {{
            if (method.header_names?.length) {{
              return {{ headers: [`${{method.header_names[0]}}: ${{method.secret || "<api_key>"}}`], cookies: [], basic: "", query: [] }};
            }}
            if (method.query_params?.length) {{
              return {{ headers: [], cookies: [], basic: "", query: [[method.query_params[0], method.secret || "<api_key>"]] }};
            }}
            if (method.cookie_names?.length) {{
              return {{ headers: [], cookies: [`${{method.cookie_names[0]}}=${{method.secret || "<api_key>"}}`], basic: "", query: [] }};
            }}
          }}

          if (method.type === "bearer") {{
            if (method.allow_authorization_header) {{
              return {{ headers: [`Authorization: Bearer ${{method.token || "<bearer_token>"}}`], cookies: [], basic: "", query: [] }};
            }}
            if (method.header_names?.length) {{
              return {{ headers: [`${{method.header_names[0]}}: ${{method.token || "<bearer_token>"}}`], cookies: [], basic: "", query: [] }};
            }}
            if (method.query_params?.length) {{
              return {{ headers: [], cookies: [], basic: "", query: [[method.query_params[0], method.token || "<bearer_token>"]] }};
            }}
            if (method.cookie_names?.length) {{
              return {{ headers: [], cookies: [`${{method.cookie_names[0]}}=${{method.token || "<bearer_token>"}}`], basic: "", query: [] }};
            }}
          }}

          if (method.type === "header_key") {{
            return {{ headers: [`${{method.header_name || "X-Client-Key"}}: ${{method.secret || "<header_secret>"}}`], cookies: [], basic: "", query: [] }};
          }}

          if (method.type === "basic") {{
            return {{ headers: [], cookies: [], basic: `${{method.username || "<username>"}}:${{method.password || "<password>"}}`, query: [] }};
          }}

          if (method.type === "oauth_client_credentials") {{
            return {{
              headers: ["Authorization: Bearer <paste_access_token_from___oauth/token>"],
              cookies: [],
              basic: "",
              query: [],
            }};
          }}

          if (method.type === "external_service") {{
            return {{
              headers: ["Authorization: Bearer <external_service_token>"],
              cookies: [],
              basic: "",
              query: [],
            }};
          }}

          return emptyAuthSample();
        }}

        async function copyTextToClipboard(text) {{
          if (navigator.clipboard?.writeText) {{
            await navigator.clipboard.writeText(text);
            return;
          }}

          const textarea = document.createElement("textarea");
          textarea.value = text;
          textarea.setAttribute("readonly", "");
          textarea.style.position = "absolute";
          textarea.style.left = "-9999px";
          document.body.appendChild(textarea);
          textarea.select();
          document.execCommand("copy");
          textarea.remove();
        }}

        function formatDateTime(value) {{
          if (!value) return "-";
          const date = new Date(value);
          if (Number.isNaN(date.getTime())) return String(value);
          return date.toLocaleString();
        }}

        function formatBucketTime(bucket) {{
          const value = bucket?.bucket_start;
          if (!value) return String(bucket?.label || "");
          const date = new Date(value);
          if (Number.isNaN(date.getTime())) return String(bucket?.label || value);
          return date.toLocaleTimeString([], {{ hour: "2-digit", minute: "2-digit" }});
        }}

        function reportUrlWithBrowserTimezone(value) {{
          const fallback = "/__monitor/report?hours=24&bucket_minutes=60";
          const url = new URL(String(value || fallback), window.location.origin);
          url.searchParams.set("timezone_offset_minutes", String(-new Date().getTimezoneOffset()));
          return url.toString();
        }}

        function durationMicros(row) {{
          const direct = Number(row.duration_us || 0);
          if (Number.isFinite(direct) && direct > 0) {{
            return direct;
          }}
          const millis = Number(row.duration_ms || 0);
          if (!Number.isFinite(millis) || millis <= 0) {{
            return 0;
          }}
          return Math.max(0, Math.round(millis * 1000));
        }}

        function formatDuration(row) {{
          const micros = durationMicros(row);
          return `${{(micros / 1000).toFixed(3)}} ms`;
        }}

        function summarizeLiveRows(rows) {{
          const total = rows.length;
          const failures = rows.filter((row) => Number(row.status_code || 0) >= 400).length;
          const averageDurationMicros = total
            ? Math.round(rows.reduce((sum, row) => sum + durationMicros(row), 0) / total)
            : 0;
          return {{
            total,
            failures,
            averageDurationMicros,
            lastSeen: rows[0]?.created_at || "",
          }};
        }}

        function numberOrZero(value) {{
          const numeric = Number(value || 0);
          return Number.isFinite(numeric) ? numeric : 0;
        }}

        function formatMsNumber(value) {{
          return `${{numberOrZero(value).toFixed(3)}} ms`;
        }}

        function percent(numerator, denominator) {{
          const total = numberOrZero(denominator);
          if (!total) {{
            return "0.0%";
          }}
          return `${{((numberOrZero(numerator) / total) * 100).toFixed(1)}}%`;
        }}

        function liveAnalytics() {{
          const report = liveReport && typeof liveReport === "object" ? liveReport : null;
          const totals = report?.totals && typeof report.totals === "object" ? report.totals : null;
          const hourly = Array.isArray(report?.hourly) ? report.hourly : [];
          const statusBreakdown = Array.isArray(report?.status_breakdown) ? report.status_breakdown : [];
          const topServices = Array.isArray(report?.top_services) ? report.top_services : [];
          const topPaths = Array.isArray(report?.top_paths) ? report.top_paths : [];
          return {{
            report,
            totals,
            hourly,
            statusBreakdown,
            topServices,
            topPaths,
            recent: summarizeLiveRows(liveRows),
          }};
        }}

        function chartBarPath(points, baseline) {{
          if (!points.length) return "";
          return points.map((point) => `M${{point.x.toFixed(1)}} ${{baseline.toFixed(1)}} V${{point.y.toFixed(1)}}`).join(" ");
        }}

        function chartLinePath(points) {{
          if (!points.length) return "";
          return points.map((point, index) => `${{index === 0 ? "M" : "L"}}${{point.x.toFixed(1)}} ${{point.y.toFixed(1)}}`).join(" ");
        }}

        function renderTrendChart(hourly) {{
          if (!hourly.length) {{
            return '<div class="empty">No 24-hour activity has been recorded yet.</div>';
          }}
          const width = 760;
          const height = 220;
          const paddingTop = 18;
          const paddingRight = 18;
          const paddingBottom = 30;
          const paddingLeft = 18;
          const innerWidth = width - paddingLeft - paddingRight;
          const innerHeight = height - paddingTop - paddingBottom;
          const maxRequests = Math.max(1, ...hourly.map((bucket) => numberOrZero(bucket.requests)));
          const maxFailures = Math.max(1, ...hourly.map((bucket) => numberOrZero(bucket.failures)));
          const stepX = hourly.length > 1 ? innerWidth / (hourly.length - 1) : innerWidth;
          const baselineY = paddingTop + innerHeight;
          const requestPoints = hourly.map((bucket, index) => {{
            const x = paddingLeft + stepX * index;
            const requestHeight = (numberOrZero(bucket.requests) / maxRequests) * innerHeight;
            return {{
              x,
              y: baselineY - requestHeight,
              label: formatBucketTime(bucket),
              requests: numberOrZero(bucket.requests),
            }};
          }});
          const failurePoints = hourly.map((bucket, index) => {{
            const x = paddingLeft + stepX * index;
            const failureHeight = (numberOrZero(bucket.failures) / maxFailures) * innerHeight;
            return {{
              x,
              y: baselineY - failureHeight,
              failures: numberOrZero(bucket.failures),
            }};
          }});
          const gridLines = [0, 0.25, 0.5, 0.75, 1].map((ratio) => {{
            const y = paddingTop + innerHeight * ratio;
            return `<line x1="${{paddingLeft}}" y1="${{y.toFixed(1)}}" x2="${{width - paddingRight}}" y2="${{y.toFixed(1)}}" class="live-chart-grid"></line>`;
          }}).join("");
          const labelEvery = Math.max(1, Math.floor(hourly.length / 6));
          const labels = requestPoints
            .map((point, index) => index % labelEvery === 0 || index === hourly.length - 1
              ? `<text x="${{point.x.toFixed(1)}}" y="${{height - 8}}" text-anchor="middle" class="live-chart-label">${{esc(point.label)}}</text>`
              : "")
            .join("");
          const requestBarWidth = Math.max(8, innerWidth / Math.max(hourly.length * 1.85, 1));
          const bars = requestPoints
            .map((point) => `
              <rect
                x="${{(point.x - requestBarWidth / 2).toFixed(1)}}"
                y="${{point.y.toFixed(1)}}"
                width="${{requestBarWidth.toFixed(1)}}"
                height="${{Math.max(1, baselineY - point.y).toFixed(1)}}"
                rx="4"
                class="live-chart-bar"
              >
                <title>${{point.label}}: ${{point.requests}} requests</title>
              </rect>
            `)
            .join("");
          const failuresPath = chartLinePath(failurePoints);
          const failureDots = failurePoints
            .map((point, index) => `
              <circle cx="${{point.x.toFixed(1)}}" cy="${{point.y.toFixed(1)}}" r="3.2" class="live-chart-line-dot">
                <title>${{requestPoints[index].label}}: ${{point.failures}} failures</title>
              </circle>
            `)
            .join("");
          return `
            <div class="live-chart-wrap">
              <svg viewBox="0 0 ${{width}} ${{height}}" class="live-chart" role="img" aria-label="24 hour request and failure chart">
                ${{gridLines}}
                <path d="${{chartBarPath(requestPoints, baselineY)}}" class="live-chart-bar-guide"></path>
                ${{bars}}
                <path d="${{failuresPath}}" class="live-chart-line"></path>
                ${{failureDots}}
                ${{labels}}
              </svg>
              <div class="live-chart-legend">
                <span><i class="live-chart-chip requests"></i>Requests per hour</span>
                <span><i class="live-chart-chip failures"></i>4xx/5xx failures per hour</span>
              </div>
            </div>
          `;
        }}

        function renderStatusBreakdown(statusBreakdown) {{
          const items = statusBreakdown.filter((item) => numberOrZero(item?.count) > 0);
          if (!items.length) {{
            return '<div class="muted">No status buckets recorded in the last 24 hours.</div>';
          }}
          return `
            <div class="live-pill-grid">
              ${{
                items.map((item) => `
                  <div class="live-pill">
                    <span class="tag">${{esc(item.label)}}</span>
                    <strong>${{numberOrZero(item.count)}}</strong>
                  </div>
                `).join("")
              }}
            </div>
          `;
        }}

        function renderTopList(items, keyName, emptyText) {{
          if (!Array.isArray(items) || !items.length) {{
            return `<div class="muted">${{esc(emptyText)}}</div>`;
          }}
          return `
            <div class="live-list">
              ${{
                items.map((item, index) => `
                  <div class="live-list-row">
                    <div class="live-list-rank">${{index + 1}}</div>
                    <div class="live-list-main">
                      <div class="mono">${{esc(item[keyName] || "-")}}</div>
                      <div class="muted">${{numberOrZero(item.requests)}} req | ${{numberOrZero(item.failures)}} fail | ${{formatMsNumber(item.avg_duration_ms)}}</div>
                    </div>
                  </div>
                `).join("")
              }}
            </div>
          `;
        }}

        function liveBadgeState() {{
          if (!STATE.live?.can_view) {{
            return {{ label: "Monitor access required", className: "warn" }};
          }}
          if (livePaused) {{
            return {{ label: "Live updates paused", className: "paused" }};
          }}
          if (liveConnectionState === "online") {{
            return {{ label: "Live updates active", className: "ok" }};
          }}
          if (liveConnectionState === "error") {{
            return {{ label: "Reconnecting to monitor", className: "warn" }};
          }}
          return {{ label: "Connecting to monitor", className: "" }};
        }}

        async function copyLiveCurl(button) {{
          const curl = button.closest("[data-live-curl]")?.querySelector("[data-live-curl-output]")?.textContent || "";
          if (!curl.trim()) return;
          const originalText = button.dataset.label || button.textContent;
          button.dataset.label = originalText;
          try {{
            await copyTextToClipboard(curl);
            button.textContent = "Copied";
          }} catch (_error) {{
            button.textContent = "Copy failed";
          }}
          window.setTimeout(() => {{
            button.textContent = originalText;
          }}, 1400);
        }}

        function liveResponseSource(row) {{
          const explicitSource = String(row.response_source || "").trim().toLowerCase();
          if (explicitSource) {{
            return explicitSource;
          }}
          if (row.cached === true) {{
            return "cache";
          }}
          const upstreamUrl = String(row.upstream_url || "").trim();
          if (upstreamUrl === "cache://response") {{
            return "cache";
          }}
          if (upstreamUrl.startsWith("local://")) {{
            return "local";
          }}
          return "upstream";
        }}

        function renderLiveUpstreamCell(row) {{
          const source = liveResponseSource(row);
          const upstreamUrl = String(row.upstream_url || "").trim();
          const upstreamCurl = String(row.upstream_curl || "").trim();
          const requestCurl = String(row.request_curl || "").trim();
          if (source === "cache") {{
            return `
              <div style="display:flex; flex-direction:column; gap:8px; min-width:260px;">
                <div><span class="tag warn">Cache</span></div>
                <div class="muted mono">response cache hit</div>
                ${{
                  requestCurl
                    ? `
                      <details data-live-curl>
                        <summary>Incoming cURL</summary>
                        <div class="actions" style="margin-top:8px;">
                          <button class="btn light" type="button" onclick="copyLiveCurl(this)">Copy cURL</button>
                        </div>
                        <div class="detail-box" style="margin-top:8px;">
                          <pre data-live-curl-output>${{esc(requestCurl)}}</pre>
                        </div>
                      </details>
                    `
                    : '<div class="muted">Incoming cURL unavailable</div>'
                }}
              </div>
            `;
          }}
          if (source === "local") {{
            return `
              <div style="display:flex; flex-direction:column; gap:8px; min-width:260px;">
                <div><span class="tag ok">Local</span></div>
                <div class="muted">cURL unavailable</div>
              </div>
            `;
          }}
          if (!upstreamUrl && !upstreamCurl) {{
            return '<span class="muted">-</span>';
          }}
          return `
            <div style="display:flex; flex-direction:column; gap:8px; min-width:260px;">
              ${{upstreamUrl ? `<div class="mono">${{esc(upstreamUrl)}}</div>` : ""}}
              ${{
                upstreamCurl
                  ? `
                    <details data-live-curl>
                      <summary>cURL</summary>
                      <div class="actions" style="margin-top:8px;">
                        <button class="btn light" type="button" onclick="copyLiveCurl(this)">Copy cURL</button>
                      </div>
                      <div class="detail-box" style="margin-top:8px;">
                        <pre data-live-curl-output>${{esc(upstreamCurl)}}</pre>
                      </div>
                    </details>
                  `
                  : ""
              }}
            </div>
          `;
        }}

        function renderLiveResponseCell(row) {{
          const responseText = String(row.response_body || row.error || "").trim();
          if (!responseText) {{
            return '<span class="muted">-</span>';
          }}
          return `
            <div class="detail-box" style="min-width:260px;">
              <pre style="max-height:120px; overflow:auto;">${{esc(responseText)}}</pre>
            </div>
          `;
        }}

        function backupScopeCatalog() {{
          return Array.isArray(STATE.backup_scopes) ? STATE.backup_scopes : [];
        }}

        function backupScopeByCode(code) {{
          const target = String(code || "").trim().toLowerCase();
          return backupScopeCatalog().find((scope) => String(scope.code || "").trim().toLowerCase() === target) || null;
        }}

        function backupScopeSummaryHtml(scopeCode) {{
          const scope = backupScopeByCode(scopeCode);
          if (!scope) {{
            return '<div class="muted">No backup scope selected.</div>';
          }}
          const group = String(scope.group || "config");
          const groupLabel = group === "bundle"
            ? "Full snapshot"
            : group === "security"
              ? "Security section"
              : "Config section";
          return `
            <div><strong>${{esc(scope.title || scope.code || "Backup scope")}}</strong></div>
            <div class="muted" style="margin-top:6px;">${{esc(scope.description || "")}}</div>
            <div style="margin-top:8px;"><span class="tag">${{esc(groupLabel)}}</span></div>
          `;
        }}

        function syncBackupControls(root = document) {{
          const card = root.querySelector("[data-backup-card]");
          if (!card) return;
          const exportSelect = card.querySelector('[name="backup_export_scope"]');
          const importSelect = card.querySelector('[name="backup_import_scope"]');
          const exportSummary = card.querySelector("[data-backup-export-summary]");
          const importSummary = card.querySelector("[data-backup-import-summary]");

          if (exportSummary) {{
            exportSummary.innerHTML = backupScopeSummaryHtml(exportSelect?.value || "");
          }}
          if (importSummary) {{
            importSummary.innerHTML = backupScopeSummaryHtml(importSelect?.value || "");
          }}

          const refresh = () => syncBackupControls(root);
          if (exportSelect && !exportSelect.dataset.boundBackup) {{
            exportSelect.dataset.boundBackup = "1";
            exportSelect.addEventListener("change", refresh);
          }}
          if (importSelect && !importSelect.dataset.boundBackup) {{
            importSelect.dataset.boundBackup = "1";
            importSelect.addEventListener("change", refresh);
          }}
        }}

        function backupFileName(scope, format) {{
          const stamp = new Date().toISOString().replace(/[:-]/g, "").replace(/\\..+/, "").replace("T", "-");
          const extension = format === "json" ? "json" : "yaml";
          return `napigate-${{scope || "backup"}}-${{stamp}}.${{extension}}`;
        }}

        function downloadTextFile(filename, text, mimeType) {{
          const blob = new Blob([text], {{ type: mimeType }});
          const url = URL.createObjectURL(blob);
          const anchor = document.createElement("a");
          anchor.href = url;
          anchor.download = filename;
          document.body.appendChild(anchor);
          anchor.click();
          anchor.remove();
          window.setTimeout(() => URL.revokeObjectURL(url), 250);
        }}

        async function fetchBackupExport(scope, format) {{
          const response = await fetch(`/__admin/api/backup?scope=${{encodeURIComponent(scope)}}&format=${{encodeURIComponent(format)}}`, {{
            headers: {{
              "Accept": format === "json" ? "application/json" : "application/yaml",
              "X-Requested-With": "XMLHttpRequest",
            }},
          }});
          const text = await response.text();
          if (!response.ok) {{
            let detail = text || `HTTP ${{response.status}}`;
            try {{
              const payload = JSON.parse(text);
              detail = payload.detail || detail;
            }} catch (_error) {{
              // Keep raw text detail.
            }}
            throw new Error(detail);
          }}
          return {{
            text,
            mimeType: String(response.headers.get("Content-Type") || (format === "json" ? "application/json" : "application/yaml")),
          }};
        }}

        async function downloadBackupExport(button) {{
          const card = button?.closest("[data-backup-card]");
          if (!card) return;
          const scope = String(card.querySelector('[name="backup_export_scope"]')?.value || "").trim();
          const format = String(card.querySelector('[name="backup_export_format"]')?.value || "yaml").trim().toLowerCase() || "yaml";
          if (!scope) {{
            showAdminNotice("Select a backup scope first.", "error");
            return;
          }}
          showAdminNotice("");
          button?.setAttribute("disabled", "disabled");
          try {{
            const exported = await fetchBackupExport(scope, format);
            downloadTextFile(backupFileName(scope, format), exported.text, exported.mimeType);
            const label = backupScopeByCode(scope)?.title || scope;
            showAdminNotice(`${{label}} exported.`);
          }} catch (error) {{
            showAdminNotice(String(error?.message || error), "error");
          }} finally {{
            button?.removeAttribute("disabled");
          }}
        }}

        function readTextFile(file) {{
          return new Promise((resolve, reject) => {{
            const reader = new FileReader();
            reader.onload = () => resolve(String(reader.result || ""));
            reader.onerror = () => reject(new Error(`Could not read ${{file?.name || "backup file"}}.`));
            reader.readAsText(file);
          }});
        }}

        async function submitBackupImport(event, form) {{
          event.preventDefault();
          const scope = String(form?.querySelector('[name="backup_import_scope"]')?.value || "").trim();
          const scopeInfo = backupScopeByCode(scope);
          if (!scope || !scopeInfo) {{
            showAdminNotice("Select a valid backup scope first.", "error");
            return false;
          }}
          const file = form.querySelector('[name="backup_import_file"]')?.files?.[0] || null;
          const textarea = form.querySelector('[name="backup_import_body"]');
          const submitButton = form.querySelector('[type="submit"]');
          let text = "";
          try {{
            text = file ? await readTextFile(file) : String(textarea?.value || "");
          }} catch (error) {{
            showAdminNotice(String(error?.message || error), "error");
            return false;
          }}
          if (!text.trim()) {{
            showAdminNotice("Provide a backup file or paste YAML/JSON before importing.", "error");
            return false;
          }}
          const confirmText = scope === "full"
            ? "Import the full config and security snapshot? This replaces both current documents."
            : `Import ${{scopeInfo.title}}? This replaces the current section.`;
          if (!window.confirm(confirmText)) {{
            return false;
          }}
          showAdminNotice("");
          submitButton?.setAttribute("disabled", "disabled");
          try {{
            const response = await fetch(`/__admin/api/import?scope=${{encodeURIComponent(scope)}}`, {{
              method: "POST",
              headers: {{
                "Accept": "application/json",
                "Content-Type": "application/yaml; charset=UTF-8",
                "X-Requested-With": "XMLHttpRequest",
              }},
              body: text,
            }});
            const payload = await response.json().catch(() => ({{}}));
            if (!response.ok) {{
              throw new Error(payload.detail || `HTTP ${{response.status}}`);
            }}
            applyState(payload.state);
            form.reset();
            syncBackupControls(document);
            showAdminNotice(payload.message || `${{scopeInfo.title}} imported.`);
          }} catch (error) {{
            showAdminNotice(String(error?.message || error), "error");
          }} finally {{
            submitButton?.removeAttribute("disabled");
          }}
          return false;
        }}

        async function clearGatewayCache(button) {{
          if (!confirm("Clear all gateway response, pre-call, and external auth cache entries? Rate-limit counters are not affected.")) return false;
          showAdminNotice("");
          button?.setAttribute("disabled", "disabled");
          try {{
            await postAdminMutation("/__admin/api/cache/clear", new URLSearchParams());
          }} catch (error) {{
            showAdminNotice(String(error?.message || error), "error");
          }} finally {{
            button?.removeAttribute("disabled");
          }}
          return false;
        }}

        function renderConfig() {{
          const wrap = document.getElementById("config-wrap");
          if (!wrap) return;

          const retentionValue = String(STATE.settings?.log_retention_hours || "");
          const trustedProxyIpsValue = Array.isArray(STATE.settings?.trusted_proxy_ips)
            ? STATE.settings.trusted_proxy_ips.join("\\n")
            : "";
          const gatewayResponses = STATE.settings?.gateway_responses || {{}};
          const gatewayResponseMode = String(gatewayResponses.mode || "default") || "default";
          const gatewayResponseOutputProfile = String(gatewayResponses.output_profile || "");
          const gatewaySuccessKey = String(gatewayResponses.success_key || "success");
          const gatewayDataKey = String(gatewayResponses.data_key || "data");
          const gatewayMessageKey = String(gatewayResponses.message_key || "message");
          const gatewayErrorKey = String(gatewayResponses.error_key || "error");
          const gatewayHeaders = gatewayResponses.headers || {{}};
          const gatewayEmptyValueText = configValueText(
            Object.prototype.hasOwnProperty.call(gatewayResponses, "empty_value")
              ? gatewayResponses.empty_value
              : ""
          );
          const canEdit = has("services_manage");
          const retentionLabel = retentionValue ? `${{retentionValue}} hour(s)` : "Unlimited";
          const publicBaseUrl = String(STATE.network?.public_base_url || "");
          const adminBaseUrl = String(STATE.network?.admin_base_url || "");
          const servicesConfigSource = String(STATE.config_paths?.services || "");
          const securityConfigSource = String(STATE.config_paths?.security || "");
          const stateStoreMode = String(STATE.store?.mode || "file");
          const auditEnabled = Boolean(STATE.store?.audit_enabled);
          const backupScopes = Array.isArray(STATE.backup_scopes) ? STATE.backup_scopes : [];
          const backupScopeOptions = backupScopes.length
            ? backupScopes.map((scope, index) => `
                <option value="${{esc(scope.code)}}" ${{index === 0 ? "selected" : ""}}>
                  ${{esc(scope.title)}}
                </option>
              `).join("")
            : '<option value="">No backup scopes available</option>';
          const backupActionsDisabled = backupScopes.length ? "" : "disabled";
          const backupAccessLabel = backupScopes.length
            ? `${{backupScopes.length}} backup scope(s) available`
            : "No backup scopes available for this account";
          const gatewayResponseProfileOptions = STATE.output_profiles.length
            ? STATE.output_profiles.map((profile) => `
                <option value="${{esc(profile.slug)}}" ${{gatewayResponseOutputProfile === profile.slug ? "selected" : ""}}>
                  ${{esc(profile.slug)}}${{profile.enabled ? "" : " (disabled)"}}
                </option>
              `).join("")
            : '<option value="">No output profiles</option>';
          const gatewayResponseLabel = gatewayResponseMode === "profile"
            ? (gatewayResponseOutputProfile ? `Profile: ${{gatewayResponseOutputProfile}}` : "Profile not selected")
            : gatewayResponseMode === "inline"
              ? "Legacy inline envelope"
              : "Default detail shape";

          wrap.innerHTML = `
            <div class="card">
              <div class="section-head" style="margin-bottom: 14px;">
                <div>
                  <h3 class="section-title" style="font-size:16px; margin-bottom:4px;">Control Plane</h3>
                  <div class="section-note">The public listener serves gateway traffic and token issuance. Admin, monitor, and logout stay on the admin listener only.</div>
                </div>
                <div class="actions">
                  <span class="tag">Store: ${{esc(stateStoreMode.toUpperCase())}}</span>
                  <span class="tag">${{auditEnabled ? "Audit enabled" : "Audit disabled"}}</span>
                </div>
              </div>
              <div class="form-grid">
                <div class="full detail-box">
                  <div><strong>Public listener</strong></div>
                  <div class="mono">${{esc(publicBaseUrl || "-")}}</div>
                </div>
                <div class="full detail-box">
                  <div><strong>Admin listener</strong></div>
                  <div class="mono">${{esc(adminBaseUrl || "-")}}</div>
                </div>
                <div class="full detail-box">
                  <div><strong>Services config source</strong></div>
                  <div class="mono">${{esc(servicesConfigSource || "-")}}</div>
                </div>
                <div class="full detail-box">
                  <div><strong>Security config source</strong></div>
                  <div class="mono">${{esc(securityConfigSource || "-")}}</div>
                </div>
              </div>
            </div>
            <div class="card" data-backup-card style="margin-top: 12px;">
              <div class="section-head" style="margin-bottom: 14px;">
                <div>
                  <h3 class="section-title" style="font-size:16px; margin-bottom:4px;">Backup And Import</h3>
                  <div class="section-note">Download full snapshots or restore a single config/security section without leaving the control plane.</div>
                </div>
                <div class="actions">
                  <span class="tag">${{esc(backupAccessLabel)}}</span>
                </div>
              </div>
              <div class="form-grid">
                <label>
                  <span>Export Scope</span>
                  <select name="backup_export_scope" ${{backupActionsDisabled}}>
                    ${{backupScopeOptions}}
                  </select>
                </label>
                <label>
                  <span>Export Format</span>
                  <select name="backup_export_format" ${{backupActionsDisabled}}>
                    <option value="yaml" selected>YAML</option>
                    <option value="json">JSON</option>
                  </select>
                </label>
                <div class="full detail-box" data-backup-export-summary>
                  <div class="muted">Select a backup scope to see what will be exported.</div>
                </div>
                <div class="actions full">
                  <button class="btn light" type="button" onclick="downloadBackupExport(this)" ${{backupActionsDisabled}}>Download Export</button>
                </div>
              </div>
              <form data-backup-import-form onsubmit="return submitBackupImport(event, this)" style="margin-top: 14px;">
                <div class="form-grid">
                  <label>
                    <span>Import Scope</span>
                    <select name="backup_import_scope" ${{backupActionsDisabled}}>
                      ${{backupScopeOptions}}
                    </select>
                  </label>
                  <label>
                    <span>Backup File</span>
                    <input name="backup_import_file" type="file" accept=".yaml,.yml,.json,text/plain,application/json,application/yaml,text/yaml" ${{backupActionsDisabled}}>
                  </label>
                  <div class="full detail-box" data-backup-import-summary>
                    <div class="muted">For a full snapshot, provide a mapping with <span class="mono">config</span> and <span class="mono">security</span>. For single sections, paste only that raw section body.</div>
                  </div>
                  <label class="full">
                    <span>Import Body (YAML or JSON)</span>
                    <textarea name="backup_import_body" rows="10" placeholder="Paste YAML or JSON here when you do not want to upload a file." ${{backupActionsDisabled}}></textarea>
                  </label>
                  <div class="actions full">
                    <button type="submit" ${{backupActionsDisabled}}>Import Selected Scope</button>
                  </div>
                </div>
              </form>
            </div>
            <div class="card" style="margin-top: 12px;">
              <div class="section-head" style="margin-bottom: 14px;">
                <div>
                  <h3 class="section-title" style="font-size:16px; margin-bottom:4px;">Cache Maintenance</h3>
                  <div class="section-note">Clear runtime cache entries from the active cache backend without changing gateway configuration.</div>
                </div>
                <div class="actions">
                  <span class="tag">Response / pre-call / external auth</span>
                  <span class="tag">Rate-limit unchanged</span>
                </div>
              </div>
              <div class="form-grid">
                <div class="full detail-box">
                  This clears response-cache entries, cached <span class="mono">pre_call</span> variables, and cached <span class="mono">external_service</span> auth results from memory or Redis. Sliding-window rate-limit state is intentionally not cleared.
                </div>
                <div class="actions full">
                  <button class="btn danger" type="button" onclick="clearGatewayCache(this)" ${{canEdit ? "" : "disabled"}}>Clear All Cache</button>
                  ${{
                    canEdit
                      ? ""
                      : '<span class="muted">This account does not have <code>services_manage</code> for cache maintenance.</span>'
                  }}
                </div>
              </div>
            </div>
            <form method="post" action="/__admin/settings/save" data-gateway-settings-form onsubmit="return submitGatewaySettings(event, this)" style="margin-top: 12px;">
              <div class="card">
                <div class="section-head" style="margin-bottom: 14px;">
                  <div>
                    <h3 class="section-title" style="font-size:16px; margin-bottom:4px;">Gateway Settings</h3>
                    <div class="section-note">Daily file rotation stays enabled. Hourly cleanup only applies when retention is set.</div>
                  </div>
                  <div class="actions">
                    <span class="tag">Current retention: ${{esc(retentionLabel)}}</span>
                    <span class="tag">Cleanup cadence: hourly</span>
                  </div>
                </div>
                <div class="form-grid">
                  <label data-help="log_retention_hours">
                    <span>Log Retention (hours)</span>
                    <input
                      name="log_retention_hours"
                      type="number"
                      min="1"
                      step="1"
                      value="${{esc(retentionValue)}}"
                      placeholder="Leave blank for unlimited"
                      ${{canEdit ? "" : "disabled"}}
                    >
                  </label>
                  <div class="full section-note">
                    This applies to monitor rows in <span class="mono">data/monitor.db</span> and rotated files under <span class="mono">logs/</span>.
                  </div>
                  <label class="full" data-help="trusted_proxy_ips">
                    <span>Trusted Proxy IPs / CIDRs</span>
                    <textarea
                      name="trusted_proxy_ips"
                      rows="4"
                      placeholder="One IP or CIDR per line"
                      ${{canEdit ? "" : "disabled"}}
                    >${{esc(trustedProxyIpsValue)}}</textarea>
                  </label>
                  <div class="full section-note">
                    Forwarded headers such as <span class="mono">X-Forwarded-For</span> are only trusted when the direct peer matches one of these entries.
                  </div>
                </div>
              </div>
              <div class="card" style="margin-top: 12px;">
                <div class="section-head" style="margin-bottom: 14px;">
                  <div>
                    <h3 class="section-title" style="font-size:16px; margin-bottom:4px;">Gateway Response Output</h3>
                    <div class="section-note">Applies to public runtime errors generated by NapiGate itself, such as 401, 403, 404, 429, and 5xx. Admin and monitor APIs keep their existing JSON contract.</div>
                  </div>
                  <div class="actions">
                    <span class="tag">${{esc(gatewayResponseLabel)}}</span>
                    <span class="tag">${{Object.keys(gatewayHeaders).length}} custom header(s)</span>
                  </div>
                </div>
                <div class="form-grid">
                  <label data-help="gateway_response_mode">
                    <span>Gateway Response Mode</span>
                    <select name="gateway_response_mode" ${{canEdit ? "" : "disabled"}}>
                      <option value="default" ${{gatewayResponseMode === "default" ? "selected" : ""}}>default detail</option>
                      <option value="profile" ${{gatewayResponseMode === "profile" ? "selected" : ""}}>selected output profile</option>
                      <option value="inline" ${{gatewayResponseMode === "inline" ? "selected" : ""}}>legacy inline envelope</option>
                    </select>
                  </label>
                  <label class="full" data-help="gateway_response_output_profile" data-gateway-profile-field>
                    <span>Gateway Error Output Profile</span>
                    <select name="gateway_response_output_profile" ${{canEdit ? "" : "disabled"}}>
                      <option value="">Select an output profile</option>
                      ${{gatewayResponseProfileOptions}}
                    </select>
                    <div class="muted" style="margin-top:6px;">
                      The selected profile receives a gateway error payload with <span class="mono">detail</span>, <span class="mono">message</span>, <span class="mono">error</span>, <span class="mono">status_code</span>, and <span class="mono">status</span>.
                    </div>
                  </label>
                  <div class="output-flow full">
                    <div class="output-flow-head">
                      <div>
                        <div class="output-flow-title">Gateway error rule</div>
                        <div class="output-flow-subtitle">This shape is used only when NapiGate itself is generating the response body.</div>
                      </div>
                      <span class="tag">pseudo-code</span>
                    </div>
                    <pre class="pseudo-code" data-gateway-response-preview></pre>
                  </div>
                  <label data-help="success_key" data-gateway-inline-field>
                    <span>Success Key</span>
                    <input name="gateway_response_success_key" value="${{esc(gatewaySuccessKey)}}" ${{canEdit ? "" : "disabled"}}>
                  </label>
                  <label data-help="data_key" data-gateway-inline-field>
                    <span>Data Key</span>
                    <input name="gateway_response_data_key" value="${{esc(gatewayDataKey)}}" ${{canEdit ? "" : "disabled"}}>
                  </label>
                  <label data-help="message_key" data-gateway-inline-field>
                    <span>Message Key</span>
                    <input name="gateway_response_message_key" value="${{esc(gatewayMessageKey)}}" ${{canEdit ? "" : "disabled"}}>
                  </label>
                  <label data-help="error_key" data-gateway-inline-field>
                    <span>Error Key</span>
                    <input name="gateway_response_error_key" value="${{esc(gatewayErrorKey)}}" ${{canEdit ? "" : "disabled"}}>
                  </label>
                  <label class="full" data-help="gateway_response_empty_value" data-gateway-inline-field>
                    <span>Empty Value (YAML/JSON Scalar Or Structure)</span>
                    <textarea name="gateway_response_empty_value">${{esc(gatewayEmptyValueText)}}</textarea>
                  </label>
                  <label class="full" data-help="gateway_response_headers">
                    <span>Gateway Response Headers (JSON/YAML Mapping)</span>
                    <textarea name="gateway_response_headers_yaml">${{esc(jsonText(gatewayHeaders))}}</textarea>
                  </label>
                </div>
              </div>
              <div class="actions" style="margin-top: 12px;">
                ${{
                  canEdit
                    ? '<button type="submit">Save Settings</button>'
                    : '<span class="muted">This account does not have <code>services_manage</code> for gateway config changes.</span>'
                }}
              </div>
            </form>
          `;
          decorateHelp(wrap);
          const form = wrap.querySelector("[data-gateway-settings-form]");
          if (form) {{
            syncGatewayResponseSettings(form);
          }}
          syncBackupControls(wrap);
        }}

        function renderAudit() {{
          const wrap = document.getElementById("audit-wrap");
          const topActions = document.getElementById("audit-top-actions");
          if (!wrap || !topActions) return;

          const rows = Array.isArray(STATE.audit_logs) ? STATE.audit_logs : [];
          const stateStoreMode = String(STATE.store?.mode || "file");
          const auditEnabled = Boolean(STATE.store?.audit_enabled);

          topActions.innerHTML = `
            <span class="tag">Store ${{esc(stateStoreMode.toUpperCase())}}</span>
            <span class="tag">${{rows.length}} recent change(s)</span>
          `;

          if (!auditEnabled) {{
            wrap.innerHTML = '<div class="empty">Admin change logging is not enabled for the current state store.</div>';
            return;
          }}

          if (!rows.length) {{
            wrap.innerHTML = '<div class="empty">No admin changes have been recorded yet.</div>';
            return;
          }}

          wrap.innerHTML = `
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>User</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Listener</th>
                  <th>Client IP</th>
                  <th>Message</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                ${{
                  rows.map((entry) => {{
                    const details = entry.details && typeof entry.details === "object" ? entry.details : {{}};
                    const detailKeys = Object.keys(details);
                    const detailsHtml = detailKeys.length
                      ? `
                        <details>
                          <summary>${{detailKeys.length}} field(s)</summary>
                          <div class="detail-box" style="margin-top:8px;">
                            <pre>${{esc(JSON.stringify(details, null, 2))}}</pre>
                          </div>
                        </details>
                      `
                      : '<span class="muted">-</span>';
                    return `
                      <tr>
                        <td>${{esc(formatDateTime(entry.created_at))}}</td>
                        <td><strong>${{esc(entry.principal_username)}}</strong><div class="muted">${{esc(entry.principal_source || "")}}</div></td>
                        <td><span class="tag">${{esc(entry.action)}}</span></td>
                        <td><div><strong>${{esc(entry.target_kind)}}</strong></div><div class="mono">${{esc(entry.target_ref)}}</div></td>
                        <td><span class="tag">${{esc(entry.listener || "-")}}</span></td>
                        <td class="mono">${{esc(entry.client_ip || "-")}}</td>
                        <td>${{esc(entry.message || "")}}</td>
                        <td>${{detailsHtml}}</td>
                      </tr>
                    `;
                  }}).join("")
                }}
              </tbody>
            </table>
          `;
        }}

        async function submitGatewaySettings(event, form) {{
          event.preventDefault();
          showAdminNotice("");
          if (!validateAdminForm(form)) return false;
          const submitButton = form.querySelector('[type="submit"]');
          submitButton?.setAttribute("disabled", "disabled");
          try {{
            const payload = await postAdminMutation(form.action, formPayload(form));
            showAdminNotice(payload.message || "Saved.");
          }} catch (error) {{
            showAdminNotice(String(error?.message || error), "error");
          }} finally {{
            submitButton?.removeAttribute("disabled");
          }}
          return false;
        }}

        function renderLive() {{
          const wrap = document.getElementById("live-wrap");
          const topActions = document.getElementById("live-top-actions");
          if (!wrap || !topActions) return;

          topActions.innerHTML = STATE.live?.can_view
            ? `
              <button class="btn light" type="button" onclick="toggleLivePause()">${{livePaused ? "Resume Live" : "Pause Live"}}</button>
              <a class="btn light" href="${{esc(STATE.live.monitor_url || "/__monitor")}}">Show Log Table</a>
            `
            : "";

          if (!STATE.live?.can_view) {{
            wrap.innerHTML = `
              <div class="card">
                <div class="empty">
                  This account can open the admin panel, but it does not have <code>monitor_access</code> for live gateway logs.
                </div>
              </div>
            `;
            return;
          }}

          const analytics = liveAnalytics();
          const summary = analytics.recent;
          const totals = analytics.totals || {{
            requests: summary.total,
            failures: summary.failures,
            successes: Math.max(0, summary.total - summary.failures),
            failure_rate: summary.total ? (summary.failures / summary.total) * 100 : 0,
            cache_hits: liveRows.filter((row) => liveResponseSource(row) === "cache").length,
            cache_hit_rate: summary.total
              ? (liveRows.filter((row) => liveResponseSource(row) === "cache").length / summary.total) * 100
              : 0,
            avg_duration_ms: summary.averageDurationMicros / 1000,
            p95_duration_ms: 0,
            requests_last_hour: summary.total,
            failures_last_hour: summary.failures,
            peak_bucket_requests: summary.total,
          }};
          const badge = liveBadgeState();
          const recentRows = liveRows.slice(0, 12);
          const reportGeneratedAt = analytics.report?.generated_at || summary.lastSeen || "";

          wrap.innerHTML = `
            <div class="live-grid">
              <div class="live-stat">
                <div class="live-label">Services</div>
                <div class="live-value">${{STATE.services.length}}</div>
                <div class="live-subvalue">${{(STATE.routes || []).length}} route(s), ${{STATE.clients.length}} client(s)</div>
              </div>
              <div class="live-stat">
                <div class="live-label">Requests | 24h</div>
                <div class="live-value">${{numberOrZero(totals.requests)}}</div>
                <div class="live-subvalue">${{numberOrZero(totals.requests_last_hour)}} in the last hour</div>
              </div>
              <div class="live-stat">
                <div class="live-label">Failures | 24h</div>
                <div class="live-value">${{numberOrZero(totals.failures)}}</div>
                <div class="live-subvalue">${{percent(totals.failures, totals.requests)}} failure rate</div>
              </div>
              <div class="live-stat">
                <div class="live-label">Cache Hit Rate | 24h</div>
                <div class="live-value">${{percent(totals.cache_hits, totals.requests)}}</div>
                <div class="live-subvalue">${{numberOrZero(totals.cache_hits)}} cached responses</div>
              </div>
              <div class="live-stat">
                <div class="live-label">Average Duration | 24h</div>
                <div class="live-value">${{formatMsNumber(totals.avg_duration_ms)}}</div>
                <div class="live-subvalue">Visible sample: ${{formatMsNumber(summary.averageDurationMicros / 1000)}}</div>
              </div>
              <div class="live-stat">
                <div class="live-label">P95 Duration | 24h</div>
                <div class="live-value">${{formatMsNumber(totals.p95_duration_ms)}}</div>
                <div class="live-subvalue">Peak hour: ${{numberOrZero(totals.peak_bucket_requests)}} req</div>
              </div>
              <div class="live-stat">
                <div class="live-label">Latest Visible</div>
                <div class="live-value">${{summary.total}}</div>
                <div class="live-subvalue">Recent rows refreshed: ${{esc(formatDateTime(summary.lastSeen))}}</div>
              </div>
            </div>

            <div class="live-report-grid">
              <div class="live-chart-card">
                <h3 class="live-card-title">24 Hour Activity</h3>
                <div class="live-card-note">
                  Hourly requests and failures from monitor storage, refreshed with the Live tab.
                  Snapshot time: <span class="mono">${{esc(formatDateTime(reportGeneratedAt))}}</span>
                </div>
                ${{renderTrendChart(analytics.hourly)}}
              </div>

              <div class="live-report-side">
                <div class="live-list-card">
                  <h3 class="live-card-title">Status Breakdown | 24h</h3>
                  <div class="live-card-note">Count of 2xx, 3xx, 4xx, 5xx, and other responses in the report window.</div>
                  ${{renderStatusBreakdown(analytics.statusBreakdown)}}
                </div>
                <div class="live-list-card">
                  <h3 class="live-card-title">Top Services | 24h</h3>
                  <div class="live-card-note">Busiest upstream services by request volume and average latency.</div>
                  ${{renderTopList(analytics.topServices, "name", "No service activity in the last 24 hours.")}}
                </div>
                <div class="live-list-card">
                  <h3 class="live-card-title">Top Gateway Paths | 24h</h3>
                  <div class="live-card-note">Most active public routes in the same report window.</div>
                  ${{renderTopList(analytics.topPaths, "path", "No gateway path activity in the last 24 hours.")}}
                </div>
              </div>
            </div>

            <div class="live-table-card">
              <div class="live-head">
                <div>
                  <h3 class="section-title" style="font-size:16px; margin-bottom:4px;">Live Request Feed</h3>
                  <div class="section-note">${{livePaused
                    ? 'Updates are paused. Resume when you want the table to move again.'
                    : 'This tab refreshes automatically from <span class="mono">/__monitor/logs</span>. For richer upstream and response details, use the standalone monitor table.'}}</div>
                </div>
                <span class="live-badge ${{badge.className}}">
                  <span class="live-dot"></span>
                  ${{esc(badge.label)}}
                </span>
              </div>

              ${{
                recentRows.length
                  ? `
                    <table>
                      <thead>
	                        <tr>
	                          <th>Time</th>
	                          <th>Method</th>
	                          <th>Gateway Path</th>
	                          <th>Service</th>
	                          <th>Status</th>
	                          <th>Duration</th>
	                          <th>Client IP</th>
	                        </tr>
                      </thead>
                      <tbody>
                        ${{
                          recentRows.map((row) => `
	                            <tr>
	                              <td>${{esc(formatDateTime(row.created_at))}}</td>
	                              <td>${{esc(row.method)}}</td>
	                              <td class="mono">${{esc(row.gateway_path)}}</td>
	                              <td>${{esc(row.service_name)}} / ${{esc(row.endpoint_name)}}</td>
	                              <td><span class="tag ${{statusClass(row.status_code)}}">${{esc(row.status_code)}}</span></td>
	                              <td>${{esc(row.duration_display || formatDuration(row))}}</td>
	                              <td class="mono">${{esc(row.client_ip)}}</td>
                            </tr>
                          `).join("")
                        }}
                      </tbody>
                    </table>
                  `
                  : '<div class="empty">No monitor rows yet. Send a few requests through the gateway to populate live data.</div>'
              }}
            </div>
          `;
        }}

        async function refreshLiveLogs() {{
          if (!STATE.live?.can_view || livePaused) return;
          try {{
            const [logsResponse, reportResponse] = await Promise.all([
              fetch(STATE.live.logs_url || "/__monitor/logs", {{
                headers: {{
                  "Accept": "application/json",
                }},
                cache: "no-store",
              }}),
              fetch(reportUrlWithBrowserTimezone(STATE.live.report_url), {{
                headers: {{
                  "Accept": "application/json",
                }},
                cache: "no-store",
              }}),
            ]);
            if (livePaused) return;
            if (!logsResponse.ok) {{
              throw new Error(`HTTP ${{logsResponse.status}}`);
            }}
            if (!reportResponse.ok) {{
              throw new Error(`HTTP ${{reportResponse.status}}`);
            }}
            const [payload, reportPayload] = await Promise.all([
              logsResponse.json(),
              reportResponse.json(),
            ]);
            if (livePaused) return;
            liveRows = Array.isArray(payload) ? payload : [];
            liveReport = reportPayload && typeof reportPayload === "object" ? reportPayload : liveReport;
            liveConnectionState = "online";
          }} catch (_error) {{
            if (livePaused) return;
            liveConnectionState = "error";
          }}
          renderLive();
        }}

        function stopLivePolling() {{
          if (livePollTimer !== null) {{
            window.clearInterval(livePollTimer);
            livePollTimer = null;
          }}
        }}

        function toggleLivePause() {{
          if (!STATE.live?.can_view) return;
          livePaused = !livePaused;
          if (livePaused) {{
            liveConnectionState = "paused";
            stopLivePolling();
            renderLive();
            return;
          }}
          liveConnectionState = "connecting";
          renderLive();
          startLivePolling();
        }}

        function startLivePolling() {{
          renderLive();
          if (!STATE.live?.can_view || livePaused || livePollTimer !== null) return;
          refreshLiveLogs();
          livePollTimer = window.setInterval(refreshLiveLogs, 3000);
        }}

        function protocolCatalog(kind) {{
          return Array.isArray(STATE.catalog?.[kind]) ? STATE.catalog[kind] : [];
        }}

        function protocolOptionLabel(item) {{
          if (!item) return "";
          return item.implemented ? item.code : `${{item.code}} (planned)`;
        }}

        function serviceProtocolOptionsHtml(selected = "http") {{
          return protocolCatalog("service_protocols")
            .map((item) => `<option value="${{esc(item.code)}}" ${{(selected || "http") === item.code ? "selected" : ""}}>${{esc(protocolOptionLabel(item))}}</option>`)
            .join("");
        }}

        function routeProtocolOptionsHtml(selected = "http") {{
          return protocolCatalog("route_protocols")
            .map((item) => `<option value="${{esc(item.code)}}" ${{(selected || "http") === item.code ? "selected" : ""}}>${{esc(protocolOptionLabel(item))}}</option>`)
            .join("");
        }}

        function protocolTag(code, implemented) {{
          return `<span class="tag ${{implemented ? "ok" : "warn"}}">Protocol ${{esc(code)}}${{implemented ? "" : " planned"}}</span>`;
        }}

        function serviceProtocolImplemented(code) {{
          return protocolCatalog("service_protocols").some((item) => item.code === code && item.implemented);
        }}

        function routeProtocolImplemented(code) {{
          return protocolCatalog("route_protocols").some((item) => item.code === code && item.implemented);
        }}

        function renderServices() {{
          const wrap = document.getElementById("services-table-wrap");
          const topActions = document.getElementById("services-top-actions");
          topActions.innerHTML = has("services_manage")
            ? '<button class="btn" type="button" onclick="showServiceForm()">Add Service</button>'
            : '';

          if (!STATE.services.length) {{
            wrap.innerHTML = '<div class="empty">No services found.</div>';
            return;
          }}

          wrap.innerHTML = `
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Protocol</th>
                  <th>Base URL / Target</th>
                  <th>Timeout</th>
                  <th>Endpoints</th>
                  <th>Features</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${{
                  STATE.services.map((service) => `
                    <tr>
                      <td><strong>${{esc(service.name)}}</strong></td>
                      <td>${{protocolTag(service.protocol || "http", serviceProtocolImplemented(service.protocol || "http"))}}</td>
                      <td class="mono">${{esc(service.base_url)}}</td>
                      <td>${{service.timeout_seconds}}</td>
                      <td>${{service.endpoints.length}}</td>
                      <td>
                        <span class="tag">${{scopedClientsCount(service.name)}} scoped client(s)</span>
                        <span class="tag ${{service.verify_ssl ? 'ok' : 'warn'}}">SSL ${{service.verify_ssl ? 'On' : 'Off'}}</span>
                        <span class="tag ${{service.trust_env_proxy ? 'warn' : 'ok'}}">Proxy ${{service.trust_env_proxy ? 'Env' : 'Direct'}}</span>
                        <span class="tag ${{service.forward_napigate_headers ? 'ok' : 'warn'}}">NapiGate Headers ${{service.forward_napigate_headers ? 'On' : 'Off'}}</span>
                        ${{service.pre_call?.code ? '<span class="tag warn">pre_call</span>' : ''}}
                        ${{service.response_cache?.ttl_seconds ? `<span class="tag warn">Cache ${{esc(service.response_cache.ttl_seconds)}}s</span>` : ''}}
                        <span class="tag ${{service.cors?.enabled ? 'ok' : ''}}">CORS ${{service.cors?.enabled ? 'On' : 'Off'}}</span>
                        <span class="tag ${{service.rate_limit?.enabled ? 'warn' : ''}}">Rate Limit ${{service.rate_limit?.enabled ? `${{service.rate_limit.requests}}/${{service.rate_limit.window_seconds}}s` : 'Off'}}</span>
                      </td>
                      <td>
                        <div class="actions">
                          <button class="btn light" type="button" onclick="showServiceView(decodeURIComponent('${{arg(service.name)}}'))">View</button>
                          <button class="btn secondary" type="button" onclick="showEndpoints(decodeURIComponent('${{arg(service.name)}}'))">Endpoints</button>
                          ${{
                            has("services_manage")
                              ? `
                                <button class="btn" type="button" onclick="showServiceForm(decodeURIComponent('${{arg(service.name)}}'))">Edit</button>
                                <button class="btn danger" type="button" onclick="deleteService(decodeURIComponent('${{arg(service.name)}}'))">Delete</button>
                              `
                              : ''
                          }}
                        </div>
                      </td>
                    </tr>
                  `).join('')
                }}
              </tbody>
            </table>
          `;
        }}

        function routeTargetsText(route) {{
          return (route.targets || []).map((target) => `${{target.service}} / ${{target.endpoint}}`).join(", ");
        }}

        function routesForEndpoint(serviceName, endpointName) {{
          const endpoint = endpointByName(serviceName, endpointName);
          return (STATE.routes || []).filter((route) =>
            (route.targets || []).some((target) =>
              target.service === serviceName && (target.endpoint === endpointName || target.endpoint === endpoint?.slug)
            )
          );
        }}

        function resolveRouteTarget(target) {{
          const service = serviceByName(target.service);
          const endpoint = service?.endpoints.find((item) => item.name === target.endpoint || item.slug === target.endpoint);
          if (!service || !endpoint) return null;
          return {{ service, endpoint }};
        }}

        function routeTargetsForCurl(route) {{
          return (route?.targets || [])
            .map((target) => resolveRouteTarget(target))
            .filter(Boolean);
        }}

        function routeProtectedTargets(route) {{
          return route?.auth?.required ? routeTargetsForCurl(route) : [];
        }}

        function routeEligibleClients(route) {{
          const routeTargets = routeTargetsForCurl(route);
          if (!routeTargets.length) return [];
          return STATE.clients.filter((client) =>
            client.enabled
            && routeTargets.some((target) => clientTouchesEndpoint(client, target.service.name, target.endpoint))
          );
        }}

        function routeEligibleAuthMethods(route, clientSlug) {{
          const client = clientBySlug(clientSlug);
          if (!client) return [];
          const methods = [];
          const seenCodes = new Set();
          (client.auth_methods || []).forEach((method) => {{
            const code = String(method.code || "").trim();
            if (!method.enabled || !code || seenCodes.has(code)) return;
            seenCodes.add(code);
            methods.push(method);
          }});
          return methods.sort((left, right) => authPriority(left.type) - authPriority(right.type));
        }}

        function buildRouteCurl(routeSlug, methodName = "", authSample = null) {{
          const route = routeBySlug(routeSlug);
          if (!route) return "";
          if (String(route.protocol || "http").toLowerCase() !== "http") return "";
          const requestMethod = String(methodName || route.methods?.[0] || "GET").toUpperCase();
          const publicBaseUrl = String(STATE.network?.public_base_url || window.location.origin || "").trim();
          let url = `${{publicBaseUrl}}${{sampleGatewayPath(route.gateway_path)}}`;
          const command = ["curl", `-X ${{requestMethod}}`];

          const sample = authSample || emptyAuthSample();
          (sample.query || []).forEach(([key, value]) => {{
            url = appendQueryParam(url, key, value);
          }});
          if (sample.basic) {{
            command.push(`-u ${{shellQuote(sample.basic)}}`);
          }}
          if ((sample.headers || []).length) {{
            sample.headers.forEach((header) => command.push(`-H ${{shellQuote(header)}}`));
          }}
          if ((sample.cookies || []).length) {{
            command.push(`-b ${{shellQuote(sample.cookies.join('; '))}}`);
          }}

          if (["POST", "PUT", "PATCH"].includes(requestMethod)) {{
            command.push(`-H ${{shellQuote("Content-Type: application/json")}}`);
            command.push(`-d ${{shellQuote("{{}}")}}`);
          }}

          command.push(shellQuote(url));
          return command.join(" \\\n  ");
        }}

        function routeCurlButtonHtml(routeSlug, methodName = "", label = "Copy cURL") {{
          const route = routeBySlug(routeSlug);
          if (route && String(route.protocol || "http").toLowerCase() !== "http") {{
            return `<span class="tag warn">cURL unavailable for ${{esc(route.protocol)}}</span>`;
          }}
          return `
            <button
              class="btn light"
              type="button"
              onclick="showRouteCurlModal(decodeURIComponent('${{arg(routeSlug)}}'), decodeURIComponent('${{arg(methodName)}}'))"
            >
              ${{esc(label)}}
            </button>
          `;
        }}

        async function copyGeneratedCurl(button) {{
          const curl = button.closest("[data-curl-modal]")?.querySelector("[data-curl-output]")?.textContent || "";
          if (!curl.trim()) return;
          const originalText = button.dataset.label || button.textContent;
          button.dataset.label = originalText;
          try {{
            await copyTextToClipboard(curl);
            button.textContent = "Copied";
          }} catch (_error) {{
            button.textContent = "Copy failed";
          }}
          window.setTimeout(() => {{
            button.textContent = originalText;
          }}, 1400);
        }}

        function syncRouteCurlModal(container, options = {{}}) {{
          const route = routeBySlug(container?.dataset.routeSlug || "");
          if (!route) return;

          const resetClient = Boolean(options.resetClient);
          const resetMethod = Boolean(options.resetMethod);
          const methodName = String(container.dataset.methodName || route.methods?.[0] || "GET").toUpperCase();
          const modeSelect = container.querySelector('[name="curl_auth_mode"]');
          const clientWrap = container.querySelector("[data-curl-client-wrap]");
          const methodWrap = container.querySelector("[data-curl-method-wrap]");
          const clientSelect = container.querySelector('[name="curl_client_slug"]');
          const methodSelect = container.querySelector('[name="curl_auth_method_code"]');
          const note = container.querySelector("[data-curl-note]");
          const output = container.querySelector("[data-curl-output]");

          if (!modeSelect || !clientWrap || !methodWrap || !clientSelect || !methodSelect || !note || !output) return;

          const authMode = modeSelect.value || "without_auth";
          const protectedTargets = routeProtectedTargets(route);
          const eligibleClients = routeEligibleClients(route);
          const shouldShowAuth = authMode === "with_auth";
          const authRequired = protectedTargets.length > 0;

          clientWrap.style.display = shouldShowAuth ? "" : "none";
          methodWrap.style.display = shouldShowAuth ? "" : "none";

          if (!shouldShowAuth) {{
            note.textContent = authRequired
              ? "Command is generated without incoming client credentials."
              : "This route does not require incoming client authentication.";
            output.textContent = buildRouteCurl(route.slug, methodName);
            return;
          }}

          const currentClientSlug = resetClient ? "" : clientSelect.value;
          clientSelect.innerHTML = eligibleClients.length
            ? eligibleClients
                .map((client) => `<option value="${{esc(client.slug)}}">${{esc(client.title || client.code)}} (${{esc(client.code)}})</option>`)
                .join("")
            : '<option value="">No eligible clients</option>';
          clientSelect.value = eligibleClients.some((client) => client.slug === currentClientSlug)
            ? currentClientSlug
            : (eligibleClients[0]?.slug || "");

          const methods = routeEligibleAuthMethods(route, clientSelect.value);
          const currentMethodCode = resetMethod ? "" : methodSelect.value;
          methodSelect.innerHTML = methods.length
            ? methods
                .map((method) => `<option value="${{esc(method.code)}}">${{esc(method.title || method.code)}} (${{esc(method.type)}})</option>`)
                .join("")
            : '<option value="">No enabled auth methods</option>';
          methodSelect.value = methods.some((method) => method.code === currentMethodCode)
            ? currentMethodCode
            : (methods[0]?.code || "");

          if (!eligibleClients.length) {{
            note.textContent = authRequired
              ? "No enabled client matches the protected route targets."
              : "No enabled client is scoped to this route.";
            output.textContent = buildRouteCurl(route.slug, methodName);
            return;
          }}

          if (!methods.length) {{
            note.textContent = authRequired
              ? "Selected client has no enabled auth methods."
              : "Selected client is scoped to this route but has no enabled auth methods.";
            output.textContent = buildRouteCurl(route.slug, methodName);
            return;
          }}

          const selectedClient = eligibleClients.find((client) => client.slug === clientSelect.value) || null;
          const selectedMethod = methods.find((method) => method.code === methodSelect.value) || methods[0];
          note.textContent = authRequired
            ? `Using ${{selectedClient?.title || selectedClient?.code || "client"}} via ${{selectedMethod.title || selectedMethod.code}} (${{selectedMethod.type}}).`
            : `Using ${{selectedClient?.title || selectedClient?.code || "client"}} via ${{selectedMethod.title || selectedMethod.code}} (${{selectedMethod.type}}), even though this route does not require incoming client authentication.`;
          output.textContent = buildRouteCurl(route.slug, methodName, authSampleForMethod(selectedMethod));
        }}

        function showRouteCurlModal(routeSlug, methodName = "") {{
          const route = routeBySlug(routeSlug);
          if (!route) return;
          if (String(route.protocol || "http").toLowerCase() !== "http") {{
            openModal("Generate cURL", `
              <div class="detail-box">
                <strong>${{esc(route.protocol || "route")}}</strong>
                <div class="muted" style="margin-top:8px;">Sample cURL generation is only available for HTTP ingress routes right now.</div>
              </div>
            `);
            return;
          }}

          const requestMethod = String(methodName || route.methods?.[0] || "GET").toUpperCase();
          const protectedTargets = routeProtectedTargets(route);
          const defaultAuthMode = protectedTargets.length ? "with_auth" : "without_auth";

          openModal(`Generate ${{requestMethod}} cURL`, `
            <div class="stack" data-curl-modal data-route-slug="${{esc(route.slug)}}" data-method-name="${{esc(requestMethod)}}">
              <div class="section-note">
                Build a sample request for <span class="mono">${{esc(route.gateway_path)}}</span> using <span class="mono">${{esc(requestMethod)}}</span>.
              </div>
              <div class="form-grid">
                <label>
                  <span>Auth Mode</span>
                  <select name="curl_auth_mode">
                    <option value="without_auth" ${{defaultAuthMode === "without_auth" ? "selected" : ""}}>Without Auth</option>
                    <option value="with_auth" ${{defaultAuthMode === "with_auth" ? "selected" : ""}}>With Auth</option>
                  </select>
                </label>
                <label data-curl-client-wrap>
                  <span>Client</span>
                  <select name="curl_client_slug"></select>
                </label>
                <label data-curl-method-wrap>
                  <span>Auth Method</span>
                  <select name="curl_auth_method_code"></select>
                </label>
              </div>
              <div class="section-note" data-curl-note></div>
              <div class="detail-box">
                <pre data-curl-output></pre>
              </div>
              <div class="actions">
                <button class="btn" type="button" onclick="copyGeneratedCurl(this)">Copy Command</button>
              </div>
            </div>
          `);

          const container = modalBody.querySelector("[data-curl-modal]");
          const modeSelect = container?.querySelector('[name="curl_auth_mode"]');
          const clientSelect = container?.querySelector('[name="curl_client_slug"]');
          const methodSelect = container?.querySelector('[name="curl_auth_method_code"]');

          modeSelect?.addEventListener("change", () => syncRouteCurlModal(container, {{ resetClient: true, resetMethod: true }}));
          clientSelect?.addEventListener("change", () => syncRouteCurlModal(container, {{ resetMethod: true }}));
          methodSelect?.addEventListener("change", () => syncRouteCurlModal(container));
          syncRouteCurlModal(container);
        }}

        function renderRoutes() {{
          const wrap = document.getElementById("routes-table-wrap");
          const topActions = document.getElementById("routes-top-actions");
          if (!wrap || !topActions) return;

          topActions.innerHTML = has("services_manage")
            ? '<button class="btn" type="button" onclick="showRouteForm()">Add Route</button>'
            : '';

          if (!STATE.routes?.length) {{
            wrap.innerHTML = '<div class="empty">No routes found. Create endpoints first, then expose gateway paths from this tab.</div>';
            return;
          }}

          wrap.innerHTML = `
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Protocol</th>
                  <th>Gateway Path</th>
                  <th>Methods</th>
                  <th>Strategy</th>
                  <th>Targets</th>
                  <th>Output</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${{
                  STATE.routes.map((route) => `
                    <tr>
                      <td><strong>${{esc(route.name)}}</strong><div class="muted mono">${{esc(route.slug)}}</div></td>
                      <td>${{protocolTag(route.protocol || "http", routeProtocolImplemented(route.protocol || "http"))}}</td>
                      <td class="mono">${{esc(route.gateway_path)}}</td>
                      <td>${{(route.methods || []).map((method) => `<span class="tag">${{esc(method)}}</span>`).join('')}}</td>
                      <td><span class="tag ${{route.strategy === 'failover' ? 'warn' : route.strategy === 'parallel_race' ? 'ok' : ''}}">${{esc(route.strategy)}}</span></td>
                      <td class="mono">${{esc(routeTargetsText(route))}}</td>
                      <td>
                        <span class="tag ${{route.auth?.required ? 'warn' : 'ok'}}">${{route.auth?.required ? 'Protected' : 'Public'}}</span>
                        ${{
                          route.output_profile
                            ? `<span class="tag ok">${{esc(route.output_profile)}}</span>`
                            : '<span class="muted">passthrough</span>'
                        }}
                        ${{
                          Number(route.response_cache?.ttl_seconds || 0) > 0
                            ? `<span class="tag warn">Cache ${{esc(route.response_cache.ttl_seconds)}}s</span>`
                            : ''
                        }}
                        ${{
                          route.success_hook?.url
                            ? '<span class="tag ok">Hook</span>'
                            : ''
                        }}
                        ${{route.pre_call?.code ? '<span class="tag warn">pre_call</span>' : ''}}
                      </td>
                      <td>
                        <div class="actions">
                          <button class="btn light" type="button" onclick="showRouteView(decodeURIComponent('${{arg(route.slug)}}'))">View</button>
                          ${{
                            (route.protocol || "http") === "http"
                              ? `<button class="btn light" type="button" onclick="showRouteCurlModal(decodeURIComponent('${{arg(route.slug)}}'), decodeURIComponent('${{arg(route.methods?.[0] || 'GET')}}'))">Copy cURL</button>`
                              : `<span class="tag warn">No cURL</span>`
                          }}
                          ${{
                            has("services_manage")
                              ? `
                                <button class="btn" type="button" onclick="showRouteForm(decodeURIComponent('${{arg(route.slug)}}'))">Edit</button>
                                <button class="btn danger" type="button" onclick="deleteRoute(decodeURIComponent('${{arg(route.slug)}}'))">Delete</button>
                              `
                              : ''
                          }}
                        </div>
                      </td>
                    </tr>
                  `).join('')
                }}
              </tbody>
            </table>
          `;
        }}

        function renderClients() {{
          const wrap = document.getElementById("clients-table-wrap");
          const topActions = document.getElementById("clients-top-actions");
          topActions.innerHTML = has("services_manage")
            ? '<button class="btn" type="button" onclick="showClientForm()">Add Client</button>'
            : '';

          if (!STATE.clients.length) {{
            wrap.innerHTML = '<div class="empty">No gateway clients found.</div>';
            return;
          }}

          wrap.innerHTML = `
            <table>
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Slug</th>
                  <th>Code</th>
                  <th>Auth Methods</th>
                  <th>Access Scope</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${{
                  STATE.clients.map((client) => `
                    <tr>
                      <td><strong>${{esc(client.title)}}</strong></td>
                      <td class="mono">${{esc(client.slug)}}</td>
                      <td class="mono">${{esc(client.code)}}</td>
                      <td>
                        <span class="tag">${{client.auth_methods.length}} method(s)</span>
                        ${{
                          client.auth_methods.map((method) =>
                            `<span class="tag ${{method.enabled ? 'ok' : 'warn'}}">${{esc(method.type)}}</span>`
                          ).join('')
                        }}
                      </td>
                      <td>
                        <span class="tag">${{esc(clientScopeSummary(client))}}</span>
                        ${{
                          client.ip_allowlist.length
                            ? `<span class="tag warn">${{client.ip_allowlist.length}} IP rule(s)</span>`
                            : '<span class="muted">No IP restriction</span>'
                        }}
                      </td>
                      <td><span class="tag ${{client.enabled ? 'ok' : 'warn'}}">${{client.enabled ? 'Enabled' : 'Disabled'}}</span></td>
                      <td>
                        <div class="actions">
                          <button class="btn light" type="button" onclick="showClientView(decodeURIComponent('${{arg(client.slug)}}'))">View</button>
                          ${{
                            has("services_manage")
                              ? `
                                <button class="btn" type="button" onclick="showClientForm(decodeURIComponent('${{arg(client.slug)}}'))">Edit</button>
                                <button class="btn danger" type="button" onclick="deleteClient(decodeURIComponent('${{arg(client.slug)}}'))">Delete</button>
                              `
                              : ''
                          }}
                        </div>
                      </td>
                    </tr>
                  `).join('')
                }}
              </tbody>
            </table>
          `;
        }}

        function renderOutputProfiles() {{
          const wrap = document.getElementById("output-table-wrap");
          const topActions = document.getElementById("output-top-actions");
          if (!wrap || !topActions) return;

          topActions.innerHTML = has("services_manage")
            ? '<button class="btn" type="button" onclick="showOutputProfileForm()">Add Output Profile</button>'
            : '';

          if (!STATE.output_profiles.length) {{
            wrap.innerHTML = '<div class="empty">No output profiles found. Routes will stay passthrough until you define one.</div>';
            return;
          }}

          wrap.innerHTML = `
            <table>
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Slug</th>
                  <th>Type</th>
                  <th>Rule</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${{
                  STATE.output_profiles.map((profile) => `
                    <tr>
                      <td><strong>${{esc(profile.title)}}</strong></td>
                      <td class="mono">${{esc(profile.slug)}}</td>
                      <td><span class="tag">${{esc(profile.type)}}</span></td>
                      <td class="mono">${{esc(outputProfileRuleSummary(profile))}}</td>
                      <td><span class="tag ${{profile.enabled ? 'ok' : 'warn'}}">${{profile.enabled ? 'Enabled' : 'Disabled'}}</span></td>
                      <td>
                        <div class="actions">
                          <button class="btn light" type="button" onclick="showOutputProfileView(decodeURIComponent('${{arg(profile.slug)}}'))">View</button>
                          ${{
                            has("services_manage")
                              ? `
                                <button class="btn" type="button" onclick="showOutputProfileForm(decodeURIComponent('${{arg(profile.slug)}}'))">Edit</button>
                                <button class="btn danger" type="button" onclick="deleteOutputProfile(decodeURIComponent('${{arg(profile.slug)}}'))">Delete</button>
                              `
                              : ''
                          }}
                        </div>
                      </td>
                    </tr>
                  `).join('')
                }}
              </tbody>
            </table>
          `;
        }}

        function renderRoles() {{
          const wrap = document.getElementById("roles-table-wrap");
          const topActions = document.getElementById("roles-top-actions");
          topActions.innerHTML = has("security_manage")
            ? '<button class="btn" type="button" onclick="showRoleForm()">Add Role</button>'
            : '';

          if (!STATE.security.roles.length) {{
            wrap.innerHTML = '<div class="empty">No roles found.</div>';
            return;
          }}

          wrap.innerHTML = `
            <table>
              <thead>
                <tr>
                  <th>Role Name</th>
                  <th>Permissions</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${{
                  STATE.security.roles.map((role) => `
                    <tr>
                      <td><strong>${{esc(role.name)}}</strong></td>
                      <td>
                        ${{
                          role.permissions.length
                            ? role.permissions.map((permission) => `<span class="tag">${{esc(STATE.security.permission_labels[permission] || permission)}}</span>`).join('')
                            : '<span class="muted">No permissions</span>'
                        }}
                      </td>
                      <td>
                        <div class="actions">
                          <button class="btn light" type="button" onclick="showRoleView(decodeURIComponent('${{arg(role.name)}}'))">View</button>
                          ${{
                            has("security_manage")
                              ? `
                                <button class="btn" type="button" onclick="showRoleForm(decodeURIComponent('${{arg(role.name)}}'))">Edit</button>
                                <button class="btn danger" type="button" onclick="deleteRole(decodeURIComponent('${{arg(role.name)}}'))">Delete</button>
                              `
                              : ''
                          }}
                        </div>
                      </td>
                    </tr>
                  `).join('')
                }}
              </tbody>
            </table>
          `;
        }}

        function renderUsers() {{
          const wrap = document.getElementById("users-table-wrap");
          const topActions = document.getElementById("users-top-actions");
          topActions.innerHTML = has("security_manage")
            ? '<button class="btn" type="button" onclick="showUserForm()">Add User</button>'
            : '';

          if (!STATE.security.users.length) {{
            wrap.innerHTML = '<div class="empty">No users found yet. You can still sign in with the bootstrap admin from `.env`.</div>';
            return;
          }}

          wrap.innerHTML = `
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Roles</th>
                  <th>Status</th>
                  <th>Source</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${{
                  STATE.security.users.map((user) => `
                    <tr>
                      <td><strong>${{esc(user.username)}}</strong></td>
                      <td>
                        ${{
                          user.roles.length
                            ? user.roles.map((role) => `<span class="tag">${{esc(role)}}</span>`).join('')
                            : '<span class="muted">No roles</span>'
                        }}
                      </td>
                      <td><span class="tag ${{user.enabled ? 'ok' : 'warn'}}">${{user.enabled ? 'Enabled' : 'Disabled'}}</span></td>
                      <td>${{esc(user.source)}}</td>
                      <td>
                        <div class="actions">
                          <button class="btn light" type="button" onclick="showUserView(decodeURIComponent('${{arg(user.username)}}'))">View</button>
                          ${{
                            has("security_manage")
                              ? `
                                <button class="btn" type="button" onclick="showUserForm(decodeURIComponent('${{arg(user.username)}}'))">Edit</button>
                                <button class="btn danger" type="button" onclick="deleteUser(decodeURIComponent('${{arg(user.username)}}'))">Delete</button>
                              `
                              : ''
                          }}
                        </div>
                      </td>
                    </tr>
                  `).join('')
                }}
              </tbody>
            </table>
          `;
        }}

        function showServiceView(name) {{
          const service = serviceByName(name);
          openModal("View Service", `
            <div class="detail-box">
              <pre>${{esc(JSON.stringify(service, null, 2))}}</pre>
            </div>
          `);
        }}

        function showServiceForm(name = "") {{
          const service = name ? serviceByName(name) : null;
          openModal(service ? "Edit Service" : "Add Service", `
            <form method="post" action="/__admin/service/save" class="form-grid">
              <input type="hidden" name="original_name" value="${{esc(service?.name || "")}}">
              <label data-help="service_name">
                <span>Service Name</span>
                <input name="service_name" value="${{esc(service?.name || "")}}" required>
              </label>
              <label data-help="service_protocol">
                <span>Service Protocol</span>
                <select name="protocol">
                  ${{serviceProtocolOptionsHtml(service?.protocol || "http")}}
                </select>
              </label>
              <label data-help="base_url">
                <span>Base URL / Target</span>
                <input name="base_url" value="${{esc(service?.base_url || "")}}" required>
              </label>
              <label data-help="timeout_seconds">
                <span>Timeout Seconds</span>
                <input name="timeout_seconds" type="number" step="0.1" min="0" value="${{esc(String(service?.timeout_seconds ?? 30))}}">
              </label>
              <label class="check-item" data-help="verify_ssl">
                <input type="checkbox" name="verify_ssl" ${{service ? (service.verify_ssl ? "checked" : "") : "checked"}}>
                <div>
                  <strong>Verify SSL</strong>
                  <div class="muted">Send upstream requests with SSL verification enabled.</div>
                </div>
              </label>
              <label class="check-item" data-help="trust_env_proxy">
                <input type="checkbox" name="trust_env_proxy" ${{service?.trust_env_proxy ? "checked" : ""}}>
                <div>
                  <strong>Trust Env Proxy</strong>
                  <div class="muted">Allow upstream requests to inherit proxy settings from the environment.</div>
                </div>
              </label>
              <label class="check-item" data-help="forward_napigate_headers">
                <input type="checkbox" name="forward_napigate_headers" ${{service ? (service.forward_napigate_headers ? "checked" : "") : "checked"}}>
                <div>
                  <strong>Forward NapiGate Headers</strong>
                  <div class="muted">Send internal X-NapiGate route and client metadata headers to this upstream service.</div>
                </div>
              </label>
              <label class="full" data-help="variables_yaml">
                <span>Variables (JSON/YAML Mapping)</span>
                <textarea name="variables_yaml">${{esc(jsonText(service?.variables || {{}}))}}</textarea>
              </label>
              <label class="full" data-help="headers_yaml">
                <span>Headers (JSON/YAML Mapping)</span>
                <textarea name="headers_yaml">${{esc(jsonText(service?.headers || {{}}))}}</textarea>
              </label>
              <label data-help="pre_call_cache_ttl_seconds">
                <span>Pre-call Cache TTL</span>
                <input name="pre_call_cache_ttl_seconds" type="number" min="0" value="${{esc(String(service?.pre_call?.cache_ttl_seconds ?? 0))}}">
              </label>
              <label data-help="pre_call_cache_key">
                <span>Pre-call Cache Key</span>
                <input name="pre_call_cache_key" value="${{esc(service?.pre_call?.cache_key || "")}}">
              </label>
              <label class="full" data-help="pre_call_code">
                <span>Pre-call Code</span>
                <textarea name="pre_call_code">${{esc(service?.pre_call?.code || "")}}</textarea>
              </label>
              <label data-help="response_cache_ttl_seconds">
                <span>Response Cache TTL</span>
                <input name="response_cache_ttl_seconds" type="number" min="0" value="${{esc(String(service?.response_cache?.ttl_seconds ?? 0))}}">
              </label>
              <label class="check-item" data-help="response_cache_vary_by_client">
                <input type="checkbox" name="response_cache_vary_by_client" ${{service ? (service.response_cache?.vary_by_client ? "checked" : "") : "checked"}}>
                <div>
                  <strong>Cache Per Client</strong>
                  <div class="muted">Separate cached responses by authenticated client identity.</div>
                </div>
              </label>
              <label data-help="response_cache_methods">
                <span>Cache Methods</span>
                <input name="response_cache_methods" value="${{esc((service?.response_cache?.methods || ['GET']).join(', '))}}">
              </label>
              <label class="full" data-help="response_cache_vary_headers">
                <span>Cache Vary Headers (CSV)</span>
                <input name="response_cache_vary_headers" value="${{esc((service?.response_cache?.vary_headers || []).join(', '))}}">
              </label>
              <label class="check-item" data-help="cors_enabled">
                <input type="checkbox" name="cors_enabled" ${{service?.cors?.enabled ? "checked" : ""}}>
                <div>
                  <strong>Enable CORS</strong>
                  <div class="muted">Generate browser CORS headers and automatic OPTIONS preflight responses for this service.</div>
                </div>
              </label>
              <label class="full" data-help="cors_allow_origins">
                <span>Allowed Origins (CSV or newline)</span>
                <textarea name="cors_allow_origins">${{esc((service?.cors?.allow_origins || []).join('\\n'))}}</textarea>
              </label>
              <label data-help="cors_allow_methods">
                <span>Allowed Methods (CSV)</span>
                <input name="cors_allow_methods" value="${{esc((service?.cors?.allow_methods || []).join(', '))}}">
              </label>
              <label data-help="cors_allow_headers">
                <span>Allowed Headers (CSV)</span>
                <input name="cors_allow_headers" value="${{esc((service?.cors?.allow_headers || []).join(', '))}}">
              </label>
              <label data-help="cors_expose_headers">
                <span>Expose Headers (CSV)</span>
                <input name="cors_expose_headers" value="${{esc((service?.cors?.expose_headers || []).join(', '))}}">
              </label>
              <label data-help="cors_max_age_seconds">
                <span>CORS Max Age (seconds)</span>
                <input name="cors_max_age_seconds" type="number" min="0" value="${{esc(String(service?.cors?.max_age_seconds ?? 600))}}">
              </label>
              <label class="check-item" data-help="cors_allow_credentials">
                <input type="checkbox" name="cors_allow_credentials" ${{service?.cors?.allow_credentials ? "checked" : ""}}>
                <div>
                  <strong>Allow CORS Credentials</strong>
                  <div class="muted">Permit cookies or browser-managed auth headers on cross-origin requests.</div>
                </div>
              </label>
              <label class="check-item" data-help="rate_limit_enabled">
                <input type="checkbox" name="rate_limit_enabled" ${{service?.rate_limit?.enabled ? "checked" : ""}}>
                <div>
                  <strong>Enable Rate Limit</strong>
                  <div class="muted">Apply a sliding in-memory request limit before proxying upstream.</div>
                </div>
              </label>
              <label data-help="rate_limit_requests">
                <span>Rate Limit Requests</span>
                <input name="rate_limit_requests" type="number" min="1" value="${{esc(String(service?.rate_limit?.requests ?? 60))}}">
              </label>
              <label data-help="rate_limit_window_seconds">
                <span>Rate Limit Window (seconds)</span>
                <input name="rate_limit_window_seconds" type="number" min="1" value="${{esc(String(service?.rate_limit?.window_seconds ?? 60))}}">
              </label>
              <label data-help="rate_limit_scope">
                <span>Rate Limit Scope</span>
                <select name="rate_limit_scope">
                  <option value="client_or_ip" ${{(service?.rate_limit?.scope || "client_or_ip") === "client_or_ip" ? "selected" : ""}}>client_or_ip</option>
                  <option value="client" ${{service?.rate_limit?.scope === "client" ? "selected" : ""}}>client</option>
                  <option value="ip" ${{service?.rate_limit?.scope === "ip" ? "selected" : ""}}>ip</option>
                </select>
              </label>
              <div class="actions full">
                <button type="submit">Save Service</button>
              </div>
            </form>
          `);
        }}

        function showEndpoints(serviceName) {{
          const service = serviceByName(serviceName);
          openModal(`Endpoints for ${{service.name}}`, `
            <div class="section-head" style="margin-bottom: 10px;">
              <div>
                <div class="section-title" style="font-size:16px;">Endpoints Table</div>
                <div class="section-note">${{esc(service.base_url)}}</div>
              </div>
              <div class="actions">
                ${{
                  has("services_manage")
                    ? `<button class="btn" type="button" onclick="showEndpointForm(decodeURIComponent('${{arg(service.name)}}'))">Add Endpoint</button>`
                    : ''
                }}
              </div>
            </div>
            ${{
              service.endpoints.length
                ? `
                  <table>
                    <thead>
                      <tr>
                        <th>Name</th>
                        <th>Slug</th>
                        <th>Upstream</th>
                        <th>Routes</th>
                        <th>Pre-call</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      ${{service.endpoints.map((endpoint) => `
                        <tr>
                          <td><strong>${{esc(endpoint.name)}}</strong></td>
                          <td class="mono">${{esc(endpoint.slug || endpoint.name)}}</td>
                          <td class="mono">
                            ${{
                              endpoint.response
                                ? '<span class="tag ok">Local Response</span>'
                                : esc(endpoint.upstream_path)
                            }}
                          </td>
                          <td>
                            ${{
                              routesForEndpoint(service.name, endpoint.name).length
                                ? routesForEndpoint(service.name, endpoint.name).map((route) => `<span class="tag">${{esc(route.slug)}}</span>`).join('')
                                : '<span class="muted">No route</span>'
                            }}
                          </td>
                          <td>
                            ${{endpoint.pre_call?.code ? '<span class="tag warn">pre_call</span>' : '<span class="muted">None</span>'}}
                            ${{
                              endpoint.response_cache?.ttl_seconds
                                ? `<span class="tag warn">Endpoint Cache ${{esc(endpoint.response_cache.ttl_seconds)}}s</span>`
                                : service.response_cache?.ttl_seconds
                                  ? `<span class="tag">Service Cache ${{esc(service.response_cache.ttl_seconds)}}s</span>`
                                  : ''
                            }}
                          </td>
                          <td>
                            <div class="actions">
                              <button class="btn light" type="button" onclick="showEndpointView(decodeURIComponent('${{arg(service.name)}}'), decodeURIComponent('${{arg(endpoint.name)}}'))">View</button>
                              ${{
                                has("services_manage")
                                  ? `
                                    <button class="btn" type="button" onclick="showEndpointForm(decodeURIComponent('${{arg(service.name)}}'), decodeURIComponent('${{arg(endpoint.name)}}'))">Edit</button>
                                    <button class="btn danger" type="button" onclick="deleteEndpoint(decodeURIComponent('${{arg(service.name)}}'), decodeURIComponent('${{arg(endpoint.name)}}'))">Delete</button>
                                  `
                                  : ''
                              }}
                            </div>
                          </td>
                        </tr>
                      `).join('')}}
                    </tbody>
                  </table>
                `
                : '<div class="empty">No endpoints found for this service.</div>'
            }}
          `);
        }}

        function endpointByName(serviceName, endpointName) {{
          const service = serviceByName(serviceName);
          return service?.endpoints.find((endpoint) => endpoint.name === endpointName);
        }}

        function endpointRouteButtonsHtml(serviceName, endpointName) {{
          const routes = routesForEndpoint(serviceName, endpointName);
          if (!routes.length) return '<span class="muted">No public route points to this endpoint yet.</span>';
          return routes.flatMap((route) =>
            (route.methods || ["GET"]).map((method) =>
              routeCurlButtonHtml(route.slug, method, `Copy ${{route.slug}} ${{method}} cURL`)
            )
          ).join("");
        }}

        function showEndpointView(serviceName, endpointName) {{
          const endpoint = endpointByName(serviceName, endpointName);
          const curlButtons = endpointRouteButtonsHtml(serviceName, endpointName);
          openModal("View Endpoint", `
            <div class="stack">
              <div class="actions">${{curlButtons}}</div>
              <div class="detail-box">
                <pre>${{esc(JSON.stringify(endpoint, null, 2))}}</pre>
              </div>
            </div>
          `);
        }}

        function showEndpointForm(serviceName, endpointName = "") {{
          const endpoint = endpointName ? endpointByName(serviceName, endpointName) : null;
          openModal(endpoint ? "Edit Endpoint" : "Add Endpoint", `
            <form method="post" action="/__admin/endpoint/save" class="form-grid">
              <input type="hidden" name="service_name" value="${{esc(serviceName)}}">
              <input type="hidden" name="original_name" value="${{esc(endpoint?.name || "")}}">
              <input type="hidden" name="original_slug" value="${{esc(endpoint?.slug || "")}}">
              <label data-help="endpoint_name">
                <span>Endpoint Name</span>
                <input name="endpoint_name" value="${{esc(endpoint?.name || "")}}" required>
              </label>
              <label data-help="endpoint_slug">
                <span>Endpoint Slug</span>
                <input name="endpoint_slug" value="${{esc(endpoint?.slug || endpoint?.name || "")}}" required>
              </label>
              <label data-help="upstream_path">
                <span>Upstream Path</span>
                <input name="upstream_path" value="${{esc(endpoint?.upstream_path || "")}}">
              </label>
              ${{
                endpoint?.response
                  ? `
                    <div class="full detail-box">
                      <strong>Local Response Enabled</strong>
                      <div class="muted">This endpoint returns a built-in response from NapiGate. The admin form preserves that response block even though it is not edited here.</div>
                    </div>
                  `
                  : ''
              }}
              <label data-help="endpoint_output_profile">
                <span>Output Profile</span>
                <select name="output_profile">
                  <option value="">— inherit from route —</option>
                  ${{
                    STATE.output_profiles.map((profile) =>
                      `<option value="${{esc(profile.slug)}}" ${{(endpoint?.output_profile || "") === profile.slug ? "selected" : ""}}>${{esc(profile.slug)}}${{profile.enabled ? "" : " (disabled)"}}</option>`
                    ).join("")
                  }}
                </select>
              </label>
              <label class="full" data-help="endpoint_headers_yaml">
                <span>Headers (JSON/YAML Mapping)</span>
                <textarea name="headers_yaml">${{esc(jsonText(endpoint?.headers || {{}}))}}</textarea>
              </label>
              <label class="full" data-help="query_yaml">
                <span>Query (JSON/YAML Mapping)</span>
                <textarea name="query_yaml">${{esc(jsonText(endpoint?.query || {{}}))}}</textarea>
              </label>
              <label data-help="pre_call_cache_ttl_seconds">
                <span>Pre-call Cache TTL</span>
                <input name="pre_call_cache_ttl_seconds" type="number" min="0" value="${{esc(String(endpoint?.pre_call?.cache_ttl_seconds ?? 0))}}">
              </label>
              <label data-help="pre_call_cache_key">
                <span>Pre-call Cache Key</span>
                <input name="pre_call_cache_key" value="${{esc(endpoint?.pre_call?.cache_key || "")}}">
              </label>
              <label class="full" data-help="pre_call_code">
                <span>Pre-call Code</span>
                <textarea name="pre_call_code">${{esc(endpoint?.pre_call?.code || "")}}</textarea>
              </label>
              <label data-help="response_cache_ttl_seconds">
                <span>Response Cache TTL</span>
                <input name="response_cache_ttl_seconds" type="number" min="0" value="${{esc(String(endpoint?.response_cache?.ttl_seconds ?? 0))}}">
              </label>
              <label class="check-item" data-help="response_cache_vary_by_client">
                <input type="checkbox" name="response_cache_vary_by_client" ${{endpoint ? (endpoint.response_cache?.vary_by_client ? "checked" : "") : "checked"}}>
                <div>
                  <strong>Cache Per Client</strong>
                  <div class="muted">Separate cached responses by authenticated client identity.</div>
                </div>
              </label>
              <label data-help="response_cache_methods">
                <span>Cache Methods</span>
                <input name="response_cache_methods" value="${{esc((endpoint?.response_cache?.methods || ['GET']).join(', '))}}">
              </label>
              <label class="full" data-help="response_cache_vary_headers">
                <span>Cache Vary Headers (CSV)</span>
                <input name="response_cache_vary_headers" value="${{esc((endpoint?.response_cache?.vary_headers || []).join(', '))}}">
              </label>
              <div class="actions full">
                <button type="submit">Save Endpoint</button>
              </div>
            </form>
          `);
        }}

        function showRouteView(slug) {{
          const route = routeBySlug(slug);
          const curlButtons = (route?.methods || ["GET"])
            .map((method) => routeCurlButtonHtml(route.slug, method, `Copy ${{method}} cURL`))
            .join("");
          openModal("View Route", `
            <div class="stack">
              <div class="actions">${{curlButtons}}</div>
              <div class="detail-box">
                <pre>${{esc(JSON.stringify(route, null, 2))}}</pre>
              </div>
            </div>
          `);
        }}

        function showRouteForm(slug = "") {{
          const route = slug ? routeBySlug(slug) : null;
          const selectedTargets = new Set((route?.targets || []).map((target) => `${{target.service}}::${{target.endpoint}}`));
          const targetOptions = endpointOptions()
            .map((item) => `
              <label class="mini-check compact-target">
                <input type="checkbox" name="targets" data-route-target value="${{esc(item.ref)}}" ${{selectedTargets.has(item.ref) || selectedTargets.has(`${{item.service}}::${{item.slug}}`) ? "checked" : ""}}>
                <div class="target-line">
                  <span class="target-service mono">${{esc(item.service)}}</span>
                  <span class="muted">/</span>
                  <span class="target-endpoint">${{esc(item.endpoint)}}</span>
                </div>
              </label>
            `)
            .join("");

          openModal(route ? "Edit Route" : "Add Route", `
            <form method="post" action="/__admin/route/save" class="form-grid">
              <input type="hidden" name="original_slug" value="${{esc(route?.slug || "")}}">
              <label data-help="route_name">
                <span>Route Name</span>
                <input name="route_name" value="${{esc(route?.name || "")}}" required>
              </label>
              <label data-help="route_slug">
                <span>Route Slug</span>
                <input name="route_slug" value="${{esc(route?.slug || "")}}" required>
              </label>
              <label data-help="route_protocol">
                <span>Route Protocol</span>
                <select name="protocol">
                  ${{routeProtocolOptionsHtml(route?.protocol || "http")}}
                </select>
              </label>
              <label data-help="methods">
                <span>Methods</span>
                <input name="methods" value="${{esc((route?.methods || ['GET']).join(','))}}" required>
              </label>
              <label data-help="gateway_path">
                <span>Gateway Path</span>
                <input name="gateway_path" value="${{esc(route?.gateway_path || "")}}" required>
              </label>
              <label data-help="route_strategy">
                <span>Strategy</span>
                <select name="strategy">
                  <option value="single" ${{(route?.strategy || "single") === "single" ? "selected" : ""}}>single</option>
                  <option value="round_robin" ${{route?.strategy === "round_robin" ? "selected" : ""}}>round_robin</option>
                  <option value="failover" ${{route?.strategy === "failover" ? "selected" : ""}}>failover</option>
                  <option value="parallel_race" ${{route?.strategy === "parallel_race" ? "selected" : ""}}>parallel_race</option>
                </select>
              </label>
              <label class="check-item" data-help="auth_required">
                <input type="checkbox" name="auth_required" ${{route?.auth?.required ? "checked" : ""}}>
                <div>
                  <strong>Protect This Route</strong>
                  <div class="muted">Require a scoped client auth method before this public route can be called.</div>
                </div>
              </label>
              <label data-help="output_profile">
                <span>Output Profile</span>
                <select name="output_profile">
                  <option value="">passthrough</option>
                  ${{
                    STATE.output_profiles.map((profile) =>
                      `<option value="${{esc(profile.slug)}}" ${{(route?.output_profile || "") === profile.slug ? "selected" : ""}}>${{esc(profile.slug)}}${{profile.enabled ? "" : " (disabled)"}}</option>`
                    ).join("")
                  }}
                </select>
              </label>
              <div class="full" data-help="route_targets">
                <span style="display:block; font-weight:700; margin-bottom:8px;">Targets</span>
                ${{targetOptions ? `<div class="scope-grid route-target-grid">${{targetOptions}}</div>` : '<div class="empty">Create a service endpoint first.</div>'}}
              </div>
              <label data-help="pre_call_cache_ttl_seconds">
                <span>Pre-call Cache TTL</span>
                <input name="pre_call_cache_ttl_seconds" type="number" min="0" value="${{esc(String(route?.pre_call?.cache_ttl_seconds ?? 0))}}">
              </label>
              <label data-help="pre_call_cache_key">
                <span>Pre-call Cache Key</span>
                <input name="pre_call_cache_key" value="${{esc(route?.pre_call?.cache_key || "")}}">
              </label>
              <label class="full" data-help="pre_call_code">
                <span>Pre-call Code</span>
                <textarea name="pre_call_code">${{esc(route?.pre_call?.code || "")}}</textarea>
              </label>
              <div class="full detail-box">
                <pre class="pseudo-code"><code>single:        call targets[0]
round_robin:   call next target for each request
failover:      try next target when a target returns 5xx or is unreachable
parallel_race: call all targets concurrently and return first healthy response</code></pre>
              </div>
              <label data-help="response_cache_ttl_seconds">
                <span>Response Cache TTL</span>
                <input name="response_cache_ttl_seconds" type="number" min="0" value="${{esc(String(route?.response_cache?.ttl_seconds ?? 0))}}">
              </label>
              <label class="check-item" data-help="response_cache_vary_by_client">
                <input type="checkbox" name="response_cache_vary_by_client" ${{route ? (route.response_cache?.vary_by_client ? "checked" : "") : "checked"}}>
                <div>
                  <strong>Cache Per Client</strong>
                  <div class="muted">Separate cached responses by authenticated client identity.</div>
                </div>
              </label>
              <label data-help="response_cache_methods">
                <span>Cache Methods</span>
                <input name="response_cache_methods" value="${{esc((route?.response_cache?.methods || ['GET']).join(', '))}}">
              </label>
              <label class="full" data-help="response_cache_vary_headers">
                <span>Cache Vary Headers (CSV)</span>
                <input name="response_cache_vary_headers" value="${{esc((route?.response_cache?.vary_headers || []).join(', '))}}">
              </label>
              <label class="full" data-help="success_hook_url">
                <span>Success Hook URL</span>
                <input name="success_hook_url" value="${{esc(route?.success_hook?.url || "")}}">
              </label>
              <label data-help="success_hook_timeout_seconds">
                <span>Success Hook Timeout</span>
                <input name="success_hook_timeout_seconds" type="number" min="0.1" step="0.1" value="${{esc(String(route?.success_hook?.timeout_seconds ?? 5))}}">
              </label>
              <label data-help="success_hook_event_type">
                <span>Success Hook Event Type</span>
                <input name="success_hook_event_type" value="${{esc(route?.success_hook?.event_type || "financial")}}">
              </label>
              <label class="check-item" data-help="success_hook_include_request_body">
                <input type="checkbox" name="success_hook_include_request_body" ${{route?.success_hook?.include_request_body ? "checked" : ""}}>
                <div>
                  <strong>Include Request Body</strong>
                  <div class="muted">Attach the original request payload to the async success event.</div>
                </div>
              </label>
              <label class="check-item" data-help="success_hook_include_response_body">
                <input type="checkbox" name="success_hook_include_response_body" ${{route?.success_hook?.include_response_body ? "checked" : ""}}>
                <div>
                  <strong>Include Response Body</strong>
                  <div class="muted">Attach the rendered response payload to the async success event.</div>
                </div>
              </label>
              <label class="full" data-help="success_hook_headers_yaml">
                <span>Success Hook Headers (JSON/YAML Mapping)</span>
                <textarea name="success_hook_headers_yaml">${{esc(jsonText(route?.success_hook?.headers || {{}}))}}</textarea>
              </label>
              <div class="actions full">
                <button type="submit">Save Route</button>
              </div>
            </form>
          `);
        }}

        function showClientView(slug) {{
          const client = clientBySlug(slug);
          const methodsHtml = (client?.auth_methods || []).map((method) => {{
            const outputKey = encodeURIComponent(`${{client.code}}::${{method.code}}`);
            return `
              <div class="auth-method-card">
                <div class="auth-method-head">
                  <div>
                    <strong>${{esc(method.title || method.code)}}</strong>
                    <div class="muted mono">${{esc(method.code)}}</div>
                  </div>
                  <div class="actions">
                    <span class="tag ${{method.enabled ? 'ok' : 'warn'}}">${{method.enabled ? 'Enabled' : 'Disabled'}}</span>
                    <span class="tag">${{esc(method.type)}}</span>
                    ${{
                      method.type === "oauth_client_credentials"
                        ? `<button class="btn light" type="button" onclick="issueOauthToken(decodeURIComponent('${{arg(client.code)}}'), decodeURIComponent('${{arg(method.code)}}'))">Issue Token</button>`
                        : ''
                    }}
                  </div>
                </div>
                <div class="detail-box"><pre>${{esc(JSON.stringify(method, null, 2))}}</pre></div>
                ${{
                  method.type === "oauth_client_credentials"
                    ? `<div class="detail-box" style="margin-top:12px;"><pre data-oauth-token-output="${{esc(outputKey)}}">Press "Issue Token" to request a live token for this auth method.</pre></div>`
                    : ''
                }}
              </div>
            `;
          }}).join('');

          openModal("View Client", `
            <div class="stack">
              <div class="detail-box">
                <pre>${{esc(JSON.stringify({{
                  slug: client?.slug,
                  title: client?.title,
                  code: client?.code,
                  enabled: client?.enabled,
                  ip_allowlist: client?.ip_allowlist,
                  access: client?.access,
                }}, null, 2))}}</pre>
              </div>
              ${{methodsHtml || '<div class="empty">No auth methods configured.</div>'}}
            </div>
          `);
        }}

        function authMethodCardTemplate(method = null) {{
          const item = method || {{
            title: "",
            code: "",
            type: "api_key",
            enabled: true,
            secret: "",
            token: "",
            username: "",
            password: "",
            client_id: "",
            client_secret: "",
            token_ttl_seconds: 3600,
            header_name: "X-Client-Key",
            header_names: ["X-API-Key"],
            query_params: ["api_key"],
            cookie_names: [],
            allow_authorization_header: true,
            script: "",
            cache_ttl_seconds: 0,
            cache_key: "",
          }};
          return `
            <div class="auth-method-card" data-auth-method-card>
              <div class="auth-method-head">
                <div data-help="auth_methods">
                  <strong>Auth Method</strong>
                  <div class="muted">Each client can accept one or more authentication methods.</div>
                </div>
                <button type="button" class="btn light" onclick="this.closest('.auth-method-card').remove()">Remove</button>
              </div>
              <div class="form-grid">
                <label data-help="auth_method_title">
                  <span>Method Title</span>
                  <input data-field="title" value="${{esc(item.title || "")}}" required>
                </label>
                <label data-help="auth_method_code">
                  <span>Method Code</span>
                  <input data-field="code" value="${{esc(item.code || "")}}" required>
                </label>
                <label data-help="auth_type">
                  <span>Auth Type</span>
                  <select data-field="type" onchange="syncAuthMethodCard(this.closest('.auth-method-card'))">
                    <option value="api_key" ${{item.type === "api_key" ? "selected" : ""}}>api_key</option>
                    <option value="bearer" ${{item.type === "bearer" ? "selected" : ""}}>bearer</option>
                    <option value="basic" ${{item.type === "basic" ? "selected" : ""}}>basic</option>
                    <option value="header_key" ${{item.type === "header_key" ? "selected" : ""}}>header_key</option>
                    <option value="oauth_client_credentials" ${{item.type === "oauth_client_credentials" ? "selected" : ""}}>oauth_client_credentials</option>
                    <option value="external_service" ${{item.type === "external_service" ? "selected" : ""}}>external_service</option>
                  </select>
                </label>
                <label class="check-item" data-help="auth_method_enabled">
                  <input type="checkbox" data-field="enabled" ${{item.enabled ? "checked" : ""}}>
                  <div>
                    <strong>Enabled</strong>
                    <div class="muted">Disabled auth methods are ignored by the gateway.</div>
                  </div>
                </label>

                <label data-auth-types="api_key" data-help="api_key_secret">
                  <span>Secret</span>
                  <input data-field="secret" value="${{esc(item.secret || "")}}">
                </label>
                <label data-auth-types="api_key" class="check-item">
                  <button type="button" class="btn light" onclick="fillMethodField(this, 'secret', 40, 'key_')">Generate API Key</button>
                </label>
                <label data-auth-types="api_key" data-help="api_key_header_names">
                  <span>Header Names (CSV)</span>
                  <input data-field="header_names" value="${{esc(listText(item.header_names || []))}}">
                </label>
                <label data-auth-types="api_key" data-help="api_key_query_params">
                  <span>Query Params (CSV)</span>
                  <input data-field="query_params" value="${{esc(listText(item.query_params || []))}}">
                </label>
                <label data-auth-types="api_key" class="full" data-help="api_key_cookie_names">
                  <span>Cookie Names (CSV)</span>
                  <input data-field="cookie_names" value="${{esc(listText(item.cookie_names || []))}}">
                </label>

                <label data-auth-types="bearer" data-help="bearer_token">
                  <span>Bearer Token</span>
                  <input data-field="token" value="${{esc(item.token || "")}}">
                </label>
                <label data-auth-types="bearer" class="check-item">
                  <button type="button" class="btn light" onclick="fillMethodField(this, 'token', 48, 'tok_')">Generate Bearer Token</button>
                </label>
                <label data-auth-types="bearer" class="check-item" data-help="bearer_allow_authorization_header">
                  <input type="checkbox" data-field="allow_authorization_header" ${{item.allow_authorization_header ? "checked" : ""}}>
                  <div>
                    <strong>Allow Authorization Header</strong>
                    <div class="muted">Accept <code>Authorization: Bearer ...</code> for this method.</div>
                  </div>
                </label>
                <label data-auth-types="bearer" data-help="bearer_header_names">
                  <span>Extra Header Names (CSV)</span>
                  <input data-field="header_names" value="${{esc(listText(item.header_names || []))}}">
                </label>
                <label data-auth-types="bearer" data-help="bearer_query_params">
                  <span>Query Params (CSV)</span>
                  <input data-field="query_params" value="${{esc(listText(item.query_params || []))}}">
                </label>
                <label data-auth-types="bearer" class="full" data-help="bearer_cookie_names">
                  <span>Cookie Names (CSV)</span>
                  <input data-field="cookie_names" value="${{esc(listText(item.cookie_names || []))}}">
                </label>

                <label data-auth-types="basic" data-help="basic_username">
                  <span>Basic Username</span>
                  <input data-field="username" value="${{esc(item.username || "")}}">
                </label>
                <label data-auth-types="basic" data-help="basic_password">
                  <span>Basic Password</span>
                  <input data-field="password" value="${{esc(item.password || "")}}">
                </label>
                <label data-auth-types="basic" class="check-item">
                  <button type="button" class="btn light" onclick="fillMethodField(this, 'password', 28, 'pwd_')">Generate Password</button>
                </label>

                <label data-auth-types="header_key" data-help="header_key_name">
                  <span>Header Name</span>
                  <input data-field="header_name" value="${{esc(item.header_name || "X-Client-Key")}}">
                </label>
                <label data-auth-types="header_key" data-help="header_key_secret">
                  <span>Secret</span>
                  <input data-field="secret" value="${{esc(item.secret || "")}}">
                </label>
                <label data-auth-types="header_key" class="check-item">
                  <button type="button" class="btn light" onclick="fillMethodField(this, 'secret', 40, 'hdr_')">Generate Header Secret</button>
                </label>

                <label data-auth-types="oauth_client_credentials" data-help="oauth_client_id">
                  <span>OAuth Client ID</span>
                  <input data-field="client_id" value="${{esc(item.client_id || "")}}">
                </label>
                <label data-auth-types="oauth_client_credentials" data-help="oauth_client_secret">
                  <span>OAuth Client Secret</span>
                  <input data-field="client_secret" value="${{esc(item.client_secret || "")}}">
                </label>
                <label data-auth-types="oauth_client_credentials" data-help="oauth_token_ttl_seconds">
                  <span>Token TTL (seconds)</span>
                  <input type="number" min="60" data-field="token_ttl_seconds" value="${{esc(String(item.token_ttl_seconds ?? 3600))}}">
                </label>
                <label data-auth-types="oauth_client_credentials" class="check-item">
                  <button type="button" class="btn light" onclick="fillOauthFields(this)">Generate Client ID / Secret</button>
                </label>

                <label data-auth-types="external_service" class="full" data-help="external_auth_script">
                  <span>External Auth Script</span>
                  <textarea data-field="script">${{esc(item.script || "")}}</textarea>
                </label>
                <label data-auth-types="external_service" data-help="external_cache_ttl_seconds">
                  <span>Cache TTL (seconds)</span>
                  <input type="number" min="0" data-field="cache_ttl_seconds" value="${{esc(String(item.cache_ttl_seconds ?? 0))}}">
                </label>
                <label data-auth-types="external_service" data-help="external_cache_key">
                  <span>Cache Key Template</span>
                  <input data-field="cache_key" value="${{esc(item.cache_key || "")}}">
                </label>
              </div>
            </div>
          `;
        }}

        function syncAuthMethodCard(card) {{
          const type = card?.querySelector('[data-field="type"]')?.value || "api_key";
          card?.querySelectorAll("[data-auth-types]").forEach((element) => {{
            const allowed = String(element.dataset.authTypes || "").split(",").map((item) => item.trim());
            element.style.display = allowed.includes(type) ? "" : "none";
          }});
        }}

        function addAuthMethodCard(method = null) {{
          const list = modalBody.querySelector("#auth-methods-list");
          if (!list) return;
          const wrapper = document.createElement("div");
          wrapper.innerHTML = authMethodCardTemplate(method);
          const card = wrapper.firstElementChild;
          list.appendChild(card);
          decorateHelp(card);
          syncAuthMethodCard(card);
        }}

        function renderClientScopeChoices(access) {{
          const selectedServices = new Set(access?.services || []);
          const selectedEndpoints = new Set((access?.endpoints || []).map((item) => `${{item.service}}::${{item.endpoint}}`));
          const servicesWrap = modalBody.querySelector("[data-scope-services]");
          const endpointsWrap = modalBody.querySelector("[data-scope-endpoints]");

          servicesWrap.innerHTML = serviceOptions().length
            ? `<div class="scope-grid">${{serviceOptions().map((serviceName) => `
                <label class="mini-check">
                  <input type="checkbox" data-scope-service value="${{esc(serviceName)}}" ${{selectedServices.has(serviceName) ? "checked" : ""}}>
                  <div>
                    <strong>${{esc(serviceName)}}</strong>
                    <div class="muted">All endpoints in this service</div>
                  </div>
                </label>
              `).join('')}}</div>`
            : '<div class="empty">Create a service first.</div>';

          endpointsWrap.innerHTML = endpointOptions().length
            ? `<div class="scope-grid">${{endpointOptions().map((item) => `
                <label class="mini-check">
                  <input type="checkbox" data-scope-endpoint value="${{esc(item.ref)}}" ${{selectedEndpoints.has(item.ref) ? "checked" : ""}}>
                  <div>
                    <strong>${{esc(item.endpoint)}}</strong>
                    <div class="muted mono">${{esc(item.service)}}</div>
                  </div>
                </label>
              `).join('')}}</div>`
            : '<div class="empty">Create an endpoint first.</div>';
        }}

        function syncClientScopePanels() {{
          const mode = modalBody.querySelector('[name="access_mode"]')?.value || "all";
          modalBody.querySelectorAll("[data-scope-panel]").forEach((panel) => {{
            panel.style.display = panel.dataset.scopePanel === mode ? "" : "none";
          }});
        }}

        function collectClientAccess(form) {{
          const mode = form.querySelector('[name="access_mode"]').value;
          if (mode === "all") {{
            return {{ mode: "all" }};
          }}
          if (mode === "services") {{
            const services = Array.from(form.querySelectorAll("[data-scope-service]:checked")).map((input) => input.value);
            return {{ mode: "services", services }};
          }}
          const endpoints = Array.from(form.querySelectorAll("[data-scope-endpoint]:checked")).map((input) => {{
            const [service, endpoint] = input.value.split("::", 2);
            return {{ service, endpoint }};
          }});
          return {{ mode: "endpoints", endpoints }};
        }}

        function collectAuthMethods(form) {{
          const cards = Array.from(form.querySelectorAll("[data-auth-method-card]"));
          if (!cards.length) {{
            throw new Error("Add at least one auth method.");
          }}
          return cards.map((card) => {{
            const type = card.querySelector('[data-field="type"]').value;
            const item = {{
              title: card.querySelector('[data-field="title"]').value.trim(),
              code: card.querySelector('[data-field="code"]').value.trim(),
              type,
              enabled: card.querySelector('[data-field="enabled"]').checked,
            }};
            if (!item.title || !item.code) {{
              throw new Error("Each auth method needs both title and code.");
            }}

            if (type === "api_key") {{
              item.secret = (visibleMethodField(card, "secret")?.value || "").trim();
              item.header_names = splitList(visibleMethodField(card, "header_names")?.value || "");
              item.query_params = splitList(visibleMethodField(card, "query_params")?.value || "");
              item.cookie_names = splitList(visibleMethodField(card, "cookie_names")?.value || "");
            }} else if (type === "bearer") {{
              item.token = (visibleMethodField(card, "token")?.value || "").trim();
              item.allow_authorization_header = card.querySelector('[data-field="allow_authorization_header"]').checked;
              item.header_names = splitList(visibleMethodField(card, "header_names")?.value || "");
              item.query_params = splitList(visibleMethodField(card, "query_params")?.value || "");
              item.cookie_names = splitList(visibleMethodField(card, "cookie_names")?.value || "");
            }} else if (type === "basic") {{
              item.username = (visibleMethodField(card, "username")?.value || "").trim();
              item.password = (visibleMethodField(card, "password")?.value || "").trim();
            }} else if (type === "header_key") {{
              item.header_name = (visibleMethodField(card, "header_name")?.value || "").trim();
              item.secret = (visibleMethodField(card, "secret")?.value || "").trim();
            }} else if (type === "oauth_client_credentials") {{
              item.client_id = (visibleMethodField(card, "client_id")?.value || "").trim();
              item.client_secret = (visibleMethodField(card, "client_secret")?.value || "").trim();
              item.token_ttl_seconds = Number(visibleMethodField(card, "token_ttl_seconds")?.value || 0);
            }} else if (type === "external_service") {{
              item.script = (visibleMethodField(card, "script")?.value || "").replace(/\\s+$/, "");
              item.cache_ttl_seconds = Number(visibleMethodField(card, "cache_ttl_seconds")?.value || 0);
              item.cache_key = (visibleMethodField(card, "cache_key")?.value || "").trim();
            }}
            return item;
          }});
        }}

        function submitClientForm(form) {{
          try {{
            form.querySelector('[name="access_json"]').value = JSON.stringify(collectClientAccess(form));
            form.querySelector('[name="auth_methods_json"]').value = JSON.stringify(collectAuthMethods(form));
            return true;
          }} catch (error) {{
            alert(String(error?.message || error));
            return false;
          }}
        }}

        function mountClientForm(client) {{
          renderClientScopeChoices(client?.access || {{ mode: "all", services: [], endpoints: [] }});
          syncClientScopePanels();
          const list = modalBody.querySelector("#auth-methods-list");
          list.innerHTML = "";
          const methods = client?.auth_methods?.length ? client.auth_methods : [null];
          methods.forEach((method) => addAuthMethodCard(method));
        }}

        function showClientForm(slug = "") {{
          const client = slug ? clientBySlug(slug) : null;
          openModal(client ? "Edit Client" : "Add Client", `
            <form method="post" action="/__admin/client/save" class="form-grid" onsubmit="return submitClientForm(this)">
              <input type="hidden" name="original_slug" value="${{esc(client?.slug || "")}}">
              <input type="hidden" name="access_json">
              <input type="hidden" name="auth_methods_json">
              <label data-help="client_title">
                <span>Client Title</span>
                <input name="client_title" value="${{esc(client?.title || "")}}" required>
              </label>
              <label data-help="client_slug">
                <span>Client Slug</span>
                <input name="client_slug" value="${{esc(client?.slug || "")}}" required>
              </label>
              <label data-help="client_code">
                <span>Client Code</span>
                <input name="client_code" value="${{esc(client?.code || "")}}" required>
              </label>
              <label class="check-item" data-help="client_enabled">
                <input type="checkbox" name="enabled" ${{client ? (client.enabled ? "checked" : "") : "checked"}}>
                <div>
                  <strong>Enabled</strong>
                  <div class="muted">Disabled clients cannot authenticate with the gateway.</div>
                </div>
              </label>
              <label class="full" data-help="ip_allowlist">
                <span>IP Allowlist (CSV or newline)</span>
                <textarea name="ip_allowlist">${{esc((client?.ip_allowlist || []).join('\\n'))}}</textarea>
              </label>
              <label data-help="access_mode">
                <span>Access Scope</span>
                <select name="access_mode" onchange="syncClientScopePanels()">
                  <option value="all" ${{(client?.access?.mode || "all") === "all" ? "selected" : ""}}>All services</option>
                  <option value="services" ${{client?.access?.mode === "services" ? "selected" : ""}}>Selected services</option>
                  <option value="endpoints" ${{client?.access?.mode === "endpoints" ? "selected" : ""}}>Selected endpoints</option>
                </select>
              </label>
              <div class="full" data-scope-panel="services" data-help="allowed_services">
                <span style="display:block; font-weight:700; margin-bottom:8px;">Allowed Services</span>
                <div data-scope-services></div>
              </div>
              <div class="full" data-scope-panel="endpoints" data-help="allowed_endpoints">
                <span style="display:block; font-weight:700; margin-bottom:8px;">Allowed Endpoints</span>
                <div data-scope-endpoints></div>
              </div>
              <div class="full auth-method-card" data-help="auth_methods">
                <div class="auth-method-head">
                  <div>
                    <strong>Authentication Methods</strong>
                    <div class="muted">Use multiple methods if the same client must authenticate in several common ways.</div>
                  </div>
                  <button type="button" class="btn light" onclick="addAuthMethodCard()">Add Auth Method</button>
                </div>
                <div id="auth-methods-list" class="stack"></div>
              </div>
              <div class="actions full">
                <button type="submit">Save Client</button>
              </div>
            </form>
          `);
          mountClientForm(client);
        }}

        function showOutputProfileView(slug) {{
          const profile = outputProfileBySlug(slug);
          openModal("View Output Profile", `
            <div class="detail-box">
              <pre>${{esc(JSON.stringify(profile, null, 2))}}</pre>
            </div>
          `);
        }}

        function showOutputProfileForm(slug = "") {{
          const profile = slug ? outputProfileBySlug(slug) : null;
          const successKey = profile?.success_key || "success";
          const dataKey = profile?.data_key || "data";
          const messageKey = profile?.message_key || "message";
          const errorKey = profile?.error_key || "error";
          const sourceSuccessKey = profile?.source_success_key || "";
          const messageSourceKeys = outputProfileListText(profile?.message_source_keys || []);
          const errorSourceKeys = outputProfileListText(profile?.error_source_keys || []);
          const dataFields = outputProfileDataFieldsText(profile?.data_fields || {{}});
          const emptyValue = configValueText(profile?.empty_value ?? "");
          const jsonpParam = profile?.jsonp_callback_param || "callback";
          const jsonpDefault = profile?.jsonp_default_callback || "callback";
          const passthroughKeys = outputProfileListText(profile?.passthrough_keys || []);
          const transformCode = profile?.transform_code || "";
          const customValidation = profile?.custom_validation || {{}};
          const customValidationMode = customValidation.mode || "status_code";
          const customValidationSourceKey = customValidation.source_key || "";
          const customValidationExpectedValue = configValueText(
            Object.prototype.hasOwnProperty.call(customValidation, "expected_value")
              ? customValidation.expected_value
              : true
          );
          const customValidationErrorSourceKeys = outputProfileListText(customValidation.error_source_keys || []);
          openModal(profile ? "Edit Output Profile" : "Add Output Profile", `
            <form method="post" action="/__admin/output-profile/save" class="form-grid" data-output-profile-form>
              <input type="hidden" name="original_slug" value="${{esc(profile?.slug || "")}}">
              <label data-help="profile_title">
                <span>Profile Title</span>
                <input name="profile_title" value="${{esc(profile?.title || "")}}" required>
              </label>
              <label data-help="profile_slug">
                <span>Profile Slug</span>
                <input name="profile_slug" value="${{esc(profile?.slug || "")}}" required>
              </label>
              <label data-help="profile_type">
                <span>Profile Type</span>
                <select name="profile_type">
                  <option value="passthrough" ${{(profile?.type || "passthrough") === "passthrough" ? "selected" : ""}}>passthrough</option>
                  <option value="json_envelope" ${{profile?.type === "json_envelope" ? "selected" : ""}}>json_envelope</option>
                  <option value="jsonp" ${{profile?.type === "jsonp" ? "selected" : ""}}>jsonp</option>
                  <option value="custom" ${{profile?.type === "custom" ? "selected" : ""}}>custom</option>
                </select>
              </label>
              <label class="check-item" data-help="profile_enabled">
                <input type="checkbox" name="enabled" ${{profile ? (profile.enabled ? "checked" : "") : "checked"}}>
                <div>
                  <strong>Enabled</strong>
                  <div class="muted">Disabled profiles remain saved but are ignored by route output settings.</div>
                </div>
              </label>
              <div class="output-flow full">
                <div class="output-flow-head">
                  <div>
                    <div class="output-flow-title">Response shaping rule</div>
                    <div class="output-flow-subtitle">The selected mode is stored as config, and the preview updates as you edit the contract.</div>
                  </div>
                  <span class="tag">pseudo-code</span>
                </div>
                <pre class="pseudo-code" data-output-preview></pre>
                <div class="output-rule" data-output-rule="passthrough">
                  <div class="output-mode-note">
                    <div><strong>Best for</strong> Images, files, raw APIs, existing contracts.</div>
                    <div><strong>Headers</strong> Profile headers can still be merged.</div>
                    <div><strong>Body</strong> The response body is untouched.</div>
                  </div>
                </div>
                <div class="output-rule" data-output-rule="json_envelope">
                  <div class="output-mode-note">
                    <div><strong>Success</strong> Read the normal success key or compute it from a source path.</div>
                    <div><strong>Data</strong> Reuse the upstream body directly or build a mapped data object.</div>
                    <div><strong>Existing envelope</strong> Existing keys listed below are allowed to pass through unchanged.</div>
                  </div>
                </div>
                <div class="output-rule" data-output-rule="jsonp">
                  <div class="output-mode-note">
                    <div><strong>Best for</strong> Browser clients that still need JSONP.</div>
                    <div><strong>Callback param</strong> Configure the query key below.</div>
                    <div><strong>Body</strong> The parsed response body is wrapped in JavaScript.</div>
                  </div>
                </div>
                <div class="output-rule" data-output-rule="custom">
                  <div class="output-mode-note">
                    <div><strong>Validation</strong> Detect success first by status code or a payload key such as <span class="mono">IsSuccessful</span>.</div>
                    <div><strong>Available state</strong> The transform code receives <span class="mono">validation</span> with <span class="mono">ok</span>, <span class="mono">error</span>, <span class="mono">actual</span>, and <span class="mono">expected</span>.</div>
                    <div><strong>Allowed code</strong> Assignments, if/else blocks, literals, indexing, and safe helper calls only.</div>
                    <div><strong>Available inputs</strong> payload, status_code, detail, validation, headers, query, and helper functions like pick() and text().</div>
                    <div><strong>Required output</strong> Your code must assign the final shaped body to <span class="mono">result</span>.</div>
                  </div>
                </div>
              </div>
              <div class="output-config full" data-output-envelope-field>
                <div class="output-config-head">
                  <div class="output-config-title">Envelope contract</div>
                  <div class="output-config-note">These fields control the actual JSON output shape and how values are extracted from upstream payloads.</div>
                </div>
                <div class="form-grid">
                  <label data-help="success_key">
                    <span>Success Key</span>
                    <input name="success_key" value="${{esc(successKey)}}" required>
                  </label>
                  <label data-help="data_key">
                    <span>Data Key</span>
                    <input name="data_key" value="${{esc(dataKey)}}" required>
                  </label>
                  <label data-help="message_key">
                    <span>Message Key</span>
                    <input name="message_key" value="${{esc(messageKey)}}" required>
                  </label>
                  <label data-help="error_key">
                    <span>Error Key</span>
                    <input name="error_key" value="${{esc(errorKey)}}" required>
                  </label>
                  <label class="full" data-help="passthrough_keys">
                    <span>Existing Envelope Keys (CSV)</span>
                    <input name="passthrough_keys" value="${{esc(passthroughKeys)}}">
                  </label>
                  <label data-help="source_success_key">
                    <span>Success Source Path</span>
                    <input name="source_success_key" value="${{esc(sourceSuccessKey)}}">
                  </label>
                  <label data-help="message_source_keys">
                    <span>Message Source Paths (CSV)</span>
                    <input name="message_source_keys" value="${{esc(messageSourceKeys)}}">
                  </label>
                  <label data-help="error_source_keys">
                    <span>Error Source Paths (CSV)</span>
                    <input name="error_source_keys" value="${{esc(errorSourceKeys)}}">
                  </label>
                  <label class="full" data-help="data_fields_yaml">
                    <span>Mapped Data Fields (JSON/YAML, supports {{{{field}}}} templates)</span>
                    <textarea name="data_fields_yaml">${{esc(dataFields)}}</textarea>
                  </label>
                  <label class="full" data-help="empty_value_yaml">
                    <span>Empty Value (JSON/YAML)</span>
                    <textarea name="empty_value_yaml">${{esc(emptyValue)}}</textarea>
                  </label>
                </div>
              </div>
              <label data-help="jsonp_callback_param" data-output-jsonp-field>
                <span>JSONP Callback Param</span>
                <input name="jsonp_callback_param" value="${{esc(jsonpParam)}}">
              </label>
              <label data-help="jsonp_default_callback" data-output-jsonp-field>
                <span>JSONP Default Callback</span>
                <input name="jsonp_default_callback" value="${{esc(jsonpDefault)}}">
              </label>
              <label data-help="custom_validation_mode" data-output-custom-field>
                <span>Custom Success Detection</span>
                <select name="custom_validation_mode">
                  <option value="status_code" ${{customValidationMode === "status_code" ? "selected" : ""}}>status_code</option>
                  <option value="payload_key" ${{customValidationMode === "payload_key" ? "selected" : ""}}>payload_key</option>
                </select>
              </label>
              <label data-help="custom_validation_source_key" data-output-custom-field data-output-custom-validation-key-field>
                <span>Validation Source Path</span>
                <input name="custom_validation_source_key" value="${{esc(customValidationSourceKey)}}">
              </label>
              <label class="full" data-help="custom_validation_expected_value_yaml" data-output-custom-field data-output-custom-validation-key-field>
                <span>Expected Success Value (JSON/YAML)</span>
                <textarea name="custom_validation_expected_value_yaml">${{esc(customValidationExpectedValue)}}</textarea>
              </label>
              <label class="full" data-help="custom_validation_error_source_keys" data-output-custom-field>
                <span>Validation Error Paths (CSV)</span>
                <input name="custom_validation_error_source_keys" value="${{esc(customValidationErrorSourceKeys)}}">
              </label>
              <label class="full" data-help="transform_code" data-output-custom-field>
                <span>Custom Transform Code</span>
                <textarea name="transform_code" placeholder="result = {{&#10;  &quot;message&quot;: pick(&quot;message&quot;, detail),&#10;  &quot;error&quot;: pick(&quot;error&quot;, detail),&#10;}}">${{esc(transformCode)}}</textarea>
                <div class="muted" style="margin-top:6px;">
                  Gateway error profiles receive a payload with <span class="mono">detail</span>, <span class="mono">message</span>, <span class="mono">error</span>, <span class="mono">status_code</span>, and <span class="mono">status</span>.
                </div>
              </label>
              <label class="full" data-help="output_headers_yaml">
                <span>Profile Headers (JSON/YAML Mapping)</span>
                <textarea name="headers_yaml">${{esc(jsonText(profile?.headers || {{}}))}}</textarea>
              </label>
              <div class="actions full">
                <button type="submit">Save Output Profile</button>
              </div>
            </form>
          `);
          syncOutputProfileRules(modalBody.querySelector("[data-output-profile-form]"));
        }}

        function showRoleView(name) {{
          const role = roleByName(name);
          openModal("View Role", `
            <div class="detail-box">
              <pre>${{esc(JSON.stringify(role, null, 2))}}</pre>
            </div>
          `);
        }}

        function showRoleForm(name = "") {{
          const role = name ? roleByName(name) : null;
          const permissionOptions = Object.entries(STATE.security.permission_labels)
            .map(([permission, label]) => `
              <label class="check-item">
                <input type="checkbox" name="permissions" value="${{esc(permission)}}" ${{role?.permissions?.includes(permission) ? "checked" : ""}}>
                <div>
                  <strong>${{esc(label)}}</strong>
                  <div class="muted mono">${{esc(permission)}}</div>
                </div>
              </label>
            `)
            .join('');

          openModal(role ? "Edit Role" : "Add Role", `
            <form method="post" action="/__admin/role/save" class="form-grid">
              <input type="hidden" name="original_name" value="${{esc(role?.name || "")}}">
              <label class="full" data-help="role_name">
                <span>Role Name</span>
                <input name="role_name" value="${{esc(role?.name || "")}}" required>
              </label>
              <div class="full" data-help="role_permissions">
                <span style="display:block; font-weight:700; margin-bottom:8px;">Permissions</span>
                <div class="check-grid">${{permissionOptions}}</div>
              </div>
              <div class="actions full">
                <button type="submit">Save Role</button>
              </div>
            </form>
          `);
        }}

        function showUserView(username) {{
          const user = userByName(username);
          openModal("View User", `
            <div class="detail-box">
              <pre>${{esc(JSON.stringify(user, null, 2))}}</pre>
            </div>
          `);
        }}

        function showUserForm(username = "") {{
          const user = username ? userByName(username) : null;
          const roleOptions = STATE.security.roles
            .map((role) => `
              <label class="check-item">
                <input type="checkbox" name="roles" value="${{esc(role.name)}}" ${{user?.roles?.includes(role.name) ? "checked" : ""}}>
                <div>
                  <strong>${{esc(role.name)}}</strong>
                  <div class="muted">${{role.permissions.length}} permission(s)</div>
                </div>
              </label>
            `)
            .join('');

          openModal(user ? "Edit User" : "Add User", `
            <form method="post" action="/__admin/user/save" class="form-grid">
              <input type="hidden" name="original_username" value="${{esc(user?.username || "")}}">
              <label data-help="username">
                <span>Username</span>
                <input name="username" value="${{esc(user?.username || "")}}" required>
              </label>
              <label data-help="password">
                <span>Password</span>
                <input type="password" name="password" placeholder="${{user ? 'Leave blank to keep the current password' : ''}}" ${{user ? '' : 'required'}}>
              </label>
              <label class="check-item" data-help="user_enabled">
                <input type="checkbox" name="enabled" ${{user ? (user.enabled ? "checked" : "") : "checked"}}>
                <div>
                  <strong>Enabled</strong>
                  <div class="muted">If disabled, the user will no longer be able to sign in.</div>
                </div>
              </label>
              <div class="full" data-help="user_roles">
                <span style="display:block; font-weight:700; margin-bottom:8px;">Roles</span>
                <div class="check-grid">${{roleOptions || '<div class="muted">Create a role first.</div>'}}</div>
              </div>
              <div class="actions full">
                <button type="submit">Save User</button>
              </div>
            </form>
          `);
        }}

        function deleteService(name) {{
          postDelete("/__admin/service/delete", {{ service_name: name }});
        }}

        function deleteEndpoint(serviceName, endpointName) {{
          postDelete("/__admin/endpoint/delete", {{ service_name: serviceName, endpoint_name: endpointName }});
        }}

        function deleteRoute(slug) {{
          postDelete("/__admin/route/delete", {{ route_slug: slug }});
        }}

        function deleteClient(slug) {{
          postDelete("/__admin/client/delete", {{ client_slug: slug }});
        }}

        function deleteOutputProfile(slug) {{
          postDelete("/__admin/output-profile/delete", {{ profile_slug: slug }});
        }}

        function deleteRole(name) {{
          postDelete("/__admin/role/delete", {{ role_name: name }});
        }}

        function deleteUser(username) {{
          postDelete("/__admin/user/delete", {{ username }});
        }}

        startLivePolling();
        renderServices();
        renderRoutes();
        renderOutputProfiles();
        renderClients();
        renderConfig();
        renderAudit();
        renderUsers();
        renderRoles();
      </script>
    </body>
    </html>
    """


class PooledHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a bounded thread pool instead of unbounded thread spawning."""

    def __init__(
        self,
        server_address,
        RequestHandlerClass,
        max_workers: int = 256,
        *,
        listener_role: str = "public",
        public_port: int = 8000,
        admin_port: int = 8001,
    ) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self._pool = ThreadPoolExecutor(max_workers=max_workers)
        self.listener_role = listener_role
        self.public_port = public_port
        self.admin_port = admin_port

    def process_request(self, request, client_address) -> None:  # type: ignore[override]
        self._pool.submit(self.process_request_thread, request, client_address)

    def server_close(self) -> None:
        self._pool.shutdown(wait=False)
        super().server_close()


class GatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NapiGate/0.1.2"

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch()

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PUT(self) -> None:  # noqa: N802
        self._dispatch()

    def do_PATCH(self) -> None:  # noqa: N802
        self._dispatch()

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._dispatch()

    def do_HEAD(self) -> None:  # noqa: N802
        self._dispatch()

    def log_message(self, fmt: str, *args) -> None:
        LOGGER.info("%s - %s", self.address_string(), fmt % args)

    def _listener_role(self) -> str:
        return str(getattr(self.server, "listener_role", "public") or "public")

    def _is_admin_listener(self) -> bool:
        return self._listener_role() == "admin"

    def _raw_client_ip(self) -> str:
        return self.client_address[0] if self.client_address else "-"

    def _ip_in_allowlist(self, client_ip: str, allowlist: list[str]) -> bool:
        try:
            address = ipaddress.ip_address(client_ip)
        except ValueError:
            return False
        return any(address in ipaddress.ip_network(entry, strict=False) for entry in allowlist)

    def _request_via_trusted_proxy(self) -> bool:
        allowlist = runtime.trusted_proxy_allowlist()
        return bool(allowlist) and self._ip_in_allowlist(self._raw_client_ip(), allowlist)

    def _normalize_forwarded_ip(self, raw_value: str) -> str:
        value = str(raw_value or "").strip().strip('"').strip("'")
        if not value:
            return ""
        if value.lower().startswith("for="):
            value = value[4:].strip().strip('"').strip("'")
        if not value or value.lower() == "unknown" or value.startswith("_"):
            return ""
        if value.startswith("["):
            closing = value.find("]")
            if closing == -1:
                return ""
            value = value[1:closing]
        elif value.count(":") == 1 and "." in value:
            value = value.rsplit(":", 1)[0]
        try:
            ipaddress.ip_address(value)
        except ValueError:
            return ""
        return value

    def _forwarded_ip_chain(self) -> list[str]:
        x_forwarded_for = str(self.headers.get("X-Forwarded-For", "") or "")
        chain = [
            candidate
            for candidate in (
                self._normalize_forwarded_ip(part)
                for part in x_forwarded_for.split(",")
            )
            if candidate
        ]
        if chain:
            return chain

        forwarded_header = str(self.headers.get("Forwarded", "") or "")
        forwarded_chain: list[str] = []
        for segment in forwarded_header.split(","):
            for item in segment.split(";"):
                candidate = self._normalize_forwarded_ip(item)
                if candidate:
                    forwarded_chain.append(candidate)
                    break
        return forwarded_chain

    def _request_scheme(self) -> str:
        if not self._request_via_trusted_proxy():
            return "http"
        forwarded = str(self.headers.get("X-Forwarded-Proto", "") or "").split(",", 1)[0].strip()
        if forwarded:
            return forwarded
        return "http"

    def _request_host_name(self) -> str:
        raw_host = self._request_authority()
        if raw_host.startswith("["):
            closing = raw_host.find("]")
            if closing != -1:
                return raw_host[: closing + 1]
        if ":" in raw_host:
            return raw_host.rsplit(":", 1)[0]
        return raw_host

    def _request_authority(self) -> str:
        raw_host = str(self.headers.get("Host", "127.0.0.1") or "127.0.0.1").strip()
        if not self._request_via_trusted_proxy():
            return raw_host

        forwarded_host = str(self.headers.get("X-Forwarded-Host", "") or "").split(",", 1)[0].strip()
        authority = forwarded_host or raw_host
        forwarded_port = str(self.headers.get("X-Forwarded-Port", "") or "").split(",", 1)[0].strip()
        scheme = str(self.headers.get("X-Forwarded-Proto", "") or "").split(",", 1)[0].strip() or "http"
        if (
            forwarded_port
            and ":" not in authority
            and not ((scheme == "http" and forwarded_port == "80") or (scheme == "https" and forwarded_port == "443"))
        ):
            authority = f"{authority}:{forwarded_port}"
        return authority

    def _base_url_for_port(self, port: int) -> str:
        scheme = self._request_scheme()
        if self._request_via_trusted_proxy():
            authority = self._request_authority() or "127.0.0.1"
            return f"{scheme}://{authority}"
        host = self._request_host_name() or "127.0.0.1"
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    def _public_base_url(self) -> str:
        return self._base_url_for_port(int(getattr(self.server, "public_port", SETTINGS.public_port)))

    def _admin_base_url(self) -> str:
        return self._base_url_for_port(int(getattr(self.server, "admin_port", SETTINGS.admin_port)))

    def _not_found(self) -> None:
        self._discard_request_body()
        self._send_json({"detail": "Not found."}, status_code=404)

    def _audit_admin_change(
        self,
        *,
        action: str,
        target_kind: str,
        target_ref: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        principal = self._authenticate_principal()
        if principal is None:
            return
        try:
            state_store.log_admin_change(
                principal_username=principal.username,
                principal_source=principal.source,
                listener=self._listener_role(),
                action=action,
                target_kind=target_kind,
                target_ref=target_ref,
                message=message,
                client_ip=self._client_ip(),
                details=details or {},
            )
        except Exception:  # noqa: BLE001
            LOGGER.exception("Failed to persist admin audit log for %s %s", action, target_ref)

    def _dispatch(self) -> None:
        runtime.maybe_reload()
        security.maybe_reload()
        request_target = normalize_request_target(self.path)
        parsed = urlsplit(request_target)
        query = {key: values[-1] for key, values in parse_qs(parsed.query, keep_blank_values=True).items()}

        if parsed.path == "/__health":
            self._send_json(
                {
                    "status": "ok",
                    "listener_role": self._listener_role(),
                    "service_count": runtime.service_count(),
                    "route_count": runtime.route_count(),
                    "output_profile_count": runtime.output_profile_count(),
                    "config_source": get_config_source_label(runtime.config_path),
                    "security_source": get_security_source_label(security.config_path),
                    "state_store_mode": getattr(state_store, "mode", "file"),
                    "public_port": int(getattr(self.server, "public_port", SETTINGS.public_port)),
                    "admin_port": int(getattr(self.server, "admin_port", SETTINGS.admin_port)),
                }
            )
            return

        if parsed.path == "/__login":
            if not self._is_admin_listener():
                self._not_found()
                return
            if self.command == "GET":
                self._handle_login_page(query)
                return
            if self.command == "POST":
                self._handle_login_submit()
                return
            self._not_found()
            return

        if parsed.path == "/__logout":
            if not self._is_admin_listener():
                self._not_found()
                return
            self._force_logout()
            return

        if parsed.path == "/__oauth/token" and self.command == "POST":
            if self._is_admin_listener():
                self._not_found()
                return
            self._handle_oauth_token()
            return

        if parsed.path.startswith("/__monitor"):
            if not self._is_admin_listener():
                self._not_found()
                return
            principal = self._require_permission("monitor_access", interactive=parsed.path == "/__monitor")
            if principal is None:
                return

            if parsed.path == "/__monitor":
                body = render_monitor_page(principal).encode("utf-8")
                self._write_response(
                    OutgoingResponse(
                        status_code=200,
                        headers={
                            "Content-Type": "text/html; charset=utf-8",
                            "Cache-Control": "no-store",
                        },
                        body=body if self.command != "HEAD" else b"",
                    )
                )
                return

            if parsed.path == "/__monitor/logs":
                self._send_json(runtime.list_logs(limit=200))
                return

            if parsed.path == "/__monitor/report":
                try:
                    hours = max(1, int(str(query.get("hours", "24") or "24")))
                except ValueError:
                    hours = 24
                try:
                    bucket_minutes = max(1, int(str(query.get("bucket_minutes", "60") or "60")))
                except ValueError:
                    bucket_minutes = 60
                try:
                    timezone_offset_minutes = max(
                        -840,
                        min(840, int(str(query.get("timezone_offset_minutes", "0") or "0"))),
                    )
                except ValueError:
                    timezone_offset_minutes = 0
                self._send_json(
                    runtime.log_report(
                        hours=hours,
                        bucket_minutes=bucket_minutes,
                        timezone_offset_minutes=timezone_offset_minutes,
                    )
                )
                return

            if parsed.path == "/__monitor/stream":
                self._stream_monitor()
                return

        if parsed.path.startswith("/__admin"):
            if not self._is_admin_listener():
                self._not_found()
                return
            if not self._ensure_admin_ip_allowed():
                return
            if parsed.path == "/__admin":
                principal = self._require_permission("admin_access", interactive=True)
                if principal is None:
                    return
                body = render_admin_page(
                    principal=principal,
                    document=load_config_document(runtime.config_path),
                    public_base_url=self._public_base_url(),
                    admin_base_url=self._admin_base_url(),
                    message=query.get("message", ""),
                    error=query.get("error", ""),
                ).encode("utf-8")
                self._write_response(
                    OutgoingResponse(
                        status_code=200,
                        headers={
                            "Content-Type": "text/html; charset=utf-8",
                            "Cache-Control": "no-store",
                        },
                        body=body if self.command != "HEAD" else b"",
                    )
                )
                return

            if parsed.path == "/__admin/api/backup" and self.command == "GET":
                if self._handle_admin_backup_export(parsed):
                    return

            if parsed.path == "/__admin/api/import" and self.command == "POST":
                if self._handle_admin_backup_import(parsed):
                    return

            if parsed.path == "/__admin/api/cache/clear" and self.command == "POST":
                if self._require_permission("services_manage") is None:
                    return
                self._handle_admin_cache_clear()
                return

            if parsed.path == "/__admin/api/config":
                if self._require_permission("services_manage") is None:
                    return
                if self.command == "GET":
                    self._handle_admin_config_get(parsed)
                    return
                if self.command in {"PUT", "POST"}:
                    self._handle_admin_config_replace()
                    return

            if parsed.path == "/__admin/api/clients":
                if self._require_permission("services_manage") is None:
                    return
                if self.command == "GET":
                    self._handle_admin_clients_list()
                    return
                if self.command == "POST":
                    self._handle_admin_client_upsert()
                    return

            if parsed.path.startswith("/__admin/api/clients/"):
                if self._require_permission("services_manage") is None:
                    return
                if self.command == "GET":
                    self._handle_admin_client_get(parsed)
                    return
                if self.command in {"PUT", "PATCH"}:
                    self._handle_admin_client_upsert(parsed)
                    return
                if self.command == "DELETE":
                    self._handle_admin_client_delete(parsed)
                    return

            if parsed.path == "/__admin/api/output-profiles":
                if self._require_permission("services_manage") is None:
                    return
                if self.command == "GET":
                    self._handle_admin_output_profiles_list()
                    return
                if self.command == "POST":
                    self._handle_admin_output_profile_upsert()
                    return

            if parsed.path.startswith("/__admin/api/output-profiles/"):
                if self._require_permission("services_manage") is None:
                    return
                if self.command == "GET":
                    self._handle_admin_output_profile_get(parsed)
                    return
                if self.command in {"PUT", "PATCH"}:
                    self._handle_admin_output_profile_upsert(parsed)
                    return
                if self.command == "DELETE":
                    self._handle_admin_output_profile_delete(parsed)
                    return

            if parsed.path == "/__admin/settings/save" and self.command == "POST":
                if self._require_permission("services_manage") is None:
                    return
                self._handle_settings_save()
                return

            if parsed.path == "/__admin/service/save" and self.command == "POST":
                if self._require_permission("services_manage") is None:
                    return
                self._handle_service_save()
                return

            if parsed.path == "/__admin/service/delete" and self.command == "POST":
                if self._require_permission("services_manage") is None:
                    return
                self._handle_service_delete()
                return

            if parsed.path == "/__admin/client/save" and self.command == "POST":
                if self._require_permission("services_manage") is None:
                    return
                self._handle_client_save()
                return

            if parsed.path == "/__admin/client/delete" and self.command == "POST":
                if self._require_permission("services_manage") is None:
                    return
                self._handle_client_delete()
                return

            if parsed.path == "/__admin/endpoint/save" and self.command == "POST":
                if self._require_permission("services_manage") is None:
                    return
                self._handle_endpoint_save()
                return

            if parsed.path == "/__admin/endpoint/delete" and self.command == "POST":
                if self._require_permission("services_manage") is None:
                    return
                self._handle_endpoint_delete()
                return

            if parsed.path == "/__admin/route/save" and self.command == "POST":
                if self._require_permission("services_manage") is None:
                    return
                self._handle_route_save()
                return

            if parsed.path == "/__admin/route/delete" and self.command == "POST":
                if self._require_permission("services_manage") is None:
                    return
                self._handle_route_delete()
                return

            if parsed.path == "/__admin/output-profile/save" and self.command == "POST":
                if self._require_permission("services_manage") is None:
                    return
                self._handle_output_profile_save()
                return

            if parsed.path == "/__admin/output-profile/delete" and self.command == "POST":
                if self._require_permission("services_manage") is None:
                    return
                self._handle_output_profile_delete()
                return

            if parsed.path == "/__admin/role/save" and self.command == "POST":
                if self._require_permission("security_manage") is None:
                    return
                self._handle_role_save()
                return

            if parsed.path == "/__admin/role/delete" and self.command == "POST":
                if self._require_permission("security_manage") is None:
                    return
                self._handle_role_delete()
                return

            if parsed.path == "/__admin/user/save" and self.command == "POST":
                if self._require_permission("security_manage") is None:
                    return
                self._handle_user_save()
                return

            if parsed.path == "/__admin/user/delete" and self.command == "POST":
                if self._require_permission("security_manage") is None:
                    return
                self._handle_user_delete()
                return

        if self._is_admin_listener():
            self._not_found()
            return

        request = None
        try:
            request = self._build_request(parsed, request_target=request_target)
            if self.command == "OPTIONS":
                options_response = runtime.handle_options(request)
                if options_response is not None:
                    self._write_response(options_response)
                    return
            response = runtime.handle_proxy(request)
            if self.command == "HEAD":
                response = OutgoingResponse(
                    status_code=response.status_code,
                    headers=response.headers,
                    body=b"",
                )
            self._write_response(response)
        except GatewayError as exc:
            self._write_response(
                runtime.build_gateway_error_response(
                    status_code=exc.status_code,
                    detail=exc.detail,
                    request=request,
                    preflight=self.command == "OPTIONS",
                    extra_headers=exc.headers,
                    include_body=self.command != "HEAD",
                )
            )

    def _read_body(self) -> bytes:
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(content_length) if content_length > 0 else b""

    def _parse_form(self) -> dict[str, str | list[str]]:
        body = self._read_body()
        raw = body.decode("utf-8", errors="ignore")
        parsed = parse_qs(raw, keep_blank_values=True)
        return {
            key: (values if len(values) > 1 else values[-1])
            for key, values in parsed.items()
        }

    def _safe_next_path(self, raw_value: str | None) -> str:
        candidate = str(raw_value or "").strip()
        if not candidate:
            return "/__admin"
        parsed = urlsplit(candidate)
        if parsed.scheme or parsed.netloc:
            return "/__admin"
        path = str(parsed.path or "").strip()
        if not path.startswith("/__"):
            return "/__admin"
        if not (
            path == "/__admin"
            or path.startswith("/__admin/")
            or path == "/__monitor"
            or path.startswith("/__monitor/")
        ):
            return "/__admin"
        return f"{path}?{parsed.query}" if parsed.query else path

    def _default_control_plane_path(self, principal: AuthenticatedPrincipal | None = None) -> str:
        if principal is not None:
            if principal.can("admin_access"):
                return "/__admin"
            if principal.can("monitor_access"):
                return "/__monitor"
        return "/__admin"

    def _post_login_target(
        self,
        principal: AuthenticatedPrincipal,
        requested_next: str | None = None,
    ) -> str:
        target = self._safe_next_path(requested_next)
        if target.startswith("/__admin") and principal.can("admin_access"):
            return target
        if target.startswith("/__monitor") and principal.can("monitor_access"):
            return target
        return self._default_control_plane_path(principal)

    def _login_location(
        self,
        *,
        next_path: str | None = None,
        error: str = "",
        message: str = "",
    ) -> str:
        safe_next = self._safe_next_path(next_path)
        query_parts = [f"next={quote(safe_next, safe='/?=&')}"]
        if error:
            query_parts.append(f"error={quote(str(error))}")
        if message:
            query_parts.append(f"message={quote(str(message))}")
        return f"/__login?{'&'.join(query_parts)}"

    def _send_login_page(
        self,
        *,
        next_path: str,
        error: str = "",
        message: str = "",
        username: str = "",
        status_code: int = 200,
    ) -> None:
        body = render_login_page(
            error=error,
            message=message,
            next_path=self._safe_next_path(next_path),
            username=username,
        ).encode("utf-8")
        self._write_response(
            OutgoingResponse(
                status_code=status_code,
                headers={
                    "Content-Type": "text/html; charset=utf-8",
                    "Cache-Control": "no-store",
                },
                body=body if self.command != "HEAD" else b"",
            )
        )

    def _build_admin_session_token(self, principal: AuthenticatedPrincipal) -> str:
        expires_at = int(time.time()) + ADMIN_SESSION_TTL_SECONDS
        payload = json.dumps(
            {
                "u": principal.username,
                "s": principal.source,
                "e": expires_at,
            },
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        signature = hmac.new(_admin_session_secret(), payload, hashlib.sha256).digest()
        return f"{_urlsafe_b64encode(payload)}.{_urlsafe_b64encode(signature)}"

    def _admin_session_cookie_header(self, *, principal: AuthenticatedPrincipal | None = None, clear: bool = False) -> str:
        parts = [f"{ADMIN_SESSION_COOKIE}={'' if clear else self._build_admin_session_token(principal)}"]
        parts.append(f"Path={ADMIN_SESSION_PATH}")
        parts.append("HttpOnly")
        parts.append("SameSite=Lax")
        if self._request_scheme() == "https":
            parts.append("Secure")
        if clear:
            parts.append("Max-Age=0")
            parts.append("Expires=Thu, 01 Jan 1970 00:00:00 GMT")
        else:
            parts.append(f"Max-Age={ADMIN_SESSION_TTL_SECONDS}")
        return "; ".join(parts)

    def _session_token_from_cookie(self) -> str:
        cookie_header = str(self.headers.get("Cookie", "") or "")
        if not cookie_header:
            return ""
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
        except Exception:  # noqa: BLE001
            return ""
        morsel = cookie.get(ADMIN_SESSION_COOKIE)
        return morsel.value if morsel else ""

    def _principal_from_session(self) -> AuthenticatedPrincipal | None:
        token = self._session_token_from_cookie()
        if not token or "." not in token:
            return None
        encoded_payload, encoded_signature = token.split(".", 1)
        try:
            payload = _urlsafe_b64decode(encoded_payload)
            signature = _urlsafe_b64decode(encoded_signature)
        except Exception:  # noqa: BLE001
            return None
        expected_signature = hmac.new(_admin_session_secret(), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_signature):
            return None
        try:
            parsed = json.loads(payload.decode("utf-8"))
        except Exception:  # noqa: BLE001
            return None

        expires_at = int(parsed.get("e", 0) or 0)
        if expires_at <= int(time.time()):
            return None

        username = str(parsed.get("u", "")).strip()
        source = str(parsed.get("s", "")).strip().lower()
        if not username or source not in {"bootstrap", "config"}:
            return None

        return security.restore_session_principal(
            username,
            source=source,
            bootstrap_username=SETTINGS.admin_auth.username,
        )

    def _authenticate_principal(self) -> AuthenticatedPrincipal | None:
        cached = getattr(self, "_principal_cache", _PRINCIPAL_CACHE_EMPTY)
        if cached is not _PRINCIPAL_CACHE_EMPTY:
            return cached
        principal = self._principal_from_session()
        self._principal_cache = principal
        return principal

    def _redirect_for_available_surface(
        self,
        principal: AuthenticatedPrincipal,
        permission: str,
    ) -> bool:
        if permission == "admin_access" and principal.can("monitor_access"):
            self._redirect("/__monitor")
            return True
        if permission == "monitor_access" and principal.can("admin_access"):
            self._redirect("/__admin")
            return True
        return False

    def _require_permission(
        self,
        permission: str,
        *,
        interactive: bool = False,
    ) -> AuthenticatedPrincipal | None:
        principal = self._authenticate_principal()
        if principal is None:
            self._discard_request_body()
            next_path = normalize_request_target(self.path)
            if interactive and self.command == "GET":
                self._redirect(self._login_location(next_path=next_path))
            else:
                self._auth_required_json(next_path=next_path)
            return None
        if permission and not principal.can(permission):
            self._discard_request_body()
            if interactive and self.command == "GET" and self._redirect_for_available_surface(principal, permission):
                return None
            self._forbidden(permission)
            return None
        return principal

    def _discard_request_body(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        if content_length > 0:
            self.rfile.read(content_length)

    def _auth_required_json(self, *, next_path: str | None = None) -> None:
        safe_next = self._safe_next_path(next_path or "/__admin")
        body = json.dumps(
            {
                "detail": "Authentication required.",
                "login_url": self._login_location(next_path=safe_next),
            }
        ).encode("utf-8")
        self.send_response(401, HTTPStatus.UNAUTHORIZED.phrase)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _force_logout(self) -> None:
        self.send_response(303, HTTPStatus.SEE_OTHER.phrase)
        self.send_header("Location", self._login_location(next_path="/__admin", message="Signed out."))
        self.send_header("Set-Cookie", self._admin_session_cookie_header(clear=True))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _handle_login_page(self, query: dict[str, str]) -> None:
        principal = self._authenticate_principal()
        if principal is not None:
            self._redirect(self._post_login_target(principal, query.get("next", "")))
            return
        self._send_login_page(
            next_path=query.get("next", "/__admin"),
            error=query.get("error", ""),
            message=query.get("message", ""),
        )

    def _handle_login_submit(self) -> None:
        form = self._parse_form()
        username = str(form.get("username", "")).strip()
        password = str(form.get("password", ""))
        next_path = self._safe_next_path(str(form.get("next", "/__admin")))

        principal = security.authenticate(
            username,
            password,
            bootstrap_username=SETTINGS.admin_auth.username,
            bootstrap_password=SETTINGS.admin_auth.password,
        )
        if principal is None:
            self._send_login_page(
                next_path=next_path,
                error="Invalid username or password.",
                username=username,
                status_code=401,
            )
            return
        if not principal.can("admin_access") and not principal.can("monitor_access"):
            self._send_login_page(
                next_path=next_path,
                error="This account does not have admin or monitor access.",
                username=username,
                status_code=403,
            )
            return

        self._principal_cache = principal
        self.send_response(303, HTTPStatus.SEE_OTHER.phrase)
        self.send_header("Location", self._post_login_target(principal, next_path))
        self.send_header("Set-Cookie", self._admin_session_cookie_header(principal=principal))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _forbidden(self, permission: str) -> None:
        self._send_json(
            {
                "detail": "Permission denied.",
                "required_permission": permission,
            },
            status_code=403,
        )

    def _stream_monitor(self) -> None:
        self.send_response(200, HTTPStatus.OK.phrase)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-transform")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Content-Encoding", "identity")
        self.end_headers()
        self.wfile.write(b"retry: 2000\n: stream-open\n\n")
        self.wfile.flush()

        last_payload = ""
        try:
            while True:
                payload = json.dumps(
                    runtime.list_logs(limit=200),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                if payload != last_payload:
                    self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
                    last_payload = payload
                else:
                    self.wfile.write(b": ping\n\n")
                self.wfile.flush()
                time.sleep(2)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return

    def _parse_yaml_mapping(self, raw: str, label: str) -> dict[str, Any]:
        text = raw.strip()
        if not text:
            return {}
        value = yaml.safe_load(text)
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError(f"{label} must be a YAML mapping.")
        return value

    def _parse_yaml_value(self, raw: str, label: str, *, default: Any = "") -> Any:
        text = raw.strip()
        if not text:
            return default
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"{label} must be valid YAML or JSON.") from exc

    def _parse_methods(self, raw: str) -> list[str]:
        methods = [part.strip().upper() for part in raw.split(",") if part.strip()]
        if not methods:
            raise ValueError("At least one HTTP method is required.")
        return list(dict.fromkeys(methods))

    def _parse_name_list(self, raw: str) -> list[str]:
        values = []
        for part in raw.replace("\n", ",").split(","):
            item = part.strip()
            if item and item not in values:
                values.append(item)
        return values

    def _parse_ip_network_list(self, raw: str, label: str) -> list[str]:
        values = []
        for part in raw.replace("\n", ",").split(","):
            item = part.strip()
            if not item:
                continue
            try:
                ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise ValueError(f"{label} contains invalid IP/CIDR '{item}'.") from exc
            if item not in values:
                values.append(item)
        return values

    def _validate_output_key(self, value: str, label: str) -> str:
        key = value.strip()
        if not key:
            raise ValueError(f"{label} is required.")
        if len(key) > 64:
            raise ValueError(f"{label} must be 64 characters or fewer.")
        if not (key[0].isalpha() or key[0] == "_"):
            raise ValueError(f"{label} must start with a letter or underscore.")
        if any(not (char.isalnum() or char in {"_", "-"}) for char in key):
            raise ValueError(f"{label} can only contain letters, numbers, underscore, or dash.")
        return key

    def _validate_jsonp_callback_param(self, value: str) -> str:
        param = value.strip() or "callback"
        if len(param) > 64 or any(char in param for char in "<>\"'();={}[]"):
            raise ValueError("JSONP callback param contains unsafe characters.")
        return param

    def _validate_jsonp_default_callback(self, value: str) -> str:
        callback = value.strip() or "callback"
        if len(callback) > 128:
            raise ValueError("JSONP default callback is too long.")
        for segment in callback.split("."):
            if not segment or not (segment[0].isalpha() or segment[0] in {"_", "$"}):
                raise ValueError("JSONP default callback must be a valid JavaScript identifier path.")
            if any(not (char.isalnum() or char in {"_", "$"}) for char in segment):
                raise ValueError("JSONP default callback must be a valid JavaScript identifier path.")
        return callback

    def _parse_json_value(self, raw: str, label: str) -> Any:
        text = raw.strip()
        if not text:
            raise ValueError(f"{label} is required.")
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{label} must be valid JSON.") from exc

    def _parse_basic_header(self, header: str) -> tuple[str, str] | None:
        if not header.startswith("Basic "):
            return None
        try:
            decoded = base64.b64decode(header[6:].encode("ascii")).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:  # noqa: BLE001
            return None
        return username, password

    def _client_ip(self) -> str:
        peer_ip = self._raw_client_ip()
        if not self._request_via_trusted_proxy():
            return peer_ip

        proxy_allowlist = runtime.trusted_proxy_allowlist()
        for candidate in reversed(self._forwarded_ip_chain()):
            if not self._ip_in_allowlist(candidate, proxy_allowlist):
                return candidate

        real_ip = self._normalize_forwarded_ip(str(self.headers.get("X-Real-IP", "") or ""))
        if real_ip:
            return real_ip

        chain = self._forwarded_ip_chain()
        if chain:
            return chain[0]
        return peer_ip

    def _admin_ip_allowed(self) -> bool:
        allowlist = SETTINGS.admin_access_allowlist
        if not allowlist:
            return True
        return self._ip_in_allowlist(self._client_ip(), allowlist)

    def _ensure_admin_ip_allowed(self) -> bool:
        if self._admin_ip_allowed():
            return True
        self._discard_request_body()
        self._send_json(
            {
                "detail": "Admin access is not allowed from this IP address.",
                "client_ip": self._client_ip(),
                "allowlist": SETTINGS.admin_access_allowlist,
            },
            status_code=403,
        )
        return False

    def _parse_structured_body(self, *, label: str) -> Any:
        body = self._read_body()
        text = body.decode("utf-8", errors="ignore")
        if not text.strip():
            raise ValueError(f"{label} body is required.")
        content_type = str(self.headers.get("Content-Type", "")).lower()
        try:
            if "application/json" in content_type:
                return json.loads(text)
            return yaml.safe_load(text)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"{label} body must be valid JSON or YAML.") from exc

    def _config_response_format(self, parsed) -> str:
        query = parse_qs(parsed.query, keep_blank_values=True)
        explicit = str((query.get("format") or [""])[-1]).strip().lower()
        if explicit in {"yaml", "json"}:
            return explicit
        accept = str(self.headers.get("Accept", "")).lower()
        if "yaml" in accept or "x-yaml" in accept:
            return "yaml"
        return "json"

    def _send_structured_document(self, document: Any, *, parsed) -> None:
        response_format = self._config_response_format(parsed)
        if response_format == "yaml":
            body = yaml.safe_dump(document, sort_keys=False, allow_unicode=False).encode("utf-8")
            self._write_response(
                OutgoingResponse(
                    status_code=200,
                    headers={"Content-Type": "application/yaml; charset=utf-8"},
                    body=body if self.command != "HEAD" else b"",
                )
            )
            return
        self._send_json(document)

    def _send_config_document(self, document: dict[str, Any], *, parsed) -> None:
        self._send_structured_document(document, parsed=parsed)

    def _require_backup_scope_permissions(self, scope: str) -> AuthenticatedPrincipal | None:
        definition = backup_scope_definition(scope)
        granted: AuthenticatedPrincipal | None = None
        for permission in definition.get("permissions") or ():
            principal = self._require_permission(str(permission))
            if principal is None:
                return None
            granted = principal
        return granted

    def _client_document_by_slug(self, slug: str) -> dict[str, Any] | None:
        document = load_config_document(runtime.config_path)
        for item in (document.get("clients") or []):
            if not isinstance(item, dict):
                continue
            item_slug = str(item.get("slug", item.get("code", ""))).strip().lower()
            if item_slug == slug:
                return item
        return None

    def _output_profile_document_by_slug(self, slug: str) -> dict[str, Any] | None:
        document = load_config_document(runtime.config_path)
        profile = (document.get("output_profiles") or {}).get(slug)
        return profile if isinstance(profile, dict) else None

    def _redirect(self, location: str) -> None:
        self.send_response(303, HTTPStatus.SEE_OTHER.phrase)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _wants_admin_json(self) -> bool:
        accept = str(self.headers.get("Accept", "")).lower()
        requested_with = str(self.headers.get("X-Requested-With", "")).lower()
        return requested_with == "xmlhttprequest" or "application/json" in accept

    def _send_admin_mutation_success(self, message: str) -> None:
        if not self._wants_admin_json():
            self._redirect(build_status_query(message=message))
            return
        principal = self._authenticate_principal()
        document = load_config_document(runtime.config_path)
        self._send_json(
            {
                "message": message,
                "state": (
                    build_admin_state(
                        principal=principal,
                        document=document,
                        public_base_url=self._public_base_url(),
                        admin_base_url=self._admin_base_url(),
                    )
                    if principal
                    else None
                ),
            }
        )

    def _send_admin_mutation_error(self, error: Exception | str) -> None:
        detail = str(error)
        if not self._wants_admin_json():
            self._redirect(build_status_query(error=detail))
            return
        self._send_json({"detail": detail}, status_code=400)

    def _handle_oauth_token(self) -> None:
        try:
            header_credentials = self._parse_basic_header(self.headers.get("Authorization", ""))
            form = {} if header_credentials else self._parse_form()
            client_id = header_credentials[0] if header_credentials else str(form.get("client_id", "")).strip()
            client_secret = header_credentials[1] if header_credentials else str(form.get("client_secret", "")).strip()
            if not client_id or not client_secret:
                raise GatewayError(400, "client_id and client_secret are required.")

            client_ip = self.client_address[0] if self.client_address else ""
            access_token, expires_in, client_code, auth_method_code = runtime.issue_oauth_token(
                client_id=client_id,
                client_secret=client_secret,
                client_ip=client_ip,
            )
            self._send_json(
                {
                    "token_type": "Bearer",
                    "access_token": access_token,
                    "expires_in": expires_in,
                    "client_code": client_code,
                    "auth_method_code": auth_method_code,
                }
            )
        except GatewayError as exc:
            self._send_json({"detail": exc.detail}, status_code=exc.status_code)
        except Exception as exc:  # noqa: BLE001
            self._send_json({"detail": str(exc)}, status_code=400)

    def _handle_settings_save(self) -> None:
        try:
            form = self._parse_form()
            retention_raw = str(form.get("log_retention_hours", "")).strip()
            log_retention_hours = int(retention_raw) if retention_raw else None
            trusted_proxy_ips = self._parse_ip_network_list(
                str(form.get("trusted_proxy_ips", "")),
                "Trusted proxy IPs",
            )
            gateway_response_mode = str(form.get("gateway_response_mode", "default")).strip().lower() or "default"
            gateway_response_output_profile = (
                str(form.get("gateway_response_output_profile", "")).strip().lower()
            )
            gateway_response_success_key = self._validate_output_key(
                str(form.get("gateway_response_success_key", "success")),
                "Gateway success key",
            )
            gateway_response_data_key = self._validate_output_key(
                str(form.get("gateway_response_data_key", "data")),
                "Gateway data key",
            )
            gateway_response_message_key = self._validate_output_key(
                str(form.get("gateway_response_message_key", "message")),
                "Gateway message key",
            )
            gateway_response_error_key = self._validate_output_key(
                str(form.get("gateway_response_error_key", "error")),
                "Gateway error key",
            )
            gateway_response_empty_value = self._parse_yaml_value(
                str(form.get("gateway_response_empty_value", "")),
                "Gateway empty value",
                default="",
            )
            gateway_response_headers = self._parse_yaml_mapping(
                str(form.get("gateway_response_headers_yaml", "")),
                "Gateway response headers",
            )
            if log_retention_hours is not None and log_retention_hours <= 0:
                raise ValueError("Log retention hours must be a positive number.")
            if gateway_response_mode not in {"default", "profile", "inline"}:
                raise ValueError("Gateway response mode must be default, profile, or inline.")
            if gateway_response_mode == "profile" and not gateway_response_output_profile:
                raise ValueError("Select an output profile for gateway-generated errors.")
            if (
                gateway_response_output_profile
                and gateway_response_output_profile not in runtime.output_profiles
            ):
                raise ValueError(
                    f"Gateway response output profile '{gateway_response_output_profile}' was not found."
                )
            message = save_gateway_settings(
                runtime.config_path,
                log_retention_hours=log_retention_hours,
                trusted_proxy_ips=trusted_proxy_ips,
                gateway_response_mode=gateway_response_mode,
                gateway_response_output_profile=gateway_response_output_profile,
                gateway_response_success_key=gateway_response_success_key,
                gateway_response_data_key=gateway_response_data_key,
                gateway_response_message_key=gateway_response_message_key,
                gateway_response_error_key=gateway_response_error_key,
                gateway_response_empty_value=gateway_response_empty_value,
                gateway_response_headers=gateway_response_headers,
            )
            runtime.load()
            self._audit_admin_change(
                action="save",
                target_kind="settings",
                target_ref="gateway",
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_service_save(self) -> None:
        try:
            form = self._parse_form()
            original_name = str(form.get("original_name", "")).strip()
            service_name = str(form.get("service_name", "")).strip()
            protocol = str(form.get("protocol", "http")).strip().lower() or "http"
            base_url = str(form.get("base_url", "")).strip()
            timeout_seconds = float(str(form.get("timeout_seconds", "30")).strip() or "30")
            variables = self._parse_yaml_mapping(str(form.get("variables_yaml", "")), "Variables")
            headers = self._parse_yaml_mapping(str(form.get("headers_yaml", "")), "Headers")
            pre_call_code = str(form.get("pre_call_code", "")).rstrip()
            pre_call_cache_ttl = int(str(form.get("pre_call_cache_ttl_seconds", "0")).strip() or "0")
            pre_call_cache_key = str(form.get("pre_call_cache_key", "")).strip()
            response_cache_ttl = int(str(form.get("response_cache_ttl_seconds", "0")).strip() or "0")
            response_cache_vary_by_client = "response_cache_vary_by_client" in form
            response_cache_vary_headers = self._parse_name_list(
                str(form.get("response_cache_vary_headers", ""))
            )
            response_cache_methods = self._parse_methods(
                str(form.get("response_cache_methods", "GET"))
            ) if response_cache_ttl > 0 else []
            cors_allow_origins = self._parse_name_list(str(form.get("cors_allow_origins", "")))
            cors_allow_methods = [
                item.upper() for item in self._parse_name_list(str(form.get("cors_allow_methods", "")))
            ]
            cors_allow_headers = self._parse_name_list(str(form.get("cors_allow_headers", "")))
            cors_expose_headers = self._parse_name_list(str(form.get("cors_expose_headers", "")))
            cors_max_age_seconds = int(str(form.get("cors_max_age_seconds", "600")).strip() or "600")
            rate_limit_requests = int(str(form.get("rate_limit_requests", "60")).strip() or "60")
            rate_limit_window_seconds = int(
                str(form.get("rate_limit_window_seconds", "60")).strip() or "60"
            )
            rate_limit_scope = (
                str(form.get("rate_limit_scope", "client_or_ip")).strip().lower() or "client_or_ip"
            )

            if not service_name:
                raise ValueError("Service name is required.")
            if not base_url:
                raise ValueError("Base URL/Target is required.")
            if protocol not in SERVICE_PROTOCOL_CHOICES:
                raise ValueError(
                    f"Service protocol must be one of: {', '.join(SERVICE_PROTOCOL_CHOICES)}."
                )
            if protocol == "http" and not base_url.startswith(("http://", "https://")):
                raise ValueError("HTTP services must use an absolute http(s) Base URL.")
            if timeout_seconds < 0:
                raise ValueError("Timeout seconds must be zero or positive.")
            if pre_call_cache_ttl < 0:
                raise ValueError("Pre-call cache TTL must be zero or positive.")
            if response_cache_ttl < 0:
                raise ValueError("Response cache TTL must be zero or positive.")
            if cors_max_age_seconds < 0:
                raise ValueError("CORS max age must be zero or positive.")
            if "rate_limit_enabled" in form:
                if rate_limit_requests <= 0:
                    raise ValueError("Rate limit requests must be positive.")
                if rate_limit_window_seconds <= 0:
                    raise ValueError("Rate limit window seconds must be positive.")
            if rate_limit_scope not in {"client_or_ip", "client", "ip"}:
                raise ValueError("Rate limit scope must be client_or_ip, client, or ip.")

            message = save_service(
                runtime.config_path,
                original_name=original_name,
                service_name=service_name,
                protocol=protocol,
                base_url=base_url,
                timeout_seconds=timeout_seconds,
                verify_ssl="verify_ssl" in form,
                trust_env_proxy="trust_env_proxy" in form,
                forward_napigate_headers="forward_napigate_headers" in form,
                variables=variables,
                headers=headers,
                pre_call_code=pre_call_code,
                pre_call_cache_ttl=pre_call_cache_ttl,
                pre_call_cache_key=pre_call_cache_key,
                response_cache_ttl=response_cache_ttl,
                response_cache_vary_by_client=response_cache_vary_by_client,
                response_cache_vary_headers=response_cache_vary_headers,
                response_cache_methods=response_cache_methods,
                cors_enabled="cors_enabled" in form,
                cors_allow_origins=cors_allow_origins,
                cors_allow_methods=cors_allow_methods,
                cors_allow_headers=cors_allow_headers,
                cors_expose_headers=cors_expose_headers,
                cors_allow_credentials="cors_allow_credentials" in form,
                cors_max_age_seconds=cors_max_age_seconds,
                rate_limit_enabled="rate_limit_enabled" in form,
                rate_limit_requests=rate_limit_requests,
                rate_limit_window_seconds=rate_limit_window_seconds,
                rate_limit_scope=rate_limit_scope,
            )
            runtime.load()
            self._audit_admin_change(
                action="save",
                target_kind="service",
                target_ref=service_name,
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_service_delete(self) -> None:
        try:
            form = self._parse_form()
            service_name = str(form.get("service_name", "")).strip()
            message = delete_service(runtime.config_path, service_name=service_name)
            runtime.load()
            self._audit_admin_change(
                action="delete",
                target_kind="service",
                target_ref=service_name,
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_client_save(self) -> None:
        try:
            form = self._parse_form()
            original_slug = str(form.get("original_slug", "")).strip().lower()
            client_slug = str(form.get("client_slug", "")).strip().lower()
            client_code = str(form.get("client_code", "")).strip()
            client_title = str(form.get("client_title", "")).strip()
            enabled = "enabled" in form
            ip_allowlist = self._parse_name_list(str(form.get("ip_allowlist", "")))
            access = self._parse_json_value(str(form.get("access_json", "")), "Client access")
            auth_methods = self._parse_json_value(str(form.get("auth_methods_json", "")), "Client auth methods")

            if not client_slug:
                raise ValueError("Client slug is required.")
            if not client_code:
                raise ValueError("Client code is required.")
            if not client_title:
                raise ValueError("Client title is required.")
            if not isinstance(access, dict):
                raise ValueError("Client access must be a JSON object.")
            if not isinstance(auth_methods, list):
                raise ValueError("Client auth methods must be a JSON list.")

            message = save_client(
                runtime.config_path,
                original_slug=original_slug,
                client_slug=client_slug,
                client_code=client_code,
                client_title=client_title,
                enabled=enabled,
                ip_allowlist=ip_allowlist,
                access=access,
                auth_methods=auth_methods,
            )
            runtime.load()
            self._audit_admin_change(
                action="save",
                target_kind="client",
                target_ref=client_slug or client_code,
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_client_delete(self) -> None:
        try:
            form = self._parse_form()
            client_slug = str(form.get("client_slug", "")).strip().lower()
            message = delete_client(runtime.config_path, client_slug=client_slug)
            runtime.load()
            self._audit_admin_change(
                action="delete",
                target_kind="client",
                target_ref=client_slug,
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_endpoint_save(self) -> None:
        try:
            form = self._parse_form()
            service_name = str(form.get("service_name", "")).strip()
            original_name = str(form.get("original_name", "")).strip()
            original_slug = str(form.get("original_slug", "")).strip().lower()
            endpoint_name = str(form.get("endpoint_name", "")).strip()
            endpoint_slug = str(form.get("endpoint_slug", "")).strip().lower()
            upstream_path = str(form.get("upstream_path", "")).strip()
            headers = self._parse_yaml_mapping(str(form.get("headers_yaml", "")), "Headers")
            query = self._parse_yaml_mapping(str(form.get("query_yaml", "")), "Query")
            pre_call_code = str(form.get("pre_call_code", "")).rstrip()
            pre_call_cache_ttl = int(str(form.get("pre_call_cache_ttl_seconds", "0")).strip() or "0")
            pre_call_cache_key = str(form.get("pre_call_cache_key", "")).strip()
            output_profile = str(form.get("output_profile", "")).strip().lower()
            response_cache_ttl = int(str(form.get("response_cache_ttl_seconds", "0")).strip() or "0")
            response_cache_vary_by_client = "response_cache_vary_by_client" in form
            response_cache_vary_headers = self._parse_name_list(
                str(form.get("response_cache_vary_headers", ""))
            )
            response_cache_methods = self._parse_methods(
                str(form.get("response_cache_methods", "GET"))
            ) if response_cache_ttl > 0 else []

            if not service_name:
                raise ValueError("Service name is required.")
            if not endpoint_name:
                raise ValueError("Endpoint name is required.")
            if not endpoint_slug:
                raise ValueError("Endpoint slug is required.")
            if pre_call_cache_ttl < 0:
                raise ValueError("Pre-call cache TTL must be zero or positive.")
            if response_cache_ttl < 0:
                raise ValueError("Response cache TTL must be zero or positive.")

            message = save_endpoint(
                runtime.config_path,
                service_name=service_name,
                original_name=original_name,
                original_slug=original_slug,
                endpoint_name=endpoint_name,
                endpoint_slug=endpoint_slug,
                upstream_path=upstream_path,
                headers=headers,
                query=query,
                pre_call_code=pre_call_code,
                pre_call_cache_ttl=pre_call_cache_ttl,
                pre_call_cache_key=pre_call_cache_key,
                output_profile=output_profile,
                response_cache_ttl=response_cache_ttl,
                response_cache_vary_by_client=response_cache_vary_by_client,
                response_cache_vary_headers=response_cache_vary_headers,
                response_cache_methods=response_cache_methods,
            )
            runtime.load()
            self._audit_admin_change(
                action="save",
                target_kind="endpoint",
                target_ref=f"{service_name}/{endpoint_name}",
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_endpoint_delete(self) -> None:
        try:
            form = self._parse_form()
            service_name = str(form.get("service_name", "")).strip()
            endpoint_name = str(form.get("endpoint_name", "")).strip()
            message = delete_endpoint(
                runtime.config_path,
                service_name=service_name,
                endpoint_name=endpoint_name,
            )
            runtime.load()
            self._audit_admin_change(
                action="delete",
                target_kind="endpoint",
                target_ref=f"{service_name}/{endpoint_name}",
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_route_save(self) -> None:
        try:
            form = self._parse_form()
            original_slug = str(form.get("original_slug", "")).strip().lower()
            route_name = str(form.get("route_name", "")).strip()
            route_slug = str(form.get("route_slug", "")).strip().lower()
            protocol = str(form.get("protocol", "http")).strip().lower() or "http"
            methods = self._parse_methods(str(form.get("methods", "GET")))
            gateway_path = str(form.get("gateway_path", "")).strip()
            strategy = str(form.get("strategy", "single")).strip().lower() or "single"
            target_values = form.get("targets", [])
            if isinstance(target_values, str):
                target_values = [target_values] if target_values else []
            targets: list[dict[str, str]] = []
            for value in target_values:
                service_name, _, endpoint_name = str(value).partition("::")
                service_name = service_name.strip()
                endpoint_name = endpoint_name.strip()
                if service_name and endpoint_name:
                    target = {"service": service_name, "endpoint": endpoint_name}
                    if target not in targets:
                        targets.append(target)

            output_profile = str(form.get("output_profile", "")).strip().lower()
            auth_required = "auth_required" in form
            pre_call_code = str(form.get("pre_call_code", "")).rstrip()
            pre_call_cache_ttl = int(str(form.get("pre_call_cache_ttl_seconds", "0")).strip() or "0")
            pre_call_cache_key = str(form.get("pre_call_cache_key", "")).strip()
            response_cache_ttl = int(str(form.get("response_cache_ttl_seconds", "0")).strip() or "0")
            response_cache_vary_by_client = "response_cache_vary_by_client" in form
            response_cache_vary_headers = self._parse_name_list(
                str(form.get("response_cache_vary_headers", ""))
            )
            response_cache_methods = self._parse_methods(
                str(form.get("response_cache_methods", "GET"))
            ) if response_cache_ttl > 0 else []
            success_hook_url = str(form.get("success_hook_url", "")).strip()
            success_hook_timeout_seconds = float(
                str(form.get("success_hook_timeout_seconds", "5")).strip() or "5"
            )
            success_hook_event_type = str(form.get("success_hook_event_type", "financial")).strip()
            success_hook_headers = self._parse_yaml_mapping(
                str(form.get("success_hook_headers_yaml", "")),
                "Success hook headers",
            )
            success_hook_include_response_body = "success_hook_include_response_body" in form
            success_hook_include_request_body = "success_hook_include_request_body" in form

            if not route_name:
                raise ValueError("Route name is required.")
            if not route_slug:
                raise ValueError("Route slug is required.")
            if protocol not in ROUTE_PROTOCOL_CHOICES:
                raise ValueError(
                    f"Route protocol must be one of: {', '.join(ROUTE_PROTOCOL_CHOICES)}."
                )
            if not gateway_path:
                raise ValueError("Gateway path is required.")
            if not gateway_path.startswith("/"):
                raise ValueError("Gateway path must start with /.")
            if strategy not in {"single", "round_robin", "failover", "parallel_race"}:
                raise ValueError("Route strategy must be single, round_robin, failover, or parallel_race.")
            if pre_call_cache_ttl < 0:
                raise ValueError("Pre-call cache TTL must be zero or positive.")
            if response_cache_ttl < 0:
                raise ValueError("Response cache TTL must be zero or positive.")
            if success_hook_timeout_seconds <= 0:
                raise ValueError("Success hook timeout must be positive.")

            message = save_route(
                runtime.config_path,
                original_slug=original_slug,
                route_name=route_name,
                route_slug=route_slug,
                protocol=protocol,
                methods=methods,
                gateway_path=gateway_path,
                strategy=strategy,
                targets=targets,
                auth_required=auth_required,
                pre_call_code=pre_call_code,
                pre_call_cache_ttl=pre_call_cache_ttl,
                pre_call_cache_key=pre_call_cache_key,
                output_profile=output_profile,
                response_cache_ttl=response_cache_ttl,
                response_cache_vary_by_client=response_cache_vary_by_client,
                response_cache_vary_headers=response_cache_vary_headers,
                response_cache_methods=response_cache_methods,
                success_hook_url=success_hook_url,
                success_hook_timeout_seconds=success_hook_timeout_seconds,
                success_hook_event_type=success_hook_event_type,
                success_hook_headers=success_hook_headers,
                success_hook_include_response_body=success_hook_include_response_body,
                success_hook_include_request_body=success_hook_include_request_body,
            )
            runtime.load()
            self._audit_admin_change(
                action="save",
                target_kind="route",
                target_ref=route_slug,
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_route_delete(self) -> None:
        try:
            form = self._parse_form()
            route_slug = str(form.get("route_slug", "")).strip().lower()
            message = delete_route(runtime.config_path, route_slug=route_slug)
            runtime.load()
            self._audit_admin_change(
                action="delete",
                target_kind="route",
                target_ref=route_slug,
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_output_profile_save(self) -> None:
        try:
            form = self._parse_form()
            original_slug = str(form.get("original_slug", "")).strip().lower()
            profile_slug = str(form.get("profile_slug", "")).strip().lower()
            profile_title = str(form.get("profile_title", "")).strip()
            profile_type = str(form.get("profile_type", "passthrough")).strip().lower()
            success_key = self._validate_output_key(str(form.get("success_key", "success")), "Success key")
            data_key = self._validate_output_key(str(form.get("data_key", "data")), "Data key")
            message_key = self._validate_output_key(str(form.get("message_key", "message")), "Message key")
            error_key = self._validate_output_key(str(form.get("error_key", "error")), "Error key")
            passthrough_keys = self._parse_name_list(str(form.get("passthrough_keys", "")))
            passthrough_keys = [
                self._validate_output_key(item, "Existing envelope key")
                for item in passthrough_keys
            ]
            source_success_key = str(form.get("source_success_key", "")).strip()
            message_source_keys = self._parse_name_list(str(form.get("message_source_keys", "")))
            error_source_keys = self._parse_name_list(str(form.get("error_source_keys", "")))
            data_fields_raw = self._parse_yaml_mapping(str(form.get("data_fields_yaml", "")), "Data fields")
            data_fields = {
                self._validate_output_key(str(field_name), "Data field key"): str(source_path).strip()
                for field_name, source_path in data_fields_raw.items()
                if str(field_name).strip() and str(source_path).strip()
            }
            empty_value = self._parse_yaml_value(
                str(form.get("empty_value_yaml", "")),
                "Empty value",
                default="",
            )
            custom_validation_mode = (
                str(form.get("custom_validation_mode", "status_code")).strip().lower()
                or "status_code"
            )
            custom_validation_source_key = str(form.get("custom_validation_source_key", "")).strip()
            custom_validation_expected_value = self._parse_yaml_value(
                str(form.get("custom_validation_expected_value_yaml", "")),
                "Custom validation expected value",
                default=True,
            )
            custom_validation_error_source_keys = self._parse_name_list(
                str(form.get("custom_validation_error_source_keys", ""))
            )
            transform_code = str(form.get("transform_code", "")).rstrip()
            jsonp_callback_param = self._validate_jsonp_callback_param(
                str(form.get("jsonp_callback_param", "callback"))
            )
            jsonp_default_callback = self._validate_jsonp_default_callback(
                str(form.get("jsonp_default_callback", "callback"))
            )
            headers = self._parse_yaml_mapping(str(form.get("headers_yaml", "")), "Profile headers")

            if not profile_slug:
                raise ValueError("Output profile slug is required.")
            if not profile_title:
                raise ValueError("Output profile title is required.")
            if profile_type not in {"passthrough", "json_envelope", "jsonp", "custom"}:
                raise ValueError("Output profile type must be passthrough, json_envelope, jsonp, or custom.")
            if custom_validation_mode not in {"status_code", "payload_key"}:
                raise ValueError("Custom success detection must be status_code or payload_key.")
            if profile_type == "custom":
                if custom_validation_mode == "payload_key" and not custom_validation_source_key:
                    raise ValueError("Validation source path is required when custom success detection uses payload_key.")
                validate_custom_output_code(transform_code)

            message = save_output_profile(
                runtime.config_path,
                original_slug=original_slug,
                profile_slug=profile_slug,
                profile_title=profile_title,
                enabled="enabled" in form,
                profile_type=profile_type,
                success_key=success_key,
                data_key=data_key,
                message_key=message_key,
                error_key=error_key,
                passthrough_keys=passthrough_keys,
                source_success_key=source_success_key,
                message_source_keys=message_source_keys,
                error_source_keys=error_source_keys,
                data_fields=data_fields,
                empty_value=empty_value,
                jsonp_callback_param=jsonp_callback_param,
                jsonp_default_callback=jsonp_default_callback,
                transform_code=transform_code,
                custom_validation_mode=custom_validation_mode,
                custom_validation_source_key=custom_validation_source_key,
                custom_validation_expected_value=custom_validation_expected_value,
                custom_validation_error_source_keys=custom_validation_error_source_keys,
                headers=headers,
            )
            runtime.load()
            self._audit_admin_change(
                action="save",
                target_kind="output_profile",
                target_ref=profile_slug,
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_output_profile_delete(self) -> None:
        try:
            form = self._parse_form()
            profile_slug = str(form.get("profile_slug", "")).strip().lower()
            message = delete_output_profile(runtime.config_path, profile_slug=profile_slug)
            runtime.load()
            self._audit_admin_change(
                action="delete",
                target_kind="output_profile",
                target_ref=profile_slug,
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_role_save(self) -> None:
        try:
            form = self._parse_form()
            original_name = str(form.get("original_name", "")).strip()
            role_name = str(form.get("role_name", "")).strip()
            permissions_raw = form.get("permissions", [])
            permissions = permissions_raw if isinstance(permissions_raw, list) else [str(permissions_raw)]

            if not role_name:
                raise ValueError("Role name is required.")

            message = save_role(
                security.config_path,
                original_name=original_name,
                role_name=role_name,
                permissions=permissions,
            )
            security.load()
            self._audit_admin_change(
                action="save",
                target_kind="role",
                target_ref=role_name,
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_role_delete(self) -> None:
        try:
            form = self._parse_form()
            role_name = str(form.get("role_name", "")).strip()
            message = delete_role(security.config_path, role_name=role_name)
            security.load()
            self._audit_admin_change(
                action="delete",
                target_kind="role",
                target_ref=role_name,
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_user_save(self) -> None:
        try:
            form = self._parse_form()
            original_username = str(form.get("original_username", "")).strip()
            username = str(form.get("username", "")).strip()
            password = str(form.get("password", ""))
            roles_raw = form.get("roles", [])
            roles = roles_raw if isinstance(roles_raw, list) else [str(roles_raw)] if roles_raw else []
            enabled = "enabled" in form

            if not username:
                raise ValueError("Username is required.")

            message = save_user(
                security.config_path,
                original_username=original_username,
                username=username,
                password=password,
                roles=roles,
                enabled=enabled,
            )
            security.load()
            self._audit_admin_change(
                action="save",
                target_kind="user",
                target_ref=username,
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_user_delete(self) -> None:
        try:
            form = self._parse_form()
            username = str(form.get("username", "")).strip()
            message = delete_user(security.config_path, username=username)
            security.load()
            self._audit_admin_change(
                action="delete",
                target_kind="user",
                target_ref=username,
                message=message,
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_admin_backup_export(self, parsed) -> bool:
        try:
            query = parse_qs(parsed.query, keep_blank_values=True)
            scope = str((query.get("scope") or ["full"])[-1]).strip().lower() or "full"
            principal = self._require_backup_scope_permissions(scope)
            if principal is None:
                return True
            payload = export_backup_scope(
                runtime.config_path,
                security.config_path,
                scope=scope,
            )
            self._audit_admin_change(
                action="export",
                target_kind="backup",
                target_ref=scope,
                message=f"Exported {backup_scope_definition(scope)['title']}.",
            )
            self._send_structured_document(payload, parsed=parsed)
            return True
        except Exception as exc:  # noqa: BLE001
            self._send_json({"detail": str(exc)}, status_code=400)
            return True

    def _handle_admin_backup_import(self, parsed) -> bool:
        try:
            query = parse_qs(parsed.query, keep_blank_values=True)
            scope = str((query.get("scope") or ["full"])[-1]).strip().lower() or "full"
            principal = self._require_backup_scope_permissions(scope)
            if principal is None:
                return True
            payload = self._parse_structured_body(label="Backup import")
            message = import_backup_scope(
                runtime.config_path,
                security.config_path,
                scope=scope,
                payload=payload,
            )
            runtime.load()
            security.load()
            self._audit_admin_change(
                action="import",
                target_kind="backup",
                target_ref=scope,
                message=message,
            )
            self._send_admin_mutation_success(message)
            return True
        except Exception as exc:  # noqa: BLE001
            self._send_json({"detail": str(exc)}, status_code=400)
            return True

    def _handle_admin_cache_clear(self) -> None:
        try:
            self._discard_request_body()
            cleared_count = runtime.clear_cache()
            entry_label = "entry" if cleared_count == 1 else "entries"
            message = f"Cleared {cleared_count} gateway cache {entry_label}."
            self._audit_admin_change(
                action="clear",
                target_kind="cache",
                target_ref="all",
                message=message,
                details={
                    "cleared_count": cleared_count,
                    "scopes": ["response", "pre_call", "external_auth"],
                    "rate_limit_cleared": False,
                },
            )
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_admin_config_get(self, parsed) -> None:
        self._send_config_document(load_config_document(runtime.config_path), parsed=parsed)

    def _handle_admin_config_replace(self) -> None:
        try:
            document = self._parse_structured_body(label="Config")
            if not isinstance(document, dict):
                raise ValueError("Config body must be a top-level mapping.")
            save_config_document(runtime.config_path, document)
            runtime.load()
            self._audit_admin_change(
                action="replace",
                target_kind="config",
                target_ref="services",
                message="Config replaced.",
            )
            self._send_json({"message": "Config replaced."})
        except Exception as exc:  # noqa: BLE001
            self._send_json({"detail": str(exc)}, status_code=400)

    def _handle_admin_clients_list(self) -> None:
        document = load_config_document(runtime.config_path)
        clients = [
            item
            for item in (document.get("clients") or [])
            if isinstance(item, dict)
        ]
        self._send_json(clients)

    def _handle_admin_client_get(self, parsed) -> None:
        slug = parsed.path.rsplit("/", 1)[-1].strip().lower()
        client = self._client_document_by_slug(slug)
        if client is None:
            self._send_json({"detail": f"Client slug '{slug}' not found."}, status_code=404)
            return
        self._send_json(client)

    def _handle_admin_client_upsert(self, parsed=None) -> None:
        try:
            payload = self._parse_structured_body(label="Client")
            if not isinstance(payload, dict):
                raise ValueError("Client body must be a mapping.")

            original_slug = (
                parsed.path.rsplit("/", 1)[-1].strip().lower()
                if parsed is not None
                else str(payload.get("original_slug", "")).strip().lower()
            )
            client_slug = str(payload.get("slug", "")).strip().lower()
            client_code = str(payload.get("code", "")).strip()
            client_title = str(payload.get("title", "")).strip()
            enabled = bool(payload.get("enabled", True))
            ip_allowlist = payload.get("ip_allowlist") or []
            access = payload.get("access") or {}
            auth_methods = payload.get("auth_methods") or []

            if not isinstance(ip_allowlist, list):
                raise ValueError("Client ip_allowlist must be a list.")
            if not isinstance(access, dict):
                raise ValueError("Client access must be a mapping.")
            if not isinstance(auth_methods, list):
                raise ValueError("Client auth_methods must be a list.")

            message = save_client(
                runtime.config_path,
                original_slug=original_slug,
                client_slug=client_slug,
                client_code=client_code,
                client_title=client_title,
                enabled=enabled,
                ip_allowlist=[str(item).strip() for item in ip_allowlist if str(item).strip()],
                access=access,
                auth_methods=auth_methods,
            )
            runtime.load()
            self._audit_admin_change(
                action="save",
                target_kind="client",
                target_ref=client_slug or client_code,
                message=message,
            )
            saved = self._client_document_by_slug(client_slug)
            self._send_json(
                {
                    "message": message,
                    "client": saved,
                },
                status_code=201 if parsed is None else 200,
            )
        except Exception as exc:  # noqa: BLE001
            self._send_json({"detail": str(exc)}, status_code=400)

    def _handle_admin_client_delete(self, parsed) -> None:
        slug = parsed.path.rsplit("/", 1)[-1].strip().lower()
        try:
            message = delete_client(runtime.config_path, client_slug=slug)
            runtime.load()
            self._audit_admin_change(
                action="delete",
                target_kind="client",
                target_ref=slug,
                message=message,
            )
            self._send_json({"message": message})
        except Exception as exc:  # noqa: BLE001
            self._send_json({"detail": str(exc)}, status_code=400)

    def _handle_admin_output_profiles_list(self) -> None:
        document = load_config_document(runtime.config_path)
        self._send_json(document.get("output_profiles") or {})

    def _handle_admin_output_profile_get(self, parsed) -> None:
        slug = parsed.path.rsplit("/", 1)[-1].strip().lower()
        profile = self._output_profile_document_by_slug(slug)
        if profile is None:
            self._send_json({"detail": f"Output profile '{slug}' not found."}, status_code=404)
            return
        self._send_json(profile)

    def _handle_admin_output_profile_upsert(self, parsed=None) -> None:
        try:
            payload = self._parse_structured_body(label="Output profile")
            if not isinstance(payload, dict):
                raise ValueError("Output profile body must be a mapping.")

            original_slug = (
                parsed.path.rsplit("/", 1)[-1].strip().lower()
                if parsed is not None
                else str(payload.get("original_slug", "")).strip().lower()
            )
            profile_slug = str(payload.get("slug", "")).strip().lower()
            profile_title = str(payload.get("title", "")).strip()
            profile_type = str(payload.get("type", "passthrough")).strip().lower()
            headers = payload.get("headers") or {}
            passthrough_keys = payload.get("passthrough_keys") or []
            source_success_key = str(payload.get("source_success_key", "")).strip()
            message_source_keys = payload.get("message_source_keys") or []
            error_source_keys = payload.get("error_source_keys") or []
            data_fields = payload.get("data_fields") or {}
            empty_value = payload.get("empty_value", "")
            custom_validation = payload.get("custom_validation") or {}
            transform_code = str(payload.get("transform_code", "") or "").rstrip()

            if not isinstance(headers, dict):
                raise ValueError("Output profile headers must be a mapping.")
            if not isinstance(passthrough_keys, list):
                raise ValueError("Output profile passthrough_keys must be a list.")
            if not isinstance(message_source_keys, list):
                raise ValueError("Output profile message_source_keys must be a list.")
            if not isinstance(error_source_keys, list):
                raise ValueError("Output profile error_source_keys must be a list.")
            if not isinstance(data_fields, dict):
                raise ValueError("Output profile data_fields must be a mapping.")
            if custom_validation and not isinstance(custom_validation, dict):
                raise ValueError("Output profile custom_validation must be a mapping.")
            if profile_type not in {"passthrough", "json_envelope", "jsonp", "custom"}:
                raise ValueError("Output profile type must be passthrough, json_envelope, jsonp, or custom.")
            custom_validation_mode = (
                str(custom_validation.get("mode", "status_code")).strip().lower()
                or "status_code"
            )
            custom_validation_source_key = str(custom_validation.get("source_key", "")).strip()
            custom_validation_error_source_keys = custom_validation.get("error_source_keys") or []
            if not isinstance(custom_validation_error_source_keys, list):
                raise ValueError("Output profile custom_validation.error_source_keys must be a list.")
            if profile_type == "custom":
                if custom_validation_mode not in {"status_code", "payload_key"}:
                    raise ValueError("Output profile custom_validation.mode must be status_code or payload_key.")
                if custom_validation_mode == "payload_key" and not custom_validation_source_key:
                    raise ValueError("Output profile custom_validation.source_key is required when mode is payload_key.")
                validate_custom_output_code(transform_code)

            message = save_output_profile(
                runtime.config_path,
                original_slug=original_slug,
                profile_slug=profile_slug,
                profile_title=profile_title,
                enabled=bool(payload.get("enabled", True)),
                profile_type=profile_type,
                success_key=self._validate_output_key(str(payload.get("success_key", "success")), "Success key"),
                data_key=self._validate_output_key(str(payload.get("data_key", "data")), "Data key"),
                message_key=self._validate_output_key(str(payload.get("message_key", "message")), "Message key"),
                error_key=self._validate_output_key(str(payload.get("error_key", "error")), "Error key"),
                passthrough_keys=[
                    self._validate_output_key(str(item), "Existing envelope key")
                    for item in passthrough_keys
                    if str(item).strip()
                ],
                source_success_key=source_success_key,
                message_source_keys=[str(item).strip() for item in message_source_keys if str(item).strip()],
                error_source_keys=[str(item).strip() for item in error_source_keys if str(item).strip()],
                data_fields={
                    self._validate_output_key(str(field_name), "Data field key"): str(source_path).strip()
                    for field_name, source_path in data_fields.items()
                    if str(field_name).strip() and str(source_path).strip()
                },
                empty_value=empty_value,
                jsonp_callback_param=self._validate_jsonp_callback_param(
                    str(payload.get("jsonp_callback_param", "callback"))
                ),
                jsonp_default_callback=self._validate_jsonp_default_callback(
                    str(payload.get("jsonp_default_callback", "callback"))
                ),
                transform_code=transform_code,
                custom_validation_mode=custom_validation_mode,
                custom_validation_source_key=custom_validation_source_key,
                custom_validation_expected_value=custom_validation.get("expected_value", True),
                custom_validation_error_source_keys=[
                    str(item).strip()
                    for item in custom_validation_error_source_keys
                    if str(item).strip()
                ],
                headers=headers,
            )
            runtime.load()
            self._audit_admin_change(
                action="save",
                target_kind="output_profile",
                target_ref=profile_slug,
                message=message,
            )
            profile = self._output_profile_document_by_slug(profile_slug)
            self._send_json(
                {
                    "message": message,
                    "output_profile": profile,
                },
                status_code=201 if parsed is None else 200,
            )
        except Exception as exc:  # noqa: BLE001
            self._send_json({"detail": str(exc)}, status_code=400)

    def _handle_admin_output_profile_delete(self, parsed) -> None:
        slug = parsed.path.rsplit("/", 1)[-1].strip().lower()
        try:
            message = delete_output_profile(runtime.config_path, profile_slug=slug)
            runtime.load()
            self._audit_admin_change(
                action="delete",
                target_kind="output_profile",
                target_ref=slug,
                message=message,
            )
            self._send_json({"message": message})
        except Exception as exc:  # noqa: BLE001
            self._send_json({"detail": str(exc)}, status_code=400)

    def _build_request(self, parsed, *, request_target: str) -> IncomingRequest:
        body = self._read_body()
        query = {key: values[-1] for key, values in parse_qs(parsed.query, keep_blank_values=True).items()}
        headers = {key: value for key, value in self.headers.items()}
        host = self.headers.get("Host", "127.0.0.1")
        scheme = self._request_scheme()
        authority = self._request_authority() or host
        url = f"{scheme}://{authority}{request_target}"
        client_ip = self._client_ip()
        json_body = None
        if body:
            try:
                json_body = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                json_body = None

        return IncomingRequest(
            method=self.command,
            path=parsed.path,
            query=query,
            headers=headers,
            body=body,
            client_ip=client_ip,
            url=url,
            json_body=json_body,
        )

    def _send_json(self, payload: Any, status_code: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self._write_response(
            OutgoingResponse(
                status_code=status_code,
                headers={"Content-Type": "application/json; charset=utf-8"},
                body=body if self.command != "HEAD" else b"",
            )
        )

    def _write_response(self, response: OutgoingResponse) -> None:
        self.send_response(response.status_code, HTTPStatus(response.status_code).phrase)

        if response.body_iter is not None and self.command != "HEAD":
            for key, value in response.headers.items():
                if key.lower() in {"content-length", "transfer-encoding"}:
                    continue
                self.send_header(key, value)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            try:
                for chunk in response.body_iter:
                    if chunk:
                        self.wfile.write(f"{len(chunk):x}\r\n".encode())
                        self.wfile.write(chunk)
                        self.wfile.write(b"\r\n")
            finally:
                self.wfile.write(b"0\r\n\r\n")
            return

        body = response.body or b""
        has_content_length = False
        for key, value in response.headers.items():
            if key.lower() == "content-length":
                has_content_length = True
            self.send_header(key, value)
        if not has_content_length:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the NapiGate server.")
    parser.add_argument("--host", default=get_env("NAPIGATE_PUBLIC_HOST", default="0.0.0.0"))
    parser.add_argument("--port", type=int, default=SETTINGS.public_port)
    parser.add_argument("--admin-host", default=get_env("NAPIGATE_ADMIN_HOST", default="0.0.0.0"))
    parser.add_argument("--admin-port", type=int, default=SETTINGS.admin_port)
    parser.add_argument(
        "--config",
        default=_config_path_arg_default(),
    )
    parser.add_argument(
        "--security-config",
        default=_security_path_default(),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    if args.port == args.admin_port:
        raise ValueError("Public port and admin port must be different.")
    configure_application(config_path=Path(args.config), security_path=Path(args.security_config))
    runtime.load()
    security.load()
    max_workers = int(get_env("NAPIGATE_MAX_WORKERS", default="256"))
    public_server = PooledHTTPServer(
        (args.host, args.port),
        GatewayHandler,
        max_workers=max_workers,
        listener_role="public",
        public_port=args.port,
        admin_port=args.admin_port,
    )
    admin_server = PooledHTTPServer(
        (args.admin_host, args.admin_port),
        GatewayHandler,
        max_workers=max_workers,
        listener_role="admin",
        public_port=args.port,
        admin_port=args.admin_port,
    )
    admin_thread = threading.Thread(
        target=admin_server.serve_forever,
        name="napigate-admin-listener",
        daemon=True,
    )
    admin_thread.start()
    LOGGER.info(
        "NapiGate public listener on %s:%s and admin listener on %s:%s (max_workers=%s, state_store=%s)",
        args.host,
        args.port,
        args.admin_host,
        args.admin_port,
        max_workers,
        getattr(state_store, "mode", "file"),
    )
    try:
        public_server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("Shutting down NapiGate")
    finally:
        public_server.shutdown()
        admin_server.shutdown()
        admin_thread.join(timeout=2)
        public_server.server_close()
        admin_server.server_close()
        runtime.close()
        try:
            state_store.close()
        finally:
            shutdown_logging()


if __name__ == "__main__":
    main()
