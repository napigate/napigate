from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
from pathlib import Path
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import yaml

from gateway.admin_ops import (
    build_status_query,
    delete_client,
    delete_endpoint,
    delete_output_profile,
    delete_role,
    delete_route,
    delete_service,
    delete_user,
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
from gateway.config import load_config_document, save_config_document
from gateway.logging_utils import setup_logging, shutdown_logging
from gateway.runtime import GatewayError, GatewayRuntime, IncomingRequest, OutgoingResponse
from gateway.security import (
    AuthenticatedPrincipal,
    SECURITY_CONFIG_PATH,
    SecurityManager,
)
from gateway.settings import get_env, load_env_file, load_settings


load_env_file()
setup_logging()
LOGGER = logging.getLogger("gateway.main")
SETTINGS = load_settings()
runtime = GatewayRuntime(
    config_path=Path(get_env("NAPIGATE_CONFIG", "APIGATE_CONFIG", default="config/services.yaml")),
    redis_url=SETTINGS.redis_url,
)
security = SecurityManager(
    config_path=Path(
        get_env(
            "NAPIGATE_SECURITY_CONFIG",
            "APIGATE_SECURITY_CONFIG",
            default=str(SECURITY_CONFIG_PATH),
        )
    )
)


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
              <div class="chip">Config: <span class="mono">{escape(str(runtime.config_path))}</span></div>
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
              <div class="stat-value" id="stat-duration">0 ms</div>
            </div>
            <div class="stat">
              <div class="stat-label">Last Updated</div>
              <div class="stat-value" id="stat-updated">-</div>
            </div>
          </div>
          <div style="overflow:auto; max-height:80vh;">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Method</th>
                  <th>Gateway Path</th>
                  <th>Service</th>
                  <th>Endpoint</th>
                  <th>Upstream</th>
                  <th>Status</th>
                  <th>Response</th>
                  <th>Duration (ms)</th>
                  <th>IP</th>
                </tr>
              </thead>
              <tbody id="log-rows"></tbody>
            </table>
          </div>
        </div>
      </div>
      <script>
        const initialRows = {initial_rows};
        const tbody = document.getElementById("log-rows");
        const badge = document.getElementById("connection-badge");

        function esc(value) {{
          return String(value ?? "")
            .replaceAll("&", "&amp;")
            .replaceAll("<", "&lt;")
            .replaceAll(">", "&gt;")
            .replaceAll('"', "&quot;");
        }}

        function statusClass(code) {{
          if (code >= 500) return "status-5xx";
          if (code >= 400) return "status-4xx";
          if (code >= 200) return "status-2xx";
          return "";
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
          const upstreamUrl = String(row.upstream_url || "").trim();
          const upstreamCurl = String(row.upstream_curl || "").trim();
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

        function render(rows) {{
          const totalRows = rows.length;
          const total5xx = rows.filter((row) => row.status_code >= 500).length;
          const avgDuration = totalRows
            ? Math.round(rows.reduce((sum, row) => sum + row.duration_ms, 0) / totalRows)
            : 0;

          document.getElementById("stat-rows").textContent = String(totalRows);
          document.getElementById("stat-errors").textContent = String(total5xx);
          document.getElementById("stat-duration").textContent = `${{avgDuration}} ms`;
          document.getElementById("stat-updated").textContent = new Date().toLocaleTimeString("en-US");

          tbody.innerHTML = rows.length
            ? rows.map((row) => `
                <tr>
                  <td class="mono">${{esc(row.created_at)}}</td>
                  <td>${{esc(row.method)}}</td>
                  <td class="mono">${{esc(row.gateway_path)}}</td>
                  <td>${{esc(row.service_name)}}</td>
                  <td>${{esc(row.endpoint_name)}}</td>
                  <td>${{renderUpstreamCell(row)}}</td>
                  <td><span class="status-badge ${{statusClass(row.status_code)}}">${{row.status_code}}</span></td>
                  <td>${{renderResponseCell(row)}}</td>
                  <td>${{row.duration_ms}}</td>
                  <td class="mono">${{esc(row.client_ip)}}</td>
                </tr>
              `).join("")
            : '<tr><td colspan="10">No logs yet.</td></tr>';
        }}

        function setOnlineState(online) {{
          badge.textContent = online ? "Live connection established" : "Reconnecting...";
          badge.className = online ? "chip ok" : "chip offline";
        }}

        render(initialRows);

        const source = new EventSource("/__monitor/stream");
        source.onopen = () => setOnlineState(true);
        source.onmessage = (event) => {{
          render(JSON.parse(event.data));
          setOnlineState(true);
        }};
        source.onerror = () => setOnlineState(false);
      </script>
    </body>
    </html>
    """


def build_admin_state(
    *,
    principal: AuthenticatedPrincipal,
    document: dict[str, Any],
) -> dict[str, Any]:
    can_view_live = principal.can("monitor_access")
    return build_admin_page_state(
        principal=principal,
        document=document,
        security_state=security.public_state(),
        services_config_path=str(runtime.config_path),
        security_config_path=str(security.config_path),
        live_state={
            "can_view": can_view_live,
            "logs": runtime.list_logs(limit=40) if can_view_live else [],
            "logs_url": "/__monitor/logs",
            "monitor_url": "/__monitor",
        },
    )


def render_admin_page(
    *,
    principal: AuthenticatedPrincipal,
    document: dict[str, Any],
    message: str = "",
    error: str = "",
) -> str:
    state = build_admin_state(principal=principal, document=document)
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
          --tabbg: #eef3fd;
        }}
        * {{ box-sizing: border-box; }}
        body {{
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
        .wrap {{
          max-width: 1500px;
          margin: 18px auto 28px;
          padding: 0 14px;
        }}
        .hero {{
          display: flex;
          justify-content: space-between;
          gap: 12px;
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
        }}
        .meta-box {{
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
          justify-content: flex-start;
        }}
        .chip {{
          padding: 5px 10px;
          border-radius: 999px;
          background: #fff;
          border: 1px solid var(--line);
          font-size: 12px;
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
          background: var(--paper);
          border: 1px solid var(--line);
          border-radius: 18px;
          overflow: hidden;
          box-shadow: 0 14px 34px rgba(60, 64, 67, 0.10);
        }}
        .tabs {{
          display: flex;
          gap: 6px;
          flex-wrap: wrap;
          padding: 10px;
          background: var(--tabbg);
          border-bottom: 1px solid var(--line);
        }}
        .tab {{
          border: 1px solid #202124;
          border-radius: 999px;
          background: #202124;
          color: #fff;
          padding: 7px 11px;
          font: inherit;
          font-weight: 800;
          font-size: 12px;
          cursor: pointer;
          text-decoration: none;
          line-height: 1.2;
        }}
        .tab.active {{
          background: var(--accent);
          color: white;
          border-color: var(--accent);
        }}
        .tab.logout {{
          background: #3c4043;
          color: #fff;
          border-color: #3c4043;
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
        }}
        table {{
          width: 100%;
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
          overflow: auto;
          background: white;
          border-radius: 18px;
          box-shadow: 0 22px 56px rgba(60, 64, 67, 0.18);
          border: 1px solid #d8e0ea;
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
          position: relative;
          display: inline-flex;
          align-items: center;
          justify-content: center;
          width: 16px;
          height: 16px;
          border-radius: 999px;
          border: 1px solid #c9d6eb;
          background: #f8fbff;
          color: #1a73e8;
          font-size: 10px;
          font-weight: 900;
          cursor: help;
          outline: none;
        }}
        .help-tip:hover,
        .help-tip:focus {{
          border-color: #1a73e8;
          background: #edf4ff;
        }}
        .help-popover {{
          position: absolute;
          top: calc(100% + 8px);
          inset-inline-end: 0;
          width: min(300px, calc(100vw - 40px));
          padding: 10px 12px;
          border-radius: 14px;
          border: 1px solid #d9e4f2;
          background: #fff;
          color: var(--ink);
          box-shadow: 0 16px 34px rgba(60, 64, 67, 0.16);
          opacity: 0;
          transform: translateY(6px);
          pointer-events: none;
          transition: opacity 0.18s ease, transform 0.18s ease;
          text-align: left;
          z-index: 20;
        }}
        .help-tip:hover .help-popover,
        .help-tip:focus .help-popover,
        .help-tip:focus-within .help-popover {{
          opacity: 1;
          transform: translateY(0);
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
        @media (max-width: 900px) {{
          .hero, .section-head {{
            flex-direction: column;
            align-items: flex-start;
          }}
          .live-head {{
            flex-direction: column;
            align-items: flex-start;
          }}
          .form-grid, .check-grid, .scope-grid {{
            grid-template-columns: 1fr;
          }}
          .output-mode-note {{
            grid-template-columns: 1fr;
          }}
          .tabs {{
            justify-content: stretch;
          }}
          .tab {{
            flex: 1 1 calc(50% - 8px);
          }}
        }}
      </style>
    </head>
    <body>
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
            <div class="chip">Services Config: <span class="mono">{escape(str(runtime.config_path))}</span></div>
            <div class="chip">Security Config: <span class="mono">{escape(str(security.config_path))}</span></div>
          </div>
        </div>
        {flash}
        <div id="admin-flash"></div>
        <div class="panel">
          <div class="tabs">
            <button class="tab active" data-tab="live">Live</button>
            <button class="tab" data-tab="config">Config</button>
            <button class="tab" data-tab="services">Services</button>
            <button class="tab" data-tab="routes">Routes</button>
            <button class="tab" data-tab="output">Output</button>
            <button class="tab" data-tab="clients">Clients</button>
            <button class="tab" data-tab="users">Users</button>
            <button class="tab" data-tab="roles">Roles</button>
            <a class="tab logout" href="/__logout">Logout</a>
          </div>

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
                <div class="section-note">Users sign in with Basic Auth and receive access through assigned roles.</div>
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
          base_url: {{ title: "Base URL", text: "The upstream base address joined with each endpoint upstream path.", example: "https://api.example.com" }},
          timeout_seconds: {{ title: "Timeout Seconds", text: "Maximum upstream wait time before the gateway aborts the request.", example: "15" }},
          verify_ssl: {{ title: "Verify SSL", text: "Reject upstream TLS certificates that are invalid, expired, or signed by an unknown CA.", example: "On for public HTTPS APIs" }},
          trust_env_proxy: {{ title: "Trust Env Proxy", text: "Allow upstream requests to use HTTP_PROXY or HTTPS_PROXY from the runtime environment.", example: "Enable only when the container must reach APIs through a proxy" }},
          forward_napigate_headers: {{ title: "Forward NapiGate Headers", text: "Send internal X-NapiGate route and client metadata headers to the upstream service when enabled.", example: "Turn off when the upstream should only receive business headers like Token or Cookie" }},
          variables_yaml: {{ title: "Variables", text: "Reusable values injected into templates and pre_call code for this service.", example: '{{ "client_id": "demo-client" }}' }},
          headers_yaml: {{ title: "Headers", text: "Static or templated headers added to every upstream request in this service.", example: '{{ "X-Tenant": "{{ vars.tenant }}" }}' }},
          auth_required: {{ title: "Protect This Service", text: "Require a matching enabled client auth method before this service can be called.", example: "Turn on for partner or internal APIs" }},
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
          upstream_path: {{ title: "Upstream Path", text: "The path or absolute URL sent upstream after template rendering. Leave blank only for local response endpoints.", example: "/users/{{ path.id }}" }},
          endpoint_headers_yaml: {{ title: "Endpoint Headers", text: "Headers added only for this endpoint after template rendering.", example: '{{ "Authorization": "Bearer {{ vars.access_token }}" }}' }},
          query_yaml: {{ title: "Endpoint Query", text: "Query parameters forced or templated by the gateway for this endpoint.", example: '{{ "expand": "profile" }}' }},
          pre_call_cache_ttl_seconds: {{ title: "Pre-call Cache TTL", text: "Cache successful pre_call variable output in memory for this many seconds.", example: "300" }},
          pre_call_cache_key: {{ title: "Pre-call Cache Key", text: "Optional template or literal cache key if the default service:endpoint key is too broad.", example: "{{ path.id }}" }},
          pre_call_code: {{ title: "Pre-call Code", text: "Trusted Python executed before proxying so you can fetch tokens, compute values, or enrich variables.", example: 'set_var("access_token", "demo-token")' }},
          endpoint_slug: {{ title: "Endpoint Slug", text: "Stable machine-friendly identifier for automation, success hooks, downstream mapping, and admin APIs.", example: "user_by_id" }},
          route_name: {{ title: "Route Name", text: "A stable internal name for the public gateway route.", example: "get_user" }},
          route_slug: {{ title: "Route Slug", text: "Machine-friendly route identifier used in logs, headers, and admin state.", example: "get-user" }},
          methods: {{ title: "Methods", text: "Comma-separated HTTP methods accepted by this gateway route.", example: "GET, POST" }},
          gateway_path: {{ title: "Gateway Path", text: "The public path exposed by NapiGate. Use path tokens like {{id}} or {{path:path}}.", example: "/v1/users/{{id}}" }},
          route_strategy: {{ title: "Route Strategy", text: "single calls one target, round_robin rotates targets, failover tries the next target on 5xx or connection failure, parallel_race calls targets concurrently and returns the first healthy response.", example: "failover" }},
          route_targets: {{ title: "Route Targets", text: "Select one or more service endpoints that this public route can call.", example: "protected_httpbin / user_by_id" }},
          output_profile: {{ title: "Output Profile", text: "Choose a reusable response-shaping profile for this route. Leave blank to keep the target response untouched.", example: "standard_json" }},
          endpoint_output_profile: {{ title: "Output Profile", text: "Default response-shaping profile for this endpoint. Routes that do not set their own output profile will use this value.", example: "standard_json" }},
          response_cache_ttl_seconds: {{ title: "Response Cache TTL", text: "Cache successful route responses in memory for this many seconds before calling a target again.", example: "60" }},
          response_cache_vary_headers: {{ title: "Cache Vary Headers", text: "Header names that should produce separate cache entries for the same path and query.", example: "Accept-Language, X-Tenant" }},
          response_cache_methods: {{ title: "Cache Methods", text: "HTTP methods eligible for response caching when the TTL is enabled.", example: "GET, HEAD" }},
          response_cache_vary_by_client: {{ title: "Cache Per Client", text: "Keep a separate cache bucket for each authenticated gateway client so one consumer does not reuse another's response.", example: "Recommended for scoped partner APIs" }},
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
          profile_type: {{ title: "Output Profile Type", text: "Choose passthrough, standard JSON envelope wrapping, or JSONP callback output.", example: "json_envelope" }},
          profile_enabled: {{ title: "Output Profile Enabled", text: "Disabled output profiles stay saved but cannot transform endpoint responses until re-enabled.", example: "Turn off temporarily during a response-contract rollout" }},
          success_key: {{ title: "Success Key", text: "Key name that should contain the boolean success flag in a JSON envelope.", example: "success" }},
          data_key: {{ title: "Data Key", text: "Key name that should contain the upstream payload in a JSON envelope.", example: "data" }},
          message_key: {{ title: "Message Key", text: "Key name used for human-readable response messages.", example: "message" }},
          error_key: {{ title: "Error Key", text: "Key name used for error details when the endpoint fails.", example: "error" }},
          passthrough_keys: {{ title: "Existing Envelope Keys", text: "If the upstream JSON already contains these keys, NapiGate will not wrap it again.", example: "success, data, message" }},
          jsonp_callback_param: {{ title: "JSONP Callback Param", text: "Query-string parameter name that carries the JavaScript callback function.", example: "callback" }},
          jsonp_default_callback: {{ title: "JSONP Default Callback", text: "Fallback callback name used when the request omits the callback parameter.", example: "callback" }},
          output_headers_yaml: {{ title: "Profile Headers", text: "Headers applied after the output profile transforms the response.", example: '{{ "Cache-Control": "no-store" }}' }},
          log_retention_hours: {{ title: "Log Retention Hours", text: "When set, request log rows and rotated file logs older than this many hours are deleted by an hourly cleanup worker. Leave blank for unlimited retention.", example: "168" }},
          gateway_response_enabled: {{ title: "Gateway Response Envelope", text: "When enabled, public runtime errors generated by NapiGate use the configured JSON envelope instead of the default detail-only shape.", example: "Useful when clients expect success, data, message, and error on 401, 404, 429, or 500 responses" }},
          gateway_response_empty_value: {{ title: "Gateway Empty Value", text: "Fallback value written into empty envelope fields for gateway-generated errors. Blank means an empty string.", example: 'null or ""' }},
          gateway_response_headers: {{ title: "Gateway Response Headers", text: "Extra headers merged into gateway-generated public error responses after the JSON body is rendered.", example: '{{ "Cache-Control": "no-store" }}' }},
        }};

        function helpMarkup(key) {{
          const info = FIELD_HELP[key];
          if (!info) return "";
          const example = info.example
            ? `<span class="help-example">Example: <code>${{esc(info.example)}}</code></span>`
            : "";
          return `
            <span class="help-tip" tabindex="0" aria-label="${{esc(info.title)}} help">
              ?
              <span class="help-popover">
                <span class="help-title">${{esc(info.title)}}</span>
                <span class="help-body">${{esc(info.text)}}</span>
                ${{example}}
              </span>
            </span>
          `;
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
        }}

        let liveRows = Array.isArray(STATE.live?.logs) ? STATE.live.logs : [];
        let liveConnectionState = STATE.live?.can_view ? "connecting" : "locked";
        let livePollTimer = null;

        function openModal(title, bodyHtml) {{
          modalTitle.textContent = title;
          modalBody.innerHTML = bodyHtml;
          decorateHelp(modalBody);
          overlay.classList.add("open");
        }}

        function closeModal() {{
          overlay.classList.remove("open");
          modalBody.innerHTML = "";
        }}

        modalClose.addEventListener("click", closeModal);
        overlay.addEventListener("click", (event) => {{
          if (event.target === overlay) closeModal();
        }});

        const VALID_TABS = Array.from(document.querySelectorAll(".tab[data-tab]")).map((tab) => tab.dataset.tab);
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
          renderServices();
          renderRoutes();
          renderOutputProfiles();
          renderClients();
          renderConfig();
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
            if (value && /(^|_)(url|base_url)$/.test(field.name || "") && !/^https?:\\/\\//i.test(value)) {{
              fail(field, "Use an absolute http(s) URL.");
            }}
            if (value && ["service_name", "endpoint_name", "endpoint_slug", "route_name", "route_slug", "client_slug", "client_code", "profile_slug", "role_name", "success_key", "data_key", "message_key", "error_key", "gateway_response_success_key", "gateway_response_data_key", "gateway_response_message_key", "gateway_response_error_key"].includes(field.name)) {{
              if (!isSafeIdentifier(value)) fail(field, "Use letters, numbers, underscore, or dash. Start with a letter or underscore.");
            }}
            if (value && field.name === "username" && !/^[a-zA-Z0-9_.@-]{{1,64}}$/.test(value)) {{
              fail(field, "Use letters, numbers, dot, underscore, dash, or @.");
            }}
          }});

          const profileType = form.querySelector('[name="profile_type"]')?.value;
          if (profileType && !["passthrough", "json_envelope", "jsonp"].includes(profileType)) {{
            fail(form.querySelector('[name="profile_type"]'), "Invalid output profile mode.");
          }}
          const jsonpCallback = form.querySelector('[name="jsonp_default_callback"]');
          if (profileType === "jsonp" && jsonpCallback?.value && !isSafeJsonpCallback(jsonpCallback.value.trim())) {{
            fail(jsonpCallback, "Use a JavaScript identifier path, for example callback or window.handleResponse.");
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
          const successKey = profile.success_key || "success";
          const dataKey = profile.data_key || "data";
          return `${{successKey}} = response.${{successKey}} ?? status<400; ${{dataKey}} = response.${{dataKey}} ?? body`;
        }}

        function syncOutputProfileRules(form) {{
          const select = form?.querySelector('[name="profile_type"]');
          if (!select) return;
          const sync = () => {{
            form.querySelectorAll("[data-output-rule]").forEach((panel) => {{
              panel.classList.toggle("is-active", panel.dataset.outputRule === select.value);
            }});
            form.querySelectorAll("[data-output-jsonp-field]").forEach((field) => {{
              field.hidden = select.value !== "jsonp";
            }});
          }};
          select.addEventListener("change", sync);
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

        function summarizeLiveRows(rows) {{
          const total = rows.length;
          const failures = rows.filter((row) => Number(row.status_code || 0) >= 400).length;
          const averageDuration = total
            ? Math.round(rows.reduce((sum, row) => sum + Number(row.duration_ms || 0), 0) / total)
            : 0;
          return {{
            total,
            failures,
            averageDuration,
            lastSeen: rows[0]?.created_at || "",
          }};
        }}

        function liveBadgeState() {{
          if (!STATE.live?.can_view) {{
            return {{ label: "Monitor access required", className: "warn" }};
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

        function renderLiveUpstreamCell(row) {{
          const upstreamUrl = String(row.upstream_url || "").trim();
          const upstreamCurl = String(row.upstream_curl || "").trim();
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

        function renderConfig() {{
          const wrap = document.getElementById("config-wrap");
          if (!wrap) return;

          const retentionValue = String(STATE.settings?.log_retention_hours || "");
          const gatewayResponses = STATE.settings?.gateway_responses || {{}};
          const gatewayResponseEnabled = Boolean(gatewayResponses.enabled);
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
          const gatewayResponseLabel = gatewayResponseEnabled ? "Envelope enabled" : "Default detail shape";

          wrap.innerHTML = `
            <form method="post" action="/__admin/settings/save" onsubmit="return submitGatewaySettings(event, this)">
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
                  <label class="check-item full" data-help="gateway_response_enabled">
                    <input type="checkbox" name="gateway_response_enabled" ${{gatewayResponseEnabled ? "checked" : ""}} ${{canEdit ? "" : "disabled"}}>
                    <div>
                      <strong>Use JSON envelope for gateway-generated errors</strong>
                      <div class="muted">When off, runtime errors stay on the default <span class="mono">{{"detail": "..."}}</span> body.</div>
                    </div>
                  </label>
                  <label data-help="success_key">
                    <span>Success Key</span>
                    <input name="gateway_response_success_key" value="${{esc(gatewaySuccessKey)}}" ${{canEdit ? "" : "disabled"}}>
                  </label>
                  <label data-help="data_key">
                    <span>Data Key</span>
                    <input name="gateway_response_data_key" value="${{esc(gatewayDataKey)}}" ${{canEdit ? "" : "disabled"}}>
                  </label>
                  <label data-help="message_key">
                    <span>Message Key</span>
                    <input name="gateway_response_message_key" value="${{esc(gatewayMessageKey)}}" ${{canEdit ? "" : "disabled"}}>
                  </label>
                  <label data-help="error_key">
                    <span>Error Key</span>
                    <input name="gateway_response_error_key" value="${{esc(gatewayErrorKey)}}" ${{canEdit ? "" : "disabled"}}>
                  </label>
                  <div class="output-flow full">
                    <div class="output-flow-head">
                      <div>
                        <div class="output-flow-title">Gateway error rule</div>
                        <div class="output-flow-subtitle">This shape is used only when NapiGate itself is generating the response body.</div>
                      </div>
                      <span class="tag">pseudo-code</span>
                    </div>
                    <pre class="pseudo-code"><code><span class="keyword">if not</span> gateway_responses.enabled:
  <span class="keyword">return</span> {{ "detail": error.detail }}

<span class="keyword">return</span> {{
  "${{esc(gatewaySuccessKey)}}": <span class="value">false</span>,
  "${{esc(gatewayDataKey)}}": <span class="fallback">empty_value</span>,
  "${{esc(gatewayMessageKey)}}": error.detail ?? <span class="fallback">empty_value</span>,
  "${{esc(gatewayErrorKey)}}": error.detail ?? <span class="fallback">empty_value</span>
}}</code></pre>
                  </div>
                  <label class="full" data-help="gateway_response_empty_value">
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
            ? `<a class="btn light" href="${{esc(STATE.live.monitor_url || "/__monitor")}}">Show Log Table</a>`
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

          const summary = summarizeLiveRows(liveRows);
          const badge = liveBadgeState();
          const recentRows = liveRows.slice(0, 12);

          wrap.innerHTML = `
            <div class="live-grid">
              <div class="live-stat">
                <div class="live-label">Services</div>
                <div class="live-value">${{STATE.services.length}}</div>
                <div class="live-subvalue">${{(STATE.routes || []).length}} route(s), ${{STATE.clients.length}} client(s)</div>
              </div>
              <div class="live-stat">
                <div class="live-label">Recent Requests</div>
                <div class="live-value">${{summary.total}}</div>
                <div class="live-subvalue">Loaded from monitor storage</div>
              </div>
              <div class="live-stat">
                <div class="live-label">Recent Failures</div>
                <div class="live-value">${{summary.failures}}</div>
                <div class="live-subvalue">HTTP 4xx and 5xx in the visible sample</div>
              </div>
              <div class="live-stat">
                <div class="live-label">Average Duration</div>
                <div class="live-value">${{summary.averageDuration}} ms</div>
                <div class="live-subvalue">Last event: ${{esc(formatDateTime(summary.lastSeen))}}</div>
              </div>
            </div>

            <div class="live-table-card">
              <div class="live-head">
                <div>
                  <h3 class="section-title" style="font-size:16px; margin-bottom:4px;">Live Request Feed</h3>
                  <div class="section-note">This tab refreshes automatically from <span class="mono">/__monitor/logs</span>.</div>
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
	                          <th>Upstream</th>
	                          <th>Status</th>
	                          <th>Response</th>
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
	                              <td>${{renderLiveUpstreamCell(row)}}</td>
	                              <td><span class="tag ${{statusClass(row.status_code)}}">${{esc(row.status_code)}}</span></td>
	                              <td>${{renderLiveResponseCell(row)}}</td>
	                              <td>${{esc(row.duration_ms)}} ms</td>
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
          if (!STATE.live?.can_view) return;
          try {{
            const response = await fetch(STATE.live.logs_url || "/__monitor/logs", {{
              headers: {{
                "Accept": "application/json",
              }},
              cache: "no-store",
            }});
            if (!response.ok) {{
              throw new Error(`HTTP ${{response.status}}`);
            }}
            const payload = await response.json();
            liveRows = Array.isArray(payload) ? payload : [];
            liveConnectionState = "online";
          }} catch (_error) {{
            liveConnectionState = "error";
          }}
          renderLive();
        }}

        function startLivePolling() {{
          renderLive();
          if (!STATE.live?.can_view || livePollTimer !== null) return;
          refreshLiveLogs();
          livePollTimer = window.setInterval(refreshLiveLogs, 3000);
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
                  <th>Base URL</th>
                  <th>Timeout</th>
                  <th>Endpoints</th>
                  <th>Access</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                ${{
                  STATE.services.map((service) => `
                    <tr>
                      <td><strong>${{esc(service.name)}}</strong></td>
                      <td class="mono">${{esc(service.base_url)}}</td>
                      <td>${{service.timeout_seconds}}</td>
                      <td>${{service.endpoints.length}}</td>
                      <td>
                        <span class="tag ${{service.auth?.required ? 'warn' : 'ok'}}">${{service.auth?.required ? 'Protected' : 'Public'}}</span>
                        <span class="tag">${{scopedClientsCount(service.name)}} scoped client(s)</span>
                        <span class="tag ${{service.verify_ssl ? 'ok' : 'warn'}}">SSL ${{service.verify_ssl ? 'On' : 'Off'}}</span>
                        <span class="tag ${{service.trust_env_proxy ? 'warn' : 'ok'}}">Proxy ${{service.trust_env_proxy ? 'Env' : 'Direct'}}</span>
                        <span class="tag ${{service.forward_napigate_headers ? 'ok' : 'warn'}}">NapiGate Headers ${{service.forward_napigate_headers ? 'On' : 'Off'}}</span>
                        ${{service.pre_call?.code ? '<span class="tag warn">pre_call</span>' : ''}}
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
          return routeTargetsForCurl(route).filter((target) => target.service.auth?.required);
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
          const requestMethod = String(methodName || route.methods?.[0] || "GET").toUpperCase();
          let url = `${{window.location.origin}}${{sampleGatewayPath(route.gateway_path)}}`;
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
              : "Current route targets do not require incoming client authentication.";
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
              ? "No enabled client matches the protected targets on this route."
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
            : `Using ${{selectedClient?.title || selectedClient?.code || "client"}} via ${{selectedMethod.title || selectedMethod.code}} (${{selectedMethod.type}}), even though current route targets do not require incoming client authentication.`;
          output.textContent = buildRouteCurl(route.slug, methodName, authSampleForMethod(selectedMethod));
        }}

        function showRouteCurlModal(routeSlug, methodName = "") {{
          const route = routeBySlug(routeSlug);
          if (!route) return;

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
                      <td class="mono">${{esc(route.gateway_path)}}</td>
                      <td>${{(route.methods || []).map((method) => `<span class="tag">${{esc(method)}}</span>`).join('')}}</td>
                      <td><span class="tag ${{route.strategy === 'failover' ? 'warn' : route.strategy === 'parallel_race' ? 'ok' : ''}}">${{esc(route.strategy)}}</span></td>
                      <td class="mono">${{esc(routeTargetsText(route))}}</td>
                      <td>
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
                          <button class="btn light" type="button" onclick="showRouteCurlModal(decodeURIComponent('${{arg(route.slug)}}'), decodeURIComponent('${{arg(route.methods?.[0] || 'GET')}}'))">Copy cURL</button>
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
              <label data-help="base_url">
                <span>Base URL</span>
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
              <label class="check-item" data-help="auth_required">
                <input type="checkbox" name="auth_required" ${{service?.auth?.required ? "checked" : ""}}>
                <div>
                  <strong>Protect This Service</strong>
                  <div class="muted">When enabled, only clients whose access scope matches this service or one of its endpoints can call it.</div>
                </div>
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
                          <td>${{endpoint.pre_call?.code ? '<span class="tag warn">pre_call</span>' : '<span class="muted">None</span>'}}</td>
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
              <label class="mini-check">
                <input type="checkbox" name="targets" data-route-target value="${{esc(item.ref)}}" ${{selectedTargets.has(item.ref) || selectedTargets.has(`${{item.service}}::${{item.slug}}`) ? "checked" : ""}}>
                <div>
                  <strong>${{esc(item.endpoint)}}</strong>
                  <div class="muted mono">${{esc(item.service)}}</div>
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
                ${{targetOptions ? `<div class="scope-grid">${{targetOptions}}</div>` : '<div class="empty">Create a service endpoint first.</div>'}}
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
          const jsonpParam = profile?.jsonp_callback_param || "callback";
          const jsonpDefault = profile?.jsonp_default_callback || "callback";
          const passthroughKeys = (profile?.passthrough_keys || []).join(",");
          openModal(profile ? "Edit Output Profile" : "Add Output Profile", `
            <form method="post" action="/__admin/output-profile/save" class="form-grid" data-output-profile-form>
              <input type="hidden" name="original_slug" value="${{esc(profile?.slug || "")}}">
              <input type="hidden" name="success_key" value="${{esc(successKey)}}">
              <input type="hidden" name="data_key" value="${{esc(dataKey)}}">
              <input type="hidden" name="message_key" value="${{esc(messageKey)}}">
              <input type="hidden" name="error_key" value="${{esc(errorKey)}}">
              <input type="hidden" name="passthrough_keys" value="${{esc(passthroughKeys)}}">
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
                    <div class="output-flow-subtitle">The selected mode is stored as config, but the envelope contract reads like code.</div>
                  </div>
                  <span class="tag">pseudo-code</span>
                </div>
                <div class="output-rule" data-output-rule="passthrough">
                  <pre class="pseudo-code"><code><span class="keyword">return</span> upstream.response

# No wrapping, no JSON editing, no key rewriting.</code></pre>
                  <div class="output-mode-note">
                    <div><strong>Best for</strong> Images, files, raw APIs, existing contracts.</div>
                    <div><strong>Headers</strong> Profile headers can still be merged.</div>
                    <div><strong>Body</strong> The response body is untouched.</div>
                  </div>
                </div>
                <div class="output-rule" data-output-rule="json_envelope">
                  <pre class="pseudo-code"><code><span class="keyword">if</span> response has "${{esc(successKey)}}" and "${{esc(dataKey)}}":
  <span class="keyword">return</span> response

<span class="keyword">return</span> {{
  "${{esc(successKey)}}": response["${{esc(successKey)}}"] ?? <span class="fallback">(status &lt; 400)</span>,
  "${{esc(dataKey)}}": response["${{esc(dataKey)}}"] ?? <span class="fallback">response.body</span>,
  "${{esc(messageKey)}}": response["${{esc(messageKey)}}"] ?? <span class="fallback">auto_message(response)</span>,
  "${{esc(errorKey)}}": response["${{esc(errorKey)}}"] ?? <span class="fallback">auto_error(response)</span>
}}</code></pre>
                  <div class="output-mode-note">
                    <div><strong>Success</strong> Uses response.${{esc(successKey)}} when present, otherwise HTTP status.</div>
                    <div><strong>Data</strong> Uses response.${{esc(dataKey)}} when present, otherwise the body.</div>
                    <div><strong>Existing envelope</strong> Existing ${{esc(successKey)}} + ${{esc(dataKey)}} responses are not double-wrapped.</div>
                  </div>
                </div>
                <div class="output-rule" data-output-rule="jsonp">
                  <pre class="pseudo-code"><code>callback = query["${{esc(jsonpParam)}}"] ?? <span class="value">"${{esc(jsonpDefault)}}"</span>

<span class="keyword">return</span> callback + "(" + json(response.body) + ");"</code></pre>
                  <div class="output-mode-note">
                    <div><strong>Best for</strong> Browser clients that still need JSONP.</div>
                    <div><strong>Callback param</strong> Configure the query key below.</div>
                    <div><strong>Body</strong> The parsed response body is wrapped in JavaScript.</div>
                  </div>
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
        renderUsers();
        renderRoles();
      </script>
    </body>
    </html>
    """


class PooledHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a bounded thread pool instead of unbounded thread spawning."""

    def __init__(self, server_address, RequestHandlerClass, max_workers: int = 256) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self._pool = ThreadPoolExecutor(max_workers=max_workers)

    def process_request(self, request, client_address) -> None:  # type: ignore[override]
        self._pool.submit(self.process_request_thread, request, client_address)

    def server_close(self) -> None:
        self._pool.shutdown(wait=False)
        super().server_close()


class GatewayHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "NapiGate/0.1"

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

    def _dispatch(self) -> None:
        runtime.maybe_reload()
        security.maybe_reload()
        parsed = urlsplit(self.path)
        query = {key: values[-1] for key, values in parse_qs(parsed.query, keep_blank_values=True).items()}

        if parsed.path == "/__health":
            self._send_json(
                {
                    "status": "ok",
                    "service_count": runtime.service_count(),
                    "route_count": runtime.route_count(),
                    "output_profile_count": runtime.output_profile_count(),
                    "config_path": str(runtime.config_path),
                }
            )
            return

        if parsed.path == "/__logout":
            self._force_logout()
            return

        if parsed.path == "/__oauth/token" and self.command == "POST":
            self._handle_oauth_token()
            return

        if parsed.path.startswith("/__monitor"):
            principal = self._require_permission("monitor_access")
            if principal is None:
                return

            if parsed.path == "/__monitor":
                body = render_monitor_page(principal).encode("utf-8")
                self._write_response(
                    OutgoingResponse(
                        status_code=200,
                        headers={"Content-Type": "text/html; charset=utf-8"},
                        body=body if self.command != "HEAD" else b"",
                    )
                )
                return

            if parsed.path == "/__monitor/logs":
                self._send_json(runtime.list_logs(limit=200))
                return

            if parsed.path == "/__monitor/stream":
                self._stream_monitor()
                return

        if parsed.path.startswith("/__admin"):
            if not self._ensure_admin_ip_allowed():
                return
            if parsed.path == "/__admin":
                principal = self._require_permission("admin_access")
                if principal is None:
                    return
                body = render_admin_page(
                    principal=principal,
                    document=load_config_document(runtime.config_path),
                    message=query.get("message", ""),
                    error=query.get("error", ""),
                ).encode("utf-8")
                self._write_response(
                    OutgoingResponse(
                        status_code=200,
                        headers={"Content-Type": "text/html; charset=utf-8"},
                        body=body if self.command != "HEAD" else b"",
                    )
                )
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

        request = None
        try:
            request = self._build_request(parsed)
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

    def _authenticate_principal(self) -> AuthenticatedPrincipal | None:
        cached = getattr(self, "_principal_cache", None)
        if cached is not None:
            return cached

        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return None

        try:
            decoded = base64.b64decode(header[6:].encode("ascii")).decode("utf-8")
            username, password = decoded.split(":", 1)
        except Exception:  # noqa: BLE001
            return None

        principal = security.authenticate(
            username,
            password,
            bootstrap_username=SETTINGS.admin_auth.username,
            bootstrap_password=SETTINGS.admin_auth.password,
        )
        self._principal_cache = principal
        return principal

    def _require_permission(self, permission: str) -> AuthenticatedPrincipal | None:
        principal = self._authenticate_principal()
        if principal is None:
            self._discard_request_body()
            self._auth_challenge()
            return None
        if permission and not principal.can(permission):
            self._discard_request_body()
            self._forbidden(permission)
            return None
        return principal

    def _discard_request_body(self) -> None:
        content_length = int(self.headers.get("Content-Length", "0") or "0")
        if content_length > 0:
            self.rfile.read(content_length)

    def _auth_challenge(self) -> None:
        body = b'{"detail":"Authentication required."}'
        self.send_response(401, HTTPStatus.UNAUTHORIZED.phrase)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("WWW-Authenticate", f'Basic realm="{SETTINGS.admin_auth.realm}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _force_logout(self) -> None:
        body = b'{"detail":"Logged out."}'
        self.send_response(401, HTTPStatus.UNAUTHORIZED.phrase)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("WWW-Authenticate", 'Basic realm="Logged Out"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

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
        return self.client_address[0] if self.client_address else "-"

    def _admin_ip_allowed(self) -> bool:
        allowlist = SETTINGS.admin_access_allowlist
        if not allowlist:
            return True
        try:
            address = ipaddress.ip_address(self._client_ip())
        except ValueError:
            return False
        return any(address in ipaddress.ip_network(entry, strict=False) for entry in allowlist)

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

    def _send_config_document(self, document: dict[str, Any], *, parsed) -> None:
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
                "state": build_admin_state(principal=principal, document=document) if principal else None,
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
            message = save_gateway_settings(
                runtime.config_path,
                log_retention_hours=log_retention_hours,
                gateway_response_enabled="gateway_response_enabled" in form,
                gateway_response_success_key=gateway_response_success_key,
                gateway_response_data_key=gateway_response_data_key,
                gateway_response_message_key=gateway_response_message_key,
                gateway_response_error_key=gateway_response_error_key,
                gateway_response_empty_value=gateway_response_empty_value,
                gateway_response_headers=gateway_response_headers,
            )
            runtime.load()
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_service_save(self) -> None:
        try:
            form = self._parse_form()
            original_name = str(form.get("original_name", "")).strip()
            service_name = str(form.get("service_name", "")).strip()
            base_url = str(form.get("base_url", "")).strip()
            timeout_seconds = float(str(form.get("timeout_seconds", "30")).strip() or "30")
            variables = self._parse_yaml_mapping(str(form.get("variables_yaml", "")), "Variables")
            headers = self._parse_yaml_mapping(str(form.get("headers_yaml", "")), "Headers")
            pre_call_code = str(form.get("pre_call_code", "")).rstrip()
            pre_call_cache_ttl = int(str(form.get("pre_call_cache_ttl_seconds", "0")).strip() or "0")
            pre_call_cache_key = str(form.get("pre_call_cache_key", "")).strip()
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
                raise ValueError("Base URL is required.")
            if timeout_seconds < 0:
                raise ValueError("Timeout seconds must be zero or positive.")
            if pre_call_cache_ttl < 0:
                raise ValueError("Pre-call cache TTL must be zero or positive.")
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
                auth_required="auth_required" in form,
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
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_service_delete(self) -> None:
        try:
            form = self._parse_form()
            service_name = str(form.get("service_name", "")).strip()
            message = delete_service(runtime.config_path, service_name=service_name)
            runtime.load()
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
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_client_delete(self) -> None:
        try:
            form = self._parse_form()
            client_slug = str(form.get("client_slug", "")).strip().lower()
            message = delete_client(runtime.config_path, client_slug=client_slug)
            runtime.load()
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

            if not service_name:
                raise ValueError("Service name is required.")
            if not endpoint_name:
                raise ValueError("Endpoint name is required.")
            if not endpoint_slug:
                raise ValueError("Endpoint slug is required.")
            if pre_call_cache_ttl < 0:
                raise ValueError("Pre-call cache TTL must be zero or positive.")

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
            )
            runtime.load()
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
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_route_save(self) -> None:
        try:
            form = self._parse_form()
            original_slug = str(form.get("original_slug", "")).strip().lower()
            route_name = str(form.get("route_name", "")).strip()
            route_slug = str(form.get("route_slug", "")).strip().lower()
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
                methods=methods,
                gateway_path=gateway_path,
                strategy=strategy,
                targets=targets,
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
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_route_delete(self) -> None:
        try:
            form = self._parse_form()
            route_slug = str(form.get("route_slug", "")).strip().lower()
            message = delete_route(runtime.config_path, route_slug=route_slug)
            runtime.load()
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
            if profile_type not in {"passthrough", "json_envelope", "jsonp"}:
                raise ValueError("Output profile type must be passthrough, json_envelope, or jsonp.")

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
                jsonp_callback_param=jsonp_callback_param,
                jsonp_default_callback=jsonp_default_callback,
                headers=headers,
            )
            runtime.load()
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_output_profile_delete(self) -> None:
        try:
            form = self._parse_form()
            profile_slug = str(form.get("profile_slug", "")).strip().lower()
            message = delete_output_profile(runtime.config_path, profile_slug=profile_slug)
            runtime.load()
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
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_role_delete(self) -> None:
        try:
            form = self._parse_form()
            role_name = str(form.get("role_name", "")).strip()
            message = delete_role(security.config_path, role_name=role_name)
            security.load()
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
            self._send_admin_mutation_success(message)
        except Exception as exc:  # noqa: BLE001
            self._send_admin_mutation_error(exc)

    def _handle_user_delete(self) -> None:
        try:
            form = self._parse_form()
            username = str(form.get("username", "")).strip()
            message = delete_user(security.config_path, username=username)
            security.load()
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

            if not isinstance(headers, dict):
                raise ValueError("Output profile headers must be a mapping.")
            if not isinstance(passthrough_keys, list):
                raise ValueError("Output profile passthrough_keys must be a list.")

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
                jsonp_callback_param=self._validate_jsonp_callback_param(
                    str(payload.get("jsonp_callback_param", "callback"))
                ),
                jsonp_default_callback=self._validate_jsonp_default_callback(
                    str(payload.get("jsonp_default_callback", "callback"))
                ),
                headers=headers,
            )
            runtime.load()
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
            self._send_json({"message": message})
        except Exception as exc:  # noqa: BLE001
            self._send_json({"detail": str(exc)}, status_code=400)

    def _build_request(self, parsed) -> IncomingRequest:
        body = self._read_body()
        query = {key: values[-1] for key, values in parse_qs(parsed.query, keep_blank_values=True).items()}
        headers = {key: value for key, value in self.headers.items()}
        host = self.headers.get("Host", "127.0.0.1")
        scheme = "http"
        url = f"{scheme}://{host}{self.path}"
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
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--config",
        default=get_env("NAPIGATE_CONFIG", "APIGATE_CONFIG", default="config/services.yaml"),
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    runtime.config_path = Path(args.config)
    runtime.load()
    security.load()
    max_workers = int(get_env("NAPIGATE_MAX_WORKERS", default="256"))
    server = PooledHTTPServer((args.host, args.port), GatewayHandler, max_workers=max_workers)
    LOGGER.info("NapiGate listening on %s:%s (max_workers=%s)", args.host, args.port, max_workers)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOGGER.info("Shutting down NapiGate")
    finally:
        server.server_close()
        runtime.close()
        shutdown_logging()


if __name__ == "__main__":
    main()
