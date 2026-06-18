#!/usr/bin/env python3
"""Health, BrowserServer, and connect canaries for the browser trust domain."""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import importlib.metadata
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


DEFAULT_PUBLIC_PORT = 3006
DEFAULT_INTERNAL_PORT = 3106
DEFAULT_WS_PATH = "/playwright"
DEFAULT_CONNECT_TIMEOUT_MS = 15_000


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if 0 < value < 65536 else default


def normalize_ws_path(path: str) -> str:
    trimmed = path.strip()
    if not trimmed:
        return DEFAULT_WS_PATH
    return trimmed if trimmed.startswith("/") else f"/{trimmed}"


def ws_path_for_camoufox(path: str) -> str:
    return normalize_ws_path(path).lstrip("/")


def browser_ws_endpoint(host: str, port: int, ws_path: str) -> str:
    return f"ws://{host}:{port}{normalize_ws_path(ws_path)}"


def socket_open(host: str, port: int, timeout_seconds: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_seconds):
            return True
    except OSError:
        return False


def package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def no_secret_checks() -> dict[str, bool]:
    return {
        "vaultSocket": not bool(os.environ.get("TELCLAUDE_VAULT_SOCKET")),
        "providerCredentials": not bool(os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")),
        "modelKeys": not any(
            os.environ.get(name)
            for name in [
                "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY",
                "CLAUDE_CODE_OAUTH_TOKEN",
                "TELCLAUDE_OPENAI_CODEX_PROXY_TOKEN",
            ]
        ),
    }


def canary_payload(*, check_server: bool) -> dict[str, Any]:
    camoufox_import_error = None
    try:
        import camoufox  # noqa: PLC0415,F401
    except Exception as exc:  # pragma: no cover - only happens outside the image.
        camoufox_import_error = f"{type(exc).__name__}: {exc}"

    public_port = env_int("TELCLAUDE_BROWSER_PORT", DEFAULT_PUBLIC_PORT)
    internal_port = env_int("TELCLAUDE_BROWSER_INTERNAL_PORT", DEFAULT_INTERNAL_PORT)
    ws_path = normalize_ws_path(os.environ.get("TELCLAUDE_BROWSER_WS_PATH", DEFAULT_WS_PATH))
    endpoint = os.environ.get("TELCLAUDE_BROWSER_WS_ENDPOINT") or browser_ws_endpoint(
        os.environ.get("TELCLAUDE_BROWSER_HOST", "tc-browser"),
        public_port,
        ws_path,
    )
    no_secrets = no_secret_checks()
    browser_server = {
        "endpoint": endpoint,
        "publicPort": public_port,
        "internalPort": internal_port,
        "wsPath": ws_path,
        "publicListening": socket_open("127.0.0.1", public_port) if check_server else None,
        "internalListening": socket_open("127.0.0.1", internal_port) if check_server else None,
    }
    server_ok = (
        bool(browser_server["publicListening"] and browser_server["internalListening"])
        if check_server
        else True
    )
    package_ok = camoufox_import_error is None and package_version("camoufox") is not None
    return {
        "ok": all(no_secrets.values()) and server_ok and package_ok,
        "service": "telclaude-browser",
        "camoufox": package_version("camoufox"),
        "camoufoxImportError": camoufox_import_error,
        "playwright": package_version("playwright"),
        "browserServer": browser_server,
        "proxy": {
            "http": bool(os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")),
            "https": bool(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")),
        },
        "noSecrets": no_secrets,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--health-once", action="store_true")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--connect-canary", action="store_true")
    parser.add_argument("--endpoint", default=os.environ.get("TELCLAUDE_BROWSER_WS_ENDPOINT"))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=env_int("TELCLAUDE_BROWSER_PORT", DEFAULT_PUBLIC_PORT))
    parser.add_argument(
        "--internal-port",
        type=int,
        default=env_int("TELCLAUDE_BROWSER_INTERNAL_PORT", DEFAULT_INTERNAL_PORT),
    )
    parser.add_argument(
        "--ws-path",
        default=os.environ.get("TELCLAUDE_BROWSER_WS_PATH", DEFAULT_WS_PATH),
    )
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_CONNECT_TIMEOUT_MS)
    args = parser.parse_args()

    if args.health_once:
        payload = canary_payload(check_server=True)
        print(json.dumps(payload, sort_keys=True))
        raise SystemExit(0 if payload["ok"] else 1)

    if args.connect_canary:
        endpoint = args.endpoint or browser_ws_endpoint("127.0.0.1", args.port, args.ws_path)
        run_connect_canary(endpoint, args.timeout_ms)
        return

    if args.serve:
        run_browser_front_server(args.host, args.port, args.internal_port, args.ws_path)
        return

    parser.error("choose --health-once, --serve, or --connect-canary")


def run_connect_canary(endpoint: str, timeout_ms: int) -> None:
    from playwright.sync_api import sync_playwright  # noqa: PLC0415

    with sync_playwright() as playwright:
        browser = playwright.firefox.connect(endpoint, timeout=timeout_ms)
        try:
            page = browser.new_page()
            page.goto(
                "data:text/html,<title>telclaude-browser-canary</title><main>ok</main>",
                wait_until="domcontentloaded",
            )
            title = page.title()
        finally:
            browser.close()
    ok = title == "telclaude-browser-canary"
    print(
        json.dumps(
            {
                "ok": ok,
                "endpoint": endpoint,
                "title": title,
                "playwright": package_version("playwright"),
                "camoufox": package_version("camoufox"),
            },
            sort_keys=True,
        )
    )
    raise SystemExit(0 if ok else 1)


def run_browser_front_server(host: str, public_port: int, internal_port: int, ws_path: str) -> None:
    process = start_camoufox_server(internal_port, ws_path)
    try:
        wait_for_port("127.0.0.1", internal_port, timeout_seconds=60)
        asyncio.run(front_proxy(host, public_port, internal_port, process))
    finally:
        terminate_process(process)


def start_camoufox_server(internal_port: int, ws_path: str) -> subprocess.Popen[str]:
    from camoufox.pkgman import LOCAL_DATA  # noqa: PLC0415
    from camoufox.server import get_nodejs, to_camel_case_dict  # noqa: PLC0415
    from camoufox.utils import launch_options  # noqa: PLC0415

    config = launch_options(
        headless=True,
        port=internal_port,
        ws_path=ws_path_for_camoufox(ws_path),
    )
    payload = base64.b64encode(
        json.dumps(to_camel_case_dict(strip_none_values(config)), separators=(",", ":")).encode(
            "utf-8"
        )
    ).decode("ascii")
    nodejs = get_nodejs()
    process = subprocess.Popen(  # noqa: S603
        [nodejs, str(LOCAL_DATA / "launchServer.js")],
        cwd=Path(nodejs).parent / "package",
        stdin=subprocess.PIPE,
        text=True,
    )
    if process.stdin:
        process.stdin.write(payload)
        process.stdin.close()
    return process


def strip_none_values(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: strip_none_values(child) for key, child in value.items() if child is not None}
    if isinstance(value, list):
        return [strip_none_values(child) for child in value]
    return value


def wait_for_port(host: str, port: int, *, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if socket_open(host, port):
            return
        time.sleep(0.25)
    raise RuntimeError(f"Camoufox BrowserServer did not listen on {host}:{port}")


def terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=10)
        return
    process.kill()
    process.wait()


async def front_proxy(
    host: str,
    public_port: int,
    internal_port: int,
    process: subprocess.Popen[str],
) -> None:
    server = await asyncio.start_server(
        lambda reader, writer: handle_front_connection(reader, writer, internal_port),
        host,
        public_port,
    )
    async with server:
        serve_task = asyncio.create_task(server.serve_forever())
        process_task = asyncio.create_task(asyncio.to_thread(process.wait))
        done, pending = await asyncio.wait(
            {serve_task, process_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        if process_task in done:
            raise RuntimeError(f"Camoufox BrowserServer exited with code {process.returncode}")
        await serve_task


async def handle_front_connection(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    internal_port: int,
) -> None:
    try:
        initial = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError):
        writer.close()
        await writer.wait_closed()
        return

    if is_health_request(initial):
        payload = canary_payload(check_server=True)
        status = 200 if payload["ok"] else 503
        body = json.dumps(payload).encode("utf-8")
        writer.write(
            (
                f"HTTP/1.1 {status} {'OK' if status == 200 else 'Service Unavailable'}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode("ascii")
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return

    try:
        upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", internal_port)
    except OSError:
        writer.write(
            b"HTTP/1.1 502 Bad Gateway\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b"Camoufox BrowserServer is unavailable"
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return
    upstream_writer.write(initial)
    await upstream_writer.drain()
    await asyncio.gather(pipe(reader, upstream_writer), pipe(upstream_reader, writer))


def is_health_request(initial: bytes) -> bool:
    request_line = initial.split(b"\r\n", 1)[0].decode("latin1", errors="replace")
    parts = request_line.split()
    if len(parts) < 2:
        return False
    return parts[0] == "GET" and parts[1].split("?", 1)[0] == "/health"


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while not reader.at_eof():
            chunk = await reader.read(65536)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


if __name__ == "__main__":
    main()
