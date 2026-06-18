#!/usr/bin/env python3
"""Tiny health/canary process for the isolated Telclaude browser container."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def canary_payload() -> dict[str, object]:
    import camoufox  # noqa: PLC0415

    return {
        "ok": True,
        "service": "telclaude-browser",
        "camoufox": importlib.metadata.version("camoufox"),
        "proxy": {
            "http": bool(os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")),
            "https": bool(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")),
        },
        "noSecrets": {
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
        },
    }


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self.send_response(404)
            self.end_headers()
            return
        payload = json.dumps(canary_payload()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--health-once", action="store_true")
    parser.add_argument("--serve-health", action="store_true")
    parser.add_argument("--port", type=int, default=int(os.environ.get("TELCLAUDE_BROWSER_PORT", "3006")))
    args = parser.parse_args()

    if args.health_once:
        print(json.dumps(canary_payload(), sort_keys=True))
        return

    if args.serve_health:
        server = ThreadingHTTPServer(("0.0.0.0", args.port), HealthHandler)
        server.serve_forever()
        return

    parser.error("choose --health-once or --serve-health")


if __name__ == "__main__":
    main()
