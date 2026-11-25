from __future__ import annotations

import argparse
import hmac
import json
import logging
import math
import os
import signal
import threading
from collections import OrderedDict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import __version__
from .config import add_listen_arguments, resolve_listen_address
from .metrics import MetricStore

LOG = logging.getLogger("command-audit.server")
MAX_BODY = 2 * 1024 * 1024


class EventRepository:
    def __init__(self, max_events: int = 10000, dangerous_mode: str = "collect"):
        if dangerous_mode not in {"collect", "no-alert", "drop"}:
            raise ValueError("invalid dangerous command policy")
        self.dangerous_mode = dangerous_mode
        self.events: deque[dict] = deque(maxlen=max_events)
        self.metrics = MetricStore()
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._lock = threading.Lock()

    def ingest(self, payload: dict) -> tuple[int, int]:
        default_host = str(payload.get("hostname", "unknown"))[:128]
        incoming = payload.get("events", [])
        if not isinstance(incoming, list) or len(incoming) > 1000:
            raise ValueError("events must be a list containing at most 1000 items")
        self.metrics.touch(default_host)
        accepted = 0
        duplicates = 0
        for original in incoming:
            if not isinstance(original, dict):
                continue
            event = dict(original)
            event["hostname"] = str(event.get("hostname") or default_host)[:128]
            timestamp = float(event.get("timestamp", 0))
            if not math.isfinite(timestamp) or timestamp <= 0:
                continue
            event["timestamp"] = timestamp
            key = str(event.get("dedupe_key") or f"{event['hostname']}:{event.get('event_id', '')}:{event.get('pid', '')}")
            with self._lock:
                if key in self._seen:
                    duplicates += 1
                    continue
                self._seen[key] = None
                if len(self._seen) > 50000:
                    self._seen.popitem(last=False)
                suppressed = self.dangerous_mode == "drop" and bool(event.get("danger"))
                if not suppressed:
                    if self.dangerous_mode == "no-alert":
                        event["danger"] = []
                    self.events.append(event)
            if suppressed:
                self.metrics.suppress(event["hostname"])
                continue
            self.metrics.observe(event)
            accepted += 1
        return accepted, duplicates

    def query(self, hostname: str = "", dangerous_only: bool = False, limit: int = 100) -> list[dict]:
        with self._lock:
            selected = [
                event for event in reversed(self.events)
                if (not hostname or event.get("hostname") == hostname)
                and (not dangerous_only or event.get("danger"))
            ]
        return selected[:limit]


def authorized(handler: BaseHTTPRequestHandler, token: str) -> bool:
    if not token:
        return True
    supplied = handler.headers.get("Authorization", "")
    return hmac.compare_digest(supplied, f"Bearer {token}")


def send_bytes(handler: BaseHTTPRequestHandler, status: int, body: bytes, content_type: str) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


def send_json(handler: BaseHTTPRequestHandler, status: int, data: object) -> None:
    send_bytes(handler, status, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")


def make_server(listen: str, port: int, repository: EventRepository, token: str) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        server_version = "CommandAudit/0.1"

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/healthz":
                send_json(self, 200, {"status": "ok", "recent_events": len(repository.events)})
                return
            if not authorized(self, token):
                send_json(self, 401, {"error": "unauthorized"})
                return
            if parsed.path == "/metrics":
                body = repository.metrics.render().encode("utf-8")
                send_bytes(self, 200, body, "text/plain; version=0.0.4; charset=utf-8")
                return
            if parsed.path == "/api/v1/events":
                query = parse_qs(parsed.query)
                try:
                    limit = min(1000, max(1, int(query.get("limit", ["100"])[0])))
                except ValueError:
                    send_json(self, 400, {"error": "invalid limit"})
                    return
                events = repository.query(
                    hostname=query.get("hostname", [""])[0],
                    dangerous_only=query.get("dangerous", ["false"])[0].lower() == "true",
                    limit=limit,
                )
                send_json(self, 200, {"events": events})
                return
            send_json(self, 404, {"error": "not found"})

        def do_POST(self) -> None:
            if urlparse(self.path).path != "/api/v1/events":
                send_json(self, 404, {"error": "not found"})
                return
            if not authorized(self, token):
                send_json(self, 401, {"error": "unauthorized"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_BODY:
                    raise ValueError("invalid content length")
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("JSON object required")
                accepted, duplicates = repository.ingest(payload)
                send_json(self, 202, {"accepted": accepted, "duplicates": duplicates})
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                send_json(self, 400, {"error": str(exc)})

        def log_message(self, fmt: str, *args: object) -> None:
            LOG.debug(fmt, *args)

    server = ThreadingHTTPServer((listen, port), Handler)
    server.daemon_threads = True
    return server


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="command-audit server", description="Run the command audit aggregation server")
    add_listen_arguments(parser, 9100)
    parser.add_argument("--server.max-events", "--max-events", dest="max_events", type=int, default=10000, help="recent event cache size; 0 disables event retention")
    parser.add_argument("--dangerous.commands", "--dangerous-commands", dest="dangerous_mode", choices=("collect", "no-alert", "drop"), default="collect", help="centrally enforce dangerous-command collection policy")
    parser.add_argument("--auth.token", "--token", dest="token", default=os.getenv("COMMAND_AUDIT_TOKEN", ""), help="bearer token; COMMAND_AUDIT_TOKEN is preferred")
    parser.add_argument("--log.level", "--log-level", dest="log_level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"))
    parser.add_argument("--version", action="version", version=f"command-audit {__version__}")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_events < 0:
        parser.error("server.max-events must be >=0")
    try:
        listen, port = resolve_listen_address(args, 9100)
    except (ValueError, argparse.ArgumentTypeError) as exc:
        parser.error(str(exc))
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    repository = EventRepository(args.max_events, dangerous_mode=args.dangerous_mode)
    server = make_server(listen, port, repository, args.token)
    signal.signal(signal.SIGTERM, lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
    LOG.info("server listening on %s:%d; dangerous=%s; authentication=%s", listen, port, args.dangerous_mode, "enabled" if args.token else "disabled")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
