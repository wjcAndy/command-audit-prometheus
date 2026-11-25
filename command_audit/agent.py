from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import signal
import socket
import sys
import threading
import time
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

from . import __version__
from .audit import AuditAssembler
from .config import add_bool_argument, add_listen_arguments, resolve_listen_address
from .models import AuditEvent
from .server import authorized, send_bytes, send_json

LOG = logging.getLogger("command-audit.agent")


class EventPusher:
    def __init__(self, url: str, hostname: str, token: str, on_drop, batch_size: int = 100, queue_size: int = 10000, timeout: float = 5.0, heartbeat_interval: float = 30.0):
        self.url = url.rstrip("/")
        if not self.url.endswith("/api/v1/events"):
            self.url += "/api/v1/events"
        self.hostname = hostname
        self.token = token
        self.on_drop = on_drop
        self.batch_size = batch_size
        self.timeout = timeout
        self.heartbeat_interval = heartbeat_interval
        self.queue: queue.Queue[dict] = queue.Queue(maxsize=queue_size)
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="event-pusher", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def enqueue(self, event: AuditEvent) -> None:
        try:
            self.queue.put_nowait(event.to_dict())
        except queue.Full:
            self.on_drop()

    def _post(self, batch: list[dict]) -> None:
        body = json.dumps({"hostname": self.hostname, "events": batch}).encode("utf-8")
        headers = {"Content-Type": "application/json", "User-Agent": f"command-audit-agent/{__version__}"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            if response.status != 202:
                raise RuntimeError(f"unexpected server status {response.status}")

    def _run(self) -> None:
        pending: list[dict] = []
        last_heartbeat = 0.0
        while not self.stop_event.is_set() or pending or not self.queue.empty():
            if not pending:
                try:
                    pending = [self.queue.get(timeout=0.5)]
                except queue.Empty:
                    if time.monotonic() - last_heartbeat >= self.heartbeat_interval:
                        try:
                            self._post([])
                            last_heartbeat = time.monotonic()
                        except Exception as exc:
                            LOG.warning("heartbeat failed: %s", exc)
                    continue
                while len(pending) < self.batch_size:
                    try:
                        pending.append(self.queue.get_nowait())
                    except queue.Empty:
                        break
            try:
                self._post(pending)
                pending = []
                last_heartbeat = time.monotonic()
            except Exception as exc:
                LOG.warning("push failed; retaining %d events: %s", len(pending), exc)
                self.stop_event.wait(2)

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=3)


class AgentState:
    def __init__(self, hostname: str, max_recent: int = 200, dangerous_mode: str = "collect", collect_args: bool = True, max_users: int = 200, max_commands: int = 300):
        from .metrics import MetricStore

        if dangerous_mode not in {"collect", "no-alert", "drop"}:
            raise ValueError("invalid dangerous command policy")
        self.hostname = hostname
        self.dangerous_mode = dangerous_mode
        self.collect_args = collect_args
        self.metrics = MetricStore(max_users=max_users, max_commands=max_commands)
        self.recent: deque[dict] = deque(maxlen=max_recent)
        self.lock = threading.Lock()
        self.pusher: EventPusher | None = None

    def observe(self, event: AuditEvent) -> None:
        if event.danger and self.dangerous_mode == "drop":
            self.metrics.suppress(self.hostname)
            return
        if self.dangerous_mode == "no-alert":
            event.danger = []
        if not self.collect_args:
            event.args = []
        self.metrics.observe(event)
        with self.lock:
            self.recent.append(event.to_dict())
        if self.pusher:
            self.pusher.enqueue(event)

    def query(self, dangerous_only: bool, limit: int) -> list[dict]:
        with self.lock:
            values = [event for event in reversed(self.recent) if not dangerous_only or event.get("danger")]
        return values[:limit]


def make_agent_server(listen: str, port: int, state: AgentState, token: str) -> ThreadingHTTPServer:
    # Reuse the threaded server base, but expose only the local agent API.
    from http.server import ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        server_version = "CommandAuditAgent/0.1"

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/healthz":
                send_json(self, 200, {"status": "ok", "hostname": state.hostname, "push_queue": state.pusher.queue.qsize() if state.pusher else 0})
                return
            if not authorized(self, token):
                send_json(self, 401, {"error": "unauthorized"})
                return
            if parsed.path == "/metrics":
                send_bytes(self, 200, state.metrics.render(local_agent=state.hostname).encode("utf-8"), "text/plain; version=0.0.4; charset=utf-8")
                return
            if parsed.path == "/api/v1/events":
                query = parse_qs(parsed.query)
                try:
                    limit = min(1000, max(1, int(query.get("limit", ["100"])[0])))
                except ValueError:
                    send_json(self, 400, {"error": "invalid limit"})
                    return
                events = state.query(query.get("dangerous", ["false"])[0].lower() == "true", limit)
                send_json(self, 200, {"events": events})
                return
            send_json(self, 404, {"error": "not found"})

        def log_message(self, fmt: str, *args: object) -> None:
            LOG.debug(fmt, *args)

    server = ThreadingHTTPServer((listen, port), Handler)
    server.daemon_threads = True
    return server


class AuditReader:
    def __init__(self, state: AgentState, source: str, from_start: bool = False, max_pending: int = 10000):
        self.state = state
        self.source = source
        self.from_start = from_start
        self.stop_event = threading.Event()
        self.assembler = AuditAssembler(state.hostname, max_pending=max_pending)

    def _account_parser(self) -> None:
        if self.assembler.dropped:
            self.state.metrics.drop(self.state.hostname, self.assembler.dropped)
            self.assembler.dropped = 0
        if self.assembler.parse_errors:
            self.state.metrics.parse_error(self.state.hostname, self.assembler.parse_errors)
            self.assembler.parse_errors = 0

    def _line(self, line: str) -> None:
        for event in self.assembler.ingest(line):
            self.state.observe(event)
        self._account_parser()

    def _expire(self) -> None:
        for event in self.assembler.expire():
            self.state.observe(event)
        self._account_parser()

    def run(self) -> None:
        self.state.metrics.touch(self.state.hostname)
        if self.source == "-":
            for line in sys.stdin:
                self._line(line)
            self._expire()
            return
        first_open = True
        while not self.stop_event.is_set():
            try:
                with open(self.source, "r", encoding="utf-8", errors="replace") as stream:
                    if first_open and not self.from_start:
                        stream.seek(0, os.SEEK_END)
                    first_open = False
                    while not self.stop_event.is_set():
                        line = stream.readline()
                        if line:
                            self._line(line)
                            continue
                        self._expire()
                        try:
                            rotated = os.stat(self.source).st_ino != os.fstat(stream.fileno()).st_ino
                        except FileNotFoundError:
                            rotated = False
                        if rotated:
                            break
                        self.stop_event.wait(0.25)
            except FileNotFoundError:
                LOG.warning("audit log %s does not exist; retrying", self.source)
                self.stop_event.wait(1)
            except PermissionError:
                LOG.error("permission denied reading %s; agent needs audit-log read access", self.source)
                self.stop_event.wait(5)
        self._expire()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="command-audit", description="Run the command audit agent (default mode)")
    add_listen_arguments(parser, 9101)
    parser.add_argument("--audit.log-path", "--input", dest="input", default="/var/log/audit/audit.log", help="audit log path, or - for stdin")
    add_bool_argument(
        parser,
        ("--audit.from-start", "--from-start"),
        ("--no-audit.from-start", "--no-from-start"),
        dest="from_start",
        default=False,
        help_text="read existing log content; supports =true and =false",
    )
    parser.add_argument("--audit.max-pending", dest="max_pending", type=int, default=10000, help="maximum incomplete audit events held in memory")
    parser.add_argument("--hostname", default=socket.gethostname())
    parser.add_argument("--server.url", "--server-url", dest="server_url", default=os.getenv("COMMAND_AUDIT_SERVER", ""), help="optional aggregation server URL; empty enables pull-only mode")
    parser.add_argument("--auth.token", "--token", dest="token", default=os.getenv("COMMAND_AUDIT_TOKEN", ""), help="bearer token; COMMAND_AUDIT_TOKEN is preferred to avoid process-list exposure")
    parser.add_argument("--dangerous.commands", "--dangerous-commands", dest="dangerous_mode", choices=("collect", "no-alert", "drop"), default="collect", help="collect+alert, collect without danger alerts, or drop dangerous events entirely")
    add_bool_argument(
        parser,
        ("--collector.args", "--collect-args"),
        ("--no-collector.args", "--no-collect-args"),
        dest="collect_args",
        default=True,
        help_text="collect redacted command arguments; supports =true and =false",
    )
    parser.add_argument("--collector.max-recent", "--max-recent", dest="max_recent", type=int, default=200, help="recent events retained for the local API; 0 disables the cache")
    parser.add_argument("--metrics.max-users", dest="max_users", type=int, default=200)
    parser.add_argument("--metrics.max-commands", dest="max_commands", type=int, default=300)
    parser.add_argument("--push.batch-size", dest="batch_size", type=int, default=100)
    parser.add_argument("--push.queue-size", dest="queue_size", type=int, default=10000)
    parser.add_argument("--push.timeout", dest="push_timeout", type=float, default=5.0)
    parser.add_argument("--push.heartbeat-interval", dest="heartbeat_interval", type=float, default=30.0)
    parser.add_argument("--log.level", "--log-level", dest="log_level", default="INFO", choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"))
    parser.add_argument("--version", action="version", version=f"command-audit {__version__}")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.max_recent < 0 or args.max_pending < 1 or args.batch_size < 1 or args.queue_size < 1:
        parser.error("collector limits and push batch/queue sizes must be positive (max-recent may be 0)")
    if args.max_users < 2 or args.max_commands < 2 or args.push_timeout <= 0 or args.heartbeat_interval <= 0:
        parser.error("metric label limits must be >=2 and push timeouts must be >0")
    try:
        listen, port = resolve_listen_address(args, 9101)
    except (ValueError, argparse.ArgumentTypeError) as exc:
        parser.error(str(exc))
    logging.basicConfig(level=args.log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    state = AgentState(
        args.hostname,
        args.max_recent,
        dangerous_mode=args.dangerous_mode,
        collect_args=args.collect_args,
        max_users=args.max_users,
        max_commands=args.max_commands,
    )
    if args.server_url:
        state.pusher = EventPusher(
            args.server_url,
            args.hostname,
            args.token,
            lambda: state.metrics.drop(args.hostname),
            batch_size=args.batch_size,
            queue_size=args.queue_size,
            timeout=args.push_timeout,
            heartbeat_interval=args.heartbeat_interval,
        )
        state.pusher.start()
    httpd = make_agent_server(listen, port, state, args.token)
    http_thread = threading.Thread(target=httpd.serve_forever, name="agent-http", daemon=True)
    http_thread.start()
    reader = AuditReader(state, args.input, args.from_start, max_pending=args.max_pending)
    signal.signal(signal.SIGTERM, lambda *_: (reader.stop_event.set(), threading.Thread(target=httpd.shutdown, daemon=True).start()))
    LOG.info("agent listening on %s:%d, reading %s, dangerous=%s, args=%s, push=%s", listen, port, args.input, args.dangerous_mode, args.collect_args, "enabled" if state.pusher else "disabled")
    try:
        reader.run()
    except KeyboardInterrupt:
        reader.stop_event.set()
    finally:
        reader.stop_event.set()
        httpd.shutdown()
        http_thread.join(timeout=3)
        httpd.server_close()
        if state.pusher:
            state.pusher.close()


if __name__ == "__main__":
    main()
