from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any


def _escape(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(names: tuple[str, ...], values: tuple[object, ...]) -> str:
    if not names:
        return ""
    return "{" + ",".join(f'{name}="{_escape(value)}"' for name, value in zip(names, values)) + "}"


class MetricStore:
    """Bounded-label in-memory metrics; raw arguments are deliberately excluded."""

    def __init__(self, max_users: int = 200, max_commands: int = 300, agent_stale_seconds: int = 90):
        self.max_users = max_users
        self.max_commands = max_commands
        self.agent_stale_seconds = agent_stale_seconds
        self._lock = threading.Lock()
        self._events: dict[tuple[str, str, str, str], int] = defaultdict(int)
        self._danger: dict[tuple[str, str, str, str, str], int] = defaultdict(int)
        self._last_event: dict[str, float] = {}
        self._last_seen: dict[str, float] = {}
        self._dropped: dict[str, int] = defaultdict(int)
        self._parse_errors: dict[str, int] = defaultdict(int)
        self._suppressed: dict[tuple[str, str], int] = defaultdict(int)
        self._users = {"__other__"}
        self._commands = {"__other__"}

    def _bounded(self, value: str, kind: str) -> str:
        values = self._users if kind == "user" else self._commands
        limit = self.max_users if kind == "user" else self.max_commands
        value = (value or "unknown")[:128]
        if value in values:
            return value
        if len(values) >= limit:
            return "__other__"
        values.add(value)
        return value

    def observe(self, event: AuditEventLike, seen_at: float | None = None) -> None:
        get = event.get if isinstance(event, dict) else lambda key, default=None: getattr(event, key, default)
        host = str(get("hostname", "unknown"))[:128]
        result = "success" if get("success", False) else "failed"
        timestamp = float(get("timestamp", time.time()))
        danger = get("danger", []) or []
        with self._lock:
            user = self._bounded(str(get("user", "unknown")), "user")
            command = self._bounded(str(get("command", "unknown")), "command")
            self._events[(host, user, command, result)] += 1
            for match in danger:
                if isinstance(match, dict):
                    rule = str(match.get("rule", "unknown"))[:64]
                    severity = str(match.get("severity", "warning"))[:32]
                    self._danger[(host, user, command, rule, severity)] += 1
            self._last_event[host] = max(timestamp, self._last_event.get(host, 0))
            self._last_seen[host] = seen_at or time.time()

    def touch(self, hostname: str) -> None:
        with self._lock:
            self._last_seen[hostname] = time.time()

    def drop(self, hostname: str, count: int = 1) -> None:
        with self._lock:
            self._dropped[hostname] += count

    def parse_error(self, hostname: str, count: int = 1) -> None:
        with self._lock:
            self._parse_errors[hostname] += count

    def suppress(self, hostname: str, reason: str = "dangerous_command", count: int = 1) -> None:
        with self._lock:
            self._suppressed[(hostname, reason)] += count

    def render(self, local_agent: str | None = None) -> str:
        with self._lock:
            events = dict(self._events)
            danger = dict(self._danger)
            last_event = dict(self._last_event)
            last_seen = dict(self._last_seen)
            dropped = dict(self._dropped)
            parse_errors = dict(self._parse_errors)
            suppressed = dict(self._suppressed)
        now = time.time()
        if local_agent:
            last_seen[local_agent] = now
        hosts = sorted(set(last_seen) | set(last_event) | set(dropped) | set(parse_errors) | {host for host, _ in suppressed})
        lines = [
            "# HELP command_audit_events_total Executed commands observed by auditd.",
            "# TYPE command_audit_events_total counter",
        ]
        for key, value in sorted(events.items()):
            lines.append(f"command_audit_events_total{_labels(('hostname','user','command','result'), key)} {value}")
        lines.extend([
            "# HELP command_audit_dangerous_events_total Commands matching dangerous-command rules.",
            "# TYPE command_audit_dangerous_events_total counter",
        ])
        for key, value in sorted(danger.items()):
            lines.append(f"command_audit_dangerous_events_total{_labels(('hostname','user','command','rule','severity'), key)} {value}")
        lines.extend([
            "# HELP command_audit_last_event_timestamp_seconds Unix timestamp of the latest audit event.",
            "# TYPE command_audit_last_event_timestamp_seconds gauge",
        ])
        for host in hosts:
            if host in last_event:
                lines.append(f"command_audit_last_event_timestamp_seconds{_labels(('hostname',), (host,))} {last_event[host]}")
        lines.extend([
            "# HELP command_audit_agent_last_seen_timestamp_seconds Unix timestamp when an agent was last seen.",
            "# TYPE command_audit_agent_last_seen_timestamp_seconds gauge",
        ])
        for host in hosts:
            if host in last_seen:
                lines.append(f"command_audit_agent_last_seen_timestamp_seconds{_labels(('hostname',), (host,))} {last_seen[host]}")
        lines.extend([
            "# HELP command_audit_agent_up Whether an agent is fresh (server) or running (local scrape).",
            "# TYPE command_audit_agent_up gauge",
        ])
        for host in hosts:
            up = 1 if host == local_agent or now - last_seen.get(host, 0) <= self.agent_stale_seconds else 0
            lines.append(f"command_audit_agent_up{_labels(('hostname',), (host,))} {up}")
        self._render_simple(lines, "command_audit_agent_events_dropped_total", "Events dropped by bounded buffers.", dropped, hosts)
        self._render_simple(lines, "command_audit_parse_errors_total", "Malformed audit records observed.", parse_errors, hosts)
        lines.extend([
            "# HELP command_audit_events_suppressed_total Events intentionally excluded by collection policy.",
            "# TYPE command_audit_events_suppressed_total counter",
        ])
        for key, value in sorted(suppressed.items()):
            lines.append(f"command_audit_events_suppressed_total{_labels(('hostname','reason'), key)} {value}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def _render_simple(lines: list[str], name: str, help_text: str, values: dict[str, int], hosts: list[str]) -> None:
        lines.extend([f"# HELP {name} {help_text}", f"# TYPE {name} counter"])
        for host in hosts:
            lines.append(f"{name}{_labels(('hostname',), (host,))} {values.get(host, 0)}")


AuditEventLike = Any
