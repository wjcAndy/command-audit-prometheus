from __future__ import annotations

import os
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Iterable

from .models import AuditEvent
from .rules import classify_command, redact_arguments

try:
    import pwd
except ImportError:  # Windows test/development hosts
    pwd = None

MSG_ID = re.compile(r"msg=audit\((?P<timestamp>\d+(?:\.\d+)?):(?P<serial>\d+)\)")
FIELD = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>\"(?:[^\"\\]|\\.)*\"|\S+)")
HEX = re.compile(r"^[0-9A-Fa-f]+$")
UNSET_UID = {4294967295, -1}


def decode_audit_value(value: str, allow_hex: bool = True) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    if allow_hex and len(value) >= 2 and len(value) % 2 == 0 and HEX.fullmatch(value):
        try:
            return bytes.fromhex(value).decode("utf-8", errors="replace").rstrip("\x00")
        except ValueError:
            pass
    return value


def parse_fields(line: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in FIELD.finditer(line):
        key = match.group("key")
        allow_hex = bool(re.fullmatch(r"a\d+", key)) or key in {"proctitle", "name", "exe", "cwd", "comm"}
        fields[key] = decode_audit_value(match.group("value"), allow_hex=allow_hex)
    return fields


def _integer(value: str | None, default: int = -1) -> int:
    try:
        return int(value) if value is not None else default
    except ValueError:
        return default


@lru_cache(maxsize=4096)
def resolve_user(uid: int) -> str:
    if pwd is not None and uid >= 0 and uid not in UNSET_UID:
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            pass
    return "unset" if uid in UNSET_UID else f"uid:{uid}"


@dataclass
class PartialEvent:
    timestamp: float
    event_id: str
    records: dict[str, dict[str, str]] = field(default_factory=dict)
    updated_monotonic: float = field(default_factory=time.monotonic)


class AuditAssembler:
    """Join SYSCALL/EXECVE/CWD/EOE records sharing one audit event id."""

    def __init__(self, hostname: str, max_pending: int = 10000, timeout_seconds: float = 2.0):
        self.hostname = hostname
        self.max_pending = max_pending
        self.timeout_seconds = timeout_seconds
        self.pending: OrderedDict[str, PartialEvent] = OrderedDict()
        self.dropped = 0
        self.parse_errors = 0

    def ingest(self, line: str) -> list[AuditEvent]:
        match = MSG_ID.search(line)
        if not match:
            if line.strip():
                self.parse_errors += 1
            return []
        event_type_match = re.search(r"(?:^|\s)type=([A-Z0-9_]+)", line)
        if not event_type_match:
            return []
        event_type = event_type_match.group(1)
        event_id = f"{match.group('timestamp')}:{match.group('serial')}"
        partial = self.pending.get(event_id)
        if partial is None:
            if len(self.pending) >= self.max_pending:
                self.pending.popitem(last=False)
                self.dropped += 1
            partial = PartialEvent(float(match.group("timestamp")), event_id)
            self.pending[event_id] = partial
        partial.updated_monotonic = time.monotonic()
        if event_type != "EOE":
            partial.records[event_type] = parse_fields(line)
        if event_type == "EOE":
            self.pending.pop(event_id, None)
            event = self._build(partial)
            return [event] if event else []
        return []

    def expire(self) -> list[AuditEvent]:
        cutoff = time.monotonic() - self.timeout_seconds
        expired = [key for key, value in self.pending.items() if value.updated_monotonic <= cutoff]
        events: list[AuditEvent] = []
        for key in expired:
            partial = self.pending.pop(key)
            event = self._build(partial)
            if event:
                events.append(event)
        return events

    def _build(self, partial: PartialEvent) -> AuditEvent | None:
        syscall = partial.records.get("SYSCALL")
        execve = partial.records.get("EXECVE")
        if not syscall or not execve:
            return None
        argc = max(0, _integer(execve.get("argc"), 0))
        argv = [execve.get(f"a{index}", "") for index in range(argc)]
        if not argv and execve.get("a0"):
            argv = [execve["a0"]]
        exe = syscall.get("exe", "")
        command = os.path.basename(exe or (argv[0] if argv else syscall.get("comm", "unknown")))
        auid = _integer(syscall.get("auid"), -1)
        uid = _integer(syscall.get("uid"), -1)
        euid = _integer(syscall.get("euid"), uid)
        identity_uid = auid if auid >= 0 and auid not in UNSET_UID else euid
        cwd_record = partial.records.get("CWD", {})
        session = _integer(syscall.get("ses"), -1)
        return AuditEvent(
            timestamp=partial.timestamp,
            event_id=partial.event_id,
            hostname=self.hostname,
            user=resolve_user(identity_uid),
            auid=auid,
            uid=uid,
            euid=euid,
            command=command or "unknown",
            exe=exe,
            args=redact_arguments(argv),
            cwd=cwd_record.get("cwd", ""),
            pid=_integer(syscall.get("pid"), -1),
            ppid=_integer(syscall.get("ppid"), -1),
            success=syscall.get("success", "no") == "yes",
            exit_code=_integer(syscall.get("exit"), 0),
            session=None if session < 0 else session,
            tty=syscall.get("tty", ""),
            danger=classify_command(argv, exe),
        )


def assemble_lines(lines: Iterable[str], hostname: str) -> list[AuditEvent]:
    assembler = AuditAssembler(hostname)
    events: list[AuditEvent] = []
    for line in lines:
        events.extend(assembler.ingest(line))
    events.extend(assembler.expire())
    return events
