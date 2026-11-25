from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class AuditEvent:
    timestamp: float
    event_id: str
    hostname: str
    user: str
    auid: int
    uid: int
    euid: int
    command: str
    exe: str
    args: list[str]
    cwd: str
    pid: int
    ppid: int
    success: bool
    exit_code: int = 0
    session: int | None = None
    tty: str = ""
    danger: list[dict[str, str]] = field(default_factory=list)

    @property
    def dedupe_key(self) -> str:
        return f"{self.hostname}:{self.event_id}:{self.pid}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["dedupe_key"] = self.dedupe_key
        return data
