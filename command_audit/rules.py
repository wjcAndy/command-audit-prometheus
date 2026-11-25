from __future__ import annotations

import os
import re


SENSITIVE_FLAGS = {
    "--password",
    "--passwd",
    "--token",
    "--access-token",
    "--api-key",
    "--apikey",
    "--secret",
    "--client-secret",
    "--private-key",
    "--credential",
    "--credentials",
    "--authorization",
}
SENSITIVE_ENV = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Za-z0-9_]*)=(.*)$",
    re.IGNORECASE,
)
URI_USERINFO = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*://)([^/@:]+):([^/@]*)@(.+)$")


def redact_uri_credentials(value: str) -> str:
    match = URI_USERINFO.match(value)
    if match:
        return f"{match.group(1)}{match.group(2)}:<redacted>@{match.group(4)}"
    return value


def redact_arguments(argv: list[str]) -> list[str]:
    """Retain useful parameters while masking common credential forms."""
    redacted: list[str] = []
    mask_next = False
    for index, original in enumerate(argv):
        value = original
        if mask_next:
            redacted.append("<redacted>")
            mask_next = False
            continue
        lower = value.lower()
        if index > 0 and lower in SENSITIVE_FLAGS:
            redacted.append(value)
            mask_next = True
            continue
        if index > 0 and lower.startswith(tuple(flag + "=" for flag in SENSITIVE_FLAGS)):
            redacted.append(value.split("=", 1)[0] + "=<redacted>")
            continue
        env_match = SENSITIVE_ENV.match(value)
        if env_match:
            redacted.append(env_match.group(1) + "=<redacted>")
            continue
        if index > 0 and lower.startswith("-p") and len(value) > 2 and argv and "mysql" in os.path.basename(argv[0]).lower():
            redacted.append("-p<redacted>")
            continue
        redacted.append(redact_uri_credentials(value))
    return redacted


def _rule(code: str, severity: str, description: str) -> dict[str, str]:
    return {"rule": code, "severity": severity, "description": description}


def _has_recursive_flag(args: list[str]) -> bool:
    return any(
        arg in {"-r", "-R", "--recursive"}
        or (arg.startswith("-") and not arg.startswith("--") and ("r" in arg[1:] or "R" in arg[1:]))
        for arg in args
    )


def classify_command(argv: list[str], exe: str = "") -> list[dict[str, str]]:
    if not argv and not exe:
        return []
    command = os.path.basename(exe or argv[0])
    args = argv[1:] if argv else []
    rules: list[dict[str, str]] = []

    if command in {"reboot", "poweroff", "halt", "shutdown"}:
        rules.append(_rule("system_power_state", "critical", f"{command} changes host power or run state"))
    if command in {"init", "telinit"} and any(arg in {"0", "6"} for arg in args):
        rules.append(_rule("system_runlevel", "critical", "command requests shutdown or reboot runlevel"))
    if command == "systemctl" and any(arg in {"reboot", "poweroff", "halt", "kexec"} for arg in args):
        rules.append(_rule("system_power_state", "critical", "systemctl changes host power state"))

    if command == "rm":
        recursive = _has_recursive_flag(args)
        targets_root = any(arg in {"/", "/*"} or arg.startswith("--no-preserve-root") for arg in args)
        if recursive and targets_root:
            rules.append(_rule("root_recursive_delete", "critical", "recursive deletion targets filesystem root"))
        elif recursive:
            rules.append(_rule("recursive_delete", "high", "recursive file deletion"))
        else:
            rules.append(_rule("file_delete", "warning", "file deletion command"))

    if command == "dd" and any(arg.startswith("of=/dev/") for arg in args):
        rules.append(_rule("block_device_overwrite", "critical", "dd writes directly to a block device"))
    if command == "mkfs" or command.startswith("mkfs.") or command in {"wipefs", "fdisk", "sfdisk", "parted"}:
        rules.append(_rule("disk_layout_modify", "critical", "disk or filesystem destructive operation"))
    if command in {"chmod", "chown", "chgrp"} and _has_recursive_flag(args) and "/" in args:
        rules.append(_rule("root_permission_modify", "high", "recursive permission change targets root"))

    return rules
