from __future__ import annotations

import argparse


def parse_bool(value: str | bool) -> bool:
    if isinstance(value, bool):
        return value
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise argparse.ArgumentTypeError(f"invalid boolean value: {value}")


def add_bool_argument(
    parser: argparse.ArgumentParser,
    positive: tuple[str, ...],
    negative: tuple[str, ...],
    *,
    dest: str,
    default: bool,
    help_text: str,
) -> None:
    """Support --flag, --flag=true, --flag=false and --no-flag forms."""
    parser.add_argument(
        *positive,
        dest=dest,
        nargs="?",
        const=True,
        type=parse_bool,
        default=default,
        metavar="BOOL",
        help=help_text,
    )
    parser.add_argument(
        *negative,
        dest=dest,
        action="store_const",
        const=False,
        help=f"disable {positive[0]}",
    )


def parse_listen_address(value: str, default_port: int) -> tuple[str, int]:
    """Parse node_exporter-style :9101 or host:9101 listen addresses."""
    value = value.strip()
    if not value:
        raise argparse.ArgumentTypeError("listen address cannot be empty")
    if value.startswith("[") or value.count(":") > 1:
        raise argparse.ArgumentTypeError("IPv6 listen addresses are not supported by this version")
    if ":" in value:
        host, port_text = value.rsplit(":", 1)
    else:
        host, port_text = value, str(default_port)
    host = host or "0.0.0.0"
    try:
        port = int(port_text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid listen port: {port_text}") from exc
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError("listen port must be between 0 and 65535")
    return host, port


def add_listen_arguments(parser: argparse.ArgumentParser, default_port: int) -> None:
    parser.add_argument(
        "--web.listen-address",
        dest="listen_address",
        default=f":{default_port}",
        metavar="ADDRESS",
        help=f"listen address, for example :{default_port} or 127.0.0.1:{default_port}",
    )
    parser.add_argument("--listen", dest="legacy_listen", default=None, help=argparse.SUPPRESS)
    parser.add_argument("--port", dest="legacy_port", type=int, default=None, help=argparse.SUPPRESS)


def resolve_listen_address(args: argparse.Namespace, default_port: int) -> tuple[str, int]:
    host, port = parse_listen_address(args.listen_address, default_port)
    if args.legacy_listen is not None:
        host = args.legacy_listen
    if args.legacy_port is not None:
        port = args.legacy_port
    if not 0 <= port <= 65535:
        raise ValueError("listen port must be between 0 and 65535")
    return host, port
