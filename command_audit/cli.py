from __future__ import annotations

import sys


def main() -> None:
    """Single executable: agent by default, aggregation server via `server`."""
    args = sys.argv[1:]
    if args and args[0] == "server":
        from .server import main

        main(args[1:])
        return
    if args and args[0] == "agent":
        args = args[1:]
    from .agent import main

    main(args)


if __name__ == "__main__":
    main()
