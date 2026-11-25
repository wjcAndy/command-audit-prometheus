from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def target_specs(all_linux: bool) -> list[tuple[str, str, str]]:
    if all_linux:
        return [
            ("linux", "amd64", "command-audit-linux-amd64"),
            ("linux", "arm64", "command-audit-linux-arm64"),
        ]
    system = "windows" if sys.platform == "win32" else "linux"
    architecture = "amd64" if sys.maxsize > 2**32 else "arm64"
    suffix = ".exe" if system == "windows" else ""
    return [(system, architecture, f"command-audit-{system}-{architecture}{suffix}")]


def main() -> None:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description="Build static command-audit binaries with Go")
    parser.add_argument("--output", type=Path, default=root / "dist")
    parser.add_argument("--all-linux", action="store_true", help="build Linux amd64 and arm64 binaries")
    args = parser.parse_args()
    go = shutil.which("go")
    if not go:
        raise SystemExit("Go toolchain not found; install Go 1.23 or later")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    for system, architecture, filename in target_specs(args.all_linux):
        destination = output / filename
        environment = os.environ.copy()
        environment.update({"CGO_ENABLED": "0", "GOOS": system, "GOARCH": architecture})
        command = [
            go,
            "-C",
            str(root),
            "build",
            "-trimpath",
            "-ldflags",
            "-s -w",
            "-o",
            str(destination),
            ".",
        ]
        subprocess.run(command, env=environment, check=True)
        print(f"{destination} | {destination.stat().st_size} bytes")


if __name__ == "__main__":
    main()
