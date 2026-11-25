from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import unittest
import urllib.error
import urllib.request

from command_audit.agent import AgentState, build_parser, make_agent_server
from command_audit.audit import AuditAssembler, parse_fields
from command_audit.config import parse_bool, parse_listen_address
from command_audit.metrics import MetricStore
from command_audit.rules import classify_command, redact_arguments
from command_audit.server import EventRepository, make_server


def audit_lines(command: str = "rm", args: list[str] | None = None, serial: int = 100) -> list[str]:
    args = args if args is not None else ["-rf", "/"]
    stamp = f"1760000000.123:{serial}"
    argv = [command] + args
    execve = " ".join(f'a{index}="{value}"' for index, value in enumerate(argv))
    return [
        f'type=SYSCALL msg=audit({stamp}): arch=c000003e syscall=59 success=yes exit=0 items=2 ppid=1200 pid=1201 auid=1000 uid=1000 gid=1000 euid=0 egid=0 tty=pts0 ses=22 comm="{command}" exe="/usr/bin/{command}" key="command_audit"',
        f'type=EXECVE msg=audit({stamp}): argc={len(argv)} {execve}',
        f'type=CWD msg=audit({stamp}): cwd="/home/tester"',
        f'type=EOE msg=audit({stamp}):',
    ]


def observed_event(command: str = "rm", args: list[str] | None = None):
    assembler = AuditAssembler("node-a")
    events = []
    for line in audit_lines(command, args):
        events.extend(assembler.ingest(line))
    assert len(events) == 1
    return events[0]


class AuditParserTests(unittest.TestCase):
    def test_joins_records_and_extracts_identity(self):
        event = observed_event()
        self.assertEqual(event.command, "rm")
        self.assertEqual(event.args, ["rm", "-rf", "/"])
        self.assertEqual(event.auid, 1000)
        self.assertEqual(event.euid, 0)
        self.assertEqual(event.pid, 1201)
        self.assertEqual(event.cwd, "/home/tester")
        self.assertTrue(event.success)
        self.assertEqual(event.danger[0]["rule"], "root_recursive_delete")

    def test_decodes_hex_arguments_but_not_numeric_identity(self):
        lines = audit_lines("ls", ["/tmp"])
        lines[1] = lines[1].replace('a0="ls"', 'a0=6C73').replace('a1="/tmp"', 'a1=2F746D70')
        assembler = AuditAssembler("node-a")
        events = []
        for line in lines:
            events.extend(assembler.ingest(line))
        self.assertEqual(events[0].args, ["ls", "/tmp"])
        self.assertEqual(events[0].pid, 1201)
        self.assertEqual(events[0].auid, 1000)

    def test_redacts_common_credentials(self):
        args = ["curl", "--token", "abc123", "--password=def456", "https://user:secret@example.test"]
        self.assertEqual(
            redact_arguments(args),
            ["curl", "--token", "<redacted>", "--password=<redacted>", "https://user:<redacted>@example.test"],
        )


class RuleTests(unittest.TestCase):
    def test_power_and_systemctl_commands(self):
        self.assertEqual(classify_command(["reboot"])[0]["severity"], "critical")
        self.assertEqual(classify_command(["systemctl", "poweroff"])[0]["rule"], "system_power_state")
        self.assertEqual(classify_command(["init", "6"])[0]["rule"], "system_runlevel")

    def test_rm_is_graded_by_effect(self):
        self.assertEqual(classify_command(["rm", "file.txt"])[0]["severity"], "warning")
        self.assertEqual(classify_command(["rm", "-r", "build"])[0]["severity"], "high")
        self.assertEqual(classify_command(["rm", "-rf", "/"])[0]["severity"], "critical")


class MetricsAndPipelineTests(unittest.TestCase):
    def test_metrics_never_contain_arguments(self):
        event = observed_event("rm", ["-rf", "--password=supersecret", "/"])
        metrics = MetricStore()
        metrics.observe(event)
        text = metrics.render(local_agent="node-a")
        self.assertNotIn("supersecret", text)
        self.assertNotIn('"/"', text)
        self.assertIn('command="rm"', text)
        self.assertIn('rule="root_recursive_delete"', text)
        self.assertIn('command_audit_agent_up{hostname="node-a"} 1', text)

    def test_server_deduplicates_retries_and_tracks_heartbeat(self):
        repository = EventRepository()
        event = observed_event().to_dict()
        first = repository.ingest({"hostname": "node-a", "events": [event]})
        retry = repository.ingest({"hostname": "node-a", "events": [event]})
        self.assertEqual(first, (1, 0))
        self.assertEqual(retry, (0, 1))
        self.assertEqual(repository.ingest({"hostname": "idle-node", "events": []}), (0, 0))
        metrics = repository.metrics.render()
        self.assertIn('command_audit_agent_up{hostname="idle-node"} 1', metrics)

    def test_http_authenticated_push_query_and_scrape(self):
        repository = EventRepository()
        server = make_server("127.0.0.1", 0, repository, "test-token")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_port}"
        try:
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(base + "/metrics", timeout=2)
            self.assertEqual(error.exception.code, 401)

            event = observed_event("reboot", []).to_dict()
            request = urllib.request.Request(
                base + "/api/v1/events",
                data=json.dumps({"hostname": "node-a", "events": [event]}).encode(),
                headers={"Content-Type": "application/json", "Authorization": "Bearer test-token"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                self.assertEqual(response.status, 202)
                self.assertEqual(json.loads(response.read())["accepted"], 1)

            query = urllib.request.Request(base + "/api/v1/events?dangerous=true", headers={"Authorization": "Bearer test-token"})
            with urllib.request.urlopen(query, timeout=2) as response:
                events = json.loads(response.read())["events"]
                self.assertEqual(events[0]["command"], "reboot")

            scrape = urllib.request.Request(base + "/metrics", headers={"Authorization": "Bearer test-token"})
            with urllib.request.urlopen(scrape, timeout=2) as response:
                self.assertIn(b'rule="system_power_state"', response.read())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_agent_metrics_endpoint_runs_independently(self):
        state = AgentState("node-a")
        state.observe(observed_event())
        server = make_agent_server("127.0.0.1", 0, state, "")
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{server.server_port}/metrics", timeout=2) as response:
                self.assertIn(b"command_audit_events_total", response.read())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class RuntimeFlagTests(unittest.TestCase):
    def test_explicit_boolean_flags(self):
        args = build_parser().parse_args([
            "--web.listen-address=127.0.0.1:9201",
            "--audit.from-start=true",
            "--collector.args=false",
            "--dangerous.commands=drop",
        ])
        self.assertEqual(args.listen_address, "127.0.0.1:9201")
        self.assertTrue(args.from_start)
        self.assertFalse(args.collect_args)
        self.assertEqual(args.dangerous_mode, "drop")
        self.assertFalse(build_parser().parse_args(["--no-collector.args"]).collect_args)
        self.assertTrue(build_parser().parse_args(["--collector.args"]).collect_args)

    def test_boolean_parser_rejects_unknown_values(self):
        self.assertTrue(parse_bool("yes"))
        self.assertFalse(parse_bool("OFF"))
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_bool("maybe")

    def test_listen_address_forms(self):
        self.assertEqual(parse_listen_address(":9101", 9101), ("0.0.0.0", 9101))
        self.assertEqual(parse_listen_address("127.0.0.1:0", 9101), ("127.0.0.1", 0))
        self.assertEqual(parse_listen_address("localhost", 9101), ("localhost", 9101))
        with self.assertRaises(argparse.ArgumentTypeError):
            parse_listen_address("[::]:9101", 9101)

    def test_python_dangerous_policies(self):
        drop = AgentState("node-a", dangerous_mode="drop")
        drop.observe(observed_event("reboot"))
        self.assertEqual(drop.query(False, 10), [])
        self.assertEqual(len(drop.metrics._events), 0)
        self.assertIn('command_audit_events_suppressed_total{hostname="node-a",reason="dangerous_command"} 1', drop.metrics.render())

        no_alert = AgentState("node-a", dangerous_mode="no-alert", collect_args=False)
        no_alert.observe(observed_event("ls", ["/tmp"]))
        events = no_alert.query(False, 10)
        self.assertEqual(events[0]["args"], [])
        self.assertEqual(len(no_alert.metrics._danger), 0)
        self.assertEqual(len(no_alert.metrics._events), 1)

    def test_server_central_drop_policy(self):
        repository = EventRepository(100, "drop")
        accepted, duplicates = repository.ingest({"hostname": "node-a", "events": [observed_event("reboot").to_dict()]})
        self.assertEqual((accepted, duplicates), (0, 0))
        self.assertEqual(repository.query(dangerous_only=True, limit=10), [])
        self.assertIn('reason="dangerous_command"', repository.metrics.render())

    def test_unified_python_entrypoint_version(self):
        root = Path(__file__).resolve().parents[1]
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(root)
        completed = subprocess.run(
            [sys.executable, "-m", "command_audit", "--version"],
            cwd=root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        self.assertIn("command-audit 0.2.0", completed.stdout)


if __name__ == "__main__":
    unittest.main()
