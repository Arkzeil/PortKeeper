#!/usr/bin/env python3
"""Real sockets/processes plus isolated ss failure fixtures; no privileged ports."""
import contextlib
import ctypes
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest


def holder():
    if sys.argv[2] == "inherit":
        sock = socket.socket(fileno=int(sys.argv[3]))
    else:
        family = socket.AF_INET6 if sys.argv[2] == "6" else socket.AF_INET
        kind = socket.SOCK_DGRAM if sys.argv[3] == "udp" else socket.SOCK_STREAM
        sock = socket.socket(family, kind)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", int(sys.argv[4])))
        if kind == socket.SOCK_STREAM:
            sock.listen(4)
    behavior = sys.argv[5] if len(sys.argv) > 5 else None
    if behavior == "private":
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
            raise OSError(ctypes.get_errno(), "PR_SET_DUMPABLE")
    elif behavior == "ignore":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    elif behavior == "close":
        def close_on_term(_signum, _frame):
            sock.close()
            print("closed", flush=True)
        signal.signal(signal.SIGTERM, close_on_term)
    if "PORTKEEPER_TEST_COMM" in os.environ:
        libc = ctypes.CDLL(None, use_errno=True)
        name = os.environ["PORTKEEPER_TEST_COMM"].encode("utf-8")
        if libc.prctl(15, ctypes.c_char_p(name), 0, 0, 0) != 0:  # PR_SET_NAME
            raise OSError(ctypes.get_errno(), "PR_SET_NAME")
    print(sock.getsockname()[1], flush=True)
    for command in sys.stdin:
        if command.strip() == "close":
            sock.close()
            print("closed", flush=True)


if len(sys.argv) > 1 and sys.argv[1] == "--holder":
    holder()
    sys.exit(0)

BIN = str(Path(sys.argv.pop(1)).resolve())
SS_AVAILABLE = shutil.which("ss") is not None


class Integration(unittest.TestCase):
    def run_cli(self, *args, expected=0, input="", env=None):
        result = subprocess.run([BIN, *map(str, args)], input=input, text=True,
                                capture_output=True, timeout=25, env=env)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def cleanup_process(self, process):
        if process.poll() is None:
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream:
                stream.close()

    def listener(self, protocol="tcp", family="4", port=0, inherited=None, behavior=None,
                 extra_args=(), name=None):
        args = [sys.executable, __file__, "--holder"]
        args += ["inherit", str(inherited)] if inherited is not None else [family, protocol, str(port)]
        if behavior or extra_args:
            self.assertIsNone(inherited)
            args.append(behavior or "")
        args.extend(extra_args)
        env = dict(os.environ)
        if name is not None:
            env["PORTKEEPER_TEST_COMM"] = name
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True,
                                   pass_fds=() if inherited is None else (inherited,), env=env)
        self.addCleanup(self.cleanup_process, process)
        line = process.stdout.readline()
        self.assertTrue(line, process.stderr.read() if process.poll() is not None else "holder failed")
        return process, int(line)

    def shared_listeners(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as shared:
            shared.bind(("127.0.0.1", 0))
            shared.listen(4)
            first, port = self.listener(inherited=shared.fileno())
            second, _ = self.listener(inherited=shared.fileno())
        return first, second, port

    def pending_stop(self, port, *extra):
        process = subprocess.Popen([BIN, "stop", str(port), *extra], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.cleanup_process, process)
        self.read_until(process, b"Type 'yes'")
        return process

    def read_until(self, process, marker):
        output = b""
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 8
            while marker not in output:
                self.assertLess(time.monotonic(), deadline, output.decode(errors="replace"))
                if not selector.select(timeout=0.2):
                    continue
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    self.fail(output.decode(errors="replace") + process.stderr.read().decode())
                output += chunk
        return output

    @contextlib.contextmanager
    def fake_ss(self, body=None):
        with tempfile.TemporaryDirectory(prefix="portkeeper-test-") as directory:
            if body is not None:
                script = Path(directory, "ss")
                script.write_text(f"#!{sys.executable}\n" + body)
                script.chmod(0o700)
            yield dict(os.environ, PATH=directory), directory

    def test_arguments(self):
        self.run_cli("--help")
        self.run_cli("--version")
        for args in [[], ["unknown"], ["inspect"], ["list", "80"],
                     ["list", "--dry-run"], ["stop", "80", "--yes"],
                     ["list", "--protocol", "sctp"], ["stop", "80", "81"],
                     ["inspect", "--protocol"], ["list", "--protocol", "tcp", "--protocol", "udp"]]:
            self.run_cli(*args, expected=2)
        for args in [["list", "--wait", "3s"], ["inspect", "80", "--wait", "3s"],
                     ["stop", "80", "--wait"], ["stop", "80", "--wait", "0"],
                     ["stop", "80", "--wait", "1.5s"],
                     ["stop", "80", "--wait", "1s", "--wait", "2s"]]:
            self.run_cli(*args, expected=2)
        for port in ["0", "65536", "-1", "+80", "80;touch /tmp/should-not-exist",
                     "80\n", "", "999999999999999999999999999"]:
            self.run_cli("inspect", port, expected=2)

    def test_missing_and_failed_ss(self):
        with self.fake_ss() as (env, _):
            result = self.run_cli("list", env=env, expected=4)
            self.assertIn("iproute2", result.stderr)
        with self.fake_ss("import sys\nprint('partial output')\nsys.exit(1)\n") as (env, _):
            self.run_cli("list", env=env, expected=4)

    def start_watch(self, *arguments, env=None):
        process = subprocess.Popen([BIN, *map(str, arguments)], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.addCleanup(self.cleanup_process, process)
        process.watch_buffer = b""
        return process

    def watch_document(self, process):
        deadline = time.monotonic() + 8
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while b"\n" not in process.watch_buffer:
                self.assertLess(time.monotonic(), deadline, process.watch_buffer)
                if not selector.select(timeout=0.2):
                    continue
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    self.fail(process.watch_buffer.decode(errors="replace") +
                              process.stderr.read().decode(errors="replace"))
                process.watch_buffer += chunk
        line, process.watch_buffer = process.watch_buffer.split(b"\n", 1)
        return json.loads(line)

    def watch_until(self, process, predicate):
        deadline = time.monotonic() + 8
        while True:
            document = self.watch_document(process)
            if predicate(document["sockets"]):
                return document["sockets"]
            self.assertLess(time.monotonic(), deadline, document)

    def test_watch_arguments(self):
        for command in [("list",), ("inspect", "3000")]:
            for extra in [("--watch",), ("--watch", "1s", "--watch", "2s"),
                          ("--watch", "1s", "--wait", "1s"),
                          ("--watch", "1s", "--dry-run")]:
                self.assertEqual(self.run_cli(*command, *extra, expected=2).stdout, "")
            for duration in ("", "0", "0ms", "-1", "+1s", "1.5s", "1m", "s", " 1s",
                             "1s ", "1MS", "3601s", "3600001ms", "1;id",
                             "99999999999999999999999"):
                self.run_cli(*command, "--watch", duration, expected=2)
        for extra in [("--watch", "1s"), ("--watch", "1s", "--dry-run"),
                      ("--wait", "1s", "--watch", "1s")]:
            self.run_cli("stop", "3000", *extra, expected=2)

    def test_watch_immediate_snapshot_and_interruptible_interval(self):
        cases = [("list", "3600s", signal.SIGINT),
                 ("inspect", "3600000ms", signal.SIGTERM), ("list", "3", signal.SIGHUP)]
        with self.fake_ss("pass\n") as (env, _):
            for command, interval, signum in cases:
                with self.subTest(command=command, interval=interval, signal=signum):
                    args = (command,) if command == "list" else (command, "3000")
                    started = time.monotonic()
                    process = self.start_watch(*args, "--watch", interval, "--json", env=env)
                    self.assertEqual(self.watch_document(process), {"schema_version": 1, "sockets": []})
                    self.assertLess(time.monotonic() - started, 4)
                    started = time.monotonic()
                    process.send_signal(signum)
                    stdout, stderr = process.communicate(timeout=3)
                    self.assertLess(time.monotonic() - started, 2)
                    self.assertEqual(process.returncode, 128 + signum, stderr)
                    self.assertEqual(process.watch_buffer + stdout, b"")
                    self.assertIn(f"interrupted by signal {signum}".encode(), stderr)
                    self.assertNotIn(b"no matching", stderr)

    def test_watch_json_and_table_snapshots(self):
        row = 'tcp LISTEN 0 5 127.0.0.1:3000 0.0.0.0:* ino:1 sk:1'
        body = ("import os, pathlib\n"
                "counter = pathlib.Path(os.environ['COUNTER'])\n"
                "count = int(counter.read_text()) if counter.exists() else 0\n"
                "counter.write_text(str(count + 1))\n"
                f"if count == 1: print({row!r})\n"
                "if count == 3: print('broken')\n")
        for command in [("list",), ("inspect", "3000")]:
            for json_option in [(), ("--json",)]:
                with self.subTest(command=command, json=bool(json_option)):
                    with self.fake_ss(body) as (env, directory):
                        env['COUNTER'] = str(Path(directory, "count"))
                        result = self.run_cli(*command, "--watch", "1ms", *json_option,
                                              expected=4, env=env)
                        self.assertEqual(Path(env['COUNTER']).read_text(), '4')
                    if json_option:
                        documents = [json.loads(line) for line in result.stdout.splitlines()]
                        self.assertEqual(len(documents), 3)
                        self.assertTrue(all(d['schema_version'] == 1 for d in documents))
                        self.assertEqual([len(d['sockets']) for d in documents], [0, 1, 0])
                        socket_row = documents[1]['sockets'][0]
                        self.assertEqual(socket_row['port'], 3000)
                        self.assertIsNone(socket_row['pid'])
                        self.assertEqual('command_line' in socket_row, command[0] == 'inspect')
                        self.assertTrue(result.stdout.endswith('\n'))
                    else:
                        self.assertTrue(result.stdout.startswith("Snapshot 1\nPORT"))
                        self.assertIn("\n\nSnapshot 2\nPORT", result.stdout)
                        self.assertIn("\n\nSnapshot 3\nPORT", result.stdout)
                        self.assertEqual(result.stdout.count("No matching listening sockets."), 2)
                        self.assertEqual(result.stdout.count("LOCAL ADDRESS"), 3)
                        self.assertNotIn('\x1b', result.stdout)
                    self.assertEqual(result.stderr.count('some owners are unavailable'), 1)
                    self.assertIn('cannot parse ss record', result.stderr)

    def test_watch_interval_follows_completed_snapshot(self):
        body = ("import json, os, pathlib, sys, time\n"
                "path = pathlib.Path(os.environ['CALLS'])\n"
                "count = len(path.read_text().splitlines()) if path.exists() else 0\n"
                "start = time.monotonic()\n"
                "time.sleep(0.08)\n"
                "with path.open('a') as stream:\n"
                "    stream.write(json.dumps([start, time.monotonic(), sys.argv[1:]]) + '\\n')\n"
                "if count == 2: sys.exit(1)\n")
        with self.fake_ss(body) as (env, directory):
            env['CALLS'] = str(Path(directory, "calls"))
            result = self.run_cli('inspect', '3000', '--watch', '200ms', '--family', 'ipv6',
                                  '--protocol', 'udp', '--pid', os.getpid(), '--json', env=env, expected=4)
            calls = [json.loads(line) for line in Path(env['CALLS']).read_text().splitlines()]
            self.assertEqual(len(calls), 3)
            for before, after in zip(calls, calls[1:]):
                self.assertGreaterEqual(after[0] - before[1], 0.18)
            for _, _, arguments in calls:
                self.assertIn('-6', arguments)
                self.assertEqual(arguments[-3:], ['sport', '=', ':3000'])
            self.assertEqual([json.loads(line) for line in result.stdout.splitlines()],
                             [{'schema_version': 1, 'sockets': []}] * 2)

    def test_watch_initial_discovery_failure(self):
        for body in (None, "import sys\nsys.exit(1)\n", "print('broken')\n"):
            with self.fake_ss(body) as (env, _):
                for command in [('list',), ('inspect', '3000')]:
                    result = self.run_cli(*command, '--watch', '1ms', '--json', env=env, expected=4)
                    self.assertEqual(result.stdout, '')

    def test_watch_output_failure_stops_refreshes(self):
        body = ("import os, pathlib\n"
                "counter = pathlib.Path(os.environ['COUNTER'])\n"
                "count = int(counter.read_text()) if counter.exists() else 0\n"
                "counter.write_text(str(count + 1))\n")
        for json_option in [(), ('--json',)]:
            with self.fake_ss(body) as (env, directory), open('/dev/full', 'w') as output:
                env['COUNTER'] = str(Path(directory, 'count'))
                result = subprocess.run([BIN, 'list', '--watch', '1ms', *json_option], stdout=output,
                                        stderr=subprocess.PIPE, env=env, timeout=5)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(b'write', result.stderr)
                self.assertEqual(Path(env['COUNTER']).read_text(), '1')
        with self.fake_ss('pass\n') as (env, _):
            process = self.start_watch('list', '--watch', '30ms', '--json', env=env)
            self.watch_document(process)
            process.stdout.close()
            process.stdout = None
            _, stderr = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 1, stderr)
            self.assertIn(b'write JSON output', stderr)

    def test_watch_interrupts_active_refresh_and_reaps_backend(self):
        body = ("import os, pathlib, sys, time\n"
                "counter = pathlib.Path(os.environ['COUNTER'])\n"
                "count = int(counter.read_text()) if counter.exists() else 0\n"
                "counter.write_text(str(count + 1))\n"
                "if count:\n"
                "    print(f'backend:{os.getpid()}', file=sys.stderr, flush=True)\n"
                "    time.sleep(60)\n")
        with self.fake_ss(body) as (env, directory):
            env['COUNTER'] = str(Path(directory, 'count'))
            process = self.start_watch('list', '--watch', '1ms', '--json', env=env)
            self.watch_document(process)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stderr, selectors.EVENT_READ)
                self.assertTrue(selector.select(timeout=5))
                backend = int(process.stderr.readline().split(b':')[1])
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=3)
            self.assertEqual(process.returncode, 130, stderr)
            self.assertEqual(process.watch_buffer + stdout, b'')
            with self.assertRaises(ProcessLookupError):
                os.kill(backend, 0)

    @unittest.skipUnless(SS_AVAILABLE, 'iproute2 ss unavailable')
    def test_watch_live_listener_appears_exits_and_is_replaced(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        watching = self.start_watch('inspect', port, '--watch', '30ms', '--family', 'ipv4',
                                    '--protocol', 'tcp', '--json')
        self.assertEqual(self.watch_document(watching)['sockets'], [])
        first, _ = self.listener(port=port)
        rows = self.watch_until(watching, lambda rows: any(r['pid'] == first.pid for r in rows))
        self.assertIn('--holder', rows[0]['command_line'])
        first.terminate()
        first.wait(timeout=3)
        self.watch_until(watching, lambda rows: not rows)
        replacement, _ = self.listener(port=port)
        self.watch_until(watching, lambda rows: any(r['pid'] == replacement.pid for r in rows))
        watching.send_signal(signal.SIGINT)
        _, stderr = watching.communicate(timeout=3)
        self.assertEqual(watching.returncode, 130, stderr)
        self.assertIsNone(replacement.poll())

    @unittest.skipUnless(SS_AVAILABLE, 'iproute2 ss unavailable')
    def test_watch_reapplies_pid_and_protocol_filters(self):
        first, port = self.listener()
        other, _ = self.listener('udp', port=port)
        args = ('--watch', '30ms', '--family', 'ipv4', '--protocol', 'tcp', '--pid', first.pid, '--json')
        for command in [('list',), ('inspect', port)]:
            watching = self.start_watch(*command, *args)
            rows = self.watch_document(watching)['sockets']
            self.assertEqual([(r['pid'], r['protocol']) for r in rows], [(first.pid, 'tcp')])
            watching.send_signal(signal.SIGINT)
            _, stderr = watching.communicate(timeout=3)
            self.assertEqual(watching.returncode, 130, stderr)
        watching = self.start_watch('inspect', port, *args)
        self.watch_document(watching)
        first.stdin.write('close\n')
        first.stdin.flush()
        self.assertEqual(first.stdout.readline().strip(), 'closed')
        self.watch_until(watching, lambda rows: not rows)
        replacement, _ = self.listener(port=port)
        # Rebinding the port must not switch a PID-filtered watch to the new owner.
        for _ in range(3):
            self.assertEqual(self.watch_document(watching)['sockets'], [])
        watching.send_signal(signal.SIGINT)
        _, stderr = watching.communicate(timeout=3)
        self.assertEqual(watching.returncode, 130, stderr)
        self.assertTrue(all(p.poll() is None for p in (first, other, replacement)))

    def test_pid_arguments(self):
        for command in [("list",), ("inspect", "3000"), ("stop", "3000")]:
            for extra in [("--pid",), ("--pid", "123", "--pid", "123")]:
                self.run_cli(*command, *extra, expected=2)
            for pid in ("", "0", "-1", "+123", " 123", "123 ", "123.0", "123;id",
                        "2147483648", "999999999999999999999999999"):
                self.run_cli(*command, "--pid", pid, expected=2)
        self.run_cli("stop", "--pid", "123", expected=2)
        self.run_cli("stop", "3000", "--pid", "123", "--json", expected=2)

    def test_family_arguments_and_backend_flags(self):
        commands = [("list",), ("inspect", "3000"), ("stop", "3000")]
        for command in commands:
            for extra in [("--family",), ("--family", "ipv4", "--family", "ipv6")]:
                self.run_cli(*command, *extra, expected=2)
            for value in ("", "4", "6", "inet", "IPv4", "ipv4;id", "ipv6 ", "all"):
                self.run_cli(*command, "--family", value, expected=2)
        body = ("import json, os, pathlib, sys\n"
                "pathlib.Path(os.environ['ARGV']).write_text(json.dumps(sys.argv[1:]))\n")
        with self.fake_ss(body) as (env, directory):
            env["ARGV"] = str(Path(directory, "args"))
            for family, flag in [(None, None), ("ipv4", "-4"), ("ipv6", "-6")]:
                for command in commands:
                    extra = ("--family", family) if family else ()
                    self.run_cli(*command, *extra, expected=0 if command[0] == "list" else 3,
                                 env=env)
                    args = json.loads(Path(env["ARGV"]).read_text())
                    expected = ["-H", "-l", "-n", "-t", "-u", "-p", "-O", "-e"]
                    if flag:
                        expected.append(flag)
                    if command[0] != "list":
                        expected += ["sport", "=", ":3000"]
                    self.assertEqual(args, expected)

    def require_ipv6(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 unavailable")
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
                probe.bind(("::1", 0))
        except OSError:
            self.skipTest("IPv6 loopback unavailable")

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_family_queries_and_scoped_stop(self):
        self.require_ipv6()
        real_ss = shutil.which("ss")
        body = ("import json, os, sys\n"
                "with open(os.environ['CALLS'], 'a') as stream:\n"
                "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                f"os.execv({real_ss!r}, [{real_ss!r}, *sys.argv[1:]])\n")
        for protocol in ("tcp", "udp"):
            with self.subTest(protocol=protocol):
                first, port = self.listener(protocol)
                second, _ = self.listener(protocol, family="6", port=port)
                for family, selected, other in [("ipv4", first, second), ("ipv6", second, first)]:
                    result = self.run_cli("inspect", port, "--family", family, "--protocol", protocol,
                                          "--json")
                    self.assertEqual({r["pid"] for r in json.loads(result.stdout)["sockets"]},
                                     {selected.pid})
                    result = self.run_cli("list", "--family", family, "--protocol", protocol,
                                          "--json")
                    pids = {r["pid"] for r in json.loads(result.stdout)["sockets"]}
                    self.assertIn(selected.pid, pids)
                    self.assertNotIn(other.pid, pids)
                    result = self.run_cli("stop", port, "--family", family, "--protocol", protocol,
                                          "--dry-run")
                    self.assertIn(str(selected.pid), result.stdout)
                    self.assertNotIn(str(other.pid), result.stdout)
                with self.fake_ss(body) as (env, directory):
                    env["CALLS"] = str(Path(directory, "calls"))
                    result = self.run_cli("stop", port, "--family", "ipv4", "--protocol", protocol,
                                          "--wait", "3s", input="yes\n", env=env)
                    calls = [json.loads(line) for line in Path(env["CALLS"]).read_text().splitlines()]
                    self.assertEqual(len(calls), 3)
                    self.assertTrue(all("-4" in args and "-6" not in args for args in calls))
                    self.assertTrue(all(args[-3:] == ["sport", "=", f":{port}"] for args in calls))
                self.assertIn("Verifying IPv4 sockets only", result.stdout)
                self.assertIn("no matching listening sockets", result.stdout)
                self.assertEqual(first.wait(timeout=3), -signal.SIGTERM)
                self.assertIsNone(second.poll())
                self.run_cli("inspect", port, "--family", "ipv4", "--protocol", protocol, expected=3)
                self.run_cli("stop", port, "--family", "ipv4", "--protocol", protocol,
                             "--dry-run", expected=3)
                result = self.run_cli("stop", port, "--family", "ipv6", "--protocol", protocol,
                                      "--wait", "3s", input="yes\n")
                self.assertIn("Verifying IPv6 sockets only", result.stdout)
                self.assertEqual(second.wait(timeout=3), -signal.SIGTERM)

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_family_dual_stack_wildcard(self):
        self.require_ipv6()
        for protocol, kind in [("tcp", socket.SOCK_STREAM), ("udp", socket.SOCK_DGRAM)]:
            with self.subTest(protocol=protocol):
                with socket.socket(socket.AF_INET6, kind) as sock:
                    try:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                    except OSError:
                        self.skipTest("dual-stack sockets unavailable")
                    sock.bind(("::", 0))
                    if kind == socket.SOCK_STREAM:
                        sock.listen(4)
                    process, port = self.listener(inherited=sock.fileno())
                if kind == socket.SOCK_STREAM:
                    with socket.create_connection(("127.0.0.1", port), timeout=2):
                        pass
                self.run_cli("inspect", port, "--family", "ipv4", "--protocol", protocol, expected=3)
                result = self.run_cli("inspect", port, "--family", "ipv6", "--protocol", protocol,
                                      "--json")
                self.assertEqual({r["pid"] for r in json.loads(result.stdout)["sockets"]}, {process.pid})
                self.run_cli("stop", port, "--family", "ipv4", "--protocol", protocol,
                             "--dry-run", expected=3)
                self.assertIsNone(process.poll())
                self.run_cli("stop", port, "--family", "ipv6", "--protocol", protocol,
                             "--wait", "3s", input="yes\n")
                self.assertEqual(process.wait(timeout=3), -signal.SIGTERM)

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_family_stop_ignores_unknown_owner_outside_scope(self):
        self.require_ipv6()
        public, port = self.listener()
        private, _ = self.listener(family="6", port=port, behavior="private")
        try:
            os.listdir(f"/proc/{private.pid}/fd")
        except PermissionError:
            pass
        else:
            self.skipTest("caller can bypass non-dumpable proc access restrictions")
        self.run_cli("stop", port, "--dry-run", expected=5)
        self.run_cli("stop", port, "--family", "ipv4", "--wait", "3s", input="yes\n")
        self.assertEqual(public.wait(timeout=3), -signal.SIGTERM)
        self.assertIsNone(private.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_pid_queries_filter_verified_shared_owners(self):
        first, second, port = self.shared_listeners()
        udp, _ = self.listener("udp", port=port)
        for command in [("list",), ("inspect", str(port))]:
            for selected in (first, second):
                for extra in [(), ("--protocol", "tcp", "--family", "ipv4")]:
                    result = self.run_cli(*command, "--pid", selected.pid, "--json", *extra)
                    data = json.loads(result.stdout)
                    self.assertEqual(data["schema_version"], 1)
                    self.assertEqual(len(data["sockets"]), 1)
                    row = data["sockets"][0]
                    self.assertEqual((row["pid"], row["port"], row["protocol"]),
                                     (selected.pid, port, "tcp"))
                    self.assertEqual("command_line" in row, command[0] == "inspect")
                result = self.run_cli(*command, "--pid", selected.pid, "--protocol", "tcp")
                self.assertIn(str(selected.pid), result.stdout)
                self.assertNotIn(str(second.pid if selected is first else first.pid), result.stdout)
        self.run_cli("inspect", "--pid", udp.pid, port, "--protocol", "udp", "--family", "ipv4")
        self.assertTrue(all(p.poll() is None for p in (first, second, udp)))

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_pid_queries_empty_mismatched_and_exited(self):
        first, port = self.listener()
        other, _ = self.listener()
        exited, _ = self.listener()
        exited.terminate()
        exited.wait(timeout=3)
        cases = [(other.pid, ()), (exited.pid, ()),
                 (first.pid, ("--protocol", "udp")), (first.pid, ("--family", "ipv6"))]
        for pid, extra in cases:
            for json_option in [(), ("--json",)]:
                result = self.run_cli("inspect", port, "--pid", pid, *extra, *json_option, expected=3)
                self.assertIn("no matching", result.stderr)
                if json_option:
                    self.assertEqual(json.loads(result.stdout), {"schema_version": 1, "sockets": []})
        for json_option in [(), ("--json",)]:
            result = self.run_cli("list", "--pid", exited.pid, *json_option)
            if json_option:
                self.assertEqual(json.loads(result.stdout), {"schema_version": 1, "sockets": []})
        self.assertIsNone(first.poll())
        self.assertIsNone(other.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_pid_list_collects_multiple_ports(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            tcp.listen(4)
            udp.bind(("127.0.0.1", 0))
            ports = {("tcp", tcp.getsockname()[1]), ("udp", udp.getsockname()[1])}
            process = subprocess.Popen(
                [sys.executable, "-c", "import sys; print('ready', flush=True); sys.stdin.read()"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                pass_fds=(tcp.fileno(), udp.fileno()))
            self.addCleanup(self.cleanup_process, process)
            self.assertEqual(process.stdout.readline().strip(), "ready")
        for extra, expected in [((), ports), (("--protocol", "tcp"), {p for p in ports if p[0] == "tcp"})]:
            result = self.run_cli("list", "--pid", process.pid, "--family", "ipv4", "--json", *extra)
            rows = json.loads(result.stdout)["sockets"]
            self.assertEqual({(r["protocol"], r["port"]) for r in rows}, expected)
            self.assertTrue(all(r["pid"] == process.pid for r in rows))
        self.assertIsNone(process.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_pid_queries_keep_visibility_warning_with_visible_match(self):
        public, port = self.listener()
        private, _ = self.listener("udp", port=port, behavior="private")
        try:
            os.listdir(f"/proc/{private.pid}/fd")
        except PermissionError:
            pass
        else:
            self.skipTest("caller can bypass non-dumpable proc access restrictions")
        for command in [("list",), ("inspect", str(port))]:
            result = self.run_cli(*command, "--pid", public.pid, "--family", "ipv4", "--json")
            rows = json.loads(result.stdout)["sockets"]
            self.assertEqual([(r["pid"], r["port"]) for r in rows], [(public.pid, port)])
            self.assertEqual(result.stderr.count("some owners are unavailable"), 1)
            result = self.run_cli(*command, "--pid", private.pid, "--json",
                                  expected=0 if command[0] == "list" else 3)
            self.assertEqual(json.loads(result.stdout), {"schema_version": 1, "sockets": []})
            self.assertEqual(result.stderr.count("some owners are unavailable"), 1)
        self.assertIsNone(public.poll())
        self.assertIsNone(private.poll())

    def test_pid_queries_reject_unverified_claims_and_keep_warnings(self):
        # Even a claim naming this live PID must not survive inode verification.
        output = (f'tcp LISTEN 0 4 127.0.0.1:3000 0.0.0.0:* '
                  f'users:(("claimed",pid={os.getpid()},fd=999999)) ino:1 sk:1\n'
                  'tcp LISTEN 0 4 127.0.0.1:3000 0.0.0.0:* ino:2 sk:2\n')
        with self.fake_ss(f"print({output!r})\n") as (env, _):
            for command, code in [(("list",), 0), (("inspect", "3000"), 3)]:
                result = self.run_cli(*command, "--pid", os.getpid(), "--json", expected=code, env=env)
                self.assertEqual(json.loads(result.stdout), {"schema_version": 1, "sockets": []})
                self.assertEqual(result.stderr.count("some owners are unavailable"), 1)

    def test_malformed_ss_and_unknown_owner(self):
        for output in ["broken", "tcp LISTEN 0 5 *:80 *:*", "bad\x00data"]:
            with self.fake_ss(f"import sys\nsys.stdout.write({output!r})\n") as (env, _):
                self.run_cli("list", env=env, expected=4)
        row = "tcp LISTEN 0 5 *:12345 *:* ino:999 sk:1 <->\n"
        with self.fake_ss(f"print({row!r})\n") as (env, _):
            result = self.run_cli("inspect", 12345, env=env)
            self.assertIn("<unavailable>", result.stdout)
            self.run_cli("stop", 12345, "--dry-run", env=env, expected=5)

    def test_partial_malformed_owner_metadata_refuses_stop(self):
        process, port = self.listener()
        descriptors = Path(f"/proc/{process.pid}/fd")
        descriptor = next(path for path in descriptors.iterdir()
                          if os.readlink(path).startswith("socket:["))
        inode = os.readlink(descriptor)[8:-1]
        row = (f'tcp LISTEN 0 4 127.0.0.1:{port} 0.0.0.0:* '
               f'users:(("valid",pid={process.pid},fd={descriptor.name}),'
               f'("invalid",pid=99999999999999999999999999,fd=4)) ino:{inode} sk:1')
        with self.fake_ss(f"print({row!r})\n") as (env, _):
            for command in ("inspect", "stop"):
                result = self.run_cli(command, port, input="yes\n", expected=4, env=env)
                self.assertIn("cannot parse ss record", result.stderr)
                self.assertIsNone(process.poll())

    def test_empty_and_filter(self):
        with self.fake_ss("pass\n") as (env, _):
            self.run_cli("list", env=env)
            self.run_cli("inspect", 12345, env=env, expected=3)
            self.run_cli("stop", 12345, env=env, expected=3)
        # A fake backend ignoring sport still must not expose unrelated ports.
        with self.fake_ss("print('tcp LISTEN 0 5 *:12346 *:* ino:9 sk:1')\n") as (env, _):
            self.run_cli("inspect", 12345, env=env, expected=3)

    def test_json_empty_results(self):
        with self.fake_ss("pass\n") as (env, _):
            for args, expected in [(("list", "--json"), 0),
                                   (("inspect", "12345", "--json"), 3)]:
                result = self.run_cli(*args, expected=expected, env=env)
                self.assertEqual(json.loads(result.stdout), {"schema_version": 1, "sockets": []})
                self.assertTrue(result.stdout.endswith("\n"))
                if expected == 3:
                    self.assertIn("no matching", result.stderr)

    def test_json_unknown_owners_and_filtering(self):
        output = ("udp UNCONN 0 0 [::1]:5353 [::]:* ino:12 sk:2\n"
                  "tcp LISTEN 0 4 127.0.0.1:3000 0.0.0.0:* ino:11 sk:1\n")
        with self.fake_ss(f"print({output!r})\n") as (env, _):
            result = self.run_cli("list", "--json", env=env)
            data = json.loads(result.stdout)
            self.assertEqual(set(data), {"schema_version", "sockets"})
            self.assertEqual(data["schema_version"], 1)
            self.assertEqual(data["sockets"], [
                {"port": 3000, "protocol": "tcp", "local_address": "127.0.0.1:3000",
                 "pid": None, "process": None},
                {"port": 5353, "protocol": "udp", "local_address": "[::1]:5353",
                 "pid": None, "process": None}])
            self.assertIn("permissions", result.stderr)
            result = self.run_cli("list", "--protocol", "udp", "--json", env=env)
            self.assertEqual(len(json.loads(result.stdout)["sockets"]), 1)
            result = self.run_cli("inspect", "--json", 3000, env=env)
            row = json.loads(result.stdout)["sockets"][0]
            self.assertIsNone(row["command_line"])
            self.assertIsNone(row["command_line_truncated"])

    def test_json_errors_leave_stdout_empty(self):
        for args in [("list", "--json", "--json"), ("stop", "3000", "--json"),
                     ("inspect", "invalid", "--json"), ("--json", "list")]:
            result = self.run_cli(*args, expected=2)
            self.assertEqual(result.stdout, "")
        for body in (None, "print('tcp LISTEN 0 4 *:3000 *:* ino:1 sk:1')\nprint('broken')\n"):
            with self.fake_ss(body) as (env, _):
                result = self.run_cli("list", "--json", env=env, expected=4)
                self.assertEqual(result.stdout, "")

    def test_json_write_failure(self):
        with self.fake_ss("pass\n") as (env, _), open("/dev/full", "w") as output:
            result = subprocess.run([BIN, "list", "--json"], stdout=output,
                                    stderr=subprocess.PIPE, text=True, env=env, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertIn("write JSON output", result.stderr)

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_json_live_details_and_escaping(self):
        argument = 'quoted "value" \\ path\n\t\x1b Unicode: \u0394'
        sanitized = ''.join(chr(b) if 32 <= b < 127 else '?' for b in argument.encode())
        for protocol in ("tcp", "udp"):
            with self.subTest(protocol=protocol):
                process, port = self.listener(protocol, extra_args=(argument,), name='p"k\\test')
                result = self.run_cli("inspect", port, "--json", "--protocol", protocol)
                row = json.loads(result.stdout)["sockets"][0]
                self.assertEqual(row["port"], port)
                self.assertEqual(row["protocol"], protocol)
                self.assertIs(type(row["pid"]), int)
                self.assertEqual(row["pid"], process.pid)
                self.assertEqual(row["process"], 'p"k\\test')
                self.assertIn(sanitized, row["command_line"])
                self.assertIs(row["command_line_truncated"], False)
                result = self.run_cli("list", "--json", "--protocol", protocol)
                rows = [r for r in json.loads(result.stdout)["sockets"] if r["pid"] == process.pid]
                self.assertEqual(len(rows), 1)
                self.assertNotIn("command_line", rows[0])

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_json_process_name_is_not_availability_marker(self):
        process, port = self.listener(name="<unavailable>")
        result = self.run_cli("inspect", port, "--json", "--protocol", "tcp")
        row = json.loads(result.stdout)["sockets"][0]
        self.assertEqual(row["pid"], process.pid)
        self.assertEqual(row["process"], "<unavailable>")

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_json_command_line_size_boundary(self):
        prefix = [sys.executable, __file__, "--holder", "4", "tcp", "0", ""]
        prefix_size = sum(len(os.fsencode(arg)) + 1 for arg in prefix)
        for raw_size in (4095, 4096, 5000):
            with self.subTest(raw_size=raw_size):
                payload = "x" * (raw_size - prefix_size - 1)
                process, port = self.listener(extra_args=(payload,))
                result = self.run_cli("inspect", port, "--json", "--protocol", "tcp")
                row = json.loads(result.stdout)["sockets"][0]
                self.assertEqual(row["pid"], process.pid)
                self.assertIs(row["command_line_truncated"], raw_size > 4095)
                self.assertLessEqual(len(row["command_line"]), 4095)

    def test_exec_arguments(self):
        with self.fake_ss("import json, sys\nprint(json.dumps(sys.argv), file=sys.stderr)\n") as (env, _):
            result = self.run_cli("inspect", "0012345", env=env, expected=3)
            args = json.loads(result.stderr.splitlines()[0])
            self.assertEqual(args[1:10], ["-H", "-l", "-n", "-t", "-u", "-p", "-O", "-e", "sport"])
            self.assertEqual(args[-2:], ["=", ":12345"])
            result = self.run_cli("list", env=env)
            self.assertEqual(json.loads(result.stderr)[-1], "-e")

    def test_interrupt_ss(self):
        with self.fake_ss("import os, time\nopen(os.environ['CHILD_FILE'], 'w').write(str(os.getpid()))\ntime.sleep(60)\n") as (env, directory):
            marker = Path(directory, "child")
            env["CHILD_FILE"] = str(marker)
            process = subprocess.Popen([BIN, "list"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            self.addCleanup(self.cleanup_process, process)
            deadline = time.monotonic() + 5
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(marker.exists())
            process.send_signal(signal.SIGINT)
            process.communicate(timeout=5)
            self.assertEqual(process.returncode, 130)
            self.assertFalse(Path("/proc", marker.read_text()).exists())

    def test_ss_output_limit(self):
        with self.fake_ss("import sys\nsys.stdout.write('x' * (17 * 1024 * 1024))\n") as (env, _):
            result = self.run_cli("list", env=env, expected=1)
            self.assertIn("16 MiB", result.stderr)

    def test_ss_timeout(self):
        # Closing stdout must not make the subsequent waitpid block forever.
        with self.fake_ss("import os, time\nos.close(1)\ntime.sleep(60)\n") as (env, _):
            started = time.monotonic()
            result = self.run_cli("list", env=env, expected=4)
            self.assertIn("timed out", result.stderr)
            self.assertLess(time.monotonic() - started, 22)

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_live_tcp_and_dry_run(self):
        process, port = self.listener()
        result = self.run_cli("inspect", port, "--protocol", "tcp")
        self.assertIn(str(process.pid), result.stdout)
        self.assertIn("TCP", result.stdout)
        self.assertIn("--holder", result.stdout)
        self.assertIn(str(port), self.run_cli("list").stdout)
        result = self.run_cli("stop", port, "--protocol", "tcp", "--dry-run")
        self.assertIn("No signals sent", result.stdout)
        self.assertIsNone(process.poll())
        self.run_cli("inspect", port, "--protocol", "udp", expected=3)

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_live_udp_stop(self):
        process, port = self.listener("udp")
        result = self.run_cli("inspect", port, "--protocol", "udp")
        self.assertIn(str(process.pid), result.stdout)
        self.run_cli("stop", port, "--protocol", "udp", input="yes\n")
        self.assertEqual(process.wait(timeout=3), -signal.SIGTERM)

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_wait_exit_and_socket_release(self):
        for protocol, duration in [("tcp", "3s"), ("udp", "3")]:
            with self.subTest(protocol=protocol):
                process, port = self.listener(protocol)
                result = self.run_cli("stop", port, "--wait", duration, input="yes\n")
                # The parent has not waited/reaped the holder yet: pidfd
                # readability must count a zombie as exited, not still alive.
                self.assertIn(f"PID {process.pid} exited.", result.stdout)
                self.assertIn("Processes: 1/1 exited.", result.stdout)
                self.assertIn("no matching listening sockets", result.stdout)
                self.assertEqual(process.wait(timeout=3), -signal.SIGTERM)

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_wait_timeout_while_still_listening(self):
        process, port = self.listener(behavior="ignore")
        started = time.monotonic()
        result = self.run_cli("stop", port, "--wait", "150ms", input="yes\n", expected=8)
        self.assertGreaterEqual(time.monotonic() - started, 0.14)
        self.assertLess(time.monotonic() - started, 4)
        self.assertIn("Processes: 0/1 exited.", result.stdout)
        self.assertIn(f"PID {process.pid} still running", result.stdout)
        self.assertIn("matching listening sockets remain", result.stdout)
        self.assertIsNone(process.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_wait_timeout_after_socket_release(self):
        process, port = self.listener(behavior="close")
        result = self.run_cli("stop", port, "--wait", "150ms", input="yes\n", expected=8)
        self.assertIn("still running", result.stdout)
        self.assertIn("no matching listening sockets", result.stdout)
        self.assertIsNone(process.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_wait_reports_replacement_without_signaling_it(self):
        process, port = self.listener(behavior="close")
        stopping = self.pending_stop(port, "--wait", "3s")
        stopping.stdin.write(b"yes\n")
        stopping.stdin.flush()
        self.read_until(process, b"closed")
        # Rebind after SIGTERM, before the original target exits. This models
        # a service replacing its listener while shutdown is still underway.
        replacement, _ = self.listener(port=port)
        process.stdin.close()
        stdout, stderr = stopping.communicate(timeout=8)
        self.assertEqual(stopping.returncode, 9, stdout + stderr)
        self.assertIn(f"PID {process.pid} exited.".encode(), stdout)
        self.assertIn("matching listening sockets remain", stdout.decode())
        self.assertIn(str(replacement.pid).encode(), stdout)
        self.assertIsNone(replacement.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_wait_dry_run_does_not_signal_or_wait(self):
        process, port = self.listener(behavior="ignore")
        result = self.run_cli("stop", port, "--wait", "3600s", "--dry-run")
        self.assertIn("No signals sent", result.stdout)
        self.assertNotIn("Waiting", result.stdout)
        self.assertIsNone(process.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_interrupt_wait(self):
        process, port = self.listener(behavior="ignore")
        stopping = self.pending_stop(port, "--wait", "3600s")
        stopping.stdin.write(b"yes\n")
        stopping.stdin.flush()
        self.read_until(stopping, b"Waiting up to")
        stopping.send_signal(signal.SIGINT)
        stopping.communicate(timeout=3)
        self.assertEqual(stopping.returncode, 130)
        self.assertIsNone(process.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_wait_verification_backend_failure(self):
        process, port = self.listener()
        real_ss = shutil.which("ss")
        body = ("import os, pathlib, sys\n"
                "counter = pathlib.Path(os.environ['COUNTER'])\n"
                "count = int(counter.read_text()) if counter.exists() else 0\n"
                "counter.write_text(str(count + 1))\n"
                "if count >= 2: sys.exit(1)\n"
                f"os.execv({real_ss!r}, [{real_ss!r}, *sys.argv[1:]])\n")
        with self.fake_ss(body) as (env, directory):
            env["COUNTER"] = str(Path(directory, "count"))
            result = self.run_cli("stop", port, "--wait", "3s", input="yes\n",
                                  expected=4, env=env)
            self.assertIn(f"PID {process.pid} exited.", result.stdout)
            self.assertIn("socket state could not be verified", result.stderr)
            self.assertNotIn("no matching listening sockets", result.stdout)

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_stop_protocol_scope(self):
        tcp, port = self.listener("tcp")
        udp, _ = self.listener("udp", port=port)
        result = self.run_cli("stop", port, "--protocol", "tcp", "--wait", "3s", input="yes\n")
        self.assertIn("no matching listening sockets (TCP)", result.stdout)
        self.assertEqual(tcp.wait(timeout=3), -signal.SIGTERM)
        self.assertIsNone(udp.poll())

    @unittest.skipUnless(SS_AVAILABLE and socket.has_ipv6, "IPv6/ss unavailable")
    def test_live_ipv6(self):
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
                probe.bind(("::1", 0))
        except OSError:
            self.skipTest("IPv6 loopback unavailable")
        process, port = self.listener(family="6")
        result = self.run_cli("inspect", port)
        self.assertIn(str(process.pid), result.stdout)
        self.assertIn("[::1]", result.stdout)

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_cancel_and_eof(self):
        process, port = self.listener()
        for answer in ["no\n", "YES\n", "yes please\n", ""]:
            self.run_cli("stop", port, input=answer, expected=7)
            self.assertIsNone(process.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_exit_and_port_reuse_during_confirmation(self):
        process, port = self.listener()
        stopping = self.pending_stop(port)
        process.terminate()
        process.wait(timeout=3)
        replacement, _ = self.listener(port=port)
        stdout, stderr = stopping.communicate(b"yes\n", timeout=8)
        self.assertEqual(stopping.returncode, 6, stdout + stderr)
        self.assertIsNone(replacement.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_socket_closed_during_confirmation(self):
        process, port = self.listener()
        stopping = self.pending_stop(port)
        process.stdin.write("close\n")
        process.stdin.flush()
        self.assertEqual(process.stdout.readline().strip(), "closed")
        stdout, stderr = stopping.communicate(b"yes\n", timeout=8)
        self.assertEqual(stopping.returncode, 6, stdout + stderr)
        self.assertIsNone(process.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_interrupt_confirmation(self):
        process, port = self.listener()
        stopping = self.pending_stop(port)
        stopping.send_signal(signal.SIGINT)
        stopping.communicate(timeout=5)
        self.assertEqual(stopping.returncode, 130)
        self.assertIsNone(process.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_multiple_owners(self):
        first, second, port = self.shared_listeners()
        result = self.run_cli("inspect", port)
        self.assertIn(str(first.pid), result.stdout)
        self.assertIn(str(second.pid), result.stdout)
        result = self.run_cli("inspect", port, "--json", "--protocol", "tcp")
        rows = json.loads(result.stdout)["sockets"]
        self.assertEqual({r["pid"] for r in rows}, {first.pid, second.pid})
        self.assertEqual(len(rows), 2)
        result = self.run_cli("stop", port, "--wait", "3s", input="yes\n")
        self.assertIn("Processes: 2/2 exited.", result.stdout)
        self.assertIn("no matching listening sockets", result.stdout)
        self.assertEqual(first.wait(timeout=3), -signal.SIGTERM)
        self.assertEqual(second.wait(timeout=3), -signal.SIGTERM)

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_pid_selected_shared_stop_and_dry_run(self):
        first, second, port = self.shared_listeners()
        result = self.run_cli("stop", "--pid", first.pid, port, "--protocol", "tcp", "--dry-run")
        self.assertIn(f"Only PID {first.pid} is selected", result.stdout)
        self.assertIn("would send SIGTERM to 1 process(es)", result.stdout)
        self.assertNotIn("Type 'yes'", result.stdout)
        self.assertIsNone(first.poll())
        self.assertIsNone(second.poll())
        result = self.run_cli("stop", port, "--pid", first.pid, "--protocol", "tcp", input="yes\n")
        self.assertIn(f"Sent SIGTERM to PID {first.pid}.", result.stdout)
        self.assertNotIn(f"Sent SIGTERM to PID {second.pid}.", result.stdout)
        self.assertEqual(first.wait(timeout=3), -signal.SIGTERM)
        self.assertIsNone(second.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_pid_selected_wait_reports_remaining_owner(self):
        first, second, port = self.shared_listeners()
        result = self.run_cli("stop", port, "--pid", first.pid, "--protocol", "tcp",
                              "--wait", "3s", input="yes\n", expected=9)
        self.assertIn("Processes: 1/1 exited.", result.stdout)
        self.assertIn("matching listening sockets remain", result.stdout)
        self.assertIn(str(second.pid), result.stdout)
        self.assertNotIn(f"Sent SIGTERM to PID {second.pid}.", result.stdout)
        self.assertEqual(first.wait(timeout=3), -signal.SIGTERM)
        self.assertIsNone(second.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_pid_non_owner_and_exited_pid_refused(self):
        owner, port = self.listener()
        other, _ = self.listener()
        exited, _ = self.listener()
        exited.terminate()
        exited.wait(timeout=3)
        for pid in (other.pid, exited.pid):
            result = self.run_cli("stop", port, "--pid", pid, "--protocol", "tcp",
                                  input="yes\n", expected=3)
            self.assertIn("not a verified owner", result.stderr)
            self.assertNotIn("Type 'yes'", result.stdout)
            self.assertIsNone(owner.poll())
            self.assertIsNone(other.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_pid_protocol_scope(self):
        tcp, port = self.listener("tcp")
        udp, _ = self.listener("udp", port=port)
        self.run_cli("stop", port, "--pid", tcp.pid, "--protocol", "udp",
                     "--dry-run", expected=3)
        self.assertIsNone(tcp.poll())
        self.assertIsNone(udp.poll())
        result = self.run_cli("stop", port, "--pid", udp.pid, "--protocol", "udp",
                              "--wait", "3s", input="yes\n")
        self.assertIn("no matching listening sockets (UDP)", result.stdout)
        self.assertEqual(udp.wait(timeout=3), -signal.SIGTERM)
        self.assertIsNone(tcp.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_pid_selected_timeout_leaves_other_owner_alive(self):
        tcp, port = self.listener("tcp", behavior="ignore")
        udp, _ = self.listener("udp", port=port)
        result = self.run_cli("stop", port, "--pid", tcp.pid, "--wait", "150ms",
                              input="yes\n", expected=8)
        self.assertIn("Processes: 0/1 exited.", result.stdout)
        self.assertNotIn(f"Sent SIGTERM to PID {udp.pid}.", result.stdout)
        self.assertIsNone(tcp.poll())
        self.assertIsNone(udp.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_pid_selected_exit_and_replacement_during_confirmation(self):
        process, port = self.listener()
        stopping = self.pending_stop(port, "--pid", str(process.pid), "--protocol", "tcp")
        process.terminate()
        process.wait(timeout=3)
        replacement, _ = self.listener(port=port)
        stdout, stderr = stopping.communicate(b"yes\n", timeout=8)
        self.assertEqual(stopping.returncode, 6, stdout + stderr)
        self.assertNotIn(b"Sent SIGTERM", stdout)
        self.assertIsNone(replacement.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_pid_selected_socket_changes_during_confirmation(self):
        for close_selected in (True, False):
            with self.subTest(close_selected=close_selected):
                first, second, port = self.shared_listeners()
                stopping = self.pending_stop(port, "--pid", str(first.pid), "--protocol", "tcp",
                                             "--family", "ipv4")
                closer = first if close_selected else second
                closer.stdin.write("close\n")
                closer.stdin.flush()
                self.assertEqual(closer.stdout.readline().strip(), "closed")
                stdout, stderr = stopping.communicate(b"yes\n", timeout=8)
                self.assertEqual(stopping.returncode, 6, stdout + stderr)
                self.assertNotIn(b"Sent SIGTERM", stdout)
                self.assertIsNone(first.poll())
                self.assertIsNone(second.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_pid_selected_stop_still_requires_confirmation(self):
        first, second, port = self.shared_listeners()
        for answer in ("", "no\n"):
            result = self.run_cli("stop", port, "--pid", first.pid, "--protocol", "tcp",
                                  input=answer, expected=7)
            self.assertIn("Type 'yes'", result.stdout)
            self.assertNotIn("Sent SIGTERM", result.stdout)
            self.assertIsNone(first.poll())
            self.assertIsNone(second.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_pid_selection_does_not_bypass_unknown_owner(self):
        public, port = self.listener("tcp")
        private, _ = self.listener("udp", port=port, behavior="private")
        try:
            os.listdir(f"/proc/{private.pid}/fd")
        except PermissionError:
            pass
        else:
            self.skipTest("caller can bypass non-dumpable proc access restrictions")
        result = self.run_cli("stop", port, "--pid", public.pid, "--family", "ipv4",
                              input="yes\n", expected=5)
        self.assertIn("no signals sent", result.stderr)
        self.assertNotIn("Type 'yes'", result.stdout)
        self.assertIsNone(public.poll())
        self.assertIsNone(private.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_wait_partial_exit(self):
        tcp, port = self.listener("tcp")
        udp, _ = self.listener("udp", port=port, behavior="ignore")
        result = self.run_cli("stop", port, "--wait", "150ms", input="yes\n", expected=8)
        self.assertIn(f"PID {tcp.pid} exited.", result.stdout)
        self.assertIn(f"PID {udp.pid} still running", result.stdout)
        self.assertIn("Processes: 1/2 exited.", result.stdout)
        self.assertIn("matching listening sockets remain", result.stdout)
        self.assertEqual(tcp.wait(timeout=3), -signal.SIGTERM)
        self.assertIsNone(udp.poll())

    @unittest.skipUnless(SS_AVAILABLE, "iproute2 ss unavailable")
    def test_permission_restricted_owner(self):
        for protocol in ("tcp", "udp"):
            with self.subTest(protocol=protocol):
                process, port = self.listener(protocol, behavior="private")
                try:
                    os.listdir(f"/proc/{process.pid}/fd")
                except PermissionError:
                    pass
                else:
                    self.skipTest("caller can bypass non-dumpable proc access restrictions")
                result = self.run_cli("inspect", port, "--protocol", protocol)
                self.assertIn("<unavailable>", result.stdout)
                self.assertIn("permissions", result.stderr)
                result = self.run_cli("inspect", port, "--json", "--protocol", protocol)
                row = json.loads(result.stdout)["sockets"][0]
                for field in ("pid", "process", "command_line", "command_line_truncated"):
                    self.assertIsNone(row[field])
                for extra in ((), ("--dry-run",), ("--wait", "100ms"),
                              ("--pid", str(process.pid))):
                    result = self.run_cli("stop", port, "--protocol", protocol, *extra,
                                          input="yes\n", expected=5)
                    self.assertIn("no signals sent", result.stderr)
                    self.assertIsNone(process.poll())

    @unittest.skipUnless(SS_AVAILABLE and os.geteuid() == 0,
                         "requires root to create a different-UID caller")
    def test_cross_user_owner(self):
        # The test-owned listener stays root-owned. Only the CLI subprocess
        # drops credentials; no users or system settings are changed.
        with tempfile.TemporaryDirectory(prefix="portkeeper-cross-user-") as directory:
            os.chmod(directory, 0o755)
            executable = Path(directory, "portkeeper")
            shutil.copy2(BIN, executable)
            executable.chmod(0o755)

            def drop_credentials():
                os.setgroups([])
                os.setgid(65534)
                os.setuid(65534)

            for protocol in ("tcp", "udp"):
                process, port = self.listener(protocol)
                for command, expected in (("inspect", 0), ("stop", 5)):
                    result = subprocess.run(
                        [str(executable), command, str(port), "--protocol", protocol],
                        input="yes\n", text=True, capture_output=True, timeout=10,
                        env=dict(os.environ, PATH="/usr/bin:/bin"),
                        preexec_fn=drop_credentials)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    self.assertIn("<unavailable>", result.stdout)
                    if command == "stop":
                        self.assertIn("no signals sent", result.stderr)
                    self.assertIsNone(process.poll())


if __name__ == "__main__":
    unittest.main(verbosity=2)
