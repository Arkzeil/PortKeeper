#!/usr/bin/env python3
"""Real sockets/processes plus isolated ss failure fixtures; no privileged ports."""
import contextlib
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
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream:
                stream.close()

    def listener(self, protocol="tcp", family="4", port=0, inherited=None):
        args = [sys.executable, __file__, "--holder"]
        args += ["inherit", str(inherited)] if inherited is not None else [family, protocol, str(port)]
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True,
                                   pass_fds=() if inherited is None else (inherited,))
        self.addCleanup(self.cleanup_process, process)
        line = process.stdout.readline()
        self.assertTrue(line, process.stderr.read() if process.poll() is not None else "holder failed")
        return process, int(line)

    def pending_stop(self, port, *extra):
        process = subprocess.Popen([BIN, "stop", str(port), *extra], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.cleanup_process, process)
        output = b""
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            deadline = time.monotonic() + 8
            while b"Type 'yes'" not in output:
                self.assertLess(time.monotonic(), deadline, output.decode(errors="replace"))
                if not selector.select(timeout=0.2):
                    continue
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    self.fail(output.decode(errors="replace") + process.stderr.read().decode())
                output += chunk
        return process

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
        for port in ["0", "65536", "-1", "+80", "80;touch /tmp/should-not-exist",
                     "80\n", "", "999999999999999999999999999"]:
            self.run_cli("inspect", port, expected=2)

    def test_missing_and_failed_ss(self):
        with self.fake_ss() as (env, _):
            result = self.run_cli("list", env=env, expected=4)
            self.assertIn("iproute2", result.stderr)
        with self.fake_ss("import sys\nprint('partial output')\nsys.exit(1)\n") as (env, _):
            self.run_cli("list", env=env, expected=4)

    def test_malformed_ss_and_unknown_owner(self):
        for output in ["broken", "tcp LISTEN 0 5 *:80 *:*", "bad\x00data"]:
            with self.fake_ss(f"import sys\nsys.stdout.write({output!r})\n") as (env, _):
                self.run_cli("list", env=env, expected=4)
        row = "tcp LISTEN 0 5 *:12345 *:* ino:999 sk:1 <->\n"
        with self.fake_ss(f"print({row!r})\n") as (env, _):
            result = self.run_cli("inspect", 12345, env=env)
            self.assertIn("<unavailable>", result.stdout)
            self.run_cli("stop", 12345, "--dry-run", env=env, expected=5)

    def test_empty_and_filter(self):
        with self.fake_ss("pass\n") as (env, _):
            self.run_cli("list", env=env)
            self.run_cli("inspect", 12345, env=env, expected=3)
            self.run_cli("stop", 12345, env=env, expected=3)
        # A fake backend ignoring sport still must not expose unrelated ports.
        with self.fake_ss("print('tcp LISTEN 0 5 *:12346 *:* ino:9 sk:1')\n") as (env, _):
            self.run_cli("inspect", 12345, env=env, expected=3)

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
    def test_stop_protocol_scope(self):
        tcp, port = self.listener("tcp")
        udp, _ = self.listener("udp", port=port)
        self.run_cli("stop", port, "--protocol", "tcp", input="yes\n")
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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as shared:
            shared.bind(("127.0.0.1", 0))
            shared.listen(4)
            first, port = self.listener(inherited=shared.fileno())
            second, _ = self.listener(inherited=shared.fileno())
        result = self.run_cli("inspect", port)
        self.assertIn(str(first.pid), result.stdout)
        self.assertIn(str(second.pid), result.stdout)
        self.run_cli("stop", port, input="yes\n")
        self.assertEqual(first.wait(timeout=3), -signal.SIGTERM)
        self.assertEqual(second.wait(timeout=3), -signal.SIGTERM)


if __name__ == "__main__":
    unittest.main(verbosity=2)
