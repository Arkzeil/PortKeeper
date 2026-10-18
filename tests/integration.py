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

    def listener(self, protocol="tcp", family="4", port=0, inherited=None, behavior=None):
        args = [sys.executable, __file__, "--holder"]
        args += ["inherit", str(inherited)] if inherited is not None else [family, protocol, str(port)]
        if behavior:
            self.assertIsNone(inherited)
            args.append(behavior)
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
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as shared:
            shared.bind(("127.0.0.1", 0))
            shared.listen(4)
            first, port = self.listener(inherited=shared.fileno())
            second, _ = self.listener(inherited=shared.fileno())
        result = self.run_cli("inspect", port)
        self.assertIn(str(first.pid), result.stdout)
        self.assertIn(str(second.pid), result.stdout)
        result = self.run_cli("stop", port, "--wait", "3s", input="yes\n")
        self.assertIn("Processes: 2/2 exited.", result.stdout)
        self.assertIn("no matching listening sockets", result.stdout)
        self.assertEqual(first.wait(timeout=3), -signal.SIGTERM)
        self.assertEqual(second.wait(timeout=3), -signal.SIGTERM)

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
                for extra in ((), ("--dry-run",), ("--wait", "100ms")):
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
