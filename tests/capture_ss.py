#!/usr/bin/env python3
"""Record normalized output from a supplied ss binary, using only owned sockets."""
import ctypes
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys


def worker(private):
    sockets = []
    for family, kind in [(socket.AF_INET, socket.SOCK_STREAM),
                         (socket.AF_INET, socket.SOCK_DGRAM),
                         (socket.AF_INET6, socket.SOCK_STREAM),
                         (socket.AF_INET6, socket.SOCK_DGRAM)][:1 if private else 4]:
        sock = socket.socket(family, kind)
        sock.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
        if kind == socket.SOCK_STREAM:
            sock.listen(4)
        sockets.append(sock)
    child = None
    if private:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(4, 0, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_DUMPABLE")
    else:
        child = os.fork()
        if child == 0:
            for sock in sockets[1:]:
                sock.close()
            while True:
                signal.pause()
    print(json.dumps({"pid": os.getpid(), "child": child,
                      "ports": [s.getsockname()[1] for s in sockets]}), flush=True)
    try:
        sys.stdin.read()
    finally:
        if child:
            os.kill(child, signal.SIGTERM)
            os.waitpid(child, 0)
        for sock in sockets:
            sock.close()


def capture(executable, destination):
    workers = []
    try:
        info = []
        for mode in ("public", "private"):
            process = subprocess.Popen([sys.executable, __file__, "--worker", mode],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            workers.append(process)
            info.append(json.loads(process.stdout.readline()))
        version = subprocess.check_output([executable, "-V"], text=True).strip()
        args = [executable, "-H", "-l", "-n", "-t", "-u", "-p", "-O", "-e"]
        output = subprocess.check_output(args, text=True, env=dict(os.environ, LC_ALL="C"))
        ports = dict(zip(info[0]["ports"] + info[1]["ports"], [3000, 5353, 8080, 5354, 9000]))
        pids = {info[0]["pid"]: 1001, info[0]["child"]: 1002, info[1]["pid"]: 1003}
        recorded = []
        for line in output.splitlines():
            fields = line.split()
            port = int(fields[4].rsplit(":", 1)[1])
            if port not in ports:
                continue
            # A port is protocol-specific; avoid recording an unrelated UDP
            # socket coincidentally using the same ephemeral TCP number.
            expected_protocol = "udp" if ports[port] in (5353, 5354) else "tcp"
            if fields[0] != expected_protocol:
                continue
            line = re.sub(rf":{port}(?=\s)", f":{ports[port]}", line)
            line = re.sub(r"pid=(\d+)", lambda m: f"pid={pids[int(m[1])]}", line)
            line = re.sub(r"ino:\d+", f"ino:{70000 + list(ports).index(port) + 1}", line)
            line = re.sub(r"sk:[0-9a-f]+", f"sk:{list(ports).index(port) + 1}", line)
            line = re.sub(r"uid:\d+", "uid:1000", line)
            line = re.sub(r"cgroup:\S+", "cgroup:/fixture", line)
            recorded.append(line.rstrip())
        if len(recorded) != 5 or "pid=1003" in "\n".join(recorded):
            raise RuntimeError("expected four public sockets and one restricted socket; run unprivileged")
        Path(destination).write_text("\n".join(sorted(recorded)) + "\n")
        print(f"{version}: captured {len(recorded)} sockets -> {destination}")
    finally:
        for process in workers:
            if process.stdin:
                process.stdin.close()
            process.wait(timeout=5)
            process.stdout.close()


if __name__ == "__main__":
    if sys.argv[1:2] == ["--worker"]:
        worker(sys.argv[2] == "private")
    elif len(sys.argv) == 3:
        capture(sys.argv[1], sys.argv[2])
    else:
        sys.exit("usage: capture_ss.py /path/to/ss OUTPUT.txt (requires IPv6 and an ordinary UID)")
