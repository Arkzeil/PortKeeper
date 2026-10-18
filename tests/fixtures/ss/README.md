# Captured ss compatibility fixtures

These are genuine outputs from `ss -H -l -n -t -u -p -O -e`, captured on Linux
6.17.0 as an ordinary user. Each file contains IPv4/IPv6 TCP and UDP sockets,
two visible owners sharing one TCP socket, and a non-dumpable process whose
socket is visible but owner is unavailable. Five socket lines produce six
owner rows. The C unit test checks every protocol, address, port, PID,
descriptor, and inode against expected values.

| File | Binary provenance | `ss -V` |
| --- | --- | --- |
| `iproute2-5.5.txt` | [Ubuntu iproute2 5.5.0-1ubuntu1](https://archive.ubuntu.com/ubuntu/pool/main/i/iproute2/iproute2_5.5.0-1ubuntu1_amd64.deb) | `ss utility, iproute2-ss200127` |
| `iproute2-5.15.txt` | [Ubuntu iproute2 5.15.0-1ubuntu2](https://archive.ubuntu.com/ubuntu/pool/main/i/iproute2/iproute2_5.15.0-1ubuntu2_amd64.deb) | `ss utility, iproute2-5.15.0` |
| `iproute2-6.1.txt` | Installed Ubuntu package `6.1.0-1ubuntu6.2` | `ss utility, iproute2-6.1.0` |

Downloaded package SHA-256 checksums:

```text
a85abca744b454f4d2856a5c8e0476f3614dc2881ff09b4f559bff7b41a4d2f8  iproute2_5.5.0-1ubuntu1_amd64.deb
fd3d3ce97525be164ed723e49c1e4d84328506a443d7eb2348401d26612b6a79  iproute2_5.15.0-1ubuntu2_amd64.deb
```

`tests/capture_ss.py` generates the fixtures from a supplied binary. It only
records its own test sockets. PIDs, ports, UIDs, socket inodes/cookies, and
cgroup paths are normalized; column spacing, field order, process descriptor
lists, address syntax, and optional metadata are preserved. Trailing whitespace
is removed and lines are sorted. No host process output is retained.

Reproduce with an extracted binary (no system installation needed):

```sh
dpkg-deb -x iproute2_5.15.0-1ubuntu2_amd64.deb /tmp/ss-5.15
python3 tests/capture_ss.py /tmp/ss-5.15/bin/ss /tmp/iproute2-5.15.txt
```

Generation requires IPv6 loopback, a normal UID that cannot bypass proc access
restrictions, and no other open inherited descriptors in the worker. Ordinary
unit test execution only reads the saved fixtures and requires none of these.
The capture validates these versions on this kernel; it does not establish
compatibility with every historical kernel or every iproute2 release.
