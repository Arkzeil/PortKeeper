# Portkeeper

A small Linux CLI for finding local TCP listeners and bound, unconnected UDP
sockets, inspecting their processes, and sending SIGTERM after confirmation.
Implemented in C17 with libc and the existing `ss` utility from iproute2.

## Build and install

Requires Linux, GCC or Clang, CMake 3.16+, and iproute2 (`ss` on your trusted
`PATH`). Stopping requires Linux 5.3+ with `pidfd_open` and `pidfd_send_signal`
permitted by the environment. Tests additionally require Python 3.8+.

On Debian/Ubuntu, install dependencies with:

```sh
sudo apt-get install build-essential cmake iproute2 python3
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
sudo cmake --install build
```

To select Clang, configure a fresh build directory with
`-DCMAKE_C_COMPILER=clang`. For a build without tests/Python, pass
`-DBUILD_TESTING=OFF`. No root privileges are needed to build or to query your
own processes. Use `-DCMAKE_INSTALL_PREFIX="$HOME/.local"` for a local install
without sudo. The executable is also immediately usable as `./build/portkeeper`.

## Usage

```sh
portkeeper list
portkeeper list --protocol tcp
portkeeper inspect 8080
portkeeper inspect 5353 --protocol udp
portkeeper stop 8080 --dry-run
portkeeper stop 8080
```

Example output (addresses and processes depend on your system):

```text
PORT   PROTOCOL PID     PROCESS              LOCAL ADDRESS
3000   TCP      1823    node                 127.0.0.1:3000
5000   TCP      2741    python               0.0.0.0:5000
8080   TCP      4012    nginx                [::]:8080
```

`inspect` also shows a best-effort command line, limited to 4095 bytes. Arguments
are joined with spaces for display; this is not a shell-escaped command. Process
names, arguments, and addresses have non-ASCII and control bytes replaced with
`?` to prevent terminal control sequences. Command arguments may contain secrets;
take care when sharing inspect output.

Ports must be decimal integers from 1 through 65535. Both protocols are selected
by default. IPv4 and IPv6 are included. UDP has no TCP-style listen state;
connected UDP sockets are intentionally excluded. Rows are sorted by port,
protocol, address, PID, and socket inode. Multiple owners of a shared socket are
shown separately, with duplicate descriptors for the same process collapsed.

`stop` displays the targets, then requires the exact answer `yes`. EOF, `no`,
and other answers cancel. `--dry-run` validates the visible targets without
requesting confirmation or delivering a termination signal. There is no implicit
confirmation or force option. **Terminating a process affects all its sockets
and other work, including sockets on ports you did not select.**

## Stop safety and visibility

- Socket discovery executes `ss -H -l -n -t -u -p -O -e` with an argument array,
  optionally adding `sport = :PORT`. No shell is involved. Locale is fixed to C.
  Failed, malformed, oversized (16 MiB), or timed-out (15 seconds) results are
  rejected. Use a trusted PATH, particularly when running through sudo.
- PID/descriptor claims from `ss` are checked against `/proc/PID/fd/FD` and the
  socket inode. Process descriptions are read from `/proc`, not parsed from
  quoted process names in `ss`.
- Before confirmation, stop opens a proc directory and a PID descriptor for
  each unique owner, checking the proc entry remains live across `pidfd_open`.
  The handles stay open until completion. Signals use `pidfd_send_signal`, so a
  recycled numeric PID cannot redirect the signal to a replacement process.
  PID 1 and Portkeeper itself are never stop targets.
- After confirmation, the socket/owner snapshot is collected again. Changed
  rows, exited processes, missing descriptors, and changed ownership abort the
  stop. All targets are checked before the first SIGTERM. An unresolved owner
  on any selected socket refuses the entire operation.
- Processes may still close sockets or exit immediately after the final check.
  Linux does not provide an atomic operation to validate a listening port and
  signal all its owners. A failure during signal delivery can leave some
  targets already signaled; the error reports that count. Interruption can also
  leave a partially completed stop. A successful stop means SIGTERM was sent;
  it does not guarantee the process exited or the port is free. A process may
  ignore SIGTERM, or a service manager may restart it.
- Visibility depends on your UID, proc mount settings, namespaces, and security
  policy. Unknown owners are shown as `-` / `<unavailable>` with a warning.
  `ss` may omit inaccessible co-owners of a shared socket even when one owner
  is visible. Portkeeper operates on the visible owners only and cannot certify
  that every owner was discovered. Run with appropriate privileges when needed.
  It only queries the current network/PID namespace view; namespace switching,
  setuid/setgid installation, and privilege escalation are unsupported.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Query/dry-run succeeded, or all intended SIGTERM calls succeeded |
| 1 | Runtime or I/O error; a stop may be partially completed |
| 2 | Invalid command, option, or port |
| 3 | No matching socket for inspect/stop (`list` can succeed with no rows) |
| 4 | Missing/failed/incompatible `ss`, or unavailable pidfd support |
| 5 | Insufficient permission, unresolved owner, or protected PID |
| 6 | Process/socket/owner changed; retry after inspecting the port |
| 7 | Confirmation declined or EOF |
| 128 + signal | Interrupted (130 for SIGINT, 143 for SIGTERM) |

Codes 5/6 can also occur during delivery after earlier targets received SIGTERM.

## Tests and sanitizers

```sh
cmake -S . -B build-sanitize -DCMAKE_BUILD_TYPE=Debug \
  -DPORTKEEPER_ASAN=ON -DPORTKEEPER_UBSAN=ON
cmake --build build-sanitize
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  ctest --test-dir build-sanitize --output-on-failure
```

The sanitizer options can also be enabled separately. All targets compile with
`-Wall -Wextra -Wpedantic`. The unit suite covers parsing, numeric validation,
socket-inode verification, PID descriptor signaling, and exited targets. The
Python integration suite uses isolated subprocesses and ephemeral loopback ports
to test TCP/UDP, IPv6, shared sockets, dry runs, confirmation/cancellation,
interruption, port reuse and socket closure during confirmation, and invalid or
missing `ss`. Live socket cases explicitly skip if `ss` or IPv6 is unavailable.
Tests only terminate their own fixture processes.

GitHub Actions builds and tests GCC and Clang, with and without combined ASan /
UBSan. Cross-user permission policies and actual numeric PID wraparound/reuse
are not forced by the tests; the latter is addressed by stable PID descriptors.

The first draft intentionally has no JSON output, watch mode, process-tree
termination, SIGKILL escalation, service management, remote queries, or port
reservation. `ss` supplies socket discovery; Portkeeper does not implement a
replacement network scanner or a complete `lsof`/`ss` feature set.

Reference interfaces: [ss(8)](https://man7.org/linux/man-pages/man8/ss.8.html),
[pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html), and
[pidfd_send_signal(2)](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html).
