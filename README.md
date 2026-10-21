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
man portkeeper
```

To select Clang, configure a fresh build directory with
`-DCMAKE_C_COMPILER=clang`. For a build without tests/Python, pass
`-DBUILD_TESTING=OFF`. No root privileges are needed to build or to query your
own processes. Use `-DCMAKE_INSTALL_PREFIX="$HOME/.local"` for a local install
without sudo. The executable is also immediately usable as `./build/portkeeper`.

Installation includes the executable and `portkeeper(1)`. CMake's
`CMAKE_INSTALL_BINDIR` and `CMAKE_INSTALL_MANDIR` control their destinations;
the defaults under a normal prefix are `bin` and `share/man`. The manual is
generated from [docs/portkeeper.1.in](docs/portkeeper.1.in) using the same CMake
project version as `--version`. Building/installing the manual needs no formatter.
To read a local-prefix installation explicitly, use
`man -M "$HOME/.local/share/man" 1 portkeeper` (adjust for a custom man directory).

For a package staging tree, CMake also supports `DESTDIR`:

```sh
DESTDIR="$PWD/build/stage" cmake --install build --prefix /usr
```

With the standard relative install directories this places files under
`build/stage/usr/bin` and `build/stage/usr/share/man/man1`. The test suite checks
staged installation and runs the installed binary without root privileges.
Its manual-rendering check requires `groff` and `man`; the check explicitly
skips if either is unavailable. CI installs both tools. On Debian/Ubuntu,
`sudo apt-get install groff-base man-db` supplies them for local validation.

The first-release changes are recorded in [CHANGELOG.md](CHANGELOG.md), with
version 0.1.0 currently marked unreleased.

## Usage

```sh
portkeeper list
portkeeper list --protocol tcp
portkeeper list --family ipv4
portkeeper list --pid 4012 --json
portkeeper list --watch 1s
portkeeper inspect 8080
portkeeper inspect 5353 --protocol udp
portkeeper list --json
portkeeper inspect 8080 --json
portkeeper inspect 8080 --family ipv6 --pid 4012 --json
portkeeper inspect 8080 --watch 250ms --json
portkeeper stop 8080 --dry-run
portkeeper stop 8080 --family ipv4 --dry-run
portkeeper stop 8080
portkeeper stop 8080 --wait 3s
portkeeper stop 8080 --protocol tcp --pid 4012 --wait 3s
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

`stop` displays matching owners, then requires the exact answer `yes`. EOF, `no`,
and other answers cancel. `--dry-run` validates the visible targets without
requesting confirmation or delivering a termination signal. There is no implicit
confirmation or force option. **Terminating a process affects all its sockets
and other work, including sockets on ports you did not select.**

### Filter by address family

`--family ipv4|ipv6` works with `list`, `inspect`, and `stop`. Both address
families are included when the option is omitted. It combines with `--protocol`,
`--pid`, and the command's other options.

```sh
portkeeper list --family ipv4 --protocol tcp
portkeeper inspect 8080 --family ipv6 --json
portkeeper stop 8080 --family ipv4 --wait 3s
```

The filter selects the socket's family using `ss -4` or `ss -6`, rather than
inferring it from the displayed address. An IPv6 dual-stack listener belongs to
`ipv6` even when it also accepts IPv4 traffic. Wildcard and scoped IPv6 addresses
retain their normal display format; the JSON schema remains version 1.

For stop, the same family applies to initial discovery, the complete matching
snapshot rechecked after confirmation, and final socket verification. Owners
outside that family are excluded. With `--wait`, a successful result only checks
that scope; another family may still have listeners on the port. Terminating a
selected process still affects all its sockets and work, across both families.
Missing, invalid, and repeated family arguments are usage errors (`2`).

### Find a process's ports

`list --pid PID` and `inspect PORT --pid PID` show only rows whose socket ownership
has been verified for that PID. Shared sockets keep the selected owner's row.
Table and JSON output support the same filter, combined with family and protocol:

```sh
portkeeper list --pid 4012
portkeeper list --pid 4012 --protocol tcp --family ipv4 --json
portkeeper inspect 8080 --pid 4012 --json
```

An empty filtered list succeeds (`0`). Without `--watch`, an inspect with no
verified match returns `3`; with `--json` it still emits the usual empty sockets
array. Exited PIDs, non-owners, and family/protocol mismatches follow those same rules. Unavailable
owners cannot be attributed to the requested PID and are omitted, with the
visibility warning retained on stderr. An empty result cannot establish that
an inaccessible process owns no sockets. These queries observe the current
snapshot and do not pin a process across separate invocations.

PID arguments use the same strict validation as stop: positive decimal integers
up to 2147483647, with missing, malformed, or repeated values returning `2`.
The PID filter on queries does not change stop's owner selection or safety checks.

### Choose one owner

Use `stop PORT --pid PID` to send SIGTERM to one verified owner of the matching
port, protocol, and family. Without `--pid`, stop still targets every visible owner.

```sh
portkeeper stop 8080 --pid 4012 --dry-run
portkeeper stop 8080 --protocol tcp --pid 4012 --wait 3s
```

The initial table shows all matching owners, and `Only PID 4012 is selected for
SIGTERM.` identifies the selected target. Other owners are not signaled.
Confirmation, dry-run, PID descriptor protection, and ownership revalidation
apply as usual. The selected PID must own at least one matching socket; the
option cannot be used to terminate an arbitrary process that does not own the
requested port/protocol/family. PID 1 and Portkeeper itself remain protected.

PID values must be positive decimal integers representable by a Linux PID
(at most 2147483647). Missing, malformed, and repeated `--pid` arguments return
usage error `2`. With fully visible owners, an absent, exited, or non-owner
PID returns `3` without confirmation or signals. Unresolved owners anywhere in the matching socket snapshot still
cause refusal with `5`; selecting a known PID does not bypass that policy.

The complete matching snapshot is checked again after confirmation. Changes to
the selected process, its sockets, or other matching owners abort with `6` and
send no signals. The chosen process remains pinned by its original PID
descriptor throughout confirmation and signaling.

With `--wait`, only the selected process is monitored for exit, while the final
socket query still includes all owners matching the port/protocol/family. If the
selected process exits but another owner keeps the port open, the result is
`9` and the remaining owners are displayed. Stop does not escalate or signal
those remaining owners. Without `--wait`, successful signal delivery returns
`0`, even when another owner remains.

### JSON output

Without `--watch`, `list --json` and `inspect PORT --json` write one JSON
document followed by a newline. `--protocol`, `--family`, and `--pid` work with
either command. Diagnostics and visibility warnings go to stderr; stdout contains
no table, prompt, or warning text.

For example, `portkeeper inspect 8080 --json` can return:

```json
{
  "schema_version": 1,
  "sockets": [
    {
      "port": 8080,
      "protocol": "tcp",
      "local_address": "127.0.0.1:8080",
      "pid": 4012,
      "process": "python3",
      "command_line": "python3 server.py",
      "command_line_truncated": false
    }
  ]
}
```

Version 1 has these fields. Consumers should select fields by name and tolerate
additional fields in future compatible releases; object key order and formatting
are not part of the interface.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Output schema version, currently `1` |
| `sockets` | array | Socket/visible-owner rows, in the same order as the table |
| `sockets[].port` | integer | Local port, 1–65535 |
| `sockets[].protocol` | string | `tcp` or `udp` |
| `sockets[].local_address` | string | Local endpoint including port and any IPv6 brackets/interface scope |
| `sockets[].pid` | integer or null | Verified owner PID, or null if unavailable |
| `sockets[].process` | string or null | Process name, or null if unavailable |
| `sockets[].command_line` | string or null | Inspect only: best-effort command line, or null if unavailable |
| `sockets[].command_line_truncated` | boolean or null | Inspect only: whether raw command-line data exceeded the 4095-byte capture limit; null if unavailable |

`list` omits both command-line fields and does not read process arguments.
`inspect` includes them on every row. Reading command-line details checks the
discovered socket ownership before and after the read; a process exit, changed
descriptor, or denied read yields null details. Names, arguments, and addresses
follow the existing ASCII sanitization policy, with JSON quotes and backslashes
escaped. NUL argument separators become spaces and trailing spaces are removed;
the result is a display string, not an argument array or a shell command.

Empty results use `{"schema_version":1,"sockets":[]}`. Without `--watch`, an
empty `list --json` succeeds; an unmatched `inspect --json` returns exit code
`3` and writes the no-match diagnostic to stderr. Argument and initial discovery
failures write no JSON to stdout and retain the existing exit codes. Output
failures can leave a partial document and return an I/O error. Scripts should check the exit status before
using the document. Shared sockets can have multiple rows, one per visible owner.
`stop --json` is unsupported and returns usage error `2`.

### Watch port changes

`list --watch DURATION` and `inspect PORT --watch DURATION` repeat queries until
interrupted or a query/output error occurs. `DURATION` is the pause between
snapshots, not a total runtime: use positive whole seconds (`1` or `1s`) or
milliseconds (`250ms`), up to one hour (`3600s`). Missing, invalid, and repeated
values return usage error `2`. Watch is supported by list and inspect.

```sh
portkeeper list --watch 1s
portkeeper inspect 8080 --protocol tcp --family ipv4 --watch 250ms
portkeeper list --pid 4012 --watch 1s --json
```

The first snapshot is immediate. Each later query starts after the previous
snapshot has been written and the full interval has elapsed. Queries run one
at a time, with no catch-up refreshes; discovery and output time add to the
interval. Each discovery retains its existing 15-second backend timeout.
Protocol, family, PID, and inspect-detail options apply freshly to every snapshot.
PID filtering observes the current numeric PID and does not pin identity across
refreshes; a reused PID may eventually refer to another process.

Table output appends `Snapshot 1`, `Snapshot 2`, and so on, each with a complete
table, separated by blank lines. Empty tables say `No matching listening sockets.`
The output is flushed after each snapshot and does not clear the terminal.

With `--json`, stdout is newline-delimited JSON: one complete schema-version-1
document per snapshot, without table headings or other text. Parse each line
independently; the complete stream is not a single JSON document. Empty snapshots
use the usual empty sockets array. The schema and row fields are unchanged.
Visibility warnings and errors go to stderr and may recur on each refresh.

An empty inspect snapshot keeps watching, including before a listener appears
or after its owner exits. It does not produce the one-shot no-match status `3`.
Ctrl-C exits with `130`; SIGTERM and SIGHUP use the existing `128 + signal`
convention. Interruption also cancels and reaps an active backend query.
A discovery or output failure ends the watch with its existing error code;
previously emitted JSON records remain available, but a failed discovery emits
no record for that refresh and an output failure can leave a partial final line.

### Verify a stop

Add `--wait DURATION` to observe the processes you signaled and then take a fresh
socket snapshot. Durations are positive whole seconds (`3` or `3s`) or
milliseconds (`250ms`), with a maximum of one hour (`3600s`).

```sh
portkeeper stop 8080 --wait 3s
portkeeper stop 8080 --protocol tcp --wait 500ms
```

After confirmation, output distinguishes three events:

```text
Sent SIGTERM to PID 4012.
Waiting up to 3000 ms for 1 process(es) to exit.
PID 4012 exited.
Processes: 1/1 exited.
Port 8080: no matching listening sockets (TCP/UDP) at verification.
```

The process wait uses the original PID descriptors and a shared monotonic
deadline for all targets. It returns early when all have exited. An exited
process counts as exited even if its parent has not reaped it yet. Still-running
targets are reported individually at the deadline. A separate `ss` query then
reports remaining matching sockets and their visible owners. Newly discovered
owners are never signaled. `--protocol` and `--family` apply to this query too.

Exit code `0` with `--wait` means the signaled processes exited and the final
snapshot contains no matching listening sockets. Code `8` means a target was
still running at the deadline, even if it released the socket. Code `9` means
all signaled targets exited but matching sockets remain, for example after a
replacement process binds the port. A failed final query reports socket state
as unverified and returns its error code, even if the process wait timed out.
If signal delivery partially fails, verification covers the signaled subset and
the original delivery error takes precedence. Interruption stops verification;
signals already delivered cannot be undone.

The duration bounds the process wait after signal delivery, not the entire
command: discovery/confirmation happen first, and the final socket query has
its own existing 15-second timeout. The socket result is a snapshot, not a port
reservation or a guarantee that a later bind will succeed. Established TCP,
bound but non-listening TCP, and connected UDP sockets remain outside the query.
`--dry-run --wait 3s` only validates targets; it neither signals nor waits.

## Stop safety and visibility

- Socket discovery executes `ss -H -l -n -t -u -p -O -e` with an argument array,
  optionally adding `sport = :PORT`. No shell is involved. Locale is fixed to C.
  Failed, malformed, oversized (16 MiB), or timed-out (15 seconds) results are
  rejected. Use a trusted PATH, particularly when running through sudo.
- PID/descriptor claims from `ss` are checked against `/proc/PID/fd/FD` and the
  socket inode. Process descriptions are read from `/proc`, not parsed from
  quoted process names in `ss`.
- Before confirmation, stop opens a proc directory and a PID descriptor for
  each targeted unique owner, checking the proc entry remains live across `pidfd_open`.
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
  leave a partially completed stop. Without `--wait`, a successful stop means
  SIGTERM was sent; it does not guarantee the process exited or the port is
  free. Use `--wait` to check both outcomes. A process may ignore SIGTERM, or a
  service manager may restart it after the final snapshot.
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
| 0 | Query/dry-run succeeded; stop delivered SIGTERM; with `--wait`, targets also exited and no matching sockets remained |
| 1 | Runtime or I/O error; a stop may be partially completed |
| 2 | Invalid command, option, port, or PID |
| 3 | No matching socket or requested stop owner (an empty list succeeds; watch keeps running) |
| 4 | Missing/failed/incompatible `ss`, or unavailable pidfd support |
| 5 | Insufficient permission, unresolved owner, or protected PID |
| 6 | Process/socket/owner changed; retry after inspecting the port |
| 7 | Confirmation declined or EOF |
| 8 | With `--wait`, at least one signaled target was still running at the deadline |
| 9 | With `--wait`, all signaled targets exited but matching listening sockets remained |
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
missing `ss`. Outcome tests cover TCP/UDP exit, shared owners, mixed exit/timeout,
ignored SIGTERM, release without exit, replacement owners, protocol selection,
dry runs, interrupted waits, and failed final verification. Live socket cases
explicitly skip if `ss` or IPv6 is unavailable.
Tests only terminate their own fixture processes.

Saved captures from iproute2 5.5, 5.15, and 6.1 are checked by the unit tests.
Permission tests use non-dumpable TCP/UDP listeners to verify unavailable-owner
reporting and stop refusal. A separate different-UID case runs in the
unsanitized CI jobs with sudo and explicitly skips during ordinary local runs.
Malformed PID/descriptor claims reject the complete socket result, including
when another owner in that result is valid.

JSON tests parse output using Python's JSON decoder and cover null owners,
empty results, field types, protocol filtering, shared sockets, escaped names
and arguments, exact command-line capture boundaries, and stdout write failures.

PID-selection tests cover shared owners, dry-run and confirmation, non-owner
and exited PIDs, protocol filters, ignored SIGTERM, replacement processes,
socket/owner changes during confirmation, and refusal when an owner is hidden. Query PID tests check shared owners,
protocol/family combinations, empty results, exited and unrelated PIDs, and
rejection of unverified ownership claims while preserving visibility warnings.
Family tests cover TCP/UDP across both families, dual-stack wildcard sockets,
consistent discovery arguments through stop verification, and stop scope when
another family has a hidden owner.

Watch tests exercise immediate snapshots, interval timing after slow queries,
numbered tables and newline-delimited JSON, empty-to-listening transitions,
process exit/replacement, refreshed filters, interrupted waits and active
queries, backend cleanup, and output failures including a broken pipe.

The `install_smoke` test stages a CMake installation into a temporary `DESTDIR`
with a prefix containing spaces, checks the installed executable and version,
exercises JSON output and missing-ss diagnostics, and verifies the installed
manual's version, option coverage, formatting, and discovery through `man -M`.
The build directory's previous installation manifest is preserved.

GitHub Actions builds and tests GCC and Clang, with and without combined ASan /
UBSan, and treats compilation warnings as errors. Actual numeric PID
wraparound/reuse is not forced by the tests; stable PID descriptors address
that race. See [the compatibility validation record](VALIDATION.md) for compiler
versions, fixture provenance, results, and remaining verification limits.

The tool intentionally has no process-tree termination, SIGKILL escalation,
service management, remote queries, or port reservation. `ss` supplies socket discovery; Portkeeper does not implement a
replacement network scanner or a complete `lsof`/`ss` feature set.

Reference interfaces: [ss(8)](https://man7.org/linux/man-pages/man8/ss.8.html),
[pidfd_open(2)](https://man7.org/linux/man-pages/man2/pidfd_open.2.html), and
[pidfd_send_signal(2)](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html).
