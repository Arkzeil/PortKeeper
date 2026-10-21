# Compatibility validation — 2026-10-21

The expanded suite was run on Ubuntu 24.04, Linux 6.17.0-20-generic, x86-64,
with Python 3.12.3 and system iproute2 6.1.0.

| Compiler | Sanitizers | Warnings as errors | Unit / integration result |
| --- | --- | --- | --- |
| GCC 13.3.0 | Off | Yes | Pass |
| GCC 13.3.0 | ASan + UBSan | Yes | Pass |
| Clang 18.1.3 | Off | Yes | Pass |
| Clang 18.1.3 | ASan + UBSan | Yes | Pass |

Each configuration passed the unit executable, 62 integration cases, and three
installation checks. One additional integration case, which needs root to
create a different-UID caller, was explicitly skipped locally.
ASan leak detection and UBSan halt-on-error
were enabled. No compiler warnings or sanitizer findings remained.

Clang was extracted from official Ubuntu packages into `/tmp`; no system
compiler installation was changed. Inherited Conda CFLAGS/LDFLAGS were cleared
for each configuration so the compiler used its matching sanitizer runtime.

## Socket output compatibility

The unit tests validate genuine captures from iproute2 5.5, 5.15, and 6.1.
See [fixture provenance and capture instructions](tests/fixtures/ss/README.md).
They cover whitespace variations, optional cgroup metadata, IPv4/IPv6,
TCP/UDP, shared ownership, and hidden process information.

A regression test exposed partial acceptance of malformed process metadata:
one valid owner could remain after a malformed PID/descriptor claim was
discarded. The parser now rejects the entire result instead. Unit tests cover
malformed and overflowing owner fields; an integration test uses a real
listener and verifies that inspect/stop fail without terminating it.

## JSON output

`list --json` and `inspect --json` were exercised in all four matrix entries.
Tests decode complete documents using Python's JSON parser, checking field
types, empty results and exit codes, unavailable owners, protocol filtering,
shared sockets, escaped process names and arguments, and output-write failures.
Command-line reads check ownership before and after the read; tests cover a
stale socket inode and raw capture sizes of 4095, 4096, and 5000 bytes. The
serializer unit test also covers quotes, backslashes, control bytes, and bytes
outside printable ASCII.

## Family filtering and PID queries

`--family ipv4|ipv6` was exercised for list, inspect, and stop with TCP and UDP
listeners sharing a port across IPv4 and IPv6. Tests cover strict family
arguments, default and selected `ss` arguments, and consistent family selection
across initial discovery, confirmation revalidation, and final verification.
Dual-stack wildcard sockets remain IPv6 sockets even when accepting IPv4
connections. A filtered stop leaves another family's owner untouched and its
verification excludes that family. Hidden owners inside the matching family
still refuse stop; hidden owners outside it do not enter the snapshot.
Selected and unselected ownership changes still abort before signaling.

Query `--pid` tests cover shared owners, multiple ports owned by one process,
table and JSON output, protocol/family combinations, exited and unrelated PIDs,
and unmatched inspect/list exit codes. Fake claims naming a live PID with a
stale descriptor are removed by ownership verification before PID filtering.
Real non-dumpable owners are also excluded, with exactly one visibility warning
retained even when another matching owner remains visible or the result is empty.
Stop retains its complete matching snapshot and existing PID descriptor checks.

## Watch mode

`list --watch DURATION` and `inspect PORT --watch DURATION` were checked in all
four compiler/sanitizer configurations. Nine additional integration cases cover
strict arguments and rejection on stop, immediate snapshots even with a one-hour
interval, numbered table output, and independently decoded JSON records.
Empty inspect snapshots continue through listener appearance, process exit, and
replacement. PID/protocol filters are reapplied, and family/backend arguments
remain consistent across refreshes.

A deliberately slow backend verifies that each new query starts only after the
previous query finishes and the requested interval elapses. SIGINT, SIGTERM,
and SIGHUP interrupt long refresh intervals promptly with the expected exit
codes. Interruption during a later backend query also verifies that its child
has been reaped and that no incomplete discovery record reaches stdout.
Initial and later backend failures, malformed results, `/dev/full`, and a closed
output pipe stop watch with the existing error codes. Visibility warnings stay
on stderr; JSON snapshot fields and schema version remain unchanged.

## PID-selected stops

`stop PORT --pid PID` was checked with shared listeners and separate TCP/UDP
owners on the same port. Tests verify that only the selected process receives
SIGTERM, that dry-run and cancellation leave both owners alive, and that
`--wait` reports a remaining owner with code 9. Other cases cover invalid PID
syntax, non-owner/exited PIDs, protocol mismatch, ignored SIGTERM, replacement
listeners, and selected or unselected socket changes during confirmation.
Selecting a visible PID still refuses when a different matching owner is
unavailable. PID descriptor protection and full-snapshot revalidation remain
in place.

## Permission checks

The local tests create their own TCP and UDP listeners and set
`PR_SET_DUMPABLE` to zero. They first confirm actual `PermissionError` when
reading the target's proc descriptors. Inspect then reports the owner as
unavailable, and normal stop, dry-run, and stop with verification all refuse
with exit code 5. The listener remains alive in every case.

The separate different-UID test creates a root-owned fixture, copies only the
CLI executable into a readable temporary directory, and drops the CLI child's
UID/GID to 65534. It verifies query visibility and stop refusal without
modifying user accounts or system settings. This case is configured as a
dedicated sudo step in each unsanitized CI build. It has **not been executed
locally**: sudo requires a password and user namespace UID mapping is denied.

## Hosted CI

The [hosted run for revision c0e919e](https://github.com/Arkzeil/PortKeeper/actions/runs/39276476443)
completed successfully in all four GCC/Clang × sanitizer combinations. Its
different-user ownership refusal step succeeded in both unsanitized jobs:
[GCC](https://github.com/Arkzeil/PortKeeper/actions/runs/39276476443/job/118141965918)
and [Clang](https://github.com/Arkzeil/PortKeeper/actions/runs/39276476443/job/118141965855).
The corresponding steps were intentionally skipped in sanitizer jobs.
This confirms the cross-user case in hosted CI, although it remains skipped
during ordinary unprivileged local test runs.

The manual, installation, family-filter, query-PID, and watch changes were tested
locally; no hosted run was triggered for those changes. CI now installs
groff-base and man-db so manual rendering and discovery are checked alongside
the compiler matrix.

## Installation and manual

The new `install_smoke` suite uses a temporary `DESTDIR` and an installation
prefix containing spaces. It runs the installed executable from a separate
working directory, checks `--version` and `--help`, decodes JSON output with a
fixture backend, and checks a missing-ss error. The installed manual is compared
with the configured source, checked for CLI option coverage and exit codes,
rendered with groff warnings enabled, and located using `man -M`.
The original build-directory installation manifest is restored after the test.

Version metadata for the binary and manual both comes from CMake's project
version. The 0.1.0 changelog remains marked unreleased.
Earlier release builds with `BUILD_TESTING=OFF` passed the same installation
checks using custom relative (`sbin`, `share/manual`) and absolute (`/usr/bin`,
`/usr/share/man`) destinations, with all writes contained in temporary staging
trees. The local formatter versions were groff 1.23.0 and man-db 2.12.0.

## Reproduce a matrix entry

Use a fresh build directory for each compiler/sanitizer combination:

```sh
cmake -S . -B build-check -G Ninja \
  -DCMAKE_C_COMPILER=clang -DCMAKE_C_FLAGS= -DCMAKE_EXE_LINKER_FLAGS= \
  -DCMAKE_BUILD_TYPE=Debug -DCMAKE_COMPILE_WARNING_AS_ERROR=ON \
  -DPORTKEEPER_ASAN=ON -DPORTKEEPER_UBSAN=ON
cmake --build build-check
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  ctest --test-dir build-check --output-on-failure
```

For the additional privilege case, use a regular unsanitized build:

```sh
sudo /usr/bin/python3 tests/integration.py "$PWD/build-check/portkeeper" \
  Integration.test_cross_user_owner
```

Actual numeric PID wraparound/reuse, other proc mount policies, other kernels,
and iproute2 versions beyond the captures remain unverified.
