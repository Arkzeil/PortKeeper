# Compatibility validation — 2026-10-18

The expanded suite was run on Ubuntu 24.04, Linux 6.17.0-20-generic, x86-64,
with Python 3.12.3 and system iproute2 6.1.0.

| Compiler | Sanitizers | Warnings as errors | Unit / integration result |
| --- | --- | --- | --- |
| GCC 13.3.0 | Off | Yes | Pass |
| GCC 13.3.0 | ASan + UBSan | Yes | Pass |
| Clang 18.1.3 | Off | Yes | Pass |
| Clang 18.1.3 | ASan + UBSan | Yes | Pass |

Each configuration passed the unit executable and 34 integration cases. One
additional integration case requiring root to create a different-UID caller
was explicitly skipped locally. ASan leak detection and UBSan halt-on-error
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

The [existing hosted run for starting revision 4b79079](https://github.com/Arkzeil/PortKeeper/actions/runs/39114329724)
completed successfully in all four GCC/Clang × sanitizer combinations. The
new fixtures, parser regression, permission checks, and JSON support were validated locally
as described above; they have not been pushed or run in hosted CI yet.
The workflow now also treats compilation warnings as errors and runs the
different-UID case in its unsanitized jobs.

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
