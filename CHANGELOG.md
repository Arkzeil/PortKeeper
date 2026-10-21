# Changelog

## 0.1.0 — Unreleased

### Added

- Linux C17 CLI for TCP listeners and bound, unconnected UDP sockets, with
  IPv4/IPv6 support, process details, protocol/family filtering, and versioned JSON.
- Verified PID filtering for list and inspect, with visibility warnings retained
  when unavailable owners are omitted.
- Interval-based list and inspect watch mode, with numbered tables, streaming
  JSON snapshots, refreshed filters, and interruptible waits.
- Inclusive port-range filtering for list snapshots and watch mode, combined
  with protocol, family, PID, and JSON options.
- Confirmed SIGTERM, dry-run, PID-selected stops, and optional exit/socket
  verification with separate timeout and occupied-port results.
- Socket-inode ownership checks, stable PID descriptors, conservative handling
  of unknown owners, and revalidation after confirmation.
- CMake builds and installation, an installed `portkeeper(1)` manual, and
  staged-installation tests.
- Unit and live integration tests, captured iproute2 compatibility fixtures,
  permission checks, ASan/UBSan options, and GCC/Clang CI.
