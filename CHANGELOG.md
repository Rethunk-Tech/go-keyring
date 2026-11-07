# Changelog

Notable changes to `go-keyring`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `ErrReservedName`: `Get`, `Set` and `Delete` refuse a name of the store's own service that starts with a shared service and a dot, which the Flatpak files keep for that shared item.

### Fixed

- A host purge that failed after adoption no longer marks the item checked, so `Delete` retries the purge; `Get` returns the error without the value.
- A `Get` blocked on the host keyring no longer writes its value back after a `Delete` signed the item out.
- A plain file holding JSON `null` reads as empty instead of panicking the next write.
- Services and names holding a newline or NUL no longer collide in the in-memory maps.

## [0.1.0] - 2026-10-29

### Added

- `Store` with `Get`, `Set`, `Delete` and the shared-item `GetIn`, `SetIn`, `DeleteIn`, over the OS keyring.
- Bounded reads: `ErrPending` after `ReadTimeout`, with `OnUnlocked` when the read completes.
- Flatpak fallback: a portal-sealed file, the host Secret Service, then a plain file, with migration between them; `Plaintext` reports the last.
- `ErrNotFound`, `ErrTooBig`, `ErrLocked`, `ErrNoProvider` and `ZalandoVersion`.

[Unreleased]: https://github.com/Rethunk-Tech/go-keyring/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Rethunk-Tech/go-keyring/releases/tag/v0.1.0
