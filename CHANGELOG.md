# Changelog

Notable changes to `go-keyring`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-29

### Added

- `Store` with `Get`, `Set`, `Delete` and the shared-item `GetIn`, `SetIn`, `DeleteIn`, over the OS keyring.
- Bounded reads: `ErrPending` after `ReadTimeout`, with `OnUnlocked` when the read completes.
- Flatpak fallback: a portal-sealed file, the host Secret Service, then a plain file, with migration between them; `Plaintext` reports the last.
- `ErrNotFound`, `ErrTooBig`, `ErrLocked`, `ErrNoProvider` and `ZalandoVersion`.

[Unreleased]: https://github.com/Rethunk-Tech/go-keyring/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Rethunk-Tech/go-keyring/releases/tag/v0.1.0
