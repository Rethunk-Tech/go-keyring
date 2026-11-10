<h1 align="center">go-keyring</h1>

<div align="center">

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.27.3+-00ADD8?logo=go&logoColor=white)](go.mod)

</div>

---

One credential store for a Go desktop app: the OS keyring, with a sealed-file fallback inside a Flatpak. Package `keyring`, module `github.com/Totative/go-keyring`.

A Go desktop app keeps a token in the OS keyring (Secret Service on Linux, Credential Manager on Windows; the macOS Keychain works through the same backend but is untested). Inside a Flatpak, where the session keyring is not reachable by default, the same calls fall back to a file sealed under the XDG Secret portal's per-app secret, then to the host's Secret Service, then to a plain `0600` file. Reads are bounded, so a GUI is never held by an unlock prompt nobody answers.

## Quick start

```bash
go get github.com/Totative/go-keyring
```

A worked example and the contracts: [HUMANS.md](HUMANS.md).

## Features

- One `Store` with `Get`, `Set` and `Delete`, plus `GetIn`, `SetIn` and `DeleteIn` for an item another program shares.
- A read behind an unlock prompt returns `ErrPending` after `ReadTimeout`, keeps running, and calls `OnUnlocked` when it completes.
- Inside a Flatpak: a sealed file (AES-256-GCM), else the host keyring, else a plain file; `Plaintext` says which.
- Items from an earlier fallback are found and moved forward on read, never lost.
- `ErrNotFound` and `ErrTooBig` are zalando's own values, so `errors.Is` holds against its `MockInit`.
- Typed `ErrLocked` and `ErrNoProvider` replace raw D-Bus text.

## Documentation

| Doc | Audience |
| --- | --- |
| [HUMANS.md](HUMANS.md) | Running and using the package |
| [AGENTS.md](AGENTS.md) | Internals, invariants, and why |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Process — commits, tests, docs |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |

## License

Apache-2.0, see [LICENSE](LICENSE). © 2026 Rethunk.Tech, LLC.
