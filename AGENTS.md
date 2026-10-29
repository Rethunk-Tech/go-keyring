# AGENTS.md

Package `keyring` is one credential store for a Go desktop app: the OS keyring through zalando/go-keyring, and inside a Flatpak a sealed file, the host keyring or a plain file. Any desktop app that keeps a token imports it. It never imports a consumer package, and every consumer string (service, HKDF info, folder) is an `Options` field.

## Gate

`gate` is the command. Each override in `.gate.toml` is there because a runner
cannot resolve that check from PATH. The `windows-latest` test job is the only place
Windows-only behaviour runs; `flatpak_test.go` and `live_linux_test.go` are Linux-only, `live_windows_test.go` runs only there, and the live tests need `KEYRING_LIVE=1`.

## Shape

- Service, SealInfo and Folder have no defaults, because a derived default lets two programs share a store unchosen, and a wrong value orphans every stored secret.
- The sealed file is the 12-byte GCM nonce followed by the ciphertext of a JSON object, keyed by `HKDF-SHA256(portal secret, nil salt, SealInfo, 32)`. The file names `secrets` and `secrets.json`, the flat `<service>.<name>` item names, and the tombstone key `"\x00deleted\x00" + name` are stored formats: `testdata/sealed-golden` and `testdata/plain.json` pin them.
- Flatpak detection is per call, not captured in `New`, so a `Store` built at init works once the environment says it is inside one.
- The test seams (`get`, `set`, `del`, `portalSecret`, `storeDir`) are unexported `Store` fields. Package variables would let one importer's stub rewire every other.
- No `context.Context` on methods: zalando's calls cannot be cancelled. `ReadTimeout` bounds `Get`; `PortalTimeout` bounds only the portal, and zero means unbounded because a dialog's length is the caller's policy.
- `classify` is idempotent, because a result is classified on every path it returns by.
- A sealed file with no portal is an error, never shadowed by a plain file: a second store would hide the first.
- Host adoption runs at most once per item per run, only a definite answer marks an item checked, and a tombstone stops adoption, so a signed-out secret stays signed out when its host copy could not be purged.
- zalando is bumped here first, with the live job green and `ZalandoVersion` changed in the same commit: a zalando release that changes its item encoding orphans every stored item.
- `ErrNotFound` and `ErrTooBig` are zalando's values; do not wrap them.

## Files

| File | Holds |
| --- | --- |
| `doc.go` | Package documentation |
| `keyring.go` | `Options`, `Store`, `New`, the bounded single-flight read, `Set` and `Delete` |
| `errors.go` | Sentinels, `ZalandoVersion`, `classify` |
| `flatpak.go` | The Flatpak store: location, migrations, host adoption, seal and unseal, folder checks |
| `dirowner_unix.go`, `dirowner_other.go` | The folder-owner check |
