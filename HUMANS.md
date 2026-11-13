# HUMANS.md

Run and use `go-keyring`. Internals: [AGENTS.md](AGENTS.md).

## Quick start

```bash
go get github.com/Totative/go-keyring
```

```go
package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/Totative/go-keyring"
)

func main() {
	store, err := keyring.New(keyring.Options{
		Service:    "example",
		SealInfo:   "example secrets v1",
		Folder:     "example-secrets",
		OnUnlocked: func() { fmt.Println("keyring unlocked: retry what was deferred") },
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := store.Set("api-key", "s3cret"); err != nil {
		log.Fatal(err)
	}
	v, err := store.Get("api-key")
	switch {
	case errors.Is(err, keyring.ErrNotFound):
		fmt.Println("signed out")
	case errors.Is(err, keyring.ErrPending):
		fmt.Println("waiting for the user to unlock the keyring")
	case err != nil:
		log.Fatal(err)
	default:
		fmt.Println(v)
	}
}
```

## Contracts

| Entry point | Contract |
| --- | --- |
| `New` | Refuses an empty `Service`, `SealInfo` or `Folder`, a `Folder` that is not one path element, and a `SharedServices` entry that is empty, holds a `.` or equals `Service`. No defaults. |
| `Service`, `SealInfo`, `Folder` | Change one and every stored secret becomes unreadable: keep them for the life of the app. |
| `Get`, `GetIn` | Waits at most `ReadTimeout` (3s by default), then `ErrPending`; later reads of that item fail at once. The late value is served once, with no second backend read. |
| `Set`, `Delete` and the `In` forms | Not bounded: a locked keyring holds them on the prompt. They discard a read still waiting. A missing name on `Delete` is not an error. |
| `OnUnlocked` | Runs after a read that outlived `ReadTimeout` completes, or was overtaken by a `Set` or `Delete`. |
| `Plaintext` | `(true, nil)` only inside a Flatpak with neither portal nor host Secret Service and a plain file left by an earlier release. A busy store gives `(false, ErrPending)`; an unresolvable one `(false, err)`. Outside a Flatpak it is `(false, nil)`. |
| Flatpak detection | Per call, from `FLATPAK_ID`. Sealed and plain files hold a shared item as `<service>.<name>`, so no other program reads it; sharing holds outside a Flatpak and in host-keyring mode. |
| `ErrNotFound`, `ErrTooBig` | zalando's values. `ErrTooBig` is Windows' 2,560-byte credential limit. |
| `ErrPortalUnavailable` | Wraps the portal failure (timeout, dismissed dialog, no portal) on a write that would have gone to the plain file, and on any access to a sealed file. Never cached: the next call asks the portal again. |
| `ErrLocked`, `ErrNoProvider` | Wrap the backend error. A dismissed unlock is never cached and never a reason to write the plain file. |
| One `Store` per `Folder` | Two `Store`s on one folder race on the file. |
| macOS | Compiles and vets; untested. |
| `ZalandoVersion` | The zalando version the live tests passed against; a consumer can assert its own build matches. |

## Requirements

Go 1.27.3 or newer, plus `lefthook` and `gitleaks` on PATH if you want the git hooks.

```bash
lefthook install
```

That is per clone; git does not commit hooks. Pre-commit scans staged changes for secrets, and
pre-push runs `gate`.

## Verify

```bash
gate
```
