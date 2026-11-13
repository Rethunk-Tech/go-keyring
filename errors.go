package keyring

import (
	"errors"
	"fmt"
	"strings"

	zkeyring "github.com/zalando/go-keyring"
)

var (
	// ErrNotFound is zalando's ErrNotFound, the same value, so errors.Is holds for a caller that mocks the
	// backend with zalando's MockInit.
	ErrNotFound = zkeyring.ErrNotFound
	// ErrTooBig is zalando's ErrSetDataTooBig, the same value: Windows refuses a credential over 2,560 bytes.
	ErrTooBig = zkeyring.ErrSetDataTooBig
	// ErrPending means a read is still waiting on an unlock prompt. It is not a failure: the read keeps running
	// and Options.OnUnlocked fires when it completes. Plaintext also returns it when the store is busy.
	ErrPending = errors.New("keyring: waiting for the keyring to be unlocked")
	// ErrLocked wraps the backend error when an unlock prompt was dismissed or failed. Nothing is cached: the
	// next call prompts again.
	ErrLocked = errors.New("keyring: the keyring stayed locked")
	// ErrPortalUnavailable wraps the portal failure (timeout, dismissed dialog, no portal) when a write would
	// land in the plain file, or a sealed file cannot be opened. Nothing is cached: the next call asks again.
	ErrPortalUnavailable = errors.New("keyring: the secret portal is unavailable")
	// ErrReservedName means an item of the store's own service is named "<shared service>.<name>", which the
	// Flatpak files keep for that shared service's item.
	ErrReservedName = errors.New("keyring: the name collides with a shared service's item")
	// ErrNoProvider wraps the D-Bus error raised when nothing answers as the Secret Service.
	ErrNoProvider = errors.New("keyring: no Secret Service provider is running")
)

// ZalandoVersion is the zalando/go-keyring version this release's live tests ran against.
const ZalandoVersion = "v0.2.8"

// unlockFailed is the text zalando gives when an unlock prompt is dismissed.
const unlockFailed = "failed to unlock correct collection"

// noProvider are the fragments of the D-Bus errors raised when nothing answers as the Secret Service.
var noProvider = []string{
	"org.freedesktop.DBus.Error.ServiceUnknown",
	"org.freedesktop.DBus.Error.NameHasNoOwner",
	"org.freedesktop.DBus.Error.NoServer",
	"couldn't determine address of session bus",
	"dbus-launch",
}

// classify gives a backend failure its sentinel, keeping the cause in the chain. It is idempotent: an error
// that already carries a sentinel passes through, because a result is classified on every path it returns by.
func classify(err error) error {
	switch {
	case err == nil, errors.Is(err, ErrLocked), errors.Is(err, ErrNoProvider):
		return err
	case noKeyringService(err):
		return fmt.Errorf("%w: %w", ErrNoProvider, err)
	case strings.Contains(err.Error(), unlockFailed):
		return fmt.Errorf("%w: %w", ErrLocked, err)
	}
	return err
}

func noKeyringService(err error) bool {
	msg := err.Error()
	for _, frag := range noProvider {
		if strings.Contains(msg, frag) {
			return true
		}
	}
	return false
}

// hostAbsent reports a host keyring that cannot answer (no Secret Service, or a locked collection or dismissed
// prompt), which counts as the item not being there.
func hostAbsent(err error) bool {
	return noKeyringService(err) || strings.Contains(err.Error(), unlockFailed)
}
