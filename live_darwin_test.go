//go:build darwin

package keyring

import (
	"errors"
	"os"
	"testing"

	zkeyring "github.com/zalando/go-keyring"
)

func TestLiveKeychain(t *testing.T) {
	if os.Getenv("KEYRING_LIVE") != "1" {
		t.Skip("set KEYRING_LIVE=1 to run against a real Keychain")
	}

	const (
		service = "github.com/Totative/go-keyring.live"
		name    = "ci-token"
		secret  = "live-keychain-secret"
	)
	store, err := New(Options{
		Service:  service,
		SealInfo: "go-keyring live v1",
		Folder:   "go-keyring-live",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Delete(name) })

	if err := store.Set(name, secret); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	if got != secret {
		t.Fatalf("Get: got %q, want %q", got, secret)
	}
	viaBackend, err := zkeyring.Get(service, name)
	if err != nil {
		t.Fatal(err)
	}
	if viaBackend != secret {
		t.Fatalf("zalando Get: got %q, want %q", viaBackend, secret)
	}
	if err := store.Delete(name); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: %v", err)
	}
}

func TestLiveSharedItem(t *testing.T) {
	if os.Getenv("KEYRING_LIVE") != "1" {
		t.Skip("set KEYRING_LIVE=1 to run against a real Keychain")
	}

	const (
		service = "github.com/Totative/go-keyring.live"
		shared  = "github.com/Totative/go-keyring.shared"
		name    = "ci-shared"
		secret  = "live-shared-secret"
	)
	store, err := New(Options{
		Service:        service,
		SealInfo:       "go-keyring live v1",
		Folder:         "go-keyring-live",
		SharedServices: []string{shared},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.DeleteIn(shared, name) })

	if err := store.SetIn(shared, name, secret); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetIn(shared, name)
	if err != nil {
		t.Fatal(err)
	}
	if got != secret {
		t.Fatalf("GetIn: got %q, want %q", got, secret)
	}
	viaBackend, err := zkeyring.Get(shared, name)
	if err != nil {
		t.Fatal(err)
	}
	if viaBackend != secret {
		t.Fatalf("zalando Get: got %q, want %q", viaBackend, secret)
	}
	if err := store.DeleteIn(shared, name); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetIn(shared, name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetIn after DeleteIn: %v", err)
	}
}
