//go:build windows

package keyring

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/danieljoos/wincred"
)

func liveStore(t *testing.T) *Store {
	t.Helper()
	if os.Getenv("KEYRING_LIVE") != "1" {
		t.Skip("set KEYRING_LIVE=1 to run against Credential Manager")
	}
	svc := fmt.Sprintf("go-keyring-live-%d", time.Now().UnixNano())
	s, err := New(Options{Service: svc, SealInfo: "live", Folder: "live"})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestLiveCredentialManager pins zalando's target-name encoding with the Credential Manager API itself.
func TestLiveCredentialManager(t *testing.T) {
	s := liveStore(t)
	target := s.opts.Service + ":token"
	if err := s.Set("token", "value-1"); err != nil {
		t.Fatalf("a missing backend fails the live run: %v", err)
	}
	t.Cleanup(func() { _ = s.Delete("token") })
	cred, err := wincred.GetGenericCredential(target)
	if err != nil || cred.TargetName != target || !bytes.Equal(cred.CredentialBlob, []byte("value-1")) {
		t.Fatalf("credential: %+v, %v", cred, err)
	}
	if v, err := s.Get("token"); err != nil || v != "value-1" {
		t.Fatalf("Get: %q, %v", v, err)
	}
	if err := s.Delete("token"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestLiveTooBig(t *testing.T) {
	s := liveStore(t)
	if err := s.Set("big", strings.Repeat("x", 2561)); !errors.Is(err, ErrTooBig) {
		t.Fatalf("want ErrTooBig, got %v", err)
	}
}
