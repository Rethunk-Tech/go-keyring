//go:build linux

package keyring

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	liveEnv      = "KEYRING_LIVE"
	liveChildEnv = "KEYRING_LIVE_CHILD"
)

// TestMain re-executes the live run under a private session bus with a throwaway HOME and an unlocked
// gnome-keyring-daemon, so no test ever touches the developer's session bus or real keyring. Without KEYRING_LIVE=1
// nothing is re-executed and the live tests skip.
func TestMain(m *testing.M) {
	if os.Getenv(liveEnv) != "1" || os.Getenv(liveChildEnv) == "1" {
		os.Exit(m.Run())
	}
	home, err := os.MkdirTemp("", "keyring-live-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Join(home, ".local", "share", "keyrings"), 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	script := `printf ci | gnome-keyring-daemon --unlock --components=secrets >/dev/null && exec "$0" "$@"`
	args := append([]string{"--", "sh", "-c", script, os.Args[0]}, os.Args[1:]...)
	cmd := exec.CommandContext(context.Background(), "dbus-run-session", args...) //nolint:gosec // re-executes this test binary with its own arguments
	cmd.Env = append(os.Environ(), liveChildEnv+"=1", "HOME="+home, "XDG_DATA_HOME="+filepath.Join(home, ".local", "share"),
		"DBUS_SESSION_BUS_ADDRESS=", "XDG_RUNTIME_DIR="+home)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	code := 0
	if err := cmd.Run(); err != nil {
		code = 1
		if ee, ok := errors.AsType[*exec.ExitError](err); ok {
			code = ee.ExitCode()
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
	}
	_ = os.RemoveAll(home)
	os.Exit(code)
}

func liveStore(t *testing.T) *Store {
	t.Helper()
	if os.Getenv(liveEnv) != "1" {
		t.Skip("set KEYRING_LIVE=1 to run against a real Secret Service")
	}
	svc := fmt.Sprintf("go-keyring-live-%d", time.Now().UnixNano())
	s, err := New(Options{Service: svc, SealInfo: "live", Folder: "live", SharedServices: []string{"live-shared"}})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func secretTool(t *testing.T, svc, name string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "secret-tool", "lookup", "service", svc, "username", name).Output() //nolint:gosec // svc and name are the test's own constants
	return strings.TrimSpace(string(out)), err
}

// TestLiveSecretService pins zalando's attribute encoding with a tool zalando does not own.
func TestLiveSecretService(t *testing.T) {
	s := liveStore(t)
	if err := s.Set("token", "value-1"); err != nil {
		t.Fatalf("a missing backend fails the live run: %v", err)
	}
	if v, err := s.Get("token"); err != nil || v != "value-1" {
		t.Fatalf("Get: %q, %v", v, err)
	}
	if v, err := secretTool(t, s.opts.Service, "token"); err != nil || v != "value-1" {
		t.Fatalf("secret-tool: %q, %v", v, err)
	}
	if err := s.Delete("token"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("token"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if err := s.Delete("token"); err != nil {
		t.Fatalf("deleting a missing item: %v", err)
	}
}

func TestLiveSharedItem(t *testing.T) {
	s := liveStore(t)
	if err := s.SetIn("live-shared", s.opts.Service, "team-tok"); err != nil {
		t.Fatalf("a missing backend fails the live run: %v", err)
	}
	t.Cleanup(func() { _ = s.DeleteIn("live-shared", s.opts.Service) })
	if v, err := secretTool(t, "live-shared", s.opts.Service); err != nil || v != "team-tok" {
		t.Fatalf("secret-tool: %q, %v", v, err)
	}
	if v, err := s.GetIn("live-shared", s.opts.Service); err != nil || v != "team-tok" {
		t.Fatalf("GetIn: %q, %v", v, err)
	}
}
