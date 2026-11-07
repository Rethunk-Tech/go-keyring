package keyring

import (
	"context"
	"errors"
	"os"
	"testing"
)

const (
	testService  = "app"
	testSealInfo = "example secrets v1"
	testFolder   = "app-secrets"
	testShared   = "shared"
)

var errUnset = errors.New("backend not stubbed")

// newStore builds a Store whose backend and portal fail until a test stubs them, so no test reaches the
// developer's real keyring or session bus.
func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := New(Options{Service: testService, SealInfo: testSealInfo, Folder: testFolder, SharedServices: []string{testShared}})
	if err != nil {
		t.Fatal(err)
	}
	s.get = func(string, string) (string, error) { return "", errUnset }
	s.set = func(string, string, string) error { return errUnset }
	s.del = func(string, string) error { return errUnset }
	s.portalSecret = noPortal
	s.storeDir = func() (string, error) { return "", errUnset }
	return s
}

func noPortal(context.Context) ([]byte, error) { return nil, errors.New("no portal") }

// ringByService stubs the host Secret Service keyed by service and name.
func (s *Store) ringByService(ring map[[2]string]string) {
	s.get = func(svc, name string) (string, error) {
		if v, ok := ring[[2]string{svc, name}]; ok {
			return v, nil
		}
		return "", ErrNotFound
	}
	s.set = func(svc, name, v string) error { ring[[2]string{svc, name}] = v; return nil }
	s.del = func(svc, name string) error { delete(ring, [2]string{svc, name}); return nil }
	s.resetHost()
}

// ringDown stubs a host with no Secret Service on the bus.
func (s *Store) ringDown() {
	down := errors.New("org.freedesktop.DBus.Error.ServiceUnknown")
	s.get = func(string, string) (string, error) { return "", down }
	s.set = func(string, string, string) error { return down }
	s.del = func(string, string) error { return down }
	s.resetHost()
}

// resetHost makes the next call probe the host and the portal again.
func (s *Store) resetHost() {
	s.hostChecked = map[itemKey]bool{}
	s.hostDone, s.keyDone = false, false
}

// writeIn writes a file into dir through os.Root, as the production code reads it.
func writeIn(t *testing.T, dir, name string, b []byte) {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile(name, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
