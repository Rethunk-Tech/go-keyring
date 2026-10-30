//go:build linux

package keyring

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Rethunk-Tech/go-safefs"
)

// flatpakEnv puts a Store in Flatpak mode with a temp store folder and the given portal; the host keyring is down.
func flatpakEnv(t *testing.T, portal func(context.Context) ([]byte, error)) (s *Store, dir string) {
	t.Helper()
	t.Setenv("FLATPAK_ID", "example.App")
	dir = filepath.Join(t.TempDir(), "app")
	s = newStore(t)
	s.portalSecret = portal
	s.storeDir = func() (string, error) { return dir, nil }
	s.ringDown()
	return s, dir
}

func fixedPortal(secret string) func(context.Context) ([]byte, error) {
	return func(context.Context) ([]byte, error) { return []byte(secret), nil }
}

func noPortalEnv(t *testing.T) (*Store, string) { return flatpakEnv(t, noPortal) }

func TestFlatpakStore(t *testing.T) {
	t.Run("sealed round trip", func(t *testing.T) {
		s, dir := flatpakEnv(t, fixedPortal("master"))
		if err := s.Set("token", "key-123"); err != nil {
			t.Fatal(err)
		}
		if v, err := s.Get("token"); err != nil || v != "key-123" {
			t.Fatalf("got %q, %v", v, err)
		}
		raw, err := readFile(filepath.Join(dir, "secrets"))
		if err != nil || bytes.Contains(raw, []byte("key-123")) {
			t.Fatalf("the file must be sealed: %v", err)
		}
		if err := s.Delete("token"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get("token"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("no portal falls back to a plain 0600 file", func(t *testing.T) {
		s, dir := noPortalEnv(t)
		if err := s.Set("api", "tok"); err != nil {
			t.Fatal(err)
		}
		if v, err := s.Get("api"); err != nil || v != "tok" {
			t.Fatalf("got %q, %v", v, err)
		}
		fi, err := os.Stat(filepath.Join(dir, "secrets.json"))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("plain file: %v %v", fi, err)
		}
		if di, _ := os.Stat(dir); di.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode %v", di.Mode().Perm())
		}
		if _, err := os.Stat(filepath.Join(dir, "secrets")); err == nil {
			t.Fatal("no sealed file without a portal")
		}
	})

	t.Run("a plain file is sealed once the portal answers", func(t *testing.T) {
		s, dir := noPortalEnv(t)
		if err := s.Set("token", "key-123"); err != nil {
			t.Fatal(err)
		}
		s.portalSecret, s.keyDone = fixedPortal("master"), false
		if v, err := s.Get("token"); err != nil || v != "key-123" {
			t.Fatalf("got %q, %v", v, err)
		}
		if _, err := os.Stat(filepath.Join(dir, "secrets.json")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the plain file is still there: %v", err)
		}
		raw, err := readFile(filepath.Join(dir, "secrets"))
		if err != nil || bytes.Contains(raw, []byte("key-123")) {
			t.Fatalf("the moved secrets must be sealed: %v", err)
		}
	})

	t.Run("no portal uses the host keyring and writes no file", func(t *testing.T) {
		s, dir := noPortalEnv(t)
		ring := map[[2]string]string{}
		s.ringByService(ring)
		if err := s.Set("token", "key-1"); err != nil {
			t.Fatal(err)
		}
		if v, err := s.Get("token"); err != nil || v != "key-1" || ring[[2]string{testService, "token"}] != "key-1" {
			t.Fatalf("got %q, %v, ring %v", v, err, ring)
		}
		if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("no store folder expected: %v", err)
		}
		if p, err := s.Plaintext(); p || err != nil {
			t.Fatalf("the keyring is not plain text: %v %v", p, err)
		}
		if err := s.Delete("token"); err != nil || len(ring) != 0 {
			t.Fatalf("delete: %v %v", err, ring)
		}
	})

	t.Run("neither portal nor keyring is plain text", func(t *testing.T) {
		s, dir := noPortalEnv(t)
		if err := s.Set("api", "tok"); err != nil {
			t.Fatal(err)
		}
		p, err := s.Plaintext()
		if _, serr := os.Stat(filepath.Join(dir, "secrets.json")); serr != nil || !p || err != nil {
			t.Fatalf("plain file: %v, Plaintext %v, %v", serr, p, err)
		}
	})

	t.Run("a plain file moves to the keyring once it answers", func(t *testing.T) {
		s, dir := noPortalEnv(t)
		if err := s.Set("token", "key-1"); err != nil {
			t.Fatal(err)
		}
		ring := map[[2]string]string{}
		s.ringByService(ring)
		if v, err := s.Get("token"); err != nil || v != "key-1" || ring[[2]string{testService, "token"}] != "key-1" {
			t.Fatalf("got %q, %v, ring %v", v, err, ring)
		}
		if _, err := os.Stat(filepath.Join(dir, "secrets.json")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the plain file is still there: %v", err)
		}
	})

	t.Run("wrong key errors and leaves the file alone", func(t *testing.T) {
		s, dir := flatpakEnv(t, fixedPortal("master"))
		if err := s.Set("token", "v"); err != nil {
			t.Fatal(err)
		}
		before, _ := readFile(filepath.Join(dir, "secrets"))
		s.portalSecret, s.keyDone = fixedPortal("other"), false
		if _, err := s.Get("token"); err == nil || errors.Is(err, ErrNotFound) {
			t.Fatalf("want a decrypt error, got %v", err)
		}
		if err := s.Set("x", "y"); err == nil {
			t.Fatal("Set must not overwrite an undecryptable file")
		}
		s.portalSecret, s.keyDone = noPortal, false
		if err := s.Set("x", "y"); err == nil {
			t.Fatal("a sealed file without the portal must not be shadowed by a plain one")
		}
		after, _ := readFile(filepath.Join(dir, "secrets"))
		if !bytes.Equal(before, after) {
			t.Fatal("file changed")
		}
	})
}

func TestFlatpakStoreTightensAnExistingFolderAndRefusesALink(t *testing.T) {
	s, dir := flatpakEnv(t, fixedPortal("master"))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := safefs.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("token", "k"); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("folder mode = %v, %v", info.Mode().Perm(), err)
	}

	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	linked, link := flatpakEnv(t, fixedPortal("master"))
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := linked.Set("token", "k"); err == nil {
		t.Fatal("a symlinked secrets folder was used")
	}
}

func TestStoreDirNeedsAHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	s, err := New(Options{Service: testService, SealInfo: testSealInfo, Folder: testFolder})
	if err != nil {
		t.Fatal(err)
	}
	if d, err := s.storeDir(); err == nil {
		t.Fatalf("storeDir with no home = %q, want an error", d)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_DATA_HOME", "relative/data")
	d, err := s.storeDir()
	if err != nil || !filepath.IsAbs(d) || filepath.Base(d) != testFolder {
		t.Fatalf("a relative data home must not yield a relative folder: %q, %v", d, err)
	}
}

func TestDismissedUnlockIsNotNoKeyring(t *testing.T) {
	s, dir := noPortalEnv(t)
	dismissed := errors.New("failed to unlock correct collection '/org/freedesktop/secrets/aliases/default'")
	s.get = func(string, string) (string, error) { return "", dismissed }
	if err := s.Set("api", "tok"); !errors.Is(err, ErrLocked) {
		t.Fatalf("a dismissed unlock prompt must be ErrLocked and not fall back to the plain file, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets.json")); err == nil {
		t.Fatal("secret written in plain text")
	}
	ring := map[[2]string]string{}
	s.ringByService(ring)
	if err := s.Set("api", "tok"); err != nil || ring[[2]string{testService, "api"}] != "tok" {
		t.Fatalf("the next call must retry the keyring: %v %v", err, ring)
	}
}

func TestPlaintextDoesNotWaitOnTheStore(t *testing.T) {
	s, _ := flatpakEnv(t, fixedPortal("master"))
	s.storeMu.Lock()
	defer s.storeMu.Unlock()
	if p, err := s.Plaintext(); p || !errors.Is(err, ErrPending) {
		t.Fatalf("a busy store is (false, ErrPending), got %v, %v", p, err)
	}
}

func TestPlaintextReturnsTheResolutionError(t *testing.T) {
	s, _ := flatpakEnv(t, fixedPortal("master"))
	s.storeDir = func() (string, error) { return "", errUnset }
	if p, err := s.Plaintext(); p || !errors.Is(err, errUnset) {
		t.Fatalf("got %v, %v", p, err)
	}
	t.Setenv("FLATPAK_ID", "")
	if p, err := s.Plaintext(); p || err != nil {
		t.Fatalf("outside a Flatpak nothing is plain text: %v, %v", p, err)
	}
}

func TestPortalTimeoutIsCachedLikeAnyPortalFailure(t *testing.T) {
	s, _ := flatpakEnv(t, nil)
	s.opts.PortalTimeout = 20 * time.Millisecond
	calls := 0
	s.portalSecret = func(ctx context.Context) ([]byte, error) {
		calls++
		<-ctx.Done()
		return nil, ctx.Err()
	}
	// The host keyring is down, so a portal failure lands on the plain file.
	for range 2 {
		if err := s.Set("api", "tok"); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("the portal was asked %d times", calls)
	}
	p, err := s.Plaintext()
	if !p || err != nil {
		t.Fatalf("a timed-out portal leaves the plain file: %v %v", p, err)
	}
}

func TestHostKeyringSharedItemNaming(t *testing.T) {
	newEnv := func(t *testing.T) (*Store, map[[2]string]string) {
		s, _ := noPortalEnv(t)
		ring := map[[2]string]string{}
		s.ringByService(ring)
		return s, ring
	}
	legacy := [2]string{testService, testShared + ".team"}
	shared := [2]string{testShared, "team"}

	t.Run("set writes the host-visible name and drops the old one", func(t *testing.T) {
		s, ring := newEnv(t)
		ring[legacy] = "old"
		if err := s.SetIn(testShared, "team", "tok"); err != nil {
			t.Fatal(err)
		}
		if ring[shared] != "tok" {
			t.Fatalf("new name not written: %v", ring)
		}
		if _, ok := ring[legacy]; ok {
			t.Fatalf("old name lingers: %v", ring)
		}
	})

	t.Run("get falls back to the old name", func(t *testing.T) {
		s, ring := newEnv(t)
		ring[legacy], ring[shared] = "old", "new"
		if v, err := s.GetIn(testShared, "team"); err != nil || v != "new" {
			t.Fatalf("got %q, %v", v, err)
		}
		delete(ring, shared)
		if v, err := s.GetIn(testShared, "team"); err != nil || v != "old" {
			t.Fatalf("got %q, %v", v, err)
		}
	})

	t.Run("delete removes both names", func(t *testing.T) {
		s, ring := newEnv(t)
		ring[legacy], ring[shared] = "old", "tok"
		if err := s.DeleteIn(testShared, "team"); err != nil {
			t.Fatal(err)
		}
		if len(ring) != 0 {
			t.Fatalf("left behind: %v", ring)
		}
	})

	t.Run("the store's own items keep their name", func(t *testing.T) {
		s, ring := newEnv(t)
		if err := s.Set("token", "k"); err != nil {
			t.Fatal(err)
		}
		if ring[[2]string{testService, "token"}] != "k" || len(ring) != 1 {
			t.Fatalf("got %v", ring)
		}
	})
}

func TestHostItemsAdoptedWhenPortalAppears(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		s, _ := noPortalEnv(t)
		ring := map[[2]string]string{}
		s.ringByService(ring)
		host := [2]string{testShared, "team"}
		if legacy {
			host = [2]string{testService, testShared + ".team"}
		}
		ring[host] = "tok"
		s.portalSecret = fixedPortal("portal-secret")
		s.keyDone, s.hostDone = false, false
		if v, err := s.GetIn(testShared, "team"); err != nil || v != "tok" {
			t.Fatalf("legacy=%v: got %q, %v", legacy, v, err)
		}
		if len(ring) != 0 {
			t.Fatalf("legacy=%v: host copy left behind: %v", legacy, ring)
		}
		if v, err := s.GetIn(testShared, "team"); err != nil || v != "tok" {
			t.Fatalf("legacy=%v: sealed copy missing: %q, %v", legacy, v, err)
		}
		ring[host] = "tok"
		s.hostChecked = map[string]bool{}
		if err := s.DeleteIn(testShared, "team"); err != nil || len(ring) != 0 {
			t.Fatalf("legacy=%v: delete left %v, %v", legacy, ring, err)
		}
	}
}

func TestPlainMigrationUsesSharedNaming(t *testing.T) {
	s, dir := noPortalEnv(t)
	if err := save(filepath.Join(dir, plainFile), nil, map[string]string{testShared + ".team.x": "t", "token": "k"}); err != nil {
		t.Fatal(err)
	}
	ring := map[[2]string]string{}
	s.ringByService(ring)
	if v, err := s.GetIn(testShared, "team.x"); err != nil || v != "t" {
		t.Fatalf("got %q, %v", v, err)
	}
	if ring[[2]string{testShared, "team.x"}] != "t" || ring[[2]string{testService, "token"}] != "k" || len(ring) != 2 {
		t.Fatalf("ring %v", ring)
	}
}

const lockedText = "failed to unlock correct collection '/x'"

func TestSealedHostLookupOncePerRun(t *testing.T) {
	// The probe in location() must see a Secret Service, so only the item lookups are locked.
	setup := func(t *testing.T, ring map[[2]string]string, locked bool) (s *Store, reads *int) {
		s, _ = flatpakEnv(t, fixedPortal("master"))
		s.ringByService(ring)
		n := 0
		get, del := s.get, s.del
		s.get = func(svc, name string) (string, error) {
			if name == hostProbeName {
				return get(svc, name)
			}
			n++
			if locked {
				return "", errors.New(lockedText)
			}
			return get(svc, name)
		}
		s.del = func(svc, name string) error {
			if locked {
				return errors.New(lockedText)
			}
			return del(svc, name)
		}
		return s, &n
	}
	own := [2]string{testService, "k"}

	t.Run("locked host is not-found and read once", func(t *testing.T) {
		s, reads := setup(t, map[[2]string]string{own: "v"}, true)
		for range 2 {
			if _, err := s.Get("k"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("got %v", err)
			}
		}
		if *reads != 1 {
			t.Fatalf("host read %d times", *reads)
		}
	})

	t.Run("unlocked host is adopted", func(t *testing.T) {
		ring := map[[2]string]string{own: "v"}
		s, _ := setup(t, ring, false)
		if v, err := s.Get("k"); err != nil || v != "v" {
			t.Fatalf("got %q, %v", v, err)
		}
		if _, ok := ring[own]; ok {
			t.Fatal("host copy not removed")
		}
		if v, err := s.Get("k"); err != nil || v != "v" {
			t.Fatalf("sealed copy lost: %q, %v", v, err)
		}
	})

	t.Run("delete with a locked host succeeds", func(t *testing.T) {
		s, _ := setup(t, map[[2]string]string{}, true)
		if err := s.Set("k", "v"); err != nil {
			t.Fatal(err)
		}
		if err := s.Delete("k"); err != nil {
			t.Fatal(err)
		}
	})
}

// A sign-out while the host keyring is locked must not come back when the next run finds the host unlocked, whether or
// not the item was looked up earlier in the run.
func TestSealedDeleteStaysDeleted(t *testing.T) {
	for _, getFirst := range []bool{true, false} {
		s, _ := flatpakEnv(t, fixedPortal("master"))
		s.ringByService(map[[2]string]string{{testService, "k"}: "old"})
		locked := true
		get, del := s.get, s.del
		lockErr := errors.New(lockedText)
		s.get = func(svc, name string) (string, error) {
			if name != hostProbeName && locked {
				return "", lockErr
			}
			return get(svc, name)
		}
		s.del = func(svc, name string) error {
			if locked {
				return lockErr
			}
			return del(svc, name)
		}
		if getFirst {
			if _, err := s.Get("k"); !errors.Is(err, ErrNotFound) {
				t.Fatalf("get: %v", err)
			}
		}
		if err := s.Set("k", "new"); err != nil {
			t.Fatal(err)
		}
		if err := s.Delete("k"); err != nil {
			t.Fatal(err)
		}
		s.hostChecked = map[string]bool{}
		locked = false
		if v, err := s.Get("k"); err == nil {
			t.Errorf("getFirst=%v: signed-out secret came back as %q", getFirst, v)
		}
	}
}

// A host error that is neither locked nor absent is returned, and the next call asks the host again instead of
// reading as signed out for the rest of the run.
func TestAdoptHostRetriesAfterStrayError(t *testing.T) {
	s, _ := flatpakEnv(t, fixedPortal("master"))
	s.ringByService(map[[2]string]string{{testService, "k"}: "old"})
	get := s.get
	fail := true
	s.get = func(svc, name string) (string, error) {
		if name != hostProbeName && fail {
			return "", errors.New("boom")
		}
		return get(svc, name)
	}
	if _, err := s.Get("k"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("first get should fail with the host error, got %v", err)
	}
	fail = false
	if v, err := s.Get("k"); err != nil || v != "old" {
		t.Fatalf("retry get = %q, %v", v, err)
	}
}

func TestSealAndUnsealRefuseABadKeyOrBlob(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	if _, err := seal([]byte("short"), []byte("x")); err == nil {
		t.Error("a key of the wrong length sealed")
	}
	if _, err := unseal([]byte("short"), []byte("x")); err == nil {
		t.Error("a key of the wrong length unsealed")
	}
	sealed, err := seal(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unseal(key, sealed[:3]); err == nil {
		t.Error("a truncated blob unsealed")
	}
	if _, err := unseal(bytes.Repeat([]byte{8}, 32), sealed); err == nil {
		t.Error("another key unsealed")
	}
	if got, err := unseal(key, sealed); err != nil || string(got) != "secret" {
		t.Errorf("round trip = %q, %v", got, err)
	}
}
