//go:build linux

package keyring

import (
	"errors"
	"os"
	"testing"
)

// a purge error after adoption marks the item checked, so Delete skips the host purge and reports success.
func TestDeleteRetriesHostPurgeAfterAdoptionFailed(t *testing.T) {
	s, _ := flatpakEnv(t, fixedPortal("master"))
	ring := map[[2]string]string{{testService, "k"}: "old"}
	s.ringByService(ring)
	del := s.del
	failOnce := true
	s.del = func(svc, name string) error {
		if failOnce {
			failOnce = false
			return errors.New("transient dbus failure")
		}
		return del(svc, name)
	}
	if v, err := s.Get("k"); v != "" || err == nil {
		t.Fatalf("a failed purge must not return the value: %q, %v", v, err)
	}
	if err := s.Delete("k"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, still := ring[[2]string{testService, "k"}]; still {
		t.Errorf("host copy survived Delete, which reported success")
	}
}

// a plain file holding JSON null loads a nil map and the next write panics.
func TestNullPlainFileReadsAsEmpty(t *testing.T) {
	s, dir := noPortalEnv(t)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeIn(t, dir, plainFile, []byte("null"))
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Set panicked: %v", r)
		}
	}()
	_ = s.Set("x", "y")
}

// an own item whose name starts with a shared service's name collides with that shared item.
func TestOwnNameCannotShadowSharedItem(t *testing.T) {
	s, _ := flatpakEnv(t, fixedPortal("master"))
	if err := s.SetIn(testShared, "token", "A-shared"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(testShared+".token", "B-own"); !errors.Is(err, ErrReservedName) {
		t.Fatalf("Set = %v, want ErrReservedName", err)
	}
	if v, _ := s.GetIn(testShared, "token"); v != "A-shared" {
		t.Errorf("shared item overwritten by own item: got %q", v)
	}
}

// a service or name holding a separator must not share a flight with another item.
func TestSeparatorsDoNotJoinItems(t *testing.T) {
	s, _ := flatpakEnv(t, fixedPortal("master"))
	s.ringByService(map[[2]string]string{{"a\nb", "c"}: "one", {"a", "b\nc"}: "two"})
	if v, err := s.GetIn("a\nb", "c"); err != nil || v != "one" {
		t.Fatalf("first = %q, %v", v, err)
	}
	if v, err := s.GetIn("a", "b\nc"); err != nil || v != "two" {
		t.Fatalf("second = %q, %v", v, err)
	}
}

// adoption writes a host value after a concurrent Delete, so a signed-out secret comes back.
func TestDeleteDuringAdoptionStaysDeleted(t *testing.T) {
	s, _ := flatpakEnv(t, fixedPortal("master"))
	s.ringByService(map[[2]string]string{{testService, "k"}: "old"})
	orig := s.get
	entered, release := make(chan struct{}), make(chan struct{})
	s.get = func(svc, name string) (string, error) {
		v, err := orig(svc, name)
		if name == "k" && svc == testService && err == nil {
			close(entered)
			<-release
		}
		return v, err
	}
	done := make(chan struct{})
	go func() { _, _ = s.Get("k"); close(done) }()
	<-entered
	if err := s.Delete("k"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	close(release)
	<-done
	if v, err := s.Get("k"); err == nil {
		t.Errorf("signed-out secret came back as %q", v)
	}
}
