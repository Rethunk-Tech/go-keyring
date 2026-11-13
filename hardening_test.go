//go:build linux

package keyring

import (
	"errors"
	"os"
	"testing"
	"time"
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

// a service or name holding a separator must not share a flight with another item: the second ask has to answer
// while the first is still blocked in the backend.
func TestSeparatorsDoNotJoinItems(t *testing.T) {
	s, _ := flatpakEnv(t, fixedPortal("master"))
	s.ringByService(map[[2]string]string{{"a\nb", "c"}: "one", {"a", "b\nc"}: "two"})
	orig := s.get
	entered, release := make(chan struct{}), make(chan struct{})
	s.get = func(svc, name string) (string, error) {
		if svc == "a\nb" {
			close(entered)
			<-release
		}
		return orig(svc, name)
	}
	first := make(chan string, 1)
	go func() { v, _ := s.GetIn("a\nb", "c"); first <- v }()
	<-entered
	second := make(chan string, 1)
	go func() { v, _ := s.GetIn("a", "b\nc"); second <- v }()
	var got string
	select {
	case got = <-second:
	case <-time.After(2 * time.Second):
		t.Error("the second item waited on the first's flight")
		close(release)
		got = <-second
	}
	if got != "two" {
		t.Errorf("second = %q, want two", got)
	}
	select {
	case <-release:
	default:
		close(release)
	}
	if v := <-first; v != "one" {
		t.Errorf("first = %q, want one", v)
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

// adoption writes a host value after a concurrent Set, so a newly stored secret is overwritten.
func TestSetDuringAdoptionKeepsNewValue(t *testing.T) {
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
	if err := s.Set("k", "new"); err != nil {
		t.Fatalf("set: %v", err)
	}
	close(release)
	<-done
	if v, err := s.Get("k"); err != nil || v != "new" {
		t.Errorf("Get after concurrent Set = %q, %v; want new", v, err)
	}
}

// a purge error after adoption leaves the host copy, and the next Get serves the sealed item without retrying.
func TestGetRetriesHostPurgeAfterAdoptionFailed(t *testing.T) {
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
	if v, err := s.Get("k"); err != nil || v != "old" {
		t.Fatalf("retry Get = %q, %v; want old", v, err)
	}
	if _, still := ring[[2]string{testService, "k"}]; still {
		t.Errorf("host copy survived the second Get")
	}
}

// Set writes the sealed file and leaves a host-keyring copy from when the portal was missing.
func TestSetPurgesHostCopy(t *testing.T) {
	s, _ := flatpakEnv(t, fixedPortal("master"))
	ring := map[[2]string]string{{testService, "k"}: "old"}
	s.ringByService(ring)
	if err := s.Set("k", "new"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if _, still := ring[[2]string{testService, "k"}]; still {
		t.Errorf("host copy survived Set")
	}
}
