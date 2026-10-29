package keyring

import (
	"errors"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewValidatesOptions(t *testing.T) {
	ok := Options{Service: "a", SealInfo: "b", Folder: "c"}
	bad := map[string]func(*Options){
		"no service":      func(o *Options) { o.Service = "" },
		"no seal info":    func(o *Options) { o.SealInfo = "" },
		"no folder":       func(o *Options) { o.Folder = "" },
		"dot folder":      func(o *Options) { o.Folder = "." },
		"dotdot folder":   func(o *Options) { o.Folder = ".." },
		"nested folder":   func(o *Options) { o.Folder = "a/b" },
		"windows nested":  func(o *Options) { o.Folder = `a\b` },
		"absolute folder": func(o *Options) { o.Folder = "/abs" },
		"empty shared":    func(o *Options) { o.SharedServices = []string{""} },
		"dotted shared":   func(o *Options) { o.SharedServices = []string{"a.b"} },
		"shared is own":   func(o *Options) { o.SharedServices = []string{"a"} },
		"one bad of many": func(o *Options) { o.SharedServices = []string{"x", ""} },
	}
	if _, err := New(ok); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range bad {
		o := ok
		mutate(&o)
		if _, err := New(o); err == nil {
			t.Errorf("%s: New accepted %+v", name, o)
		}
	}
}

func TestClassify(t *testing.T) {
	missing := errors.New(`The name org.freedesktop.secrets was not provided by any .service files: org.freedesktop.DBus.Error.ServiceUnknown`)
	if got := classify(missing); !errors.Is(got, ErrNoProvider) || !errors.Is(got, missing) {
		t.Fatalf("no provider: %v", got)
	}
	dismissed := errors.New("failed to unlock correct collection '/x'")
	got := classify(dismissed)
	if !errors.Is(got, ErrLocked) || !errors.Is(got, dismissed) || errors.Is(got, ErrNoProvider) {
		t.Fatalf("dismissed unlock: %v", got)
	}
	if again := classify(got); again != got {
		t.Fatal("classify must not wrap twice")
	}
	other := errors.New("boom")
	if classify(other) != other || classify(nil) != nil || classify(ErrNotFound) != ErrNotFound || classify(ErrTooBig) != ErrTooBig {
		t.Fatal("unrelated errors must pass through")
	}
}

func TestGetOutlivesTimeoutThenCaches(t *testing.T) {
	s := newStore(t)
	s.opts.ReadTimeout = 20 * time.Millisecond
	release := make(chan struct{})
	var reads atomic.Int32
	s.get = func(string, string) (string, error) {
		reads.Add(1)
		<-release
		return "token", nil
	}
	unlocked := make(chan struct{}, 1)
	s.opts.OnUnlocked = func() { unlocked <- struct{}{} }

	if _, err := s.Get("k"); !errors.Is(err, ErrPending) {
		t.Fatalf("want ErrPending, got %v", err)
	}
	start := time.Now()
	if _, err := s.Get("k"); !errors.Is(err, ErrPending) || time.Since(start) >= s.opts.ReadTimeout {
		t.Fatalf("a read behind a stuck prompt must fail at once, got %v after %v", err, time.Since(start))
	}
	close(release)
	select {
	case <-unlocked:
	case <-time.After(5 * time.Second):
		t.Fatal("no unlock notification")
	}
	if v, err := s.Get("k"); err != nil || v != "token" {
		t.Fatalf("late value: %q, %v", v, err)
	}
	if reads.Load() != 1 {
		t.Fatalf("the late result must be served without another backend read, got %d reads", reads.Load())
	}
}

func TestSetAndDeleteDiscardAReadStillWaiting(t *testing.T) {
	for _, del := range []bool{false, true} {
		s := newStore(t)
		s.opts.ReadTimeout = 20 * time.Millisecond
		ring := map[string]string{"k": "old"}
		release := make(chan struct{})
		read := make(chan struct{})
		s.get = func(_, name string) (string, error) {
			v := ring[name]
			close(read)
			<-release
			return v, nil
		}
		s.set = func(_, name, v string) error { ring[name] = v; return nil }
		s.del = func(_, name string) error { delete(ring, name); return nil }
		fired := make(chan struct{}, 1)
		s.opts.OnUnlocked = func() { fired <- struct{}{} }
		if _, err := s.Get("k"); !errors.Is(err, ErrPending) {
			t.Fatal(err)
		}
		<-read
		if del {
			_ = s.Delete("k")
		} else {
			_ = s.Set("k", "new")
		}
		close(release)
		select {
		case <-fired:
		case <-time.After(5 * time.Second):
			t.Fatalf("delete=%v: the caller told to wait never heard back", del)
		}
		s.get = func(_, name string) (string, error) {
			if v, ok := ring[name]; ok {
				return v, nil
			}
			return "", ErrNotFound
		}
		v, err := s.Get("k")
		if del && !errors.Is(err, ErrNotFound) || !del && v != "new" {
			t.Fatalf("delete=%v: got %q, %v after the stale read finished", del, v, err)
		}
	}
}

func TestHostKeyringOutsideAFlatpak(t *testing.T) {
	s := newStore(t)
	ring := map[[2]string]string{}
	s.ringByService(ring)
	if err := s.SetIn(testShared, "team", "tok"); err != nil || ring[[2]string{testShared, "team"}] != "tok" {
		t.Fatalf("SetIn: %v %v", err, ring)
	}
	if v, err := s.GetIn(testShared, "team"); err != nil || v != "tok" {
		t.Fatalf("GetIn: %q, %v", v, err)
	}
	if err := s.DeleteIn(testShared, "team"); err != nil || len(ring) != 0 {
		t.Fatalf("DeleteIn: %v %v", err, ring)
	}
	if err := s.Delete("gone"); err != nil {
		t.Fatalf("a missing name is not an error: %v", err)
	}
	if _, err := s.Get("gone"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	s.ringDown()
	if err := s.Set("k", "v"); !errors.Is(err, ErrNoProvider) {
		t.Fatalf("want ErrNoProvider, got %v", err)
	}
}

func TestZalandoVersionMatchesTheBuild(t *testing.T) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("no build info")
	}
	for _, d := range info.Deps {
		if d.Path == "github.com/zalando/go-keyring" {
			if d.Version != ZalandoVersion {
				t.Fatalf("ZalandoVersion = %s, but the build uses %s", ZalandoVersion, d.Version)
			}
			return
		}
	}
	t.Fatal("zalando/go-keyring is not in the build")
}
