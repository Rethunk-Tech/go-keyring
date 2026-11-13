package keyring

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Rethunk-Tech/go-desktopenv/flatpak"
	"github.com/Rethunk-Tech/go-desktopenv/portal"
	"github.com/Rethunk-Tech/go-desktopenv/userdirs"
	zkeyring "github.com/zalando/go-keyring"
)

const defaultReadTimeout = 3 * time.Second

// Options configures a Store. Service, SealInfo and Folder have no defaults: a derived one would let two programs
// share a store without either choosing it.
type Options struct {
	Service  string // keyring service for Get, Set and Delete. Required
	SealInfo string // HKDF info deriving the sealed file's key from the portal secret. Required
	Folder   string // the Flatpak store's folder name under the data home. Required, one path element
	// SharedServices are other programs' services whose items the Flatpak files keep as "<service>.<name>";
	// a plain file moving to the host keyring puts those back under (service, name).
	SharedServices []string
	// ReadTimeout bounds how long Get waits before returning ErrPending. Zero means 3s.
	ReadTimeout time.Duration
	// PortalTimeout bounds the Secret portal call, which may sit behind a dialog. Zero means no bound.
	PortalTimeout time.Duration
	// OnUnlocked runs after a read that outlived ReadTimeout completes, or was overtaken by a Set or Delete, so
	// the app can retry what it deferred.
	OnUnlocked func()
}

// itemKey names an item in the in-memory maps; a struct, because no separator is safe against a name that holds it.
type itemKey struct{ service, name string }

// Store is one credential store. Use one Store per Folder per process: the Flatpak store's lock is per Store.
type Store struct {
	opts Options

	// Backend and portal seams, replaced by the package's own tests.
	get          func(svc, name string) (string, error)
	set          func(svc, name, value string) error
	del          func(svc, name string) error
	portalSecret func(ctx context.Context) ([]byte, error)
	storeDir     func() (string, error)

	mu       sync.Mutex
	inflight map[itemKey]*flight
	// late holds the values of reads that finished after their caller gave up, for the next Get of that name.
	late map[itemKey]string

	storeMu sync.Mutex
	// The portal is asked once per process; a failure is cached so a missing portal is not retried on every call.
	keyDone bool
	keyVal  []byte
	keyErr  error
	// The host keyring is probed until it answers; only a definite "nothing on the bus" is cached.
	hostDone bool
	hostVal  bool

	// hostChecked holds the items already looked up in the host keyring this run: a locked host keyring raises an
	// unlock prompt on every lookup, so each item is asked about once and a later run tries again.
	hostCheckedMu sync.Mutex
	hostChecked   map[itemKey]bool
}

type flight struct {
	done  chan struct{}
	value string
	err   error
	// stuck is set once a caller gave up on it; later callers then fail at once instead of each waiting.
	stuck bool
	// stale is set when a Set or Delete of the name overtook the read: its value must not reach the cache.
	stale bool
}

// New returns a Store, or an error when a required option is empty or malformed.
func New(o Options) (*Store, error) {
	if o.Service == "" || o.SealInfo == "" || o.Folder == "" {
		return nil, errors.New("keyring: Service, SealInfo and Folder are required")
	}
	if o.Folder == "." || o.Folder == ".." || strings.ContainsAny(o.Folder, `/\`) || filepath.VolumeName(o.Folder) != "" {
		return nil, fmt.Errorf("keyring: Folder %q must be one path element", o.Folder)
	}
	for _, svc := range o.SharedServices {
		if svc == "" || strings.Contains(svc, ".") || svc == o.Service {
			return nil, fmt.Errorf("keyring: SharedServices entry %q must be non-empty, hold no \".\" and differ from Service", svc)
		}
	}
	o.SharedServices = append([]string(nil), o.SharedServices...)
	s := &Store{
		opts:        o,
		get:         zkeyring.Get,
		set:         zkeyring.Set,
		del:         zkeyring.Delete,
		inflight:    map[itemKey]*flight{},
		late:        map[itemKey]string{},
		hostChecked: map[itemKey]bool{},
	}
	s.portalSecret = portal.RetrieveSecret
	s.storeDir = s.defaultStoreDir
	return s, nil
}

// defaultStoreDir is the Flatpak store's folder in the sandbox's own data home, never a relative path.
func (s *Store) defaultStoreDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	base := userdirs.DataHome(home)
	if base == "" {
		return "", errors.New("keyring: no data home")
	}
	return filepath.Join(base, s.opts.Folder), nil
}

func (s *Store) readTimeout() time.Duration {
	if s.opts.ReadTimeout > 0 {
		return s.opts.ReadTimeout
	}
	return defaultReadTimeout
}

func (s *Store) unlocked() {
	if s.opts.OnUnlocked != nil {
		s.opts.OnUnlocked()
	}
}

// Get returns the secret stored under name.
func (s *Store) Get(name string) (string, error) { return s.GetIn(s.opts.Service, name) }

// GetIn returns the secret another program shares under its own service and name. Outside a Flatpak, and in
// host-keyring mode, that program can read it too.
func (s *Store) GetIn(service, name string) (string, error) {
	if err := s.checkName(service, name); err != nil {
		return "", err
	}
	key := itemKey{service, name}
	s.mu.Lock()
	if v, ok := s.late[key]; ok {
		delete(s.late, key)
		s.mu.Unlock()
		return v, nil
	}
	f, running := s.inflight[key]
	if running && f.stuck {
		s.mu.Unlock()
		return "", ErrPending
	}
	if !running {
		f = &flight{done: make(chan struct{})}
		s.inflight[key] = f
		go s.run(service, name, f)
	}
	s.mu.Unlock()
	timer := time.NewTimer(s.readTimeout())
	defer timer.Stop()
	select {
	case <-f.done:
		return f.value, classify(f.err)
	case <-timer.C:
		s.mu.Lock()
		select {
		case <-f.done:
			s.mu.Unlock()
			return f.value, classify(f.err)
		default:
		}
		f.stuck = true
		s.mu.Unlock()
		return "", ErrPending
	}
}

func (s *Store) run(service, name string, f *flight) {
	key := itemKey{service, name}
	var v string
	var err error
	if flatpak.Inside() {
		v, err = s.flatpakGet(service, name)
	} else {
		v, err = s.get(service, name)
	}
	s.mu.Lock()
	f.value, f.err = v, err
	if s.inflight[key] == f {
		delete(s.inflight, key)
	}
	// A stale read is not kept, but its caller was told to wait, so it still hears back and reads the new value.
	deliver := f.stuck
	if deliver && err == nil && !f.stale {
		s.late[key] = v
	}
	close(f.done)
	s.mu.Unlock()
	if deliver {
		s.unlocked()
	}
}

// Set stores value under name, replacing any earlier one. It is not bounded: a locked keyring holds it on the
// unlock prompt.
func (s *Store) Set(name, value string) error { return s.SetIn(s.opts.Service, name, value) }

// SetIn stores value under another program's service and name, as GetIn reads it.
func (s *Store) SetIn(service, name, value string) error {
	if err := s.checkName(service, name); err != nil {
		return err
	}
	s.forget(service, name)
	if flatpak.Inside() {
		return s.flatpakSet(service, name, value)
	}
	return classify(s.set(service, name, value))
}

func (s *Store) forget(service, name string) {
	key := itemKey{service, name}
	s.mu.Lock()
	delete(s.late, key)
	if f, ok := s.inflight[key]; ok {
		f.stale = true
		delete(s.inflight, key)
	}
	s.mu.Unlock()
}

// flatpakName is the sealed and plain files' name for a secret: the store's own items keep their bare name.
func (s *Store) flatpakName(service, name string) string {
	if service == s.opts.Service {
		return name
	}
	return service + "." + name
}

// Delete removes the secret under name; one that is already gone is not an error. It is not bounded.
func (s *Store) Delete(name string) error { return s.DeleteIn(s.opts.Service, name) }

// DeleteIn removes the secret under another program's service and name.
func (s *Store) DeleteIn(service, name string) error {
	if err := s.checkName(service, name); err != nil {
		return err
	}
	s.forget(service, name)
	if flatpak.Inside() {
		return s.flatpakDelete(service, name)
	}
	if err := s.del(service, name); err != nil && !errors.Is(err, ErrNotFound) {
		return classify(err)
	}
	return nil
}

// checkName refuses an item of the store's own service named like a shared one: the Flatpak files keep both as
// "<service>.<name>", so the two would be one item.
func (s *Store) checkName(service, name string) error {
	if service != s.opts.Service {
		return nil
	}
	if _, _, shared := s.sharedItem(name); shared {
		return ErrReservedName
	}
	return nil
}
