package keyring

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Rethunk-Tech/go-desktopenv/flatpak"
	"github.com/Rethunk-Tech/go-safefs"
)

// Inside a Flatpak secrets live in one file in the sandbox's own data folder, sealed with the XDG Secret portal's
// per-app master secret. Without the portal they go to the host's Secret Service, and with neither to a plain 0600
// file. The two file names are a format: a store written by an earlier release is found by them.
const (
	sealedFile = "secrets"
	plainFile  = "secrets.json"
)

// masterKey returns the AES key derived from the portal secret. The caller holds storeMu.
func (s *Store) masterKey() ([]byte, error) {
	if s.keyDone {
		return s.keyVal, s.keyErr
	}
	s.keyDone = true
	ctx := context.Background()
	if s.opts.PortalTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.opts.PortalTimeout)
		defer cancel()
	}
	secret, err := s.portalSecret(ctx)
	if err != nil {
		s.keyErr = err
		return nil, err
	}
	s.keyVal, s.keyErr = hkdf.Key(sha256.New, secret, nil, s.opts.SealInfo, 32)
	return s.keyVal, s.keyErr
}

// hostProbeName is a name no secret uses: asking for it only shows whether a Secret Service answers.
const hostProbeName = ".probe"

// hostKeyring reports whether the host's Secret Service answers. Only a definite "nothing on the bus" is cached as
// no: a locked or dismissed unlock prompt is an error to retry, never a reason to fall back to the plain file.
func (s *Store) hostKeyring() (bool, error) {
	if s.hostDone {
		return s.hostVal, nil
	}
	_, err := s.get(s.opts.Service, hostProbeName)
	switch {
	case err == nil || errors.Is(err, ErrNotFound):
		s.hostVal = true
	case noKeyringService(err):
		s.hostVal = false
	default:
		return false, classify(err)
	}
	s.hostDone = true
	return s.hostVal, nil
}

// location picks the sealed file when the portal answers, else the host keyring, else the plain file. A sealed file
// with no portal is an error: falling back would hide its contents and let the next write start a second store.
// host is true when the keyring holds the secrets and path and key are unused.
func (s *Store) location() (path string, key []byte, host bool, err error) {
	dir, err := s.storeDir()
	if err != nil {
		return "", nil, false, err
	}
	key, kerr := s.masterKey()
	if kerr == nil {
		if err := s.sealPlain(dir, key); err != nil {
			return "", nil, false, err
		}
		return filepath.Join(dir, sealedFile), key, false, nil
	}
	if _, err := os.Stat(filepath.Join(dir, sealedFile)); err == nil {
		return "", nil, false, fmt.Errorf("keyring: secrets are sealed and the secret portal is unavailable: %w", kerr)
	}
	host, herr := s.hostKeyring()
	if herr != nil {
		return "", nil, false, herr
	}
	if host {
		return "", nil, true, s.keyringPlain(dir)
	}
	return filepath.Join(dir, plainFile), nil, false, nil
}

// keyringPlain moves the secrets of a plain file into the host keyring and removes the file, so none is lost or
// left readable on disk. The file stays when any write fails.
func (s *Store) keyringPlain(dir string) error {
	plain := filepath.Join(dir, plainFile)
	if _, err := os.Lstat(plain); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	m, err := load(plain, nil)
	if err != nil {
		return err
	}
	for name, v := range m {
		svc, item := s.opts.Service, name
		if ns, rest, ok := s.sharedItem(name); ok {
			svc, item = ns, rest
		}
		if err := s.set(svc, item, v); err != nil {
			return classify(err)
		}
	}
	return safefs.Remove(plain)
}

func (s *Store) sharedItem(flat string) (svc, name string, ok bool) {
	for _, ns := range s.opts.SharedServices {
		if rest, found := strings.CutPrefix(flat, ns+"."); found && rest != "" {
			return ns, rest, true
		}
	}
	return "", "", false
}

// Plaintext reports whether secrets are in the unencrypted fallback file: inside a Flatpak, with neither the
// secret portal nor a host Secret Service. A store busy with a prompt returns (false, ErrPending) instead of
// waiting; a store that cannot be resolved returns (false, err).
func (s *Store) Plaintext() (bool, error) {
	if !flatpak.Inside() {
		return false, nil
	}
	if !s.storeMu.TryLock() {
		return false, ErrPending
	}
	defer s.storeMu.Unlock()
	_, key, host, err := s.location()
	if err != nil {
		return false, err
	}
	return !host && key == nil, nil
}

// sealPlain moves the secrets of a plain file, written while the portal was missing, into the sealed file once the
// portal answers, so they are neither lost to the sealed store nor left readable on disk.
func (s *Store) sealPlain(dir string, key []byte) error {
	plain, sealed := filepath.Join(dir, plainFile), filepath.Join(dir, sealedFile)
	_, err := os.Lstat(sealed)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err == nil {
		if err := safefs.Remove(plain); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	if _, err := os.Lstat(plain); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	m, err := load(plain, nil)
	if err != nil {
		return err
	}
	if err := save(sealed, key, m); err != nil {
		return err
	}
	return safefs.Remove(plain)
}

// readFile reads through os.Root so the name cannot leave the store folder.
func readFile(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.ReadFile(filepath.Base(path))
}

func load(path string, key []byte) (map[string]string, error) {
	b, err := readFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	if key != nil {
		if b, err = unseal(key, b); err != nil {
			return nil, err
		}
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]string{}
	}
	return m, nil
}

// secureDir creates dir and holds it to mode 0700: MkdirAll leaves an existing folder's mode alone, and a symlink or
// another user's folder would put the sealed store where someone else can reach it.
func secureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || !ownedByUser(info) {
		return fmt.Errorf("keyring: secrets folder %s is a link or belongs to another user", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return safefs.Chmod(dir, 0o700)
	}
	return nil
}

// save writes atomically (0600) into the vetted secrets folder.
func save(path string, key []byte, m map[string]string) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if key != nil {
		if b, err = seal(key, b); err != nil {
			return err
		}
	}
	dir := filepath.Dir(path)
	if err := secureDir(dir); err != nil {
		return err
	}
	return safefs.WriteFileAtomic(path, b, 0o600)
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal prepends the random nonce to the GCM ciphertext.
func seal(key, plain []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, plain, nil), nil
}

func unseal(key, sealed []byte) ([]byte, error) {
	g, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize() {
		return nil, errors.New("keyring: the secrets file is truncated")
	}
	plain, err := g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], nil)
	if err != nil {
		return nil, fmt.Errorf("keyring: the secrets file cannot be decrypted with the portal secret: %w", err)
	}
	return plain, nil
}

// update loads the store, applies fn and saves when fn reports a change.
func (s *Store) update(fn func(m map[string]string) bool) error {
	s.storeMu.Lock()
	defer s.storeMu.Unlock()
	path, key, host, err := s.location()
	if err != nil {
		return err
	}
	if host {
		return errors.New("keyring: update called on the host keyring")
	}
	m, err := load(path, key)
	if err != nil {
		return err
	}
	if !fn(m) {
		return nil
	}
	return save(path, key, m)
}

// flatpakSet stores a secret. On the host keyring another program's item sits under its own service and name, as a
// host-side reader looks it up; the flat name an earlier release wrote is removed.
func (s *Store) flatpakSet(service, name, value string) error {
	host, err := s.onHost()
	if err != nil {
		return err
	}
	if !host {
		if err := s.update(func(m map[string]string) bool {
			m[s.flatpakName(service, name)] = value
			delete(m, s.tombstone(service, name))
			return true
		}); err != nil {
			return err
		}
		return s.purgeHost(service, name)
	}
	if err := s.set(service, name, value); err != nil {
		return classify(err)
	}
	return s.dropLegacy(service, name)
}

func (s *Store) flatpakDelete(service, name string) error {
	host, err := s.onHost()
	if err != nil {
		return err
	}
	if !host {
		fn := s.flatpakName(service, name)
		if err := s.update(func(m map[string]string) bool {
			_, had := m[fn]
			_, dead := m[s.tombstone(service, name)]
			delete(m, fn)
			m[s.tombstone(service, name)] = "1"
			return had || !dead
		}); err != nil {
			return err
		}
		return s.dropHost(service, name)
	}
	if err := s.del(service, name); err != nil && !errors.Is(err, ErrNotFound) {
		return classify(err)
	}
	return s.dropLegacy(service, name)
}

// dropLegacy removes the item an earlier release stored under the store's own service as "<service>.<name>".
func (s *Store) dropLegacy(service, name string) error {
	if service == s.opts.Service {
		return nil
	}
	if err := s.del(s.opts.Service, s.flatpakName(service, name)); err != nil && !errors.Is(err, ErrNotFound) {
		return classify(err)
	}
	return nil
}

// onHost resolves the backend and reports whether the host keyring holds the secrets.
func (s *Store) onHost() (bool, error) {
	s.storeMu.Lock()
	defer s.storeMu.Unlock()
	_, _, host, err := s.location()
	return host, err
}

// flatpakGet reads the active store; on the host keyring a missing item falls back to the legacy name.
func (s *Store) flatpakGet(service, name string) (string, error) {
	var v string
	var ok bool
	s.storeMu.Lock()
	path, key, host, err := s.location()
	switch {
	case err != nil:
	case host:
		s.storeMu.Unlock()
		v, err = s.get(service, name)
		if errors.Is(err, ErrNotFound) && service != s.opts.Service {
			return s.get(s.opts.Service, s.flatpakName(service, name))
		}
		return v, err
	default:
		var m map[string]string
		if m, err = load(path, key); err == nil {
			v, ok = m[s.flatpakName(service, name)]
			if _, dead := m[s.tombstone(service, name)]; dead && !ok {
				key = nil // signed out: never adopt a host copy back
			}
		}
	}
	s.storeMu.Unlock()
	if err != nil {
		return "", err
	}
	if !ok {
		if key != nil {
			return s.adoptHost(service, name)
		}
		return "", ErrNotFound
	}
	return v, nil
}

// tombstone is the sealed-store key marking a signed-out secret, so a host-keyring copy that could not be purged
// (locked host) is never adopted back. Set clears it; a store without any reads as an empty set. The key is a
// stored format.
func (s *Store) tombstone(service, name string) string {
	return "\x00deleted\x00" + s.flatpakName(service, name)
}

// hostItems is the host-keyring namings of a secret: its own, then the flat one an earlier release wrote.
func (s *Store) hostItems(service, name string) [][2]string {
	items := [][2]string{{service, name}}
	if service != s.opts.Service {
		items = append(items, [2]string{s.opts.Service, s.flatpakName(service, name)})
	}
	return items
}

// hostCheckedAlready reports whether the item has a definite host answer this run.
func (s *Store) hostCheckedAlready(service, name string) bool {
	s.hostCheckedMu.Lock()
	defer s.hostCheckedMu.Unlock()
	return s.hostChecked[itemKey{service, name}]
}

func (s *Store) markHostChecked(service, name string) {
	s.hostCheckedMu.Lock()
	defer s.hostCheckedMu.Unlock()
	s.hostChecked[itemKey{service, name}] = true
}

// adoptHost moves a secret stored in the host keyring, while the portal was missing, into the sealed file. It looks
// once per item per run; a host that cannot answer is a plain miss. Only a definite answer marks the item checked, so
// any other error is retried by the next call.
func (s *Store) adoptHost(service, name string) (string, error) {
	if s.hostCheckedAlready(service, name) {
		return "", ErrNotFound
	}
	for _, it := range s.hostItems(service, name) {
		v, err := s.get(it[0], it[1])
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil && hostAbsent(err) {
			break
		}
		if err != nil {
			return "", classify(err)
		}
		return s.sealAdopted(service, name, v)
	}
	s.markHostChecked(service, name)
	return "", ErrNotFound
}

// A Delete that ran while the host read was blocked left a tombstone: the value is the signed-out one.
// A Set that finished in the same window already owns the sealed copy: keep it, still purge the host.
func (s *Store) sealAdopted(service, name, v string) (string, error) {
	signedOut := false
	kept, hasKept := "", false
	if err := s.update(func(m map[string]string) bool {
		if _, dead := m[s.tombstone(service, name)]; dead {
			signedOut = true
			return false
		}
		fn := s.flatpakName(service, name)
		if cur, ok := m[fn]; ok {
			kept, hasKept = cur, true
			return false
		}
		m[fn] = v
		return true
	}); err != nil {
		return "", err
	}
	if signedOut {
		return "", ErrNotFound
	}
	if err := s.purgeHost(service, name); err != nil {
		if !hasKept {
			_ = s.update(func(m map[string]string) bool {
				fn := s.flatpakName(service, name)
				if m[fn] != v {
					return false
				}
				delete(m, fn)
				return true
			})
		}
		return "", err
	}
	s.markHostChecked(service, name)
	if hasKept {
		return kept, nil
	}
	return v, nil
}

// dropHost removes any host-keyring copy of a secret that lives in the sealed file, once per item per run: a failed
// purge is not a check, so the next call tries again.
func (s *Store) dropHost(service, name string) error {
	if s.hostCheckedAlready(service, name) {
		return nil
	}
	if err := s.purgeHost(service, name); err != nil {
		return err
	}
	s.markHostChecked(service, name)
	return nil
}

func (s *Store) purgeHost(service, name string) error {
	for _, it := range s.hostItems(service, name) {
		err := s.del(it[0], it[1])
		if err == nil || errors.Is(err, ErrNotFound) {
			continue
		}
		if hostAbsent(err) {
			return nil
		}
		return classify(err)
	}
	return nil
}
