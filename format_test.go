package keyring

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// sealed-golden was written by genfixture_test.go under portal secret goldenPortalSecret and testSealInfo. It pins
// the stored format: a change to the nonce, the key derivation or the cipher makes it unreadable.
const goldenPortalSecret = "fixture-portal-secret"

func goldenKey(t *testing.T) []byte {
	t.Helper()
	key, err := hkdf.Key(sha256.New, []byte(goldenPortalSecret), nil, testSealInfo, 32)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSealedGoldenOpens(t *testing.T) {
	m, err := load(filepath.Join("testdata", "sealed-golden"), goldenKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 2 || m["token"] != "k" || m[testShared+".team"] != "t" {
		t.Fatalf("golden holds %v", m)
	}
	other, _ := hkdf.Key(sha256.New, []byte(goldenPortalSecret), nil, "another info", 32)
	if _, err := load(filepath.Join("testdata", "sealed-golden"), other); err == nil {
		t.Fatal("a different SealInfo must not open the golden file")
	}
}

func TestSealRoundTripPrependsTheNonce(t *testing.T) {
	key := goldenKey(t)
	b, err := seal(key, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 12+1+16 {
		t.Fatalf("sealed length %d, want 12-byte nonce + 1 + 16-byte tag", len(b))
	}
	if p, err := unseal(key, b); err != nil || string(p) != "x" {
		t.Fatalf("%q, %v", p, err)
	}
}

func FuzzUnseal(f *testing.F) {
	golden, err := os.ReadFile(filepath.Join("testdata", "sealed-golden"))
	if err != nil {
		f.Fatal(err)
	}
	key, err := hkdf.Key(sha256.New, []byte(goldenPortalSecret), nil, testSealInfo, 32)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{golden, nil, make([]byte, 11), make([]byte, 12), make([]byte, 28)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		plain, err := unseal(key, data)
		if err != nil {
			return
		}
		var m map[string]string
		_ = json.Unmarshal(plain, &m)
	})
}

// FuzzPlainFile feeds arbitrary bytes, which another process in the sandbox may have written, through both
// migrations of the plain file. Malformed input must give an error, leave the file in place and write no store.
func FuzzPlainFile(f *testing.F) {
	seed, err := os.ReadFile(filepath.Join("testdata", "plain-0.3.json"))
	if err != nil {
		f.Fatal(err)
	}
	for _, s := range [][]byte{seed, nil, []byte("{"), []byte(`{"a":1}`), []byte(`{"shared.":"x","":"y"}`)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		plain := filepath.Join(dir, plainFile)
		if err := os.WriteFile(plain, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_, loadErr := load(plain, nil)
		s := newStore(t)
		s.ringByService(map[[2]string]string{})
		sealErr := s.sealPlain(dir, goldenKey(t))
		ringErr := s.keyringPlain(dir)
		_, plainErr := os.Stat(plain)
		if loadErr != nil {
			if sealErr == nil || ringErr == nil || plainErr != nil {
				t.Fatalf("malformed file: seal %v, keyring %v, file %v", sealErr, ringErr, plainErr)
			}
			if _, err := os.Stat(filepath.Join(dir, sealedFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a partial sealed store was written: %v", err)
			}
		}
	})
}

// A plain file written by an earlier release must still migrate: sealed keeps both names, the host keyring gets
// the store's own item under (Service, name) and the shared one under (shared service, name).
func TestPlainFixtureMigrates(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "plain-0.3.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Run("sealed", func(t *testing.T) {
		dir := t.TempDir()
		write := func() {
			if err := os.WriteFile(filepath.Join(dir, plainFile), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		write()
		key := goldenKey(t)
		if err := newStore(t).sealPlain(dir, key); err != nil {
			t.Fatal(err)
		}
		m, err := load(filepath.Join(dir, sealedFile), key)
		if err != nil || len(m) != 2 || m["token"] != "k" || m[testShared+".team"] != "t" {
			t.Fatalf("%v, %v", m, err)
		}
		if _, err := os.Stat(filepath.Join(dir, plainFile)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("plain file left behind: %v", err)
		}
	})
	t.Run("host keyring", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, plainFile), b, 0o600); err != nil {
			t.Fatal(err)
		}
		s := newStore(t)
		ring := map[[2]string]string{}
		s.ringByService(ring)
		if err := s.keyringPlain(dir); err != nil {
			t.Fatal(err)
		}
		if ring[[2]string{testService, "token"}] != "k" || ring[[2]string{testShared, "team"}] != "t" || len(ring) != 2 {
			t.Fatalf("ring %v", ring)
		}
	})
}
