//go:build genfixture

package keyring

import (
	"os"
	"testing"
)

// TestGenSealedGolden rewrites testdata/sealed-golden with the seal in this tree:
// go test -tags genfixture -run TestGenSealedGolden .
func TestGenSealedGolden(t *testing.T) {
	b, err := seal(goldenKey(t), []byte(`{"token":"k","shared.team":"t"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("testdata/sealed-golden", b, 0o600); err != nil {
		t.Fatal(err)
	}
}
