package keyring_test

import (
	"errors"
	"fmt"

	"github.com/Totative/go-keyring"
)

func Example() {
	store, err := keyring.New(keyring.Options{
		Service:    "example",
		SealInfo:   "example secrets v1",
		Folder:     "example-secrets",
		OnUnlocked: func() { fmt.Println("keyring unlocked: retry what was deferred") },
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	if err := store.Set("api-key", "s3cret"); err != nil {
		fmt.Println(err)
		return
	}
	v, err := store.Get("api-key")
	switch {
	case errors.Is(err, keyring.ErrNotFound):
		fmt.Println("signed out")
	case errors.Is(err, keyring.ErrPending):
		fmt.Println("waiting for the user to unlock the keyring")
	case err != nil:
		fmt.Println(err)
	default:
		fmt.Println(v)
	}
	_ = store.Delete("api-key")
	// OS keyring and antivirus behaviour differ by machine, so this example asserts no output.
}

func ExampleNew() {
	store, err := keyring.New(keyring.Options{
		Service:  "example",
		SealInfo: "example secrets v1",
		Folder:   "example-secrets",
	})
	fmt.Println(err == nil, store != nil)
	// Output:
	// true true
}

func ExampleStore_Set() {
	store, err := keyring.New(keyring.Options{
		Service:  "example",
		SealInfo: "example secrets v1",
		Folder:   "example-secrets",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(store.Set("api-key", "s3cret"))
	_ = store.Delete("api-key")
	// OS keyring and antivirus behaviour differ by machine, so this example asserts no output.
}

func ExampleStore_Get() {
	store, err := keyring.New(keyring.Options{
		Service:  "example",
		SealInfo: "example secrets v1",
		Folder:   "example-secrets",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	v, err := store.Get("api-key")
	fmt.Println(v, err)
	// OS keyring and antivirus behaviour differ by machine, so this example asserts no output.
}

func ExampleStore_Delete() {
	store, err := keyring.New(keyring.Options{
		Service:  "example",
		SealInfo: "example secrets v1",
		Folder:   "example-secrets",
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(store.Delete("api-key"))
	// OS keyring and antivirus behaviour differ by machine, so this example asserts no output.
}

func ExampleStore_SetIn() {
	store, err := keyring.New(keyring.Options{
		Service:        "example",
		SealInfo:       "example secrets v1",
		Folder:         "example-secrets",
		SharedServices: []string{"other-app"},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(store.SetIn("other-app", "api-key", "s3cret"))
	_ = store.DeleteIn("other-app", "api-key")
	// OS keyring and antivirus behaviour differ by machine, so this example asserts no output.
}

func ExampleStore_GetIn() {
	store, err := keyring.New(keyring.Options{
		Service:        "example",
		SealInfo:       "example secrets v1",
		Folder:         "example-secrets",
		SharedServices: []string{"other-app"},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	v, err := store.GetIn("other-app", "api-key")
	fmt.Println(v, err)
	// OS keyring and antivirus behaviour differ by machine, so this example asserts no output.
}

func ExampleStore_DeleteIn() {
	store, err := keyring.New(keyring.Options{
		Service:        "example",
		SealInfo:       "example secrets v1",
		Folder:         "example-secrets",
		SharedServices: []string{"other-app"},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(store.DeleteIn("other-app", "api-key"))
	// OS keyring and antivirus behaviour differ by machine, so this example asserts no output.
}
