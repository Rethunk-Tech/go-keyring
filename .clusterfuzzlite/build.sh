#!/bin/bash -eu

go get github.com/AdamKorcz/go-118-fuzz-build/testing

# go-118-fuzz-build compiles the converted fuzz file as a non-test package, so
# helpers in sibling *_test.go files are dropped. Its T is not *testing.T.
python3 - <<'PY'
from pathlib import Path

iface = """
type cfliteT interface {
	Helper()
	Cleanup(func())
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	TempDir() string
	Name() string
	Logf(format string, args ...any)
	Skip(args ...any)
	Skipf(format string, args ...any)
	Error(args ...any)
	Errorf(format string, args ...any)
}
"""
import re

text = Path("helpers_test.go").read_text().replace("*testing.T", "cfliteT")
text = re.sub(r'\n\t"testing"\n', "\n", text)
text = re.sub(r'\n"testing"\n', "\n", text)
Path("helpers_cflite.go").write_text(text + "\n" + iface)
PY

compile_native_go_fuzzer github.com/Totative/go-keyring FuzzUnseal fuzz_unseal
compile_native_go_fuzzer github.com/Totative/go-keyring FuzzPlainFile fuzz_plainfile
