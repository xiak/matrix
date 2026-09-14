package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCursorKeyRequiresExactProtectedInstallationFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "iam-cursor-key")
	for _, value := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), strings.Repeat("a", 63) + " ", strings.Repeat("a", 64) + "\n", strings.Repeat("g", 64)} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if key, err := readCursorKey(path); err == nil || key != nil {
			t.Fatal("noncanonical key file accepted")
		}
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := readCursorKey(path)
	if err != nil || !bytes.Equal(key, bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatal("valid private key rejected")
	}
	clear(key)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readCursorKey(path); err == nil {
			t.Fatal("world-readable key accepted")
		}
	}
	if _, err := readCursorKey("relative-key"); err == nil {
		t.Fatal("relative key accepted")
	}
}

func TestIAMNetworkConfigurationRequiresCursorKey(t *testing.T) {
	for _, field := range []string{databaseDSNFileEnvironment, bootstrapFileEnvironment, listenAddressEnvironment, cursorKeyFileEnvironment} {
		t.Setenv(field, "fixture")
	}
	if _, err := loadConfiguration(); err != nil {
		t.Fatal(err)
	}
	t.Setenv(cursorKeyFileEnvironment, "")
	if _, err := loadConfiguration(); err == nil {
		t.Fatal("network IAM started without persistent cursor key")
	}
}
