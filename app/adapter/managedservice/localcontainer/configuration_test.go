package localcontainer

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConfigurationRejectsReplacementAndSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "configuration")
	if err := WriteImmutable(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteImmutable(path, []byte("changed"), 0o600); err == nil {
		t.Fatal("replaced immutable configuration")
	}
	content, _ := os.ReadFile(path)
	if string(content) != "original" {
		t.Fatal("changed existing configuration")
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Skip("symlink creation unavailable on this host")
	}
	if err := WriteImmutable(link, []byte("original"), 0o600); err == nil {
		t.Fatal("accepted a symlink")
	}
}

func TestProtectedConfigurationRejectsExposureBeforeWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "configuration")
	for _, mode := range []os.FileMode{0o644, 0o666, 0o700} {
		if err := WriteImmutable(path, []byte("private"), mode); err == nil {
			t.Fatal("accepted an exposed or executable configuration")
		}
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("invalid configuration created a file")
		}
	}
	if err := WriteImmutable(path, make([]byte, 64*1024+1), 0o600); err == nil {
		t.Fatal("accepted an unbounded configuration")
	}
}

func TestProtectedSecretRejectsExposureAndSymlinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := WriteImmutable(path, []byte(strings.Repeat("s", 48)), 0o600); err != nil {
		t.Fatal(err)
	}
	value, err := ReadProtectedSecret(path)
	clear(value)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		t.Skip("Linux permissions and symlinks are verified by the runtime gate")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if value, err := ReadProtectedSecret(path); err == nil {
		clear(value)
		t.Fatal("accepted a world-readable secret")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, path+".link"); err != nil {
		t.Fatal(err)
	}
	if value, err := ReadProtectedSecret(path + ".link"); err == nil {
		clear(value)
		t.Fatal("accepted a secret symlink")
	}
}
