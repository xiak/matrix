package processconfig

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadTextRequiresExactProtectedRegularFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "credential")
	if err := os.WriteFile(path, []byte("credential-exact"), 0o600); err != nil {
		t.Fatalf("write process input: %v", err)
	}
	value, err := ReadText(path, 128, true)
	if err != nil || value != "credential-exact" {
		t.Fatalf("read process text=%q err=%v", value, err)
	}
	if _, err := ReadText("credential", 128, true); err == nil {
		t.Fatal("accepted relative process input path")
	}
	if err := os.WriteFile(path, []byte("credential\n"), 0o600); err != nil {
		t.Fatalf("rewrite process input: %v", err)
	}
	if _, err := ReadText(path, 128, true); err == nil {
		t.Fatal("accepted control character in process text")
	}
}

func TestReadFileRejectsOversizeLinksAndBroadSecretModes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "input")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatalf("write process input: %v", err)
	}
	if _, err := ReadFile(path, 4, true); err == nil {
		t.Fatal("accepted oversized process input")
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(path, link); err == nil {
		if _, err := ReadFile(link, 128, true); err == nil {
			t.Fatal("accepted linked process input")
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatalf("broaden process input permissions: %v", err)
		}
		if _, err := ReadFile(path, 128, true); err == nil {
			t.Fatal("accepted broadly readable process secret")
		}
	}
}
