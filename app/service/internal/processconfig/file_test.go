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

func TestReadSystemdCredentialAcceptsOnlyImmutableDirectCredential(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "credentials")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "client.key")
	if err := os.WriteFile(target, []byte("credential"), 0o600); err != nil ||
		os.Chmod(target, 0o440) != nil || os.Chmod(directory, 0o550) != nil {
		t.Fatal("prepare systemd credential fixture failed")
	}
	value, err := ReadSystemdCredential(directory, "client.key", 128, true)
	if err != nil || string(value) != "credential" {
		t.Fatalf("read systemd credential=%q err=%v", value, err)
	}
	if _, err := ReadSystemdCredential(directory, "../client.key", 128, true); err == nil {
		t.Fatal("accepted systemd credential outside its directory")
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(target, 0o444); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadSystemdCredential(directory, "client.key", 128, true); err == nil {
			t.Fatal("accepted broadly readable systemd secret")
		}
		if err := os.Chmod(target, 0o440); err != nil || os.Chmod(directory, 0o750) != nil {
			t.Fatal("broaden systemd credential directory failed")
		}
		if _, err := ReadSystemdCredential(directory, "client.key", 128, true); err == nil {
			t.Fatal("accepted writable systemd credential directory")
		}
	}
}
