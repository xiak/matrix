package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPaaSCursorKeyRequiresExactProtectedInstallationFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "paas-cursor-key")
	for _, value := range []string{
		"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64),
		strings.Repeat("a", 63) + " ", strings.Repeat("a", 64) + "\n", strings.Repeat("g", 64),
	} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		if key, err := readPaaSCursorKey(path); err == nil || key != nil {
			t.Fatal("noncanonical PaaS cursor key accepted")
		}
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("ab", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := readPaaSCursorKey(path)
	if err != nil || !bytes.Equal(key, bytes.Repeat([]byte{0xab}, 32)) {
		t.Fatalf("valid PaaS cursor key rejected: %v", err)
	}
	clear(key)
	if _, err := readPaaSCursorKey("relative-key"); err == nil {
		t.Fatal("relative PaaS cursor key accepted")
	}
	link := filepath.Join(filepath.Dir(path), "linked-cursor-key")
	if err := os.Symlink(path, link); err == nil {
		if _, err := readPaaSCursorKey(link); err == nil {
			t.Fatal("linked PaaS cursor key accepted")
		}
	} else if runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readPaaSCursorKey(path); err == nil {
			t.Fatal("broadly readable PaaS cursor key accepted")
		}
	}
}

func TestPaaSConfigurationRequiresCursorCustodyAndProcessIdentity(t *testing.T) {
	required := []string{
		databaseDSNFileEnvironment, iamEndpointEnvironment, serviceCredentialFileEnvironment,
		cursorKeyFileEnvironment, listenAddressEnvironment, installationIDEnvironment,
		northboundOriginEnvironment, edgeAssertionFileEnvironment,
		releaseIDEnvironment, verificationDigestEnvironment,
	}
	for _, field := range required {
		t.Setenv(field, "fixture")
	}
	if config, err := loadConfiguration(); err != nil || config.cursorKeyFile != "fixture" {
		t.Fatalf("complete PaaS configuration rejected: %#v err=%v", config, err)
	}
	for _, field := range required {
		t.Run(field, func(t *testing.T) {
			t.Setenv(field, "")
			if _, err := loadConfiguration(); err == nil {
				t.Fatal("PaaS accepted missing required configuration")
			}
			t.Setenv(field, "fixture")
		})
	}
}
