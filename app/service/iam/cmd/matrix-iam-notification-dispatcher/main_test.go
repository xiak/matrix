package main

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestPrivateMailFilesHaveOneScopeAndNoPlaintextFallback(t *testing.T) {
	key, _ := iamv1.NewSecret(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x62}, 32)))
	password, _ := iamv1.NewSecret("synthetic-private-mail-password")
	scope := iamv1.SecurityMailInstallationScope{InstallationID: "install-mail", BootstrapDigest: "sha256:" + strings.Repeat("a", 64)}
	keyring := iamv1.EmailVerificationKeyring{APIVersion: iamv1.APIVersion, Kind: "EmailVerificationKeyring", Purpose: iamv1.EmailVerificationWrappingPurpose, Scope: scope,
		KeysetRevision: 1, ActiveKeyID: "mail-key", Keys: []iamv1.EmailVerificationWrappingKey{{KeyID: "mail-key", FormatVersion: 1, KeyMaterial: key}}}
	channel := iamv1.SecurityMailSMTPChannel{APIVersion: iamv1.APIVersion, Kind: "SecurityMailSMTPChannel", Purpose: iamv1.SecurityMailSubmissionPurpose, Scope: scope,
		Host: "smtp.example.test", Port: 587, TLSMode: iamv1.SecurityMailSTARTTLS, Username: "sender", Password: password, From: "sender@example.test"}
	keyBytes, err := iamv1.EncodeEmailVerificationKeyring(keyring)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyBytes)
	channelBytes, err := iamv1.EncodeSecurityMailSMTPChannel(channel)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(channelBytes)
	directory := t.TempDir()
	channelPath, keyPath := filepath.Join(directory, "smtp.json"), filepath.Join(directory, "email-key.json")
	write := func(path string, value []byte) {
		t.Helper()
		if err := os.WriteFile(path, value, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(channelPath, channelBytes)
	write(keyPath, keyBytes)
	actualChannel, actualKey, err := readMaterial(channelPath, keyPath)
	if err != nil || actualChannel.Scope != scope || actualKey.Scope != scope {
		t.Fatal("valid private scope failed", err)
	}
	assertRejected := func(channelName, keyName string) {
		t.Helper()
		gotChannel, gotKey, err := readMaterial(channelName, keyName)
		if err == nil || gotChannel.Password.Present() || len(gotKey.Keys) != 0 || strings.Contains(err.Error(), "synthetic") || strings.Contains(err.Error(), "smtp.example") {
			t.Fatal("invalid files disclosed or returned partial material")
		}
	}
	for _, paths := range [][2]string{{"", keyPath}, {channelPath, ""}, {"relative.json", keyPath}, {directory, keyPath}, {keyPath, channelPath}} {
		assertRejected(paths[0], paths[1])
	}
	keyring.Scope.InstallationID = "another-install"
	wrong, err := iamv1.EncodeEmailVerificationKeyring(keyring)
	if err != nil {
		t.Fatal(err)
	}
	write(keyPath, wrong)
	assertRejected(channelPath, keyPath)
	clear(wrong)
	write(keyPath, keyBytes)
	write(channelPath, bytes.Replace(channelBytes, []byte("STARTTLS"), []byte("NONE"), 1))
	assertRejected(channelPath, keyPath)
	write(channelPath, append(bytes.Clone(channelBytes), '\n'))
	assertRejected(channelPath, keyPath)
	write(channelPath, channelBytes)
	link := filepath.Join(directory, "linked.json")
	if err := os.Symlink(channelPath, link); err == nil {
		assertRejected(link, keyPath)
	}
	if runtime.GOOS != "windows" {
		for _, path := range []string{channelPath, keyPath} {
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			assertRejected(channelPath, keyPath)
			if err := os.Chmod(path, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
