package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	installationrelease "github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/deploy/releasebuild"
)

func TestKeygenProducesSeparateMatchingTrustWithoutSecretOutput(t *testing.T) {
	root := t.TempDir()
	privatePath := filepath.Join(root, "release-signing-key.json")
	trustPath := filepath.Join(root, "release-trust.json")
	var output bytes.Buffer
	if err := run(context.Background(), []string{
		"keygen", "--key-id", "xiak-release-2026",
		"--private-key", privatePath, "--trust-key", trustPath,
	}, &output); err != nil {
		t.Fatal(err)
	}
	material, derivedTrust, err := releasebuild.ReadSigningKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(material.PrivateKey)
	trustBytes, storedTrust, err := installationrelease.ReadTrustRootFile(trustPath)
	if err != nil {
		t.Fatal(err)
	}
	clear(trustBytes)
	if derivedTrust != storedTrust {
		t.Fatal("generated private and public files do not match")
	}
	if strings.Contains(output.String(), privatePath) || strings.Contains(output.String(), trustPath) ||
		strings.Contains(output.String(), derivedTrust.PublicKey) {
		t.Fatal("key generation output disclosed key material or local paths")
	}
}

func TestReleaseBuildRejectsUnknownCommand(t *testing.T) {
	if err := run(context.Background(), []string{"shell"}, &bytes.Buffer{}); err == nil {
		t.Fatal("arbitrary release build command was accepted")
	}
}
