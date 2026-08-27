// matrix-release is the repository-owned build entry point for authenticated
// offline releases. It is not shipped as an operator command; mx remains the
// only user-facing product CLI.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	installationrelease "github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/deploy/releasebuild"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix release build failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string, output io.Writer) error {
	if ctx == nil || output == nil || len(arguments) == 0 {
		return errors.New("release build command is required")
	}
	switch arguments[0] {
	case "keygen":
		return runKeygen(arguments[1:], output)
	case "assemble":
		return runAssemble(ctx, arguments[1:], output)
	default:
		return errors.New("release build command is unsupported")
	}
}

func runKeygen(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	keyID := flags.String("key-id", "", "release signer key ID")
	privatePath := flags.String("private-key", "", "private signing key path")
	trustPath := flags.String("trust-key", "", "public trust root path")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("release key generation input is invalid")
	}
	privateAbsolute, err := absolutePath(*privatePath)
	if err != nil {
		return err
	}
	trustAbsolute, err := absolutePath(*trustPath)
	if err != nil {
		return err
	}
	trust, err := releasebuild.GenerateSigningFiles(
		*keyID, privateAbsolute, trustAbsolute, rand.Reader,
	)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "created signer %s\n", trust.KeyID)
	return err
}

func runAssemble(ctx context.Context, arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("assemble", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	repository := flags.String("repository", ".", "clean repository root")
	bundle := flags.String("output", "", "new bundle directory")
	version := flags.String("version", "", "release semantic version")
	buildID := flags.String("build-id", "", "release build identity")
	createdAtText := flags.String("created-at", "", "UTC RFC3339 build time")
	privatePath := flags.String("private-key", "", "private signing key path")
	trustPath := flags.String("trust-key", "", "public trust root path")
	previousID := flags.String("previous-id", "", "immediate predecessor release ID")
	previousVersion := flags.String("previous-version", "", "immediate predecessor version")
	target := flags.String("target", "platform", "release target: platform or node")
	collectorArchive := flags.String("collector-archive", "", "fixed node collector release archive")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("release assembly input is invalid")
	}
	kind := installationrelease.ManifestKind
	collectorAbsolute := ""
	if *target == "node" {
		kind = installationrelease.NodeManifestKind
		var err error
		collectorAbsolute, err = absolutePath(*collectorArchive)
		if err != nil {
			return err
		}
	} else if *target != "platform" || *collectorArchive != "" {
		return errors.New("release target input is invalid")
	}
	repositoryAbsolute, err := absolutePath(*repository)
	if err != nil {
		return err
	}
	bundleAbsolute, err := absolutePath(*bundle)
	if err != nil {
		return err
	}
	privateAbsolute, err := absolutePath(*privatePath)
	if err != nil {
		return err
	}
	trustAbsolute, err := absolutePath(*trustPath)
	if err != nil {
		return err
	}
	createdAt, err := time.Parse(time.RFC3339Nano, *createdAtText)
	if err != nil {
		return errors.New("release creation time is invalid")
	}
	sourceCommit, err := cleanSourceCommit(ctx, repositoryAbsolute)
	if err != nil {
		return err
	}
	signer, derivedTrust, err := releasebuild.ReadSigningKey(privateAbsolute)
	if err != nil {
		return err
	}
	defer clear(signer.PrivateKey)
	trustBytes, suppliedTrust, err := installationrelease.ReadTrustRootFile(trustAbsolute)
	if err != nil {
		return err
	}
	defer clear(trustBytes)
	derivedBytes, err := installationrelease.EncodeTrustRoot(derivedTrust)
	if err != nil {
		return err
	}
	defer clear(derivedBytes)
	suppliedBytes, err := installationrelease.EncodeTrustRoot(suppliedTrust)
	if err != nil || subtle.ConstantTimeCompare(derivedBytes, suppliedBytes) != 1 {
		clear(suppliedBytes)
		return errors.New("release signing key and trust root do not match")
	}
	clear(suppliedBytes)
	result, err := releasebuild.Assemble(ctx, releasebuild.Config{
		Kind: kind, CollectorArchive: collectorAbsolute,
		RepositoryRoot: repositoryAbsolute, Output: bundleAbsolute,
		Version: *version, BuildID: *buildID, SourceCommit: sourceCommit,
		CreatedAt: createdAt, PreviousID: *previousID,
		PreviousVersion: *previousVersion, Signer: signer,
	}, releasebuild.NewLocalEffects())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "assembled %s\n", result.Manifest.Release.ID)
	return err
}

func cleanSourceCommit(ctx context.Context, repository string) (string, error) {
	status, err := gitOutput(ctx, repository, "status", "--porcelain=v1", "--untracked-files=normal")
	if err != nil || len(bytes.TrimSpace(status)) != 0 {
		return "", errors.New("release repository is not a clean Git worktree")
	}
	commit, err := gitOutput(ctx, repository, "rev-parse", "HEAD")
	if err != nil {
		return "", errors.New("release source commit is unavailable")
	}
	value := strings.TrimSpace(string(commit))
	if len(value) != 40 {
		return "", errors.New("release source commit is invalid")
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return "", errors.New("release source commit is invalid")
		}
	}
	return value, nil
}

func gitOutput(ctx context.Context, repository string, arguments ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, "git", append([]string{"-C", repository}, arguments...)...)
	command.Stdin = nil
	command.Stderr = io.Discard
	output := &boundedOutput{maximum: 64 * 1024}
	command.Stdout = output
	if err := command.Run(); err != nil || output.exceeded {
		return nil, errors.New("Git release source query failed")
	}
	return append([]byte(nil), output.Bytes()...), nil
}

type boundedOutput struct {
	bytes.Buffer
	maximum  int
	exceeded bool
}

func (output *boundedOutput) Write(content []byte) (int, error) {
	if output.Len()+len(content) > output.maximum {
		output.exceeded = true
		remaining := output.maximum - output.Len()
		if remaining > 0 {
			_, _ = output.Buffer.Write(content[:remaining])
		}
		return len(content), nil
	}
	return output.Buffer.Write(content)
}

func absolutePath(value string) (string, error) {
	if value == "" {
		return "", errors.New("release build path is required")
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return "", errors.New("release build path is invalid")
	}
	return filepath.Clean(absolute), nil
}
