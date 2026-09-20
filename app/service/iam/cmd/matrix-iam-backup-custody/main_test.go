package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
)

func TestSnapshotControlRequiresExactFrameAndEOF(t *testing.T) {
	for _, frame := range []string{"", "RELEASE", "release\n", "RELEASE\r\n", "RELEASE\nextra", "RELEASE\n\n"} {
		if err := awaitRelease(t.Context(), io.NopCloser(strings.NewReader(frame))); !errors.Is(err, errInvalid) {
			t.Fatal("ambiguous or partial control frame was accepted", err)
		}
	}
	if err := awaitRelease(t.Context(), io.NopCloser(strings.NewReader(installationv1.TOTPBackupCustodyReleaseFrame))); err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	written := make(chan error, 1)
	go func() { _, err := io.WriteString(writer, installationv1.TOTPBackupCustodyReleaseFrame); written <- err }()
	if err := awaitRelease(ctx, reader); !errors.Is(err, iampostgres.ErrBackupCustodyUnavailable) {
		t.Fatal("a complete frame without EOF kept/closed the lease successfully", err)
	}
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("control cancellation left a blocked writer")
	}
}

func TestBackupEntryRejectsUnscopedInputsWithoutConnecting(t *testing.T) {
	for _, args := range [][]string{nil, {"inspect"}, {"snapshot", "--timeout", "3600"}, {"snapshot", "anything"}} {
		var output bytes.Buffer
		err := run(t.Context(), args, io.NopCloser(strings.NewReader("")), &output, func(string) string { t.Fatal("invalid command read configuration"); return "" })
		if !errors.Is(err, errInvalid) || output.Len() != 0 {
			t.Fatal("invalid command reached backup", err)
		}
	}
	for _, value := range []string{"", "postgres://localhost/database", "postgres://reader@localhost:5432/database", "host=localhost user=reader password=secret",
		"postgres://reader:secret@localhost:5432/database?passfile=another-file", "postgres://reader:secret@localhost:5432/database?service=external"} {
		path := filepath.Join(t.TempDir(), "private-dsn")
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		err := run(t.Context(), []string{installationv1.TOTPBackupCustodySnapshotCommand}, io.NopCloser(strings.NewReader("")), &output,
			func(name string) string {
				if name != installationv1.TOTPBackupCustodyDatabaseDSNFileEnvironment {
					t.Fatal("read another environment")
				}
				return path
			})
		if !errors.Is(err, errInvalid) || output.Len() != 0 {
			t.Fatal("partial/ambient configuration accepted", err)
		}
	}
}

func TestBackupFailuresHaveOnlyFrozenSanitizedCodes(t *testing.T) {
	for _, test := range []struct {
		err  error
		exit int
		text string
	}{
		{errInvalid, installationv1.TOTPBackupCustodyExitInvalid, installationv1.TOTPBackupCustodyErrorInvalid},
		{iampostgres.ErrBackupCustodyForbidden, installationv1.TOTPBackupCustodyExitForbidden, installationv1.TOTPBackupCustodyErrorForbidden},
		{errors.New("native error with private path/password"), installationv1.TOTPBackupCustodyExitUnavailable, installationv1.TOTPBackupCustodyErrorUnavailable},
	} {
		exit, text := failure(test.err)
		if exit != test.exit || text != test.text || strings.ContainsAny(text, " \r\n\t") {
			t.Fatal("failure escaped fixed protocol")
		}
	}
}

func TestBackupDSNConsumesPoolOptionsWithoutSendingThemToPostgres(t *testing.T) {
	config, err := parseBackupConfig("postgres://matrix_iam_backup_custody_login:synthetic-password@127.0.0.1:5432/isolated?sslmode=disable&pool_max_conns=2&pool_min_conns=0&application_name=installed")
	if err != nil || config.User != "matrix_iam_backup_custody_login" || config.Password != "synthetic-password" ||
		config.Host != "127.0.0.1" || config.Port != 5432 || config.Database != "isolated" {
		t.Fatal("installed DSN did not preserve its explicit target and credential")
	}
	for name := range config.RuntimeParams {
		if strings.HasPrefix(name, "pool_") {
			t.Fatal("client pool setting escaped into server startup parameters")
		}
	}
}
