package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAccessAnalysisDatabaseFileRequiresExactPrivateLogin(t *testing.T) {
	directory := t.TempDir()
	valid := "postgres://" + databaseLogin + ":synthetic@127.0.0.1:5432/iam?sslmode=disable"
	path := filepath.Join(directory, "worker-dsn")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseConfig(path); err != nil {
		t.Fatal("valid private access analysis DSN failed", err)
	}
	for _, invalid := range []string{"", "relative", directory} {
		if _, err := databaseConfig(invalid); err == nil {
			t.Fatal("invalid access analysis DSN path was accepted", invalid)
		}
	}
	if err := os.WriteFile(path, []byte("postgres://matrix_iam_api_login:synthetic@127.0.0.1:5432/iam?sslmode=disable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := databaseConfig(path); err == nil {
		t.Fatal("API database identity was accepted by the access analysis worker")
	}
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(path, []byte(valid), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := databaseConfig(path); err == nil {
			t.Fatal("group-readable access analysis DSN was accepted")
		}
	}
}
