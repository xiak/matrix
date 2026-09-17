package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
	iamhttp "github.com/xiak/matrix/app/service/iam/internal/service/nethttp"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

const (
	databaseDSNFileEnvironment       = "MATRIX_IAM_DATABASE_DSN_FILE"
	bootstrapFileEnvironment         = "MATRIX_IAM_BOOTSTRAP_FILE"
	listenAddressEnvironment         = "MATRIX_IAM_LISTEN_ADDRESS"
	cursorKeyFileEnvironment         = "MATRIX_IAM_CURSOR_KEY_FILE"
	accessKeyWrappingFileEnvironment = "MATRIX_IAM_ACCESS_KEY_WRAPPING_KEYRING_FILE"
)

type configuration struct {
	databaseDSNFile       string
	bootstrapFile         string
	listenAddress         string
	cursorKeyFile         string
	accessKeyWrappingFile string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix IAM process failed")
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	config, err := loadConfiguration()
	if err != nil {
		return err
	}
	cursorKey, err := readCursorKey(config.cursorKeyFile)
	if err != nil {
		return err
	}
	defer clear(cursorKey)
	bootstrapBytes, err := processconfig.ReadFile(config.bootstrapFile, iamv1.MaxBootstrapBytes, true)
	if err != nil {
		return err
	}
	document, err := iamv1.DecodeBootstrapDocument(bytes.NewReader(bootstrapBytes))
	clear(bootstrapBytes)
	if err != nil {
		return errors.New("IAM bootstrap document is invalid")
	}
	defer func() { document = iamv1.BootstrapDocument{} }()
	keyring, err := readAccessKeyWrapping(config.accessKeyWrappingFile, document)
	if err != nil {
		return err
	}
	defer func() { keyring = iamv1.AccessKeyWrappingKeyring{} }()
	dsn, err := processconfig.ReadText(config.databaseDSNFile, 16*1024, true)
	if err != nil {
		return err
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return errors.New("IAM database configuration is invalid")
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("IAM database pool cannot start")
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return errors.New("IAM database is unavailable")
	}
	repository, err := iampostgres.NewRepository(pool)
	if err != nil {
		return err
	}
	workflow, err := identityaccess.NewAuthority(repository, identityaccess.Config{CursorKey: cursorKey, AccessKeyWrapping: &keyring})
	clear(cursorKey)
	keyring = iamv1.AccessKeyWrappingKeyring{}
	if err != nil {
		return err
	}
	schema, err := workflow.Readiness(ctx)
	if err != nil || schema.SchemaVersion != identityaccess.SchemaVersion {
		return errors.New("IAM schema is incompatible")
	}
	if _, err := workflow.Bootstrap(ctx, document); err != nil {
		document = iamv1.BootstrapDocument{}
		return errors.New("IAM bootstrap cannot converge")
	}
	document = iamv1.BootstrapDocument{}
	if err := workflow.VerifyAccessKeyCustody(ctx); err != nil {
		return errors.New("IAM access key custody is unavailable")
	}
	handler, err := iamhttp.NewHandler(workflow, iamhttp.Config{})
	if err != nil {
		return err
	}
	return processhttp.Serve(ctx, config.listenAddress, handler)
}

func loadConfiguration() (configuration, error) {
	config := configuration{
		databaseDSNFile:       os.Getenv(databaseDSNFileEnvironment),
		bootstrapFile:         os.Getenv(bootstrapFileEnvironment),
		listenAddress:         os.Getenv(listenAddressEnvironment),
		cursorKeyFile:         os.Getenv(cursorKeyFileEnvironment),
		accessKeyWrappingFile: os.Getenv(accessKeyWrappingFileEnvironment),
	}
	if config.databaseDSNFile == "" || config.bootstrapFile == "" ||
		config.listenAddress == "" || config.cursorKeyFile == "" || config.accessKeyWrappingFile == "" {
		return configuration{}, errors.New("IAM process configuration is incomplete")
	}
	return config, nil
}

// The installer verifies host ownership, private parent directories and the
// read-only IAM-only mount. This reader verifies the visible regular file and
// exact bytes once; it does not hot-reload or generate replacement material.
func readAccessKeyWrapping(path string, bootstrap iamv1.BootstrapDocument) (iamv1.AccessKeyWrappingKeyring, error) {
	invalid := errors.New("IAM access key wrapping file is unavailable")
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || (runtime.GOOS != "windows" && before.Mode() != 0o600) {
		return iamv1.AccessKeyWrappingKeyring{}, invalid
	}
	encoded, err := processconfig.ReadFile(path, iamv1.MaxAccessKeyWrappingKeyringBytes, true)
	defer clear(encoded)
	if err != nil {
		return iamv1.AccessKeyWrappingKeyring{}, invalid
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() ||
		before.Size() != after.Size() || before.ModTime() != after.ModTime() {
		return iamv1.AccessKeyWrappingKeyring{}, invalid
	}
	document, err := iamv1.DecodeAccessKeyWrappingKeyring(bytes.NewReader(encoded))
	if err != nil {
		return iamv1.AccessKeyWrappingKeyring{}, invalid
	}
	digest, err := iamv1.BootstrapDigest(bootstrap)
	if err != nil || document.Scope.InstallationID != bootstrap.InstallationID ||
		subtle.ConstantTimeCompare([]byte(document.Scope.BootstrapDigest), []byte(digest)) != 1 {
		return iamv1.AccessKeyWrappingKeyring{}, invalid
	}
	return document, nil
}

func readCursorKey(path string) ([]byte, error) {
	encoded, err := processconfig.ReadFile(path, 64, true)
	if err != nil {
		return nil, errors.New("IAM cursor key is unavailable")
	}
	defer clear(encoded)
	if len(encoded) != 64 {
		return nil, errors.New("IAM cursor key is invalid")
	}
	for _, character := range encoded {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return nil, errors.New("IAM cursor key is invalid")
		}
	}
	key := make([]byte, 32)
	if _, err := hex.Decode(key, encoded); err != nil {
		clear(key)
		return nil, errors.New("IAM cursor key is invalid")
	}
	return key, nil
}
