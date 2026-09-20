package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	iampostgres "github.com/xiak/matrix/app/service/iam/internal/data/postgres"
	iamsmtp "github.com/xiak/matrix/app/service/iam/internal/data/smtp"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/notificationdispatch"
	"github.com/xiak/matrix/app/service/internal/processconfig"
	"github.com/xiak/matrix/app/service/internal/processhttp"
)

const (
	databaseFileEnvironment  = "MATRIX_IAM_NOTIFICATION_DATABASE_DSN_FILE"
	channelFileEnvironment   = "MATRIX_IAM_SECURITY_MAIL_SMTP_CHANNEL_FILE"
	keyringFileEnvironment   = "MATRIX_IAM_EMAIL_VERIFICATION_KEYRING_FILE"
	workerIDEnvironment      = "MATRIX_IAM_NOTIFICATION_WORKER_ID"
	listenAddressEnvironment = "MATRIX_IAM_NOTIFICATION_LISTEN_ADDRESS"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "matrix IAM notification dispatcher failed")
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	workerID, listenAddress := os.Getenv(workerIDEnvironment), os.Getenv(listenAddressEnvironment)
	if iamv1.ValidateID("workerId", workerID) != nil || listenAddress == "" {
		return errors.New("notification process configuration unavailable")
	}
	channel, keyring, err := readMaterial(os.Getenv(channelFileEnvironment), os.Getenv(keyringFileEnvironment))
	if err != nil {
		return err
	}
	dsn, err := processconfig.ReadText(os.Getenv(databaseFileEnvironment), 16*1024, true)
	if err != nil {
		return errors.New("notification database configuration unavailable")
	}
	poolConfig, err := pgxpool.ParseConfig(dsn)
	dsn = ""
	if err != nil || poolConfig.ConnConfig.User != "matrix_iam_notification_worker_login" {
		return errors.New("notification database identity invalid")
	}
	poolConfig.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return errors.New("notification database unavailable")
	}
	defer pool.Close()
	repository, err := iampostgres.NewNotificationRepository(pool)
	if err != nil {
		return err
	}
	var roots *x509.CertPool
	if channel.TrustedCAPEM != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(channel.TrustedCAPEM)) {
			return errors.New("notification trust unavailable")
		}
	}
	client, err := iamsmtp.NewClient(iamsmtp.Config{InstallationID: channel.Scope.InstallationID, Host: channel.Host, Port: channel.Port, TLSMode: iamsmtp.TLSMode(channel.TLSMode),
		RootCAs: roots, Username: channel.Username, Password: channel.Password, From: channel.From})
	if err != nil {
		return errors.New("notification transport unavailable")
	}
	dispatcher, err := notificationdispatch.NewDispatcher(repository, client, notificationdispatch.Config{WorkerID: workerID, ChannelScope: channel.Scope, Keyring: keyring})
	channel = iamv1.SecurityMailSMTPChannel{}
	keyring = iamv1.EmailVerificationKeyring{}
	if err != nil {
		return err
	}
	if err := dispatcher.Ready(ctx); err != nil {
		return errors.New("notification custody unavailable")
	}
	handler, err := processhttp.NewReadinessHandler(dispatcher.Ready)
	if err != nil {
		return err
	}
	return processhttp.ServeWithBackground(ctx, listenAddress, handler, func(ctx context.Context) error { return runDispatchLoops(ctx, dispatcher) })
}

func readMaterial(channelPath, keyringPath string) (iamv1.SecurityMailSMTPChannel, iamv1.EmailVerificationKeyring, error) {
	invalid := errors.New("notification private material unavailable")
	channelBytes, err := processconfig.ReadFile(channelPath, iamv1.MaxSecurityMailSMTPChannelBytes, true)
	defer clear(channelBytes)
	if err != nil {
		return iamv1.SecurityMailSMTPChannel{}, iamv1.EmailVerificationKeyring{}, invalid
	}
	channel, err := iamv1.DecodeSecurityMailSMTPChannel(bytes.NewReader(channelBytes))
	if err != nil {
		return iamv1.SecurityMailSMTPChannel{}, iamv1.EmailVerificationKeyring{}, invalid
	}
	keyBytes, err := processconfig.ReadFile(keyringPath, iamv1.MaxEmailVerificationKeyringBytes, true)
	defer clear(keyBytes)
	if err != nil {
		return iamv1.SecurityMailSMTPChannel{}, iamv1.EmailVerificationKeyring{}, invalid
	}
	keyring, err := iamv1.DecodeEmailVerificationKeyring(bytes.NewReader(keyBytes))
	if err != nil || keyring.Scope != channel.Scope {
		return iamv1.SecurityMailSMTPChannel{}, iamv1.EmailVerificationKeyring{}, invalid
	}
	return channel, keyring, nil
}

// Exactly two bounded loops, no in-memory send queue. A transient transaction
// failure ends this cycle, not its committed intent. Unknown completion leaves
// the original lease for durable reconciliation; never retry Submit in place.
func runDispatchLoops(ctx context.Context, dispatcher *notificationdispatch.Dispatcher) error {
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() {
			for ctx.Err() == nil {
				cycle, cancel := context.WithTimeout(ctx, 35*time.Second)
				result, err := dispatcher.DispatchOnce(cycle)
				cancel()
				if ctx.Err() != nil {
					return
				}
				if err != nil {
					_, _ = fmt.Fprintln(os.Stderr, "IAM_NOTIFICATION_CYCLE_UNAVAILABLE")
				} else if result.Claimed {
					_, _ = fmt.Fprintln(os.Stderr, "IAM_NOTIFICATION_"+string(result.Observation.State))
				}
				if err == nil && result.Claimed {
					continue
				}
				timer := time.NewTimer(time.Second)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		})
	}
	workers.Wait()
	return nil
}
