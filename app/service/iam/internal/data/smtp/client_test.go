package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/mail"
	"net/textproto"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

func TestSecurityMailSMTPOutcomes(t *testing.T) {
	certificate, roots := smtpCertificate(t, "127.0.0.1")
	for _, test := range []struct {
		name  string
		mode  TLSMode
		state authority.MailSubmissionState
		code  int
		body  bool
	}{
		{"accepted", STARTTLS, authority.MailAccepted, 250, true},
		{"accepted", ImplicitTLS, authority.MailAccepted, 250, true},
		{"verification", STARTTLS, authority.MailAccepted, 250, true},
		{"lost-quit", STARTTLS, authority.MailAccepted, 250, true},
		{"lost-final", STARTTLS, authority.MailUnknown, 0, true},
		{"hold-final", STARTTLS, authority.MailUnknown, 0, true},
		{"bad-final", STARTTLS, authority.MailUnknown, 0, true},
		{"unexpected-final", STARTTLS, authority.MailUnknown, 0, true},
		{"large-final", STARTTLS, authority.MailUnknown, 0, true},
		{"truncated-final", STARTTLS, authority.MailUnknown, 0, true},
		{"bare-lf-final", STARTTLS, authority.MailUnknown, 0, true},
		{"temporary-final", STARTTLS, authority.MailRejected, 451, true},
		{"permanent-final", STARTTLS, authority.MailRejected, 550, true},
		{"reject-data", STARTTLS, authority.MailRejected, 554, false},
		{"reject-recipient", STARTTLS, authority.MailRejected, 550, false},
		{"reject-sender", STARTTLS, authority.MailRejected, 553, false},
		{"reject-auth", STARTTLS, authority.MailRejected, 535, false},
		{"no-auth", STARTTLS, authority.MailUnavailable, 0, false},
		{"wrong-auth", STARTTLS, authority.MailUnavailable, 0, false},
		{"no-starttls", STARTTLS, authority.MailUnavailable, 0, false},
		{"reject-starttls", STARTTLS, authority.MailRejected, 454, false},
		{"bad-greeting", STARTTLS, authority.MailUnavailable, 0, false},
		{"large-greeting", STARTTLS, authority.MailUnavailable, 0, false},
	} {
		t.Run(test.name+"/"+string(test.mode), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			config, observations := smtpPeer(t, certificate, roots, test.mode, test.name, func() {
				if test.name == "hold-final" {
					cancel()
				}
			})
			client, err := NewClient(config)
			if err != nil {
				t.Fatal(err)
			}
			message := smtpMessage()
			if test.name == "verification" {
				message.Kind = authority.MailAddressVerification
				message.VerificationCode = mustSMTPSecret(t, "01234567")
				message.VerificationExpiresAt = message.OccurredAt.Add(5 * time.Minute)
			}
			result, err := client.Submit(ctx, message)
			if err != nil || result != (authority.MailSubmission{State: test.state, SMTPCode: test.code}) {
				t.Fatalf("submission outcome=%+v, error=%v", result, err)
			}
			observed := awaitSMTP(t, observations)
			if observed.cleartextAuth || (len(observed.body) > 0) != test.body {
				t.Fatal("TLS boundary or message transmission differs")
			}
			if test.body {
				if !observed.authenticated || observed.sender != config.From || observed.recipient != smtpMessage().Recipient {
					t.Fatal("message was not scoped to exactly the authenticated sender and recipient")
				}
				parsed, err := mail.ReadMessage(bytes.NewReader(observed.body))
				if err != nil {
					t.Fatal("wire message is not a mail document")
				}
				if parsed.Header.Get("To") != smtpMessage().Recipient || parsed.Header.Get("From") != config.From ||
					parsed.Header.Get("Message-ID") == "" || parsed.Header.Get("Bcc") != "" || parsed.Header.Get("Cc") != "" {
					t.Fatal("wire message headers differ")
				}
				if bytes.Contains(observed.body, []byte("smtp-test-password")) {
					t.Fatal("SMTP credential entered the message")
				}
				if bytes.Contains(observed.body, []byte("01234567")) != (test.name == "verification") {
					t.Fatal("verification secret crossed its message purpose")
				}
			}
			if observed.connections.Load() != 1 {
				t.Fatal("adapter retried implicitly")
			}
		})
	}
}

func TestSecurityMailSMTPCertificateAndTLSFailures(t *testing.T) {
	for _, mode := range []TLSMode{STARTTLS, ImplicitTLS} {
		for _, failure := range []string{"untrusted", "wrong-name", "obsolete-tls"} {
			t.Run(string(mode)+"/"+failure, func(t *testing.T) {
				ip := "127.0.0.1"
				if failure == "wrong-name" {
					ip = "127.0.0.2"
				}
				certificate, roots := smtpCertificate(t, ip)
				config, observations := smtpPeer(t, certificate, roots, mode, failure)
				if failure == "untrusted" {
					config.RootCAs = x509.NewCertPool()
				}
				client, err := NewClient(config)
				if err != nil {
					t.Fatal(err)
				}
				result, err := client.Submit(context.Background(), smtpMessage())
				if err != nil || result.State != authority.MailUnavailable {
					t.Fatalf("bad TLS result=%+v err=%v", result, err)
				}
				observed := awaitSMTP(t, observations)
				if observed.authenticated || observed.cleartextAuth || len(observed.body) != 0 {
					t.Fatal("invalid TLS exposed credentials or message")
				}
			})
		}
	}
}

func TestSecurityMailSMTPConfigAndRedaction(t *testing.T) {
	certificate, roots := smtpCertificate(t, "127.0.0.1")
	config, observations := smtpPeer(t, certificate, roots, STARTTLS, "accepted")
	for _, mutate := range []func(*Config){
		func(c *Config) { c.InstallationID = "" },
		func(c *Config) { c.InstallationID = "installation\r\n" },
		func(c *Config) { c.Port = 0 },
		func(c *Config) { c.Host = "smtp://matrix.test" },
		func(c *Config) { c.Host = "matrix.test\r\n" },
		func(c *Config) { c.TLSMode = "NONE" },
		func(c *Config) { c.From = "sender@matrix.test\r\nBcc:other@matrix.test" },
		func(c *Config) { c.Username = "" },
		func(c *Config) { c.Username = "user\x00" },
		func(c *Config) { c.Password = iamv1.Secret{} },
		func(c *Config) { c.Password, _ = iamv1.NewSecret(strings.Repeat("a", 1025)) },
	} {
		candidate := config
		mutate(&candidate)
		if _, err := NewClient(candidate); !errors.Is(err, ErrConfig) {
			t.Fatal("bad channel accepted")
		}
	}
	// Installation syntax belongs to the IAM bootstrap/private-file contract.
	// SMTP must not invent a second ID namespace for already sealed installs.
	for _, installation := range []string{"installation-http-integration", "mxi-" + strings.Repeat("a", 32)} {
		candidate := config
		candidate.InstallationID = installation
		if iamv1.ValidateID("installationId", installation) != nil {
			t.Fatal("invalid contract fixture")
		}
		if _, err := NewClient(candidate); err != nil {
			t.Fatal("SMTP rejected an IAM installation identity", err)
		}
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{config, client} {
		for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
			printed := fmt.Sprintf(format, value)
			if strings.Contains(printed, "smtp-test-password") || strings.Contains(printed, config.Username) {
				t.Fatal("channel credentials formatted")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("channel serialized")
		}
	}
	invalid := smtpMessage()
	invalid.Recipient = "a@matrix.test\r\nRCPT TO:<b@matrix.test>"
	if _, err := client.Submit(context.Background(), invalid); !errors.Is(err, authority.ErrSecurityMail) {
		t.Fatal("recipient injection accepted")
	}
	if _, err := client.Submit(nil, smtpMessage()); !errors.Is(err, authority.ErrSecurityMail) {
		t.Fatal("nil context accepted")
	}
	var unavailable *Client
	if result, err := unavailable.Submit(context.Background(), smtpMessage()); err != nil || result.State != authority.MailUnavailable {
		t.Fatal("nil client accepted")
	}
	// Earlier invalid submissions must not consume the peer's sole connection.
	if result, err := client.Submit(context.Background(), smtpMessage()); err != nil || result.State != authority.MailAccepted {
		t.Fatal("valid submission failed")
	}
	if awaitSMTP(t, observations).connections.Load() != 1 {
		t.Fatal("invalid input reached network")
	}
}

func TestSecurityMailSMTPEncodingIsStableAndClosed(t *testing.T) {
	config := Config{InstallationID: "mxi-" + strings.Repeat("a", 32), Host: "mail.matrix.test", Port: 587, TLSMode: STARTTLS,
		Username: "smtp-user", Password: mustSMTPSecret(t, "smtp-test-password"), From: "sender@matrix.test"}
	client, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	message := smtpMessage()
	code := mustSMTPSecret(t, "01234567")
	message.Kind = authority.MailAddressVerification
	message.VerificationCode = code
	message.VerificationExpiresAt = message.OccurredAt.Add(5 * time.Minute)
	wire := client.encode(message)
	parsed, err := mail.ReadMessage(bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wire, []byte("01234567")) || !bytes.Equal(wire, client.encode(message)) {
		t.Fatal("verification material or deterministic encoding differs")
	}
	id := parsed.Header.Get("Message-ID")
	config.From = "other@new.matrix.test"
	otherChannel, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	otherParsed, _ := mail.ReadMessage(bytes.NewReader(otherChannel.encode(message)))
	if otherParsed.Header.Get("Message-ID") != id {
		t.Fatal("channel rotation changed notification identity")
	}
	config.InstallationID = "mxi-" + strings.Repeat("b", 32)
	otherInstall, _ := NewClient(config)
	otherParsed, _ = mail.ReadMessage(bytes.NewReader(otherInstall.encode(message)))
	if otherParsed.Header.Get("Message-ID") == id {
		t.Fatal("installation identity collided")
	}
	message.NotificationID = "notice-other"
	otherParsed, _ = mail.ReadMessage(bytes.NewReader(client.encode(message)))
	if otherParsed.Header.Get("Message-ID") == id {
		t.Fatal("notification identity collided")
	}
	for _, kind := range []authority.SecurityMailKind{authority.MailAuthenticatorBound, authority.MailAuthenticatorReplaced,
		authority.MailAuthenticatorRemoved, authority.MailRecoveryStarted, authority.MailAuthenticatorRecovered,
		authority.MailRecoveryCodesRegenerated, authority.MailSecuritySettingsChanged} {
		message = smtpMessage()
		message.Kind = kind
		wire := client.encode(message)
		parsed, err := mail.ReadMessage(bytes.NewReader(wire))
		if err != nil || parsed.Header.Get("Subject") == "" || bytes.Contains(wire, []byte("01234567")) || len(wire) > maxMessageBytes {
			t.Fatal("closed security notification content differs")
		}
	}
}

func TestSecurityMailSMTPBoundedConcurrencyAndCancellation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 2)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		for range 2 {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted <- conn
		}
	}()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	config := Config{InstallationID: "mxi-" + strings.Repeat("a", 32), Host: "127.0.0.1", Port: port, TLSMode: STARTTLS,
		Username: "smtp-user", Password: mustSMTPSecret(t, "smtp-test-password"), From: "sender@matrix.test"}
	client, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	results := make(chan authority.MailSubmission, 2)
	for range 2 {
		go func() { result, _ := client.Submit(ctx, smtpMessage()); results <- result }()
	}
	for range 2 {
		select {
		case conn := <-accepted:
			defer conn.Close()
		case <-ctx.Done():
			t.Fatal("two bounded submissions never reached peer")
		}
	}
	start := time.Now()
	result, err := client.Submit(ctx, smtpMessage())
	if err != nil || result.State != authority.MailUnavailable || time.Since(start) > 500*time.Millisecond {
		t.Fatal("capacity queued or accepted more sockets")
	}
	cancel()
	for range 2 {
		select {
		case result := <-results:
			if result.State != authority.MailUnavailable {
				t.Fatal("cancelled pre-DATA request did not close")
			}
		case <-time.After(time.Second):
			t.Fatal("cancellation did not close a live socket")
		}
	}
	<-finished
}

// This opt-in gate uses a real, separately provisioned Postfix and its local
// Maildir. It never starts/stops containers or sends Internet email. The exact
// local container must be task-labelled, resource-limited and loopback-only;
// all users, addresses and credentials below are synthetic fixture material.
func TestSecurityMailPostfixMailbox(t *testing.T) {
	container := os.Getenv("MATRIX_IAM_SMTP_POSTFIX_CONTAINER")
	task := os.Getenv("MATRIX_IAM_SMTP_POSTFIX_TASK")
	if container == "" && task == "" {
		t.Skip("dedicated local Postfix mailbox is not configured")
	}
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(container) ||
		!regexp.MustCompile(`^iam012-smtp-[a-f0-9]{32}$`).MatchString(task) {
		t.Fatal("invalid dedicated Postfix identity")
	}
	docker := func(arguments ...string) []byte {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		output, err := exec.CommandContext(ctx, "docker", arguments...).Output()
		if err != nil || len(output) > 64*1024 {
			t.Fatal("dedicated Postfix inspection failed")
		}
		return output
	}
	dockerContext := strings.TrimSpace(string(docker("context", "show")))
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`).MatchString(dockerContext) {
		t.Fatal("invalid local Docker context")
	}
	endpoint := strings.TrimSpace(string(docker("context", "inspect", dockerContext, "--format", "{{.Endpoints.docker.Host}}")))
	if !strings.HasPrefix(endpoint, "npipe:///") && !strings.HasPrefix(endpoint, "unix:///") {
		t.Fatal("Postfix gate refuses a remote Docker endpoint")
	}
	localDocker := func(arguments ...string) []byte {
		t.Helper()
		return docker(append([]string{"--context", dockerContext}, arguments...)...)
	}
	var inspected struct {
		ID        string
		Running   bool
		Labels    map[string]string
		NanoCPUs  int64
		Memory    int64
		PidsLimit int64
		Ports     map[string][]struct{ HostIP, HostPort string }
	}
	projection := `{"ID":{{json .Id}},"Running":{{json .State.Running}},"Labels":{{json .Config.Labels}},"NanoCPUs":{{json .HostConfig.NanoCpus}},"Memory":{{json .HostConfig.Memory}},"PidsLimit":{{json .HostConfig.PidsLimit}},"Ports":{{json .NetworkSettings.Ports}}}`
	if err := json.Unmarshal(localDocker("inspect", "--format", projection, container), &inspected); err != nil {
		t.Fatal("invalid dedicated Postfix metadata")
	}
	ports := inspected.Ports["25/tcp"]
	if inspected.ID != container || !inspected.Running || inspected.Labels["matrix.task"] != task ||
		inspected.Labels["matrix.owner"] != "feat-iam" || inspected.NanoCPUs <= 0 || inspected.NanoCPUs > 2_000_000_000 ||
		inspected.Memory <= 0 || inspected.Memory > 1024*1024*1024 || inspected.PidsLimit <= 0 || inspected.PidsLimit > 128 ||
		len(ports) != 1 || ports[0].HostIP != "127.0.0.1" {
		t.Fatal("Postfix gate requires its dedicated, bounded, loopback-only fixture")
	}
	port, err := strconv.ParseUint(ports[0].HostPort, 10, 16)
	if err != nil || port == 0 {
		t.Fatal("invalid dedicated SMTP port")
	}
	version := strings.TrimSpace(string(localDocker("exec", container, "postconf", "-h", "mail_version")))
	if !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(version) {
		t.Fatal("fixture is not an identifiable Postfix")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(localDocker("exec", container, "head", "-c", "16385", "/etc/matrix-smtp-test/server.crt")) {
		t.Fatal("invalid fixture public trust")
	}
	config := Config{InstallationID: "mxi-" + strings.Repeat("a", 32), Host: "127.0.0.1", Port: uint16(port), TLSMode: STARTTLS,
		RootCAs: roots, Username: "smtp-user@matrix.test", Password: mustSMTPSecret(t, "smtp-test-password"), From: "sender@matrix.test"}
	client, err := NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("test intent generation failed")
	}
	reference := "notice-postfix-" + hex.EncodeToString(random[:])
	verification := authority.SecurityMail{NotificationID: reference + "-verify", Recipient: "receiver@matrix.test",
		Kind: authority.MailAddressVerification, OccurredAt: time.Now().UTC().Truncate(time.Microsecond),
		VerificationCode: mustSMTPSecret(t, "01234567")}
	verification.VerificationExpiresAt = verification.OccurredAt.Add(5 * time.Minute)
	security := authority.SecurityMail{NotificationID: reference + "-security", Recipient: verification.Recipient,
		Kind: authority.MailAuthenticatorBound, OccurredAt: verification.OccurredAt}
	for _, message := range []authority.SecurityMail{verification, security, security} {
		result, err := client.Submit(context.Background(), message)
		if err != nil || result.State != authority.MailAccepted {
			t.Fatalf("real Postfix did not accept valid submission: %+v", result)
		}
	}
	mailbox := func() (map[string][]*mail.Message, int) {
		t.Helper()
		files := strings.Fields(string(localDocker("exec", container, "find", "/home/receiver/Maildir/new", "/home/receiver/Maildir/cur",
			"-maxdepth", "1", "-type", "f", "-print")))
		if len(files) > 100 {
			t.Fatal("dedicated test mailbox exceeded its bound")
		}
		result := make(map[string][]*mail.Message)
		for _, path := range files {
			if !regexp.MustCompile(`^/home/receiver/Maildir/(new|cur)/[a-zA-Z0-9_.,:=+-]+$`).MatchString(path) {
				t.Fatal("unexpected dedicated mailbox path")
			}
			wire := localDocker("exec", container, "head", "-c", "16385", "--", path)
			if len(wire) > 16384 || bytes.Contains(wire, []byte("smtp-test-password")) {
				t.Fatal("mailbox content exceeded bound or contained SMTP credential")
			}
			message, err := mail.ReadMessage(bytes.NewReader(wire))
			if err != nil {
				t.Fatal("Postfix mailbox contains invalid message")
			}
			result[message.Header.Get("Message-ID")] = append(result[message.Header.Get("Message-ID")], message)
		}
		return result, len(files)
	}
	messageID := func(message authority.SecurityMail) string {
		parsed, err := mail.ReadMessage(bytes.NewReader(client.encode(message)))
		if err != nil {
			t.Fatal("invalid expected message")
		}
		return parsed.Header.Get("Message-ID")
	}
	verificationID, securityID := messageID(verification), messageID(security)
	var delivered map[string][]*mail.Message
	var before int
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		delivered, before = mailbox()
		if len(delivered[verificationID]) == 1 && len(delivered[securityID]) == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(delivered[verificationID]) != 1 || len(delivered[securityID]) != 2 {
		t.Fatal("SMTP acceptance did not produce the expected real mailbox deliveries")
	}
	for _, expected := range []authority.SecurityMail{verification, security} {
		for _, received := range delivered[messageID(expected)] {
			body, err := io.ReadAll(received.Body)
			if err != nil || received.Header.Get("To") != expected.Recipient || received.Header.Get("From") != config.From ||
				received.Header.Get("Received") == "" || received.Header.Get("Bcc") != "" || received.Header.Get("Cc") != "" ||
				!bytes.Contains(body, []byte(expected.NotificationID)) ||
				bytes.Contains(body, []byte("01234567")) != (expected.Kind == authority.MailAddressVerification) {
				t.Fatal("delivered notification purpose or recipient differs")
			}
		}
	}
	config.Password = mustSMTPSecret(t, "incorrect-test-password")
	wrongCredential, _ := NewClient(config)
	if result, err := wrongCredential.Submit(context.Background(), security); err != nil || result != (authority.MailSubmission{State: authority.MailRejected, SMTPCode: 535}) {
		t.Fatal("real SMTP accepted wrong credentials")
	}
	external := security
	external.Recipient = "receiver@outside.invalid"
	if result, err := client.Submit(context.Background(), external); err != nil || result.State != authority.MailRejected || result.SMTPCode < 500 {
		t.Fatal("test SMTP did not reject external relay")
	}
	_, after := mailbox()
	if before != after {
		t.Fatal("rejected submissions changed the real mailbox")
	}
	t.Logf("Postfix %s: verification and security notices reached the actual local Maildir; explicit replay delivered twice with one stable Message-ID; bad credentials and external relay rejected", version)
}

type smtpObservation struct {
	connections   *atomic.Int32
	cleartextAuth bool
	authenticated bool
	sender        string
	recipient     string
	body          []byte
}

// This is a deliberately hostile protocol peer, not an actual SMTP delivery
// service or evidence of mailbox receipt. All sockets/certificates are local.
func smtpPeer(t *testing.T, certificate tls.Certificate, roots *x509.CertPool, mode TLSMode, scenario string, onData ...func()) (Config, <-chan smtpObservation) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	acceptDone := make(chan struct{})
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-acceptDone:
		case <-time.After(time.Second):
			t.Error("SMTP accept loop did not close")
		}
	})
	first := make(chan net.Conn, 1)
	connections := &atomic.Int32{}
	go func() {
		defer close(acceptDone)
		defer close(first)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if connections.Add(1) == 1 {
				first <- conn
			} else {
				_ = conn.Close()
			}
		}
	}()
	observations := make(chan smtpObservation, 1)
	go func() {
		observed := smtpObservation{connections: connections}
		defer func() { observations <- observed }()
		conn, ok := <-first
		if !ok {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		secure := false
		serverConfig := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
		if scenario == "obsolete-tls" {
			serverConfig.MinVersion = tls.VersionTLS10
			serverConfig.MaxVersion = tls.VersionTLS11
		}
		if mode == ImplicitTLS {
			tlsConn := tls.Server(conn, serverConfig)
			if tlsConn.Handshake() != nil {
				return
			}
			conn = tlsConn
			secure = true
		}
		reader := textproto.NewReader(bufio.NewReader(conn))
		write := func(value string) bool { _, err := io.WriteString(conn, value+"\r\n"); return err == nil }
		if scenario == "bad-greeting" {
			write("bad smtp-test-password")
			return
		}
		if scenario == "large-greeting" {
			write("220 " + strings.Repeat("x", maxResponseBytes+1024))
			return
		}
		if !write("220 mail.matrix.test") {
			return
		}
		for {
			line, err := reader.ReadLine()
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO "):
				if !secure && scenario != "no-starttls" {
					if !write("250-mail.matrix.test\r\n250 STARTTLS") {
						return
					}
					continue
				}
				mechanism := "AUTH PLAIN"
				if scenario == "no-auth" {
					mechanism = "SIZE 4096"
				}
				if scenario == "wrong-auth" {
					mechanism = "AUTH LOGIN"
				}
				if !write("250-mail.matrix.test\r\n250 " + mechanism) {
					return
				}
			case line == "STARTTLS":
				if scenario == "reject-starttls" {
					write("454 smtp-test-password")
					continue
				}
				if !write("220 go ahead") {
					return
				}
				tlsConn := tls.Server(conn, serverConfig)
				if tlsConn.Handshake() != nil {
					return
				}
				conn = tlsConn
				reader = textproto.NewReader(bufio.NewReader(conn))
				secure = true
			case strings.HasPrefix(line, "AUTH PLAIN "):
				if !secure {
					observed.cleartextAuth = true
					return
				}
				decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
				if err != nil || string(decoded) != "\x00smtp-user\x00smtp-test-password" {
					write("535 bad authentication")
					continue
				}
				clear(decoded)
				if scenario == "reject-auth" {
					write("535 smtp-test-password")
					continue
				}
				observed.authenticated = true
				if !write("235 authenticated") {
					return
				}
			case line == "*":
				write("501 aborted")
			case strings.HasPrefix(line, "MAIL FROM:<"):
				observed.sender = strings.TrimSuffix(strings.TrimPrefix(line, "MAIL FROM:<"), ">")
				if scenario == "reject-sender" {
					write("553 smtp-test-password")
					continue
				}
				if !write("250 sender") {
					return
				}
			case strings.HasPrefix(line, "RCPT TO:<"):
				observed.recipient = strings.TrimSuffix(strings.TrimPrefix(line, "RCPT TO:<"), ">")
				if scenario == "reject-recipient" {
					write("550 smtp-test-password")
					continue
				}
				if !write("250 recipient") {
					return
				}
			case line == "DATA":
				if scenario == "reject-data" {
					write("554 smtp-test-password")
					continue
				}
				if !write("354 send message") {
					return
				}
				observed.body, err = io.ReadAll(io.LimitReader(reader.DotReader(), maxMessageBytes+1))
				if err != nil {
					return
				}
				if len(onData) == 1 {
					onData[0]()
				}
				switch scenario {
				case "lost-final":
					return
				case "hold-final":
					_, _ = reader.ReadLine()
					return
				case "bad-final":
					write("bad smtp-test-password")
				case "unexpected-final":
					write("251 smtp-test-password")
				case "large-final":
					write("250 " + strings.Repeat("x", maxResponseBytes+1024))
				case "truncated-final":
					_, _ = io.WriteString(conn, "250 accepted")
					_ = conn.Close()
					return
				case "bare-lf-final":
					_, _ = io.WriteString(conn, "250 accepted\n")
				case "temporary-final":
					write("451 smtp-test-password")
				case "permanent-final":
					write("550 smtp-test-password")
				default:
					write("250 accepted")
				}
				if scenario == "lost-quit" {
					return
				}
			case line == "QUIT":
				write("221 bye")
				return
			default:
				write("500 unsupported")
			}
		}
	}()
	config := Config{InstallationID: "mxi-" + strings.Repeat("a", 32), Host: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port),
		TLSMode: mode, RootCAs: roots, Username: "smtp-user", Password: mustSMTPSecret(t, "smtp-test-password"), From: "sender@matrix.test"}
	return config, observations
}

func awaitSMTP(t *testing.T, observations <-chan smtpObservation) smtpObservation {
	t.Helper()
	select {
	case result := <-observations:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("protocol peer did not finish")
		return smtpObservation{}
	}
}

func smtpCertificate(t *testing.T, ip string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "smtp fixture"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP(ip)},
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func smtpMessage() authority.SecurityMail {
	return authority.SecurityMail{NotificationID: "notice-1", Recipient: "User+notice@matrix.test", Kind: authority.MailAuthenticatorBound,
		OccurredAt: time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)}
}

func mustSMTPSecret(t *testing.T, value string) iamv1.Secret {
	t.Helper()
	secret, err := iamv1.NewSecret(value)
	if err != nil {
		t.Fatal("invalid synthetic secret")
	}
	return secret
}
