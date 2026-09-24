// Package smtp implements the IAM security-mail submission boundary. It has
// no mailbox discovery, authorization, persistence, retry loop or HTTP route.
package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	netsmtp "net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

var ErrConfig = errors.New("security mail channel is invalid")

type TLSMode string

const (
	STARTTLS         TLSMode = "STARTTLS"
	ImplicitTLS      TLSMode = "IMPLICIT_TLS"
	maxResponseBytes         = 128 * 1024
	maxMessageBytes          = 4096
)

// Config is supplied by a protected deployment consumer, never a business
// request. A nil RootCAs uses system trust; custom roots are copied. There is
// deliberately no insecure verification, plaintext, custom dialer or fallback.
type Config struct {
	InstallationID string
	Host           string
	Port           uint16
	TLSMode        TLSMode
	RootCAs        *x509.CertPool
	Username       string
	Password       iamv1.Secret
	From           string
}

func (Config) String() string               { return "[REDACTED]" }
func (Config) GoString() string             { return "smtp.Config{[REDACTED]}" }
func (Config) MarshalJSON() ([]byte, error) { return nil, ErrConfig }
func (*Config) UnmarshalJSON([]byte) error  { return ErrConfig }

type Client struct {
	config Config
	slots  chan struct{}
}

func (*Client) String() string               { return "[REDACTED]" }
func (*Client) GoString() string             { return "smtp.Client{[REDACTED]}" }
func (*Client) MarshalJSON() ([]byte, error) { return nil, ErrConfig }

func NewClient(config Config) (*Client, error) {
	if iamv1.ValidateID("installationId", config.InstallationID) != nil || config.Port == 0 ||
		(config.TLSMode != STARTTLS && config.TLSMode != ImplicitTLS) ||
		(net.ParseIP(config.Host) == nil && !iamv1.SecurityMailDNSName(config.Host)) ||
		iamv1.ValidateSecurityMailAddress(config.From) != nil ||
		len(config.Username) == 0 || len(config.Username) > 254 ||
		!config.Password.Present() {
		return nil, ErrConfig
	}
	for _, c := range config.Username {
		if c < 33 || c > 126 {
			return nil, ErrConfig
		}
	}
	password := config.Password.CopyBytes()
	defer clear(password)
	if len(password) > 1024 {
		return nil, ErrConfig
	}
	if config.RootCAs != nil {
		config.RootCAs = config.RootCAs.Clone()
	}
	return &Client{config: config, slots: make(chan struct{}, 2)}, nil
}

func (client *Client) Submit(ctx context.Context, message authority.SecurityMail) (authority.MailSubmission, error) {
	if ctx == nil || message.Validate() != nil {
		return authority.MailSubmission{}, authority.ErrSecurityMail
	}
	if client == nil || client.slots == nil {
		return authority.MailSubmission{State: authority.MailUnavailable}, nil
	}
	select {
	case client.slots <- struct{}{}:
		defer func() { <-client.slots }()
	default:
		return authority.MailSubmission{State: authority.MailUnavailable}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	body := client.encode(message)
	defer clear(body)
	if len(body) > maxMessageBytes {
		return authority.MailSubmission{}, authority.ErrSecurityMail
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(client.config.Host, strconv.Itoa(int(client.config.Port))))
	if err != nil {
		return authority.MailSubmission{State: authority.MailUnavailable}, nil
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if raw.SetDeadline(deadline) != nil {
		return authority.MailSubmission{State: authority.MailUnavailable}, nil
	}
	bounded := &boundedConnection{Conn: raw, remaining: maxResponseBytes}
	var conn net.Conn = bounded
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: client.config.Host, RootCAs: client.config.RootCAs}
	if client.config.TLSMode == ImplicitTLS {
		secure := tls.Client(conn, tlsConfig)
		if secure.HandshakeContext(ctx) != nil {
			return authority.MailSubmission{State: authority.MailUnavailable}, nil
		}
		conn = secure
	}
	channel, err := netsmtp.NewClient(conn, client.config.Host)
	if err != nil {
		return beforeData(err), nil
	}
	defer channel.Close()
	if bounded.failed {
		return authority.MailSubmission{State: authority.MailUnavailable}, nil
	}
	strictReplies(channel)
	if err := channel.Hello("localhost"); err != nil {
		return beforeData(err), nil
	}
	if client.config.TLSMode == STARTTLS {
		if ok, _ := channel.Extension("STARTTLS"); !ok {
			return authority.MailSubmission{State: authority.MailUnavailable}, nil
		}
		if err := channel.StartTLS(tlsConfig); err != nil {
			return beforeData(err), nil
		}
		// StartTLS replaces Text. Keep any already buffered bytes, and restore
		// strict framing for every subsequent authentication/envelope/DATA reply.
		strictReplies(channel)
	}
	state, secure := channel.TLSConnectionState()
	if bounded.failed || !secure || !state.HandshakeComplete || len(state.VerifiedChains) == 0 || state.Version < tls.VersionTLS12 {
		return authority.MailSubmission{State: authority.MailUnavailable}, nil
	}
	ok, mechanisms := channel.Extension("AUTH")
	if !ok || !containsPlain(mechanisms) {
		return authority.MailSubmission{State: authority.MailUnavailable}, nil
	}
	password := client.config.Password.CopyBytes()
	defer clear(password)
	if err := channel.Auth(netsmtp.PlainAuth("", client.config.Username, string(password), client.config.Host)); err != nil {
		return beforeData(err), nil
	}
	if err := channel.Mail(client.config.From); err != nil {
		return beforeData(err), nil
	}
	if err := channel.Rcpt(message.Recipient); err != nil {
		return beforeData(err), nil
	}
	// Keep the DATA terminator write error separate from its final reply. The
	// standard convenience Data closer does not propagate its writer.Close error.
	id, err := channel.Text.Cmd("DATA")
	if err != nil {
		return beforeData(err), nil
	}
	channel.Text.StartResponse(id)
	_, _, err = channel.Text.ReadResponse(354)
	channel.Text.EndResponse(id)
	if err != nil {
		return beforeData(err), nil
	}
	writer := channel.Text.DotWriter()
	if _, err := writer.Write(body); err != nil {
		return authority.MailSubmission{State: authority.MailUnavailable}, nil
	}
	if writer.Close() != nil {
		return authority.MailSubmission{State: authority.MailUnknown}, nil
	}
	if _, _, err := channel.Text.ReadResponse(250); err != nil {
		result := beforeData(err)
		if result.State != authority.MailRejected {
			result.State = authority.MailUnknown
		}
		return result, nil
	}
	// Once the final 250 was observed, failure during QUIT/close cannot undo it.
	_ = channel.Quit()
	return authority.MailSubmission{State: authority.MailAccepted, SMTPCode: 250}, nil
}

func beforeData(err error) authority.MailSubmission {
	var response *textproto.Error
	if errors.As(err, &response) && response.Code >= 400 && response.Code <= 599 {
		return authority.MailSubmission{State: authority.MailRejected, SMTPCode: response.Code}
	}
	return authority.MailSubmission{State: authority.MailUnavailable}
}

func containsPlain(mechanisms string) bool {
	for _, mechanism := range strings.Fields(mechanisms) {
		if mechanism == "PLAIN" {
			return true
		}
	}
	return false
}

type boundedConnection struct {
	net.Conn
	remaining int
	failed    bool
}

func (connection *boundedConnection) Read(buffer []byte) (int, error) {
	if connection.remaining <= 0 {
		connection.failed = true
		return 0, io.ErrUnexpectedEOF
	}
	if len(buffer) > connection.remaining {
		buffer = buffer[:connection.remaining]
	}
	n, err := connection.Conn.Read(buffer)
	connection.remaining -= n
	if err != nil {
		connection.failed = true
	}
	return n, err
}

func strictReplies(channel *netsmtp.Client) {
	channel.Text.R = bufio.NewReader(&replyReader{source: channel.Text.R})
}

// textproto may accept an EOF-terminated partial line. A truncated "250 ..."
// is not proof that the peer completed its final reply. Pass only complete,
// CRLF-terminated RFC5321 reply lines, retaining the existing reader's buffer.
type replyReader struct {
	source  *bufio.Reader
	pending []byte
}

func (reader *replyReader) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if len(reader.pending) == 0 {
		line, err := reader.source.ReadSlice('\n')
		if err != nil || len(line) > 512 || !bytes.HasSuffix(line, []byte("\r\n")) {
			return 0, io.ErrUnexpectedEOF
		}
		reader.pending = bytes.Clone(line)
	}
	n := copy(buffer, reader.pending)
	reader.pending = reader.pending[n:]
	return n, nil
}

func (client *Client) encode(message authority.SecurityMail) []byte {
	id := sha256.Sum256([]byte("matrix.iam.security-mail.v1\x00" + client.config.InstallationID + "\x00" + message.NotificationID))
	var body bytes.Buffer
	fmt.Fprintf(&body, "From: %s\r\nTo: %s\r\nDate: %s\r\nMessage-ID: <%s@notifications.matrix.invalid>\r\n",
		client.config.From, message.Recipient, message.OccurredAt.Format(time.RFC1123Z), hex.EncodeToString(id[:]))
	subject, content := securityText(message.Kind)
	fmt.Fprintf(&body, "Subject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 7bit\r\n\r\n%s\r\n", subject, content)
	if message.Kind == authority.MailAddressVerification {
		code := message.VerificationCode.CopyBytes()
		fmt.Fprintf(&body, "Verification code: %s\r\nExpires at: %s\r\n", code, message.VerificationExpiresAt.Format(time.RFC3339))
		clear(code)
		body.WriteString("This code only verifies your notification address. It cannot sign in or recover your account.\r\n")
	} else {
		body.WriteString("If you did not request this change, contact your installation's security administrator through your established channel.\r\n")
	}
	fmt.Fprintf(&body, "Notification reference: %s\r\n", message.NotificationID)
	return body.Bytes()
}

func securityText(kind authority.SecurityMailKind) (string, string) {
	switch kind {
	case authority.MailAddressVerification:
		return "MATRIX notification address verification", "A request was made to verify this notification address."
	case authority.MailContactVerified:
		return "MATRIX notification address verified", "This address was verified for security notifications. Email verification does not grant login or account recovery access."
	case authority.MailAuthenticatorBound:
		return "MATRIX authenticator bound", "A TOTP authenticator was bound to your account user."
	case authority.MailAuthenticatorReplaced:
		return "MATRIX authenticator replaced", "Your TOTP authenticator was replaced."
	case authority.MailAuthenticatorRemoved:
		return "MATRIX authenticator removed", "Your TOTP authenticator was removed."
	case authority.MailRecoveryStarted:
		return "MATRIX authenticator recovery started", "Recovery of your TOTP authenticator was started."
	case authority.MailAuthenticatorRecovered:
		return "MATRIX authenticator recovered", "Recovery of your TOTP authenticator was completed."
	case authority.MailRecoveryCodesRegenerated:
		return "MATRIX recovery codes regenerated", "A new recovery-code batch was issued; the previous batch was terminated."
	case authority.MailSecuritySettingsChanged:
		return "MATRIX account security settings changed", "Your account's security settings were changed."
	default:
		// Submit validates the closed kind before encoding or opening a socket.
		return "", ""
	}
}
