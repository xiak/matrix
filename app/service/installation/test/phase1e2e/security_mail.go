package phase1e2e

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

// The signed gate uses an actual TLS SMTP exchange through the isolated
// engine's default bridge gateway. Platform release networks are replaced
// during upgrade; the default bridge survives that transition. The fixture
// owns only its listener and protected input file.
type securityMailFixture struct {
	listener    net.Listener
	directory   string
	path        string
	password    []byte
	messages    chan []byte
	mu          sync.Mutex
	connections map[net.Conn]struct{}
	wait        sync.WaitGroup
}

func startSecurityMailFixture(ctx context.Context) (*securityMailFixture, error) {
	content, err := docker(ctx, "network", "inspect", "bridge")
	if err != nil {
		return nil, fail("security-mail-network-inspection")
	}
	gateway, err := securityMailBridgeGateway(content)
	if err != nil {
		return nil, err
	}
	certificate, trust, err := securityMailCertificate(gateway)
	if err != nil {
		return nil, fail("security-mail-certificate")
	}
	raw, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		return nil, fail("security-mail-listener")
	}
	fixture := &securityMailFixture{
		listener: tls.NewListener(raw, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}),
		messages: make(chan []byte, 8), connections: make(map[net.Conn]struct{}),
	}
	randomPassword := make([]byte, 32)
	if _, err := rand.Read(randomPassword); err != nil {
		clear(randomPassword)
		_ = fixture.close()
		return nil, fail("security-mail-credential")
	}
	fixture.password = []byte(base64.RawURLEncoding.EncodeToString(randomPassword))
	clear(randomPassword)
	secret, err := iamv1.NewSecret(string(fixture.password))
	if err != nil {
		_ = fixture.close()
		return nil, fail("security-mail-credential")
	}
	configuration := installationv1.SecurityMailConfiguration{
		APIVersion: installationv1.SecurityMailConfigurationAPIVersion,
		Kind:       installationv1.SecurityMailConfigurationKind,
		Host:       gateway.String(), Port: uint16(raw.Addr().(*net.TCPAddr).Port),
		TLSMode:  iamv1.SecurityMailImplicitTLS,
		Username: "phase1-smtp", Password: secret,
		From: "security@matrix.test", TrustedCAPEM: string(trust),
	}
	encoded, err := installationv1.EncodeSecurityMailConfiguration(configuration)
	configuration.Clear()
	if err != nil {
		_ = fixture.close()
		return nil, fail("security-mail-configuration")
	}
	fixture.directory, err = os.MkdirTemp("", "matrix-mail-gate-")
	if err == nil {
		fixture.path = filepath.Join(fixture.directory, "security-mail.json")
		var file *os.File
		file, err = os.OpenFile(fixture.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			_, err = file.Write(encoded)
			if err == nil {
				err = file.Sync()
			}
			closeErr := file.Close()
			if err == nil {
				err = closeErr
			}
		}
	}
	clear(encoded)
	if err != nil {
		_ = fixture.close()
		return nil, fail("security-mail-private-input")
	}
	fixture.wait.Add(1)
	go fixture.serve()
	return fixture, nil
}

func securityMailBridgeGateway(content []byte) (net.IP, error) {
	var networks []struct {
		Name     string `json:"Name"`
		Driver   string `json:"Driver"`
		Internal bool   `json:"Internal"`
		IPAM     struct {
			Config []struct {
				Gateway string `json:"Gateway"`
			} `json:"Config"`
		} `json:"IPAM"`
	}
	if json.Unmarshal(content, &networks) != nil || len(networks) != 1 {
		return nil, fail("security-mail-network-inspection")
	}
	network := networks[0]
	if network.Name != "bridge" || network.Driver != "bridge" || network.Internal || len(network.IPAM.Config) != 1 {
		return nil, fail("security-mail-network-boundary")
	}
	gateway := net.ParseIP(network.IPAM.Config[0].Gateway).To4()
	if gateway == nil || !gateway.IsPrivate() {
		return nil, fail("security-mail-network-gateway")
	}
	return gateway, nil
}

func securityMailCertificate(gateway net.IP) (tls.Certificate, []byte, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now().UTC()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Matrix acceptance mail CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	server := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: gateway.String()},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{gateway},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	serverDER, err := x509.CreateCertificate(rand.Reader, server, ca, &serverKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyPair, err := tls.X509KeyPair(append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return keyPair, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), err
}

func (fixture *securityMailFixture) serve() {
	defer fixture.wait.Done()
	for {
		connection, err := fixture.listener.Accept()
		if err != nil {
			return
		}
		fixture.mu.Lock()
		fixture.connections[connection] = struct{}{}
		fixture.mu.Unlock()
		fixture.wait.Add(1)
		go func() {
			defer fixture.wait.Done()
			defer connection.Close()
			defer func() { fixture.mu.Lock(); delete(fixture.connections, connection); fixture.mu.Unlock() }()
			fixture.exchange(connection)
		}()
	}
}

func (fixture *securityMailFixture) exchange(connection net.Conn) {
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	reader, writer := bufio.NewReaderSize(connection, 2048), bufio.NewWriter(connection)
	reply := func(line string) bool {
		_, err := writer.WriteString(line + "\r\n")
		return err == nil && writer.Flush() == nil
	}
	read := func() (string, bool) {
		line, err := reader.ReadSlice('\n')
		return strings.TrimSuffix(strings.TrimSuffix(string(line), "\n"), "\r"), err == nil && len(line) <= 2048 && bytes.HasSuffix(line, []byte("\r\n"))
	}
	if !reply("220 matrix acceptance mail") {
		return
	}
	line, ok := read()
	if !ok || !strings.HasPrefix(line, "EHLO ") || !reply("250-matrix acceptance") || !reply("250 AUTH PLAIN") {
		return
	}
	line, ok = read()
	if !ok || !strings.HasPrefix(line, "AUTH PLAIN ") {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "AUTH PLAIN "))
	want := append([]byte("\x00phase1-smtp\x00"), fixture.password...)
	authenticated := err == nil && bytes.Equal(decoded, want)
	clear(decoded)
	clear(want)
	if !authenticated || !reply("235 authenticated") {
		return
	}
	line, ok = read()
	if !ok || line != "MAIL FROM:<security@matrix.test>" || !reply("250 sender accepted") {
		return
	}
	line, ok = read()
	if !ok || line != "RCPT TO:<phase1-admin@matrix.test>" || !reply("250 recipient accepted") {
		return
	}
	line, ok = read()
	if !ok || line != "DATA" || !reply("354 end with dot") {
		return
	}
	var message bytes.Buffer
	for message.Len() <= 16384 {
		line, ok = read()
		if !ok {
			return
		}
		if line == "." {
			break
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		message.WriteString(line + "\r\n")
	}
	if line != "." || message.Len() > 16384 {
		return
	}
	select {
	case fixture.messages <- bytes.Clone(message.Bytes()):
	default:
		return
	}
	if !reply("250 queued") {
		return
	}
	line, ok = read()
	if ok && line == "QUIT" {
		_ = reply("221 bye")
	}
}

func (fixture *securityMailFixture) receiveVerification(ctx context.Context) ([]byte, error) {
	for {
		select {
		case message := <-fixture.messages:
			if bytes.Contains(message, []byte("Verification code: ")) {
				return message, nil
			}
			clear(message)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (fixture *securityMailFixture) close() error {
	if fixture == nil {
		return nil
	}
	if fixture.listener != nil {
		_ = fixture.listener.Close()
	}
	fixture.mu.Lock()
	for connection := range fixture.connections {
		_ = connection.Close()
	}
	fixture.mu.Unlock()
	fixture.wait.Wait()
	for {
		select {
		case message := <-fixture.messages:
			clear(message)
		default:
			goto drained
		}
	}
drained:
	clear(fixture.password)
	var cleanErr error
	if fixture.path != "" {
		cleanErr = errors.Join(cleanErr, os.Remove(fixture.path))
	}
	if fixture.directory != "" {
		cleanErr = errors.Join(cleanErr, os.Remove(fixture.directory))
	}
	return cleanErr
}

func (value *gate) bindFirstAuthenticator(ctx context.Context, bearer, password []byte) ([]byte, []byte, error) {
	if value.mail == nil {
		return nil, nil, fail("security-mail-fixture")
	}
	response, err := value.edge.json(ctx, http.MethodPost,
		"/api/iam/v1/auth/notification-contact/verifications", bearer,
		struct{ Email, Password, RequestID string }{
			Email: "phase1-admin@matrix.test", Password: string(password), RequestID: "phase1-notification-contact",
		}, nil, http.StatusOK)
	if err != nil {
		return nil, nil, fail("mfa-notification-start")
	}
	var verification iamv1.NotificationContactVerification
	valid := decodeOne(response.body, &verification) == nil && iamv1.ValidateNotificationContactVerification(verification) == nil &&
		verification.State == "PENDING" && verification.Email == "phase1-admin@matrix.test" && verification.UserID == "principal-admin"
	clear(response.body)
	if !valid {
		return nil, nil, fail("mfa-notification-start")
	}
	mailContext, cancel := context.WithTimeout(ctx, 45*time.Second)
	message, err := value.mail.receiveVerification(mailContext)
	cancel()
	if err != nil {
		return nil, nil, fail("mfa-notification-delivery")
	}
	defer clear(message)
	parsed, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil || parsed.Header.Get("To") != verification.Email || parsed.Header.Get("From") != "security@matrix.test" {
		return nil, nil, fail("mfa-notification-message")
	}
	body := message
	if offset := bytes.Index(message, []byte("\r\n\r\n")); offset >= 0 {
		body = message[offset+4:]
	}
	codeMatch := regexp.MustCompile(`(?m)^Verification code: ([0-9]{8})\r?$`).FindSubmatch(body)
	reference := regexp.MustCompile(`(?m)^Notification reference: notification-[A-Za-z0-9-]+\r?$`).Find(body)
	if len(codeMatch) != 2 || len(reference) == 0 {
		return nil, nil, fail("mfa-notification-message")
	}
	mailCode := bytes.Clone(codeMatch[1])
	value.sensitive = append(value.sensitive, mailCode)
	value.edge.addForbidden(mailCode)
	response, err = value.edge.json(ctx, http.MethodPost,
		"/api/iam/v1/auth/notification-contact/verifications/"+verification.ID+":confirm", bearer,
		struct{ Code, RequestID string }{Code: string(mailCode), RequestID: "phase1-notification-confirm"}, nil, http.StatusOK)
	if err != nil {
		return nil, nil, fail("mfa-notification-confirm")
	}
	var verified iamv1.NotificationContactVerification
	valid = decodeOne(response.body, &verified) == nil && iamv1.ValidateNotificationContactVerification(verified) == nil &&
		verified.ID == verification.ID && verified.State == "VERIFIED"
	clear(response.body)
	if !valid {
		return nil, nil, fail("mfa-notification-confirm")
	}
	state, err := value.edge.authenticatorState(ctx, bearer)
	if err != nil || state.EnrollmentState != "NEVER_BOUND" {
		return nil, nil, fail("mfa-initial-factor-state")
	}
	response, err = value.edge.json(ctx, http.MethodPost, "/api/iam/v1/auth/totp/enrollments", bearer,
		struct {
			RequestID, Password    string
			ExpectedFactorRevision uint64
		}{
			RequestID: "phase1-totp-enrollment", Password: string(password), ExpectedFactorRevision: state.FactorRevision,
		}, nil, http.StatusOK)
	if err != nil {
		return nil, nil, fail("mfa-enrollment-start")
	}
	var started iamv1.StartTOTPEnrollmentResponse
	valid = decodeOne(response.body, &started) == nil && iamv1.ValidateStartTOTPEnrollmentResponse(started) == nil && started.Outcome == "APPLIED"
	clear(response.body)
	if !valid {
		return nil, nil, fail("mfa-enrollment-start")
	}
	seed := started.Provisioning.Seed.CopyBytes()
	uri := started.Provisioning.URI.CopyBytes()
	value.sensitive = append(value.sensitive, seed, uri)
	value.edge.addForbidden(seed, uri)
	code, err := fixtureTOTPCode(seed, time.Now().UTC())
	if err != nil {
		return nil, nil, fail("mfa-enrollment-code")
	}
	codeBytes := []byte(code)
	value.sensitive = append(value.sensitive, codeBytes)
	value.edge.addForbidden(codeBytes)
	response, err = value.edge.json(ctx, http.MethodPost,
		"/api/iam/v1/auth/totp/enrollments/"+started.Enrollment.ID+":confirm", bearer,
		struct{ RequestID, Code string }{RequestID: "phase1-totp-confirm", Code: code}, nil, http.StatusOK)
	if err != nil {
		return nil, nil, fail("mfa-enrollment-confirm")
	}
	var confirmed iamv1.ConfirmTOTPEnrollmentResponse
	valid = decodeOne(response.body, &confirmed) == nil && iamv1.ValidateConfirmTOTPEnrollmentResponse(confirmed) == nil &&
		confirmed.Enrollment.ID == started.Enrollment.ID && confirmed.NextStep == "REAUTHENTICATE"
	clear(response.body)
	if !valid {
		return nil, nil, fail("mfa-enrollment-confirm")
	}
	value.edge.lastTOTPStep = time.Now().Unix() / 30
	for _, recoveryCode := range confirmed.RecoveryCodes {
		copyCode := recoveryCode.CopyBytes()
		value.sensitive = append(value.sensitive, copyCode)
		value.edge.addForbidden(copyCode)
	}
	if err := value.edge.unauthorizedMe(ctx, bearer); err != nil {
		return nil, nil, fail("mfa-old-session-revoked")
	}
	newBearer, err := value.edge.loginWithTOTP(ctx, password, seed, "phase1-mfa-login")
	if err != nil {
		return nil, nil, fail("mfa-challenged-login")
	}
	value.sensitive = append(value.sensitive, newBearer)
	value.edge.addForbidden(newBearer)
	state, err = value.edge.authenticatorState(ctx, newBearer)
	if err != nil || state.EnrollmentState != "BOUND" || state.FactorID != started.Enrollment.ID {
		return nil, nil, fail("mfa-bound-factor-state")
	}
	return seed, newBearer, nil
}

func (client *edgeClient) authenticatorState(ctx context.Context, bearer []byte) (iamv1.AuthenticatorState, error) {
	response, err := client.json(ctx, http.MethodGet, "/api/iam/v1/auth/authenticators", bearer, nil, nil, http.StatusOK)
	if err != nil {
		return iamv1.AuthenticatorState{}, err
	}
	defer clear(response.body)
	var state iamv1.AuthenticatorState
	if decodeOne(response.body, &state) != nil || iamv1.ValidateAuthenticatorState(state) != nil {
		return iamv1.AuthenticatorState{}, fail("mfa-factor-state-response")
	}
	return state, nil
}

func (client *edgeClient) unauthorizedMe(ctx context.Context, bearer []byte) error {
	response, err := client.json(ctx, http.MethodGet, "/api/iam/v1/auth/me", bearer, nil, nil, http.StatusUnauthorized)
	clear(response.body)
	return err
}

func (client *edgeClient) loginWithTOTP(ctx context.Context, password, seed []byte, requestID string) ([]byte, error) {
	response, err := client.json(ctx, http.MethodPost, "/api/iam/v1/auth/login", nil,
		loginWire{LoginName: "admin", Password: string(password), RequestID: requestID}, nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	var challenge iamv1.LoginResponse
	valid := decodeOne(response.body, &challenge) == nil && iamv1.ValidateLoginResponse(challenge) == nil &&
		challenge.Outcome == iamv1.LoginChallengeRequired && challenge.Challenge.NextStep == "TOTP"
	clear(response.body)
	if !valid {
		return nil, fail("mfa-login-challenge")
	}
	for time.Now().Unix()/30 <= client.lastTOTPStep {
		next := time.Unix((client.lastTOTPStep+1)*30, 0).Add(time.Second)
		wait := time.Until(next)
		if wait < time.Second {
			wait = time.Second
		}
		select {
		case <-time.After(wait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	code, err := fixtureTOTPCode(seed, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	client.lastTOTPStep = time.Now().Unix() / 30
	codeBytes := []byte(code)
	client.transientSecrets = append(client.transientSecrets, codeBytes)
	client.addForbidden(codeBytes)
	credential := challenge.ChallengeCredential.CopyBytes()
	client.transientSecrets = append(client.transientSecrets, credential)
	client.addForbidden(credential)
	codeSecret, err := iamv1.NewSecret(code)
	if err != nil {
		return nil, err
	}
	encoded, err := iamv1.EncodeVerifyAuthenticationChallengeRequest(iamv1.VerifyAuthenticationChallengeRequest{
		RequestID: requestID + "-verify", ChallengeCredential: challenge.ChallengeCredential,
		Code: codeSecret,
	})
	if err != nil {
		return nil, err
	}
	defer clear(encoded)
	response, err = client.json(ctx, http.MethodPost, "/api/iam/v1/auth/challenges/"+challenge.Challenge.ID+":verify", nil,
		json.RawMessage(encoded), nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	defer clear(response.body)
	var authenticated iamv1.LoginResponse
	if decodeOne(response.body, &authenticated) != nil || iamv1.ValidateLoginResponse(authenticated) != nil ||
		authenticated.Outcome != iamv1.LoginAuthenticated || authenticated.Session.PrincipalID != "principal-admin" ||
		authenticated.Session.AccountID != "organization-default" {
		return nil, fail("mfa-login-completion")
	}
	result := authenticated.Credential.CopyBytes()
	if len(result) == 0 {
		return nil, fail("mfa-login-completion")
	}
	return result, nil
}

// The acceptance client implements only the published SHA1/6-digit/30-second
// verifier profile. It is deliberately independent of IAM implementation code.
func fixtureTOTPCode(encodedSeed []byte, instant time.Time) (string, error) {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(encodedSeed))
	if err != nil || len(key) != 20 || instant.Unix() < 0 {
		clear(key)
		return "", fail("mfa-fixture-seed")
	}
	defer clear(key)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(instant.Unix()/30))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	defer clear(sum)
	offset := int(sum[len(sum)-1] & 0x0f)
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000), nil
}
