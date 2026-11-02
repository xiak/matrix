// Command matrix-offline-fixture creates private inputs for the signed offline
// lifecycle gate. It is not included in Matrix or in a customer release.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/deploy/releasebuild"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 || !filepath.IsAbs(os.Args[1]) {
		return errors.New("an unused absolute fixture directory is required")
	}
	root := filepath.Clean(os.Args[1])
	if err := os.Mkdir(root, 0o700); err != nil {
		return errors.New("create private fixture directory failed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	for _, reference := range []string{
		releasebuild.APISIXBasePinnedReference, releasebuild.AlpineBasePinnedReference, releasebuild.DockerBasePinnedReference,
		releasebuild.PostgresPinnedReference, releasebuild.MySQLPinnedReference, releasebuild.ElasticsearchPinnedReference,
		releasebuild.RabbitMQPinnedReference, releasebuild.LogstashPinnedReference, releasebuild.KibanaPinnedReference,
		releasebuild.RedisPinnedReference, releasebuild.RunnerToolchainReference,
	} {
		if _, err := docker(ctx, "pull", "--platform", "linux/amd64", reference); err != nil {
			return errors.New("prepare pinned release image failed: " + reference)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	certificate := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Matrix disposable offline mail"},
		DNSNames: []string{"matrix-offline-mail.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	defer clear(privatePEM)
	password := make([]byte, 32)
	if _, err := rand.Read(password); err != nil {
		return err
	}
	defer clear(password)
	secret, err := iamv1.NewSecret(base64.RawURLEncoding.EncodeToString(password))
	if err != nil {
		return err
	}
	config, err := installationv1.EncodeSecurityMailConfiguration(installationv1.SecurityMailConfiguration{
		APIVersion: installationv1.SecurityMailConfigurationAPIVersion, Kind: installationv1.SecurityMailConfigurationKind,
		Host: "matrix-offline-mail.test", Port: 25, TLSMode: iamv1.SecurityMailSTARTTLS,
		Username: "sender@matrix.test", Password: secret, From: "sender@matrix.test", TrustedCAPEM: string(certPEM),
	})
	if err != nil {
		return errors.New("encode private SMTP channel failed")
	}
	defer clear(config)
	files := map[string][]byte{
		"security-mail.json": config, "server.crt": certPEM, "server.key": privatePEM,
		"password":   []byte(base64.RawURLEncoding.EncodeToString(password)),
		"smtpd.conf": []byte("pwcheck_method: auxprop\nauxprop_plugin: sasldb\nmech_list: PLAIN LOGIN\nsasldb_path: /etc/sasl2/sasldb2\n"),
		"main.cf": []byte(`myhostname = matrix-offline-mail.test
compatibility_level = 3.6
always_add_missing_headers = yes
mydestination = matrix.test, localhost
inet_interfaces = all
inet_protocols = ipv4
mynetworks = 127.0.0.0/8
home_mailbox = Maildir/
smtpd_tls_cert_file = /etc/postfix/server.crt
smtpd_tls_key_file = /etc/postfix/server.key
smtpd_tls_security_level = encrypt
smtpd_tls_auth_only = yes
smtpd_sasl_auth_enable = yes
smtpd_sasl_type = cyrus
smtpd_sasl_path = smtpd
smtpd_sasl_security_options = noanonymous
smtpd_relay_restrictions = reject_unauth_destination
smtpd_recipient_restrictions = permit_sasl_authenticated, reject
maillog_file = /dev/null
maillog_file_prefixes = /dev
`),
		"Dockerfile": []byte("FROM " + releasebuild.AlpineBasePinnedReference + `
RUN apk add --no-cache postfix cyrus-sasl cyrus-sasl-login
COPY server.crt server.key main.cf /etc/postfix/
COPY smtpd.conf /etc/sasl2/smtpd.conf
COPY password /tmp/password
RUN saslpasswd2 -p -c -f /etc/sasl2/sasldb2 -u matrix.test sender < /tmp/password && rm /tmp/password && \
    chown postfix:postfix /etc/sasl2/sasldb2 && chmod 600 /etc/sasl2/sasldb2 /etc/postfix/server.key && \
    for user in receiver previous current; do adduser -D "$user"; \
      mkdir -p "/home/$user/Maildir/new" "/home/$user/Maildir/cur" "/home/$user/Maildir/tmp"; \
      chown -R "$user:$user" "/home/$user/Maildir"; done && newaliases
CMD ["postfix", "start-fg"]
`),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
			return errors.New("write private fixture failed")
		}
	}
	identity, err := docker(ctx, "build", "--quiet", "--pull=false", root)
	if err != nil {
		return errors.New("build private Postfix fixture failed")
	}
	imageID := strings.TrimSpace(string(identity))
	if !strings.HasPrefix(imageID, "sha256:") || len(imageID) != 71 {
		return errors.New("private fixture image identity is invalid")
	}
	archive := filepath.Join(root, "postfix.tar")
	if _, err := docker(ctx, "image", "save", "--output", archive, imageID); err != nil {
		return errors.New("save private fixture failed")
	}
	file, err := os.Open(archive)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	size, copyErr := io.Copy(hasher, io.LimitReader(file, 256*1024*1024+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || size == 0 || size > 256*1024*1024 {
		return errors.New("private fixture archive exceeds gate bound")
	}
	metadata, err := json.Marshal(map[string]string{"imageId": imageID, "sha256": "sha256:" + hex.EncodeToString(hasher.Sum(nil))})
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "fixture.json"), metadata, 0o600)
}

func docker(ctx context.Context, args ...string) ([]byte, error) {
	// Build output can contain private file paths; it is never a public artifact.
	command := exec.CommandContext(ctx, "docker", args...)
	return command.Output()
}
