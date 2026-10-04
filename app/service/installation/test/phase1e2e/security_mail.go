package phase1e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/mail"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

const (
	securityMailRecipient         = "receiver@matrix.test"
	securityMailPreviousRecipient = "previous@matrix.test"
	securityMailCurrentRecipient  = "current@matrix.test"
)

var (
	providerIDPattern = regexp.MustCompile(`^[a-f0-9]{12,64}$`)
	mailCodePattern   = regexp.MustCompile(`(?m)^Verification code: ([0-9]{8})\r?$`)
	mailRefPattern    = regexp.MustCompile(`(?m)^Notification reference: [A-Za-z0-9][A-Za-z0-9._:-]{0,127}\r?$`)
)

type securityMailFixture struct {
	containerID string
	imageID     string
	alias       string
	sender      string
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func verifyFixtureArchive(path, expected string) error {
	if path == "" || !validSHA256(expected) {
		return errors.New("mail fixture identity is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > 256*1024*1024 {
		return errors.New("mail fixture archive is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New("open mail fixture archive failed")
	}
	defer file.Close()
	hasher := sha256.New()
	written, copyErr := io.Copy(hasher, io.LimitReader(file, 256*1024*1024+1))
	opened, statErr := file.Stat()
	want, decodeErr := hex.DecodeString(strings.TrimPrefix(expected, "sha256:"))
	if copyErr != nil || written != info.Size() || statErr != nil || !os.SameFile(info, opened) ||
		opened.Size() != info.Size() || decodeErr != nil || subtle.ConstantTimeCompare(hasher.Sum(nil), want) != 1 {
		return errors.New("mail fixture archive authentication failed")
	}
	return nil
}

func trustedCertificatesCoverWindow(encoded string, from, through time.Time) bool {
	if encoded == "" || from.After(through) {
		return false
	}
	rest := []byte(encoded)
	count := 0
	for len(rest) != 0 {
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return false
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || from.Before(certificate.NotBefore) || through.After(certificate.NotAfter) {
			return false
		}
		count++
		rest = remaining
	}
	return count != 0
}

func startSecurityMailFixture(
	ctx context.Context,
	config options,
	installationID string,
) (*securityMailFixture, error) {
	if !validSHA256(config.securityMailFixtureID) ||
		verifyFixtureArchive(config.securityMailFixture, config.securityMailFixtureSHA) != nil {
		return nil, fail("security-mail-fixture-archive")
	}
	privateInput, err := os.Open(config.securityMail)
	if err != nil {
		return nil, fail("security-mail-fixture-channel-input")
	}
	mailConfig, decodeErr := installationv1.DecodeSecurityMailConfiguration(privateInput)
	closeErr := privateInput.Close()
	if decodeErr != nil || closeErr != nil {
		mailConfig.Clear()
		return nil, fail("security-mail-fixture-channel-input")
	}
	defer mailConfig.Clear()
	lifecycleDeadline, hasDeadline := ctx.Deadline()
	if !hasDeadline || !trustedCertificatesCoverWindow(mailConfig.TrustedCAPEM, time.Now(), lifecycleDeadline) {
		return nil, fail("security-mail-fixture-channel-trust-window")
	}
	networks, err := dockerLines(
		ctx, "network", "ls", "--quiet",
		"--filter", "label=com.xiak.matrix.managed=true",
		"--filter", "label=com.xiak.matrix.installation="+installationID,
		"--filter", "label=com.xiak.matrix.role=network-mail-egress",
	)
	if err != nil || len(networks) != 1 || !providerIDPattern.MatchString(networks[0]) {
		return nil, fail("security-mail-fixture-network-discovery")
	}
	var network struct {
		ID, Name string
		Labels   map[string]string
	}
	projection := `{"ID":{{json .Id}},"Name":{{json .Name}},"Labels":{{json .Labels}}}`
	encoded, err := docker(ctx, "network", "inspect", "--format", projection, networks[0])
	if err != nil || json.Unmarshal(encoded, &network) != nil || network.ID == "" || network.Name == "" ||
		network.Labels["com.xiak.matrix.managed"] != "true" ||
		network.Labels["com.xiak.matrix.installation"] != installationID ||
		network.Labels["com.xiak.matrix.role"] != "network-mail-egress" {
		return nil, fail("security-mail-fixture-network-metadata")
	}
	if _, err := docker(ctx, "image", "load", "--quiet", "--input", config.securityMailFixture); err != nil {
		return nil, fail("security-mail-fixture-image-load")
	}
	fixture := &securityMailFixture{
		imageID: config.securityMailFixtureID,
		alias:   mailConfig.Host,
		sender:  mailConfig.From,
	}
	failFixture := func(step string) (*securityMailFixture, error) {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = fixture.close(cleanupCtx)
		return nil, fail(step)
	}
	identity, inspectErr := docker(
		ctx, "image", "inspect", "--format", "{{.Id}}|{{.Os}}|{{.Architecture}}", config.securityMailFixtureID,
	)
	if inspectErr != nil || strings.TrimSpace(string(identity)) != config.securityMailFixtureID+"|linux|amd64" {
		return failFixture("security-mail-fixture-image-identity")
	}
	name := "matrix-phase1-mailbox-" + strings.TrimPrefix(installationID, "mxi-")
	started, err := docker(
		ctx, "run", "--detach", "--pull", "never", "--restart", "no",
		"--name", name,
		"--label", "com.xiak.matrix.test=phase1-security-mail",
		"--label", "com.xiak.matrix.installation="+installationID,
		"--network", network.ID,
		"--network-alias", fixture.alias,
		"--cpus", "1", "--memory", "536870912", "--memory-swap", "536870912", "--pids-limit", "128",
		config.securityMailFixtureID,
	)
	if err != nil {
		return failFixture("security-mail-fixture-container-start")
	}
	fixture.containerID = strings.TrimSpace(string(started))
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(fixture.containerID) {
		return failFixture("security-mail-fixture-container-identity")
	}
	var observed struct {
		ID, Name, Image, NetworkMode, Restart string
		Running                               bool
		Labels                                map[string]string
		NanoCPUs, Memory, MemorySwap, Pids    int64
		Ports                                 map[string][]struct{ HostIP, HostPort string }
		Mounts                                []json.RawMessage
		Networks                              map[string]struct{ Aliases []string }
	}
	projection = `{"ID":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},"Running":{{json .State.Running}},"Labels":{{json .Config.Labels}},"NetworkMode":{{json .HostConfig.NetworkMode}},"Restart":{{json .HostConfig.RestartPolicy.Name}},"NanoCPUs":{{json .HostConfig.NanoCpus}},"Memory":{{json .HostConfig.Memory}},"MemorySwap":{{json .HostConfig.MemorySwap}},"Pids":{{json .HostConfig.PidsLimit}},"Ports":{{json .NetworkSettings.Ports}},"Mounts":{{json .Mounts}},"Networks":{{json .NetworkSettings.Networks}}}`
	encoded, err = docker(ctx, "container", "inspect", "--format", projection, fixture.containerID)
	if err != nil || json.Unmarshal(encoded, &observed) != nil || observed.ID != fixture.containerID ||
		observed.Name != "/"+name || observed.Image != fixture.imageID || !observed.Running ||
		observed.Labels["com.xiak.matrix.test"] != "phase1-security-mail" ||
		observed.Labels["com.xiak.matrix.installation"] != installationID || observed.Restart != "no" ||
		observed.NetworkMode != network.ID ||
		observed.NanoCPUs != 1_000_000_000 || observed.Memory != 536870912 || observed.MemorySwap != 536870912 ||
		observed.Pids != 128 || len(observed.Mounts) != 0 || len(observed.Networks) != 1 {
		return failFixture("security-mail-fixture-runtime-boundary")
	}
	for _, bindings := range observed.Ports {
		if len(bindings) != 0 {
			return failFixture("security-mail-fixture-host-port")
		}
	}
	attached, found := observed.Networks[network.Name]
	if !found || !slices.Contains(attached.Aliases, fixture.alias) {
		return failFixture("security-mail-fixture-network-attachment")
	}
	ready := false
	readyDeadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(readyDeadline) {
		if _, err := docker(
			ctx, "exec", fixture.containerID, "sh", "-lc", "postfix status >/dev/null 2>&1",
		); err == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return failFixture("security-mail-fixture-readiness")
	}
	return fixture, nil
}

func (fixture *securityMailFixture) close(ctx context.Context) error {
	if fixture == nil {
		return nil
	}
	var result error
	if fixture.containerID != "" {
		if _, err := docker(ctx, "container", "rm", "--force", fixture.containerID); err != nil {
			result = errors.Join(result, errors.New("mail fixture container cleanup failed"))
		}
	}
	if fixture.imageID != "" {
		if _, err := docker(ctx, "image", "rm", "--no-prune", fixture.imageID); err != nil {
			result = errors.Join(result, errors.New("mail fixture image cleanup failed"))
		}
	}
	containers, err := dockerLines(ctx, "container", "ls", "--all", "--quiet", "--filter", "label=com.xiak.matrix.test=phase1-security-mail")
	if err != nil || len(containers) != 0 {
		result = errors.Join(result, errors.New("mail fixture container remains"))
	}
	return result
}

func (fixture *securityMailFixture) receive(
	ctx context.Context,
	recipient string,
	subject string,
	forbidden [][]byte,
) ([]byte, string, error) {
	mailbox, found := map[string]string{
		securityMailRecipient:         "receiver",
		securityMailPreviousRecipient: "previous",
		securityMailCurrentRecipient:  "current",
	}[recipient]
	if !found {
		return nil, "", errors.New("mail fixture recipient is invalid")
	}
	maildir := "/home/" + mailbox + "/Maildir"
	mailPathPattern := regexp.MustCompile(`^` + regexp.QuoteMeta(maildir) + `/(new|cur)/[a-zA-Z0-9_.,:=+-]+$`)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		files, err := dockerLines(
			ctx, "exec", fixture.containerID, "find", maildir+"/new", maildir+"/cur",
			"-maxdepth", "1", "-type", "f", "-print",
		)
		if err != nil || len(files) > 100 {
			return nil, "", errors.New("mail fixture mailbox observation failed")
		}
		for _, path := range files {
			if !mailPathPattern.MatchString(path) {
				return nil, "", errors.New("mail fixture mailbox path is unsafe")
			}
			encoded, err := docker(ctx, "exec", fixture.containerID, "head", "-c", "16385", "--", path)
			if err != nil || len(encoded) == 0 || len(encoded) > 16384 ||
				bytes.Contains(encoded, []byte("smtp-test-password")) {
				clear(encoded)
				return nil, "", errors.New("mail fixture message is unsafe")
			}
			message, err := mail.ReadMessage(bytes.NewReader(encoded))
			if err != nil {
				clear(encoded)
				return nil, "", errors.New("mail fixture message is invalid")
			}
			body, readErr := io.ReadAll(io.LimitReader(message.Body, 16385))
			if readErr != nil || len(body) > 16384 {
				clear(encoded)
				clear(body)
				return nil, "", errors.New("mail fixture body is invalid")
			}
			if message.Header.Get("Subject") != subject {
				clear(encoded)
				clear(body)
				continue
			}
			if message.Header.Get("To") != recipient || message.Header.Get("From") != fixture.sender ||
				message.Header.Get("Received") == "" || message.Header.Get("Message-ID") == "" ||
				!mailRefPattern.Match(body) || containsAny(encoded, forbidden) || containsAny(body, forbidden) {
				clear(encoded)
				clear(body)
				return nil, "", errors.New("mail fixture envelope or body differs")
			}
			clear(encoded)
			return body, message.Header.Get("Message-ID"), nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, "", errors.New("mail fixture did not receive the message")
}

func (value *gate) verifySecurityMail(
	ctx context.Context,
	bearer, password []byte,
	installationID string,
) (iamv1.NotificationContact, error) {
	fixture, err := startSecurityMailFixture(ctx, value.config, installationID)
	if err != nil {
		return iamv1.NotificationContact{}, err
	}
	verifiedContact, verifyErr := value.verifySecurityMailWithFixture(
		ctx, bearer, password, fixture, securityMailRecipient, "phase1-security-mail",
	)
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cleanupErr := fixture.close(cleanupCtx)
	if verifyErr != nil {
		return iamv1.NotificationContact{}, verifyErr
	}
	if cleanupErr != nil {
		return iamv1.NotificationContact{}, fail("security-mail-fixture-cleanup")
	}
	return verifiedContact, nil
}

func (value *gate) verifySecurityMailWithFixture(
	ctx context.Context,
	bearer, password []byte,
	fixture *securityMailFixture,
	recipient string,
	requestPrefix string,
) (iamv1.NotificationContact, error) {
	var verifiedContact iamv1.NotificationContact
	verifyErr := func() error {
		verification, err := value.edge.startNotificationContactVerification(
			ctx, bearer, password, recipient, requestPrefix+"-contact",
		)
		if err != nil {
			return fail("security-mail-verification-start")
		}
		deadline := time.Now().Add(30 * time.Second)
		for verification.Delivery.State != "ACCEPTED" && time.Now().Before(deadline) {
			time.Sleep(100 * time.Millisecond)
			verification, err = value.edge.readNotificationContactVerification(ctx, bearer, verification.ID)
			if err != nil {
				return fail("security-mail-delivery-observation")
			}
		}
		if verification.Delivery.State != "ACCEPTED" || verification.Delivery.LastOutcome != "ACCEPTED" ||
			verification.Delivery.LastSMTPCode != 250 || verification.Delivery.Attempts == 0 {
			return fail("security-mail-delivery-not-accepted")
		}
		body, verificationMessageID, err := fixture.receive(
			ctx, recipient, "MATRIX notification address verification", value.edge.forbidden,
		)
		if err != nil {
			return fail("security-mail-verification-mailbox")
		}
		match := mailCodePattern.FindSubmatch(body)
		if len(match) != 2 {
			clear(body)
			return fail("security-mail-verification-code")
		}
		code := bytes.Clone(match[1])
		clear(body)
		defer clear(code)
		value.edge.addForbidden(bytes.Clone(code))
		completed, err := value.edge.confirmNotificationContactVerification(
			ctx, bearer, code, verification.ID, requestPrefix+"-confirm",
		)
		if err != nil || completed.AccountID != verification.AccountID || completed.UserID != verification.UserID {
			return fail("security-mail-verification-confirm")
		}
		contact, err := value.edge.notificationContact(ctx, bearer)
		if err != nil || contact.State != "VERIFIED" || contact.Email != recipient ||
			contact.ResourceVersion != 1 || contact.AccountID != verification.AccountID ||
			contact.UserID != verification.UserID || contact.VerifiedAt == nil {
			return fail("security-mail-contact-state")
		}
		verifiedContact = contact
		notice, noticeMessageID, err := fixture.receive(
			ctx, recipient, "MATRIX notification address verified", value.edge.forbidden,
		)
		if err != nil || noticeMessageID == verificationMessageID || bytes.Contains(notice, []byte("Verification code:")) ||
			bytes.Contains(notice, code) {
			clear(notice)
			return fail("security-mail-security-notice")
		}
		clear(notice)
		return nil
	}()
	if verifyErr != nil {
		return iamv1.NotificationContact{}, verifyErr
	}
	return verifiedContact, nil
}

func (value *gate) observeContactReplacement(
	ctx context.Context,
	installationID string,
	contact iamv1.NotificationContact,
	verification iamv1.NotificationContactVerification,
) (contactReplacementRetention, error) {
	containerID, err := postgresContainerID(ctx, installationID)
	if err != nil {
		return contactReplacementRetention{}, err
	}
	query := contactReplacementObservationQuery(contact.AccountID, contact.UserID, verification.ID)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		content, observeErr := docker(
			ctx, "container", "exec", "--user", "postgres", containerID,
			"psql", "--no-psqlrc", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1",
			"--username", "matrix", "--dbname", "matrix", "--command", query,
		)
		var observed contactReplacementRetention
		if observeErr == nil && json.Unmarshal(bytes.TrimSpace(content), &observed) == nil &&
			validContactReplacementRetention(observed, contact, verification) {
			return observed, nil
		}
		if !waitPoll(ctx, 100*time.Millisecond) {
			break
		}
	}
	return contactReplacementRetention{}, errors.New("contact replacement delivery observation failed")
}

func contactReplacementObservationQuery(
	accountID iamv1.AccountID,
	userID iamv1.PrincipalID,
	verificationID string,
) string {
	query := `SELECT jsonb_build_object(
 'accountId',v.tenant_id,'userId',v.user_id,'verificationId',v.id,
 'completionEventId',v.completion_event_id,'expectedResourceVersion',v.contact_revision,
 'email',v.email,'state',v.state,'notifications',(
   SELECT jsonb_agg(jsonb_build_object(
     'id',n.id,'eventId',n.event_id,'kind',n.kind,'email',n.email,
     'contactRevision',n.contact_revision,'state',n.state,'attempts',n.attempts,
     'lastOutcome',n.last_outcome,'lastSmtpCode',n.last_smtp_code) ORDER BY n.kind,n.id)
   FROM iam.security_notifications n WHERE n.tenant_id=v.tenant_id AND n.verification_id=v.id
 ))::text
FROM iam.notification_contact_verifications v
WHERE v.tenant_id=$TENANT AND v.user_id=$USER AND v.id=$VERIFICATION AND v.purpose='REPLACEMENT'`
	return strings.NewReplacer(
		"$TENANT", postgresHexText(string(accountID)),
		"$USER", postgresHexText(string(userID)),
		"$VERIFICATION", postgresHexText(verificationID),
	).Replace(query)
}

func postgresHexText(value string) string {
	return "convert_from(decode('" + hex.EncodeToString([]byte(value)) + "','hex'),'UTF8')"
}

func validContactReplacementRetention(
	value contactReplacementRetention,
	contact iamv1.NotificationContact,
	verification iamv1.NotificationContactVerification,
) bool {
	if contact.Email != securityMailCurrentRecipient || contact.ResourceVersion != 2 || contact.PendingVerificationID != "" ||
		value.AccountID != contact.AccountID || value.UserID != contact.UserID || value.VerificationID != verification.ID ||
		value.CompletionEventID == "" || value.ExpectedResourceVersion != 1 || value.Email != securityMailCurrentRecipient ||
		value.State != "VERIFIED" || len(value.Notifications) != 3 {
		return false
	}
	want := map[string]struct {
		email    string
		revision uint64
	}{
		"ADDRESS_VERIFICATION":      {securityMailCurrentRecipient, 1},
		"CONTACT_REPLACED_CURRENT":  {securityMailCurrentRecipient, 2},
		"CONTACT_REPLACED_PREVIOUS": {securityMailPreviousRecipient, 1},
	}
	seen := make(map[string]struct{}, len(want))
	for _, notification := range value.Notifications {
		expected, ok := want[notification.Kind]
		if !ok || notification.ID == "" || notification.EventID == "" || notification.Email != expected.email ||
			notification.ContactRevision != expected.revision || notification.State != "ACCEPTED" ||
			notification.Attempts != 1 || notification.LastOutcome != "ACCEPTED" || notification.LastSMTPCode != 250 {
			return false
		}
		if notification.Kind != "ADDRESS_VERIFICATION" && notification.EventID != value.CompletionEventID {
			return false
		}
		seen[notification.Kind] = struct{}{}
	}
	return len(seen) == len(want)
}

func sameContactReplacementRetention(left, right contactReplacementRetention) bool {
	return reflect.DeepEqual(left, right)
}
