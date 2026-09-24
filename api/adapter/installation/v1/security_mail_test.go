package installationv1

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func securityMailConfigurationFixture(t *testing.T) SecurityMailConfiguration {
	t.Helper()
	password, err := iamv1.NewSecret("smtp-private-password")
	if err != nil {
		t.Fatal(err)
	}
	return SecurityMailConfiguration{
		APIVersion: SecurityMailConfigurationAPIVersion,
		Kind:       SecurityMailConfigurationKind,
		Host:       "smtp.matrix.test", Port: 587, TLSMode: iamv1.SecurityMailSTARTTLS,
		Username: "matrix-sender", Password: password, From: "security@matrix.test",
	}
}

func TestSecurityMailConfigurationIsCanonicalPrivateInput(t *testing.T) {
	value := securityMailConfigurationFixture(t)
	encoded, err := EncodeSecurityMailConfiguration(value)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	decoded, err := DecodeSecurityMailConfiguration(bytes.NewReader(encoded))
	if err != nil || !reflect.DeepEqual(decoded, value) {
		t.Fatal("security mail configuration did not round trip")
	}
	digest, err := SecurityMailConfigurationDigest(decoded)
	if err != nil || !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		t.Fatal("security mail configuration digest is invalid")
	}
	if output, err := json.Marshal(value); !errors.Is(err, ErrInvalidSecurityMailConfiguration) || len(output) != 0 {
		t.Fatal("ordinary JSON exposed the security mail configuration")
	}
	var ordinary SecurityMailConfiguration
	if json.Unmarshal(encoded, &ordinary) != ErrInvalidSecurityMailConfiguration || ordinary.Password.Present() {
		t.Fatal("ordinary JSON admitted the security mail configuration")
	}
	if value.String() != "[REDACTED]" || !strings.Contains(value.GoString(), "[REDACTED]") {
		t.Fatal("security mail configuration formatting is not redacted")
	}
}

func TestSecurityMailConfigurationRejectsInvalidAndNonCanonicalInputs(t *testing.T) {
	fixture := securityMailConfigurationFixture(t)
	for name, mutate := range map[string]func(*SecurityMailConfiguration){
		"version":  func(v *SecurityMailConfiguration) { v.APIVersion = iamv1.APIVersion },
		"kind":     func(v *SecurityMailConfiguration) { v.Kind = "SecurityMailSMTPChannel" },
		"host":     func(v *SecurityMailConfiguration) { v.Host = "localhost" },
		"port":     func(v *SecurityMailConfiguration) { v.Port = 0 },
		"tls":      func(v *SecurityMailConfiguration) { v.TLSMode = "NONE" },
		"username": func(v *SecurityMailConfiguration) { v.Username = "" },
		"password": func(v *SecurityMailConfiguration) { v.Password = iamv1.Secret{} },
		"from":     func(v *SecurityMailConfiguration) { v.From = "bad\r\nBcc:x@matrix.test" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := fixture
			mutate(&candidate)
			if ValidateSecurityMailConfiguration(candidate) != ErrInvalidSecurityMailConfiguration {
				t.Fatal("invalid security mail configuration was accepted")
			}
		})
	}
	encoded, _ := EncodeSecurityMailConfiguration(fixture)
	defer clear(encoded)
	for _, invalid := range [][]byte{
		append(append([]byte(nil), encoded...), '\n'),
		bytes.Replace(encoded, []byte(`"kind":"SecurityMailConfiguration"`), []byte(`"kind":"SecurityMailConfiguration","unknown":true`), 1),
		bytes.Replace(encoded, []byte(`"host":"smtp.matrix.test"`), []byte(`"host":"smtp.matrix.test","host":"smtp.matrix.test"`), 1),
	} {
		if got, err := DecodeSecurityMailConfiguration(bytes.NewReader(invalid)); !errors.Is(err, ErrInvalidSecurityMailConfiguration) || !reflect.DeepEqual(got, SecurityMailConfiguration{}) {
			t.Fatal("non-canonical security mail configuration was accepted")
		}
	}
	large := strings.NewReader(strings.Repeat(" ", int(MaximumSecurityMailConfigurationBytes)+1))
	if _, err := DecodeSecurityMailConfiguration(large); !errors.Is(err, ErrInvalidSecurityMailConfiguration) {
		t.Fatal("oversized security mail configuration was accepted")
	}
}
