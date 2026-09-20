package authority

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

func TestTOTPStandardAndIndependentVectors(t *testing.T) {
	// Public synthetic 20-byte seed from RFC4226/6238. RFC6238's SHA1
	// eight-digit results reduce modulo 10^6 for the fixed six-digit profile.
	seed := authoritySecret(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	for _, vector := range []struct {
		unix int64
		code string
	}{
		{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"},
		{1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"},
		// Independently generated with Node crypto HMAC-SHA1, including the
		// epoch, actual step boundary, signed-32-bit boundary and final date.
		{0, "755224"}, {29, "755224"}, {30, "287082"}, {60, "359152"},
		{2147483647, "703886"}, {2147483648, "703886"}, {253402300799, "099568"},
	} {
		t.Run(fmt.Sprint(vector.unix), func(t *testing.T) {
			step, err := VerifyTOTP(seed, authoritySecret(t, vector.code), time.Unix(vector.unix, 0).UTC(), -1)
			if err != nil || step != vector.unix/30 {
				t.Fatal("independent OTP or exact time step rejected")
			}
		})
	}
	for counter, code := range []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"} {
		step, err := VerifyTOTP(seed, authoritySecret(t, code), time.Unix(int64(counter)*30, 0).UTC(), -1)
		if err != nil || step != int64(counter) {
			t.Fatal("RFC4226 counter vector rejected")
		}
	}
}

func TestTOTPWindowAndConsumedStepFailClosed(t *testing.T) {
	seed := authoritySecret(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	code := authoritySecret(t, "359152") // step 2
	for _, unix := range []int64{30, 59, 60, 89, 90, 119} {
		if step, err := VerifyTOTP(seed, code, time.Unix(unix, 0).UTC(), 1); err != nil || step != 2 {
			t.Fatal("fixed adjacent window rejected")
		}
	}
	for _, instant := range []time.Time{time.Unix(29, 999999000).UTC(), time.Unix(120, 0).UTC()} {
		if step, err := VerifyTOTP(seed, code, instant, -1); err != ErrTOTPRejected || step != 0 {
			t.Fatal("window was widened or a failed result exposed a step")
		}
	}
	for _, consumed := range []int64{2, 3, 100} {
		if step, err := VerifyTOTP(seed, code, time.Unix(60, 0).UTC(), consumed); err != ErrTOTPRejected || step != 0 {
			t.Fatal("consumed step or clock rollback was accepted")
		}
	}
	// Node independently found the same six digits at these adjacent steps.
	// Reject the entire match if its earlier candidate is already consumed;
	// choosing the later candidate would turn a replay into a fresh success.
	collisionTime := time.Unix(910738*30, 0).UTC()
	collisionCode := authoritySecret(t, "911617")
	if step, err := VerifyTOTP(seed, collisionCode, collisionTime, -1); err != nil || step != 910738 {
		t.Fatal("fresh collision did not select the highest matched step")
	}
	for _, consumed := range []int64{910737, 910738} {
		if step, err := VerifyTOTP(seed, collisionCode, collisionTime, consumed); err != ErrTOTPRejected || step != 0 {
			t.Fatal("colliding consumed code was accepted as a different step")
		}
	}
	// This primitive deliberately has no local replay cache. Persistence must
	// consume the returned step under the actual factor's transaction lock.
	for range 2 {
		if _, err := VerifyTOTP(seed, code, time.Unix(60, 0).UTC(), -1); err != nil {
			t.Fatal("pure validation acquired process-local consumption state")
		}
	}
}

func TestTOTPRejectsMalformedOrUnknownAuthorityState(t *testing.T) {
	seed := authoritySecret(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	code := authoritySecret(t, "287082")
	now := time.Unix(59, 0).UTC()
	for _, invalid := range []iamv1.Secret{{}, authoritySecret(t, "28708"), authoritySecret(t, "0287082"),
		authoritySecret(t, "+87082"), authoritySecret(t, "28708 "), authoritySecret(t, "２８７０８２"),
		authoritySecret(t, "28708x"), authoritySecret(t, "287082.0"), authoritySecret(t, "000000")} {
		if step, err := VerifyTOTP(seed, invalid, now, -1); err != ErrTOTPRejected || step != 0 {
			t.Fatal("malformed or incorrect code accepted")
		}
	}
	for _, invalid := range []iamv1.Secret{{}, authoritySecret(t, "gezdgnbvgy3tqojqgezdgnbvgy3tqojq"),
		authoritySecret(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ="), authoritySecret(t, strings.Repeat("0", 32)),
		authoritySecret(t, strings.Repeat("A", 31)), authoritySecret(t, strings.Repeat("A", 33)),
		authoritySecret(t, "mx1."+strings.Repeat("A", 43)), authoritySecret(t, "mrc1."+strings.Repeat("A", 22))} {
		if step, err := VerifyTOTP(invalid, code, now, -1); err != ErrAuthorityUnavailable || step != 0 {
			t.Fatal("invalid seed state was normalized or accepted")
		}
	}
	for _, invalid := range []time.Time{{}, time.Unix(-1, 0).UTC(), time.Unix(253402300800, 0).UTC(),
		now.In(time.FixedZone("not-db-clock", 0)), now.Add(time.Nanosecond), time.Now()} {
		if step, err := VerifyTOTP(seed, code, invalid, -1); err != ErrAuthorityUnavailable || step != 0 {
			t.Fatal("non-authoritative or unsupported clock accepted")
		}
	}
	for _, invalid := range []int64{-2, 8446743360, 1<<63 - 1} {
		if step, err := VerifyTOTP(seed, code, now, invalid); err != ErrAuthorityUnavailable || step != 0 {
			t.Fatal("unknown/corrupt consumption state accepted")
		}
	}
	if step, err := VerifyTOTP(authoritySecret(t, strings.Repeat("A", 32)), code, now, -1); err != ErrTOTPRejected || step != 0 {
		t.Fatal("another well-formed seed verified")
	}
}

func TestTOTPSeedGenerationAndRedaction(t *testing.T) {
	random := []byte("12345678901234567890")
	seed, err := NewCredentialIssuer(bytes.NewReader(random)).IssueTOTPSeed()
	if err != nil || !bytes.Equal(seed.CopyBytes(), []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")) {
		t.Fatal("seed did not retain all 160 random bits in canonical Base32")
	}
	for _, issuer := range []*CredentialIssuer{nil, {}, NewCredentialIssuer(failingEntropy{}), NewCredentialIssuer(bytes.NewReader(random[:19]))} {
		if seed, err := issuer.IssueTOTPSeed(); err != ErrCredentialGeneration || seed.Present() {
			t.Fatal("failed entropy produced a seed or leaked its error")
		}
	}
	first, err := NewCredentialIssuer(nil).IssueTOTPSeed()
	if err != nil {
		t.Fatal("operating-system entropy unavailable")
	}
	second, err := NewCredentialIssuer(nil).IssueTOTPSeed()
	if err != nil || bytes.Equal(first.CopyBytes(), second.CopyBytes()) {
		t.Fatal("fresh seeds were not independent")
	}
	for _, secret := range []iamv1.Secret{seed, authoritySecret(t, "287082"), first, second} {
		if output, err := json.Marshal(secret); !errors.Is(err, iamv1.ErrSecretSerialization) || len(output) != 0 {
			t.Fatal("authentication material escaped through ordinary JSON")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			if strings.Contains(fmt.Sprintf(format, secret), string(secret.CopyBytes())) {
				t.Fatal("authentication material escaped through formatting")
			}
		}
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(first.CopyBytes()))
	defer clear(decoded)
	if err != nil || len(decoded) != 20 {
		t.Fatal("generated seed cannot be provisioned with the fixed profile")
	}
}

func totpSeedVector(t testing.TB) (TOTPSeedScope, []byte, SealedTOTPSeed) {
	t.Helper()
	scope := TOTPSeedScope{Installation: iamv1.TOTPWrappingScope{InstallationID: "install-a", BootstrapDigest: "sha256:" + strings.Repeat("a", 64)},
		AccountID: "account-a", UserID: "user-a", FactorID: "factor-a"}
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index)
	}
	nonce, err := hex.DecodeString("000102030405060708090a0b")
	if err != nil {
		t.Fatal("invalid synthetic nonce")
	}
	ciphertext, err := hex.DecodeString("7ecc6f281a39028cd07fc642c83e9d09dbeced6573cc883bb6e93cabb44e5adba303f69c")
	if err != nil {
		t.Fatal("invalid independent ciphertext")
	}
	return scope, key, SealedTOTPSeed{FormatVersion: 1, KeyID: "key-a", Nonce: nonce, Ciphertext: ciphertext}
}

func TestTOTPSeedProtectionIndependentVector(t *testing.T) {
	scope, wrapping, sealed := totpSeedVector(t)
	// Node crypto.hkdfSync + AES-256-GCM, synthetic KEK00..1f and seed
	// RFC4226's ASCII12345678901234567890. Production accepts no nonce selector.
	info, aad, err := iamv1.TOTPSeedContext(scope.Installation, scope.AccountID, scope.UserID, scope.FactorID, "key-a")
	if err != nil || bytes.Equal(info, aad) {
		t.Fatal("context domains were not distinct")
	}
	derived, err := hkdf.Key(sha256.New, wrapping, []byte(totpSeedKeySalt), string(info), 32)
	defer clear(derived)
	if err != nil || hex.EncodeToString(derived) != "251cb0a5f10fb7a40a7f31140a85f16d71f72872f04920bd9954e0baf11fd197" {
		t.Fatal("per-factor key differed from independent HKDF vector")
	}
	seed, err := OpenTOTPSeed(scope, "key-a", wrapping, sealed)
	if err != nil || !bytes.Equal(seed.CopyBytes(), []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")) {
		t.Fatal("independent envelope did not recover exact seed")
	}
	if step, err := VerifyTOTP(seed, authoritySecret(t, "287082"), time.Unix(59, 0).UTC(), -1); err != nil || step != 1 {
		t.Fatal("unwrapped seed could not verify real RFC code")
	}
	otherInfo, otherAAD, err := iamv1.AccessKeySecretContext(scope.Installation.InstallationID, scope.AccountID, scope.UserID, scope.FactorID, "key-a")
	if err != nil || bytes.Equal(info, otherInfo) || bytes.Equal(aad, otherAAD) {
		t.Fatal("AccessKey and TOTP shared wrapping contexts")
	}
}

func TestTOTPSeedProtectionRejectsSubstitution(t *testing.T) {
	scope, wrapping, original := totpSeedVector(t)
	for name, change := range map[string]func(*TOTPSeedScope, *SealedTOTPSeed){
		"installation": func(s *TOTPSeedScope, _ *SealedTOTPSeed) { s.Installation.InstallationID = "install-b" },
		"bootstrap": func(s *TOTPSeedScope, _ *SealedTOTPSeed) {
			s.Installation.BootstrapDigest = "sha256:" + strings.Repeat("b", 64)
		},
		"account":          func(s *TOTPSeedScope, _ *SealedTOTPSeed) { s.AccountID = "account-b" },
		"user":             func(s *TOTPSeedScope, _ *SealedTOTPSeed) { s.UserID = "user-b" },
		"factor":           func(s *TOTPSeedScope, _ *SealedTOTPSeed) { s.FactorID = "factor-b" },
		"format":           func(_ *TOTPSeedScope, s *SealedTOTPSeed) { s.FormatVersion = 2 },
		"reference":        func(_ *TOTPSeedScope, s *SealedTOTPSeed) { s.KeyID = "key-b" },
		"nonce":            func(_ *TOTPSeedScope, s *SealedTOTPSeed) { s.Nonce[0] ^= 1 },
		"ciphertext":       func(_ *TOTPSeedScope, s *SealedTOTPSeed) { s.Ciphertext[0] ^= 1 },
		"tag":              func(_ *TOTPSeedScope, s *SealedTOTPSeed) { s.Ciphertext[len(s.Ciphertext)-1] ^= 1 },
		"missing nonce":    func(_ *TOTPSeedScope, s *SealedTOTPSeed) { s.Nonce = nil },
		"long nonce":       func(_ *TOTPSeedScope, s *SealedTOTPSeed) { s.Nonce = append(s.Nonce, 0) },
		"short ciphertext": func(_ *TOTPSeedScope, s *SealedTOTPSeed) { s.Ciphertext = s.Ciphertext[:len(s.Ciphertext)-1] },
		"long ciphertext":  func(_ *TOTPSeedScope, s *SealedTOTPSeed) { s.Ciphertext = append(s.Ciphertext, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			candidateScope, candidate := scope, original
			candidate.Nonce = bytes.Clone(original.Nonce)
			candidate.Ciphertext = bytes.Clone(original.Ciphertext)
			change(&candidateScope, &candidate)
			if result, err := OpenTOTPSeed(candidateScope, "key-a", wrapping, candidate); err != ErrTOTPSeedProtection || result.Present() {
				t.Fatal("substituted envelope exposed seed or diagnostic")
			}
		})
	}
	// Changing both the requested key and the envelope's key reference still
	// fails, even if someone configured the same raw bytes under another ID.
	candidate := original
	candidate.KeyID = "key-b"
	if result, err := OpenTOTPSeed(scope, "key-b", wrapping, candidate); err != ErrTOTPSeedProtection || result.Present() {
		t.Fatal("key identity was not authenticated")
	}
	for _, key := range [][]byte{nil, wrapping[:31], append(bytes.Clone(wrapping), 0), bytes.Repeat([]byte{0x7f}, 32)} {
		if result, err := OpenTOTPSeed(scope, "key-a", key, original); err != ErrTOTPSeedProtection || result.Present() {
			t.Fatal("wrong wrapping material decrypted")
		}
	}
}

func TestTOTPSeedProtectionRoundTripRotationAndRedaction(t *testing.T) {
	scope, wrapping, _ := totpSeedVector(t)
	seed := authoritySecret(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	sealed, err := SealTOTPSeed(scope, "key-a", wrapping, seed)
	if err != nil || sealed.FormatVersion != 1 || len(sealed.Nonce) != 12 || len(sealed.Ciphertext) != 36 {
		t.Fatal("seed was not wrapped in exact format")
	}
	opened, err := OpenTOTPSeed(scope, "key-a", wrapping, sealed)
	if err != nil || !bytes.Equal(opened.CopyBytes(), seed.CopyBytes()) {
		t.Fatal("random-nonce envelope changed seed")
	}
	newKey := bytes.Repeat([]byte{0x55}, 32)
	rewrapped, err := SealTOTPSeed(scope, "key-b", newKey, opened)
	if err != nil {
		t.Fatal("new key could not wrap same immutable factor")
	}
	if result, err := OpenTOTPSeed(scope, "key-b", newKey, rewrapped); err != nil || !bytes.Equal(result.CopyBytes(), seed.CopyBytes()) {
		t.Fatal("rewrapped seed changed")
	}
	if result, err := OpenTOTPSeed(scope, "key-a", wrapping, sealed); err != nil || !bytes.Equal(result.CopyBytes(), seed.CopyBytes()) {
		t.Fatal("new key interfered with old envelope")
	}
	if result, err := OpenTOTPSeed(scope, "key-b", newKey, sealed); err != ErrTOTPSeedProtection || result.Present() {
		t.Fatal("new active key reinterpreted old ciphertext")
	}
	for _, value := range []any{sealed, &sealed} {
		if output, err := json.Marshal(value); !errors.Is(err, ErrTOTPSeedProtection) || len(output) != 0 {
			t.Fatal("private seed envelope serialized")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			output := fmt.Sprintf(format, value)
			if strings.Contains(output, string(seed.CopyBytes())) || strings.Contains(output, hex.EncodeToString(sealed.Ciphertext)) {
				t.Fatal("private envelope exposed by formatting")
			}
		}
	}
	var decoded SealedTOTPSeed
	if err := json.Unmarshal([]byte(`{"FormatVersion":1,"KeyID":"key-a"}`), &decoded); err != ErrTOTPSeedProtection || !reflect.DeepEqual(decoded, SealedTOTPSeed{}) {
		t.Fatal("ordinary decoder accepted private envelope")
	}
	for _, invalid := range []iamv1.Secret{{}, authoritySecret(t, "gezdgnbvgy3tqojqgezdgnbvgy3tqojq"), authoritySecret(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ="), authoritySecret(t, "mrc1.cXFxcXFxcXFxcXFxcXFxcQ")} {
		if got, err := SealTOTPSeed(scope, "key-a", wrapping, invalid); err != ErrTOTPSeedProtection || !reflect.DeepEqual(got, SealedTOTPSeed{}) {
			t.Fatal("non-TOTP material accepted")
		}
	}
	for _, invalid := range []string{"", " key-a", "key\n-a", strings.Repeat("a", 129)} {
		if got, err := SealTOTPSeed(scope, invalid, wrapping, seed); err != ErrTOTPSeedProtection || !reflect.DeepEqual(got, SealedTOTPSeed{}) {
			t.Fatal("invalid key identity accepted")
		}
	}
	for index := range 6 {
		candidate := scope
		switch index {
		case 0:
			candidate.Installation.InstallationID = ""
		case 1:
			candidate.Installation.BootstrapDigest = ""
		case 2:
			candidate.AccountID = ""
		case 3:
			candidate.UserID = ""
		case 4:
			candidate.FactorID = ""
		case 5:
			candidate.FactorID = "bad\x00id"
		}
		if got, err := SealTOTPSeed(candidate, "key-a", wrapping, seed); err != ErrTOTPSeedProtection || !reflect.DeepEqual(got, SealedTOTPSeed{}) {
			t.Fatal("invalid seed scope accepted")
		}
	}
	for _, invalid := range [][]byte{nil, wrapping[:31]} {
		if got, err := SealTOTPSeed(scope, "key-a", invalid, seed); err != ErrTOTPSeedProtection || !reflect.DeepEqual(got, SealedTOTPSeed{}) {
			t.Fatal("invalid wrapping key accepted")
		}
	}
	_, unchanged, _ := totpSeedVector(t)
	if !bytes.Equal(wrapping, unchanged) || !bytes.Equal(seed.CopyBytes(), []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")) {
		t.Fatal("caller-owned material was modified")
	}
}

func FuzzTOTPSeedEnvelope(f *testing.F) {
	scope, key, vector := totpSeedVector(f)
	f.Add(vector.Nonce, vector.Ciphertext, uint8(1), "key-a")
	f.Add([]byte{}, []byte{}, uint8(0), "")
	f.Fuzz(func(t *testing.T, nonce, ciphertext []byte, format uint8, keyID string) {
		seed, err := OpenTOTPSeed(scope, keyID, key, SealedTOTPSeed{FormatVersion: format, KeyID: keyID, Nonce: nonce, Ciphertext: ciphertext})
		if err != nil {
			if err != ErrTOTPSeedProtection || seed.Present() {
				t.Fatal("failed envelope exposed partial secret or error")
			}
			return
		}
		if !bytes.Equal(seed.CopyBytes(), []byte("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")) {
			t.Fatal("unmodified authentication tag accepted another plaintext")
		}
	})
}

func FuzzTOTPStrictInputs(f *testing.F) {
	f.Add("287082", int64(59), int64(-1))
	f.Add("911617", int64(910738*30), int64(910737))
	f.Add("099568", int64(253402300799), int64(-1))
	f.Add("２８７０８２", int64(59), int64(-1))
	f.Add("755224", int64(-1), int64(-2))
	seed, _ := iamv1.NewSecret("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
	f.Fuzz(func(t *testing.T, text string, unix, consumed int64) {
		code, _ := iamv1.NewSecret(text)
		step, err := VerifyTOTP(seed, code, time.Unix(unix, 0).UTC(), consumed)
		if err != nil {
			if step != 0 || err != ErrTOTPRejected && err != ErrAuthorityUnavailable {
				t.Fatal("rejection exposed a candidate or non-closed error")
			}
			return
		}
		if unix < 0 || unix > 253402300799 || consumed < -1 || consumed > 8446743359 ||
			step < 0 || step > 8446743359 || step <= consumed || step < unix/30-1 || step > unix/30+1 || len(text) != 6 {
			t.Fatal("accepted result exceeded authoritative scope/window")
		}
		for _, digit := range text {
			if digit < '0' || digit > '9' {
				t.Fatal("accepted code was not exactly ASCII digits")
			}
		}
		if next, err := VerifyTOTP(seed, code, time.Unix(unix, 0).UTC(), step); err != ErrTOTPRejected || next != 0 {
			t.Fatal("advancing the consumed watermark allowed the same code again")
		}
	})
}
