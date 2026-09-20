package identityaccess

import (
	"context"
	"crypto/subtle"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

// These projections contain no material and are not a public API, backup
// custody lease, recovery qualification, or permission to retire a key.
type TOTPKeyCommitment struct {
	KeyID              string `json:"keyId"`
	FormatVersion      uint8  `json:"formatVersion"`
	MaterialCommitment string `json:"materialCommitment"`
}

type TOTPKeysetRegistration struct {
	Scope          iamv1.TOTPWrappingScope `json:"scope"`
	KeysetRevision uint64                  `json:"keysetRevision"`
	ActiveKeyID    string                  `json:"activeKeyId"`
	ContentDigest  string                  `json:"contentDigest"`
	Keys           []TOTPKeyCommitment     `json:"keys"`
}

type TOTPCustody struct {
	Keyset                        TOTPKeysetRegistration `json:"keyset"`
	HasUnrecognizedAuthenticators bool                   `json:"hasUnrecognizedAuthenticators"`
}

func newTOTPRegistration(document *iamv1.TOTPKeyring) (*TOTPKeysetRegistration, error) {
	// Offline password recovery does not acquire TOTP material or the ability
	// to authenticate users. Actual authentication requires it separately.
	if document == nil {
		return nil, nil
	}
	if iamv1.ValidateTOTPKeyring(*document) != nil {
		return nil, ErrInvalidArgument
	}
	digest, err := iamv1.TOTPKeysetDigest(*document)
	if err != nil {
		return nil, ErrInvalidArgument
	}
	registration := TOTPKeysetRegistration{Scope: document.Scope, KeysetRevision: document.KeysetRevision,
		ActiveKeyID: document.ActiveKeyID, ContentDigest: digest, Keys: make([]TOTPKeyCommitment, len(document.Keys))}
	for i, key := range document.Keys {
		commitment, err := iamv1.TOTPKeyMaterialCommitment(*document, key.KeyID)
		if err != nil {
			return nil, ErrInvalidArgument
		}
		registration.Keys[i] = TOTPKeyCommitment{KeyID: key.KeyID, FormatVersion: key.FormatVersion, MaterialCommitment: commitment}
	}
	return &registration, nil
}

// RegisterTOTPKeyset is called only by the network process after bootstrap.
// No HTTP handler or worker can select a document or register new material.
// An exact replay is read-only; registration cannot restore authentication.
func (service *Authority) RegisterTOTPKeyset(ctx context.Context) error {
	if service == nil || service.totp == nil {
		return ErrUnavailable
	}
	return service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.RegisterTOTPKeyset(ctx, *service.totp); err != nil {
			return err
		}
		return service.checkTOTPCustody(ctx, tx)
	})
}

func (service *Authority) checkTOTPCustody(ctx context.Context, tx Transaction) error {
	if service == nil || service.totp == nil {
		return ErrUnavailable
	}
	actual, err := tx.ReadTOTPCustody(ctx)
	if err != nil {
		return err
	}
	expected := *service.totp
	stored := actual.Keyset
	if stored.Scope != expected.Scope || stored.KeysetRevision != expected.KeysetRevision ||
		stored.ActiveKeyID != expected.ActiveKeyID || len(stored.Keys) != len(expected.Keys) ||
		subtle.ConstantTimeCompare([]byte(stored.ContentDigest), []byte(expected.ContentDigest)) != 1 {
		return ErrUnavailable
	}
	for i, key := range stored.Keys {
		if key.KeyID != expected.Keys[i].KeyID || key.FormatVersion != expected.Keys[i].FormatVersion ||
			subtle.ConstantTimeCompare([]byte(key.MaterialCommitment), []byte(expected.Keys[i].MaterialCommitment)) != 1 {
			return ErrUnavailable
		}
	}
	// Known factor lifecycles are checked by each User/Session transaction.
	// Unrecognized retained history or corrupt custody can never be treated as
	// optional MFA or a password-only fallback, including after restart.
	if actual.HasUnrecognizedAuthenticators {
		return ErrUnavailable
	}
	return nil
}
