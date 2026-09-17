package identityaccess

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
)

// Purpose-limited process custody, not a generic key store. Installation owns
// file distribution. This process owns an independent immutable material copy.
type accessKeyWrapping struct {
	scope          iamv1.AccessKeyWrappingScope
	id, commitment string
	material       []byte
}

func (*accessKeyWrapping) String() string   { return "[REDACTED]" }
func (*accessKeyWrapping) GoString() string { return "identityaccess.accessKeyWrapping{[REDACTED]}" }

func newAccessKeyWrapping(document *iamv1.AccessKeyWrappingKeyring) (*accessKeyWrapping, error) {
	if document == nil {
		return nil, nil // Non-network local workflows do not acquire this authority.
	}
	if iamv1.ValidateAccessKeyWrappingKeyring(*document) != nil {
		return nil, ErrUnavailable
	}
	commitment, err := iamv1.AccessKeyWrappingKeyCommitment(*document, document.ActiveWrappingKeyID)
	if err != nil {
		return nil, ErrUnavailable
	}
	encoded := document.Keys[0].KeyMaterial.CopyBytes()
	defer clear(encoded)
	material := make([]byte, 32)
	if n, err := base64.RawURLEncoding.Strict().Decode(material, encoded); err != nil || n != 32 {
		clear(material)
		return nil, ErrUnavailable
	}
	return &accessKeyWrapping{scope: document.Scope, id: document.ActiveWrappingKeyID, commitment: commitment, material: material}, nil
}

func (service *Authority) checkAccessKeyCustody(ctx context.Context, tx Transaction) error {
	if service.accessKeys == nil {
		return ErrUnavailable
	}
	stored, err := tx.ReadAccessKeyCustody(ctx)
	if err != nil {
		return err
	}
	expected := service.accessKeys
	if stored.InstallationID != expected.scope.InstallationID ||
		subtle.ConstantTimeCompare([]byte(stored.BootstrapDigest), []byte(expected.scope.BootstrapDigest)) != 1 ||
		stored.Keys == nil || len(stored.Keys) > 1 {
		return ErrUnavailable
	}
	for _, key := range stored.Keys {
		if key.WrappingKeyID != expected.id || subtle.ConstantTimeCompare([]byte(key.MaterialCommitment), []byte(expected.commitment)) != 1 {
			return ErrUnavailable
		}
	}
	return nil
}

// Startup compares this independently with the actual bootstrap document; it
// never repairs, registers or generates material as a side effect of a check.
func (service *Authority) VerifyAccessKeyCustody(ctx context.Context) error {
	return service.withinTransaction(ctx, func(ctx context.Context, tx Transaction) error {
		return service.checkAccessKeyCustody(ctx, tx)
	})
}

func accessKeyRead(subject SessionCredential, decision iamv1.AuthorizationDecision, user iamv1.PrincipalID, key iamv1.AccessKeyID) AccessKeyRead {
	return AccessKeyRead{AccountID: subject.Subject.Organization.ID, ActorID: subject.Subject.Principal.ID,
		ActorSessionID: subject.Subject.Session.ID, UserID: user, KeyID: key, DecisionID: decision.ID}
}

func accessKeyCapabilities(subject SessionCredential, directory AccessKeyDirectory, key iamv1.AccessKey, now time.Time) ([]iamv1.ActionCapability, error) {
	var result []iamv1.ActionCapability
	for _, action := range []iamv1.Action{iamv1.ActionIAMAccessKeyRead, iamv1.ActionIAMAccessKeySetStatus, iamv1.ActionIAMAccessKeyDelete} {
		value, err := projectCapability(subject, action, iamv1.ResourceReference{Kind: iamv1.ResourceAccessKey, ID: string(key.ID)}, iamv1.AuthorizationResourceInstance, "", now)
		if err != nil {
			return nil, err
		}
		if action != iamv1.ActionIAMAccessKeyRead && key.ResourceVersion == 9007199254740991 {
			restrictCapability(&value, iamv1.CapabilityResourceVersionExhausted)
		}
		if action == iamv1.ActionIAMAccessKeyDelete && key.Status != iamv1.AccessKeyDisabled {
			restrictCapability(&value, iamv1.CapabilityTargetMustBeDisabled)
		}
		if action == iamv1.ActionIAMAccessKeySetStatus && key.Status == iamv1.AccessKeyDisabled {
			if directory.UserStatus != iamv1.PrincipalActive {
				restrictCapability(&value, iamv1.CapabilityTargetDisabled)
			}
			if directory.MustChangePassword {
				restrictCapability(&value, iamv1.CapabilityTargetCredentialChangeRequired)
			}
		}
		result = append(result, value)
	}
	return result, nil
}

func (service *Authority) ListAccessKeys(ctx context.Context, credential iamv1.Secret, user iamv1.PrincipalID, requestID string) (iamv1.AccessKeyList, error) {
	if iamv1.ValidateID("userId", string(user)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.AccessKeyList{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccessKeyList, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(user)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.AccessKeyList, error) {
			if err := service.checkAccessKeyCustody(ctx, tx); err != nil {
				return iamv1.AccessKeyList{}, err
			}
			directory, err := tx.ReadAccessKeys(ctx, accessKeyRead(subject, decision, user, ""))
			if err != nil {
				return iamv1.AccessKeyList{}, err
			}
			create, err := projectCapability(subject, iamv1.ActionIAMAccessKeyCreate, iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(user)}, iamv1.AuthorizationResourceInstance, "", now)
			if err != nil {
				return iamv1.AccessKeyList{}, err
			}
			if directory.UserStatus != iamv1.PrincipalActive {
				restrictCapability(&create, iamv1.CapabilityTargetDisabled)
			}
			if directory.MustChangePassword {
				restrictCapability(&create, iamv1.CapabilityTargetCredentialChangeRequired)
			}
			if len(directory.Keys) >= iamv1.MaxUserAccessKeys {
				restrictCapability(&create, iamv1.CapabilityAccessKeyLimitReached)
			}
			result := iamv1.AccessKeyList{APIVersion: iamv1.APIVersion, Kind: "AccessKeyList", AccountID: subject.Subject.Organization.ID,
				UserID: user, UserResourceVersion: directory.UserResourceVersion, Capabilities: []iamv1.ActionCapability{create}, Items: []iamv1.AccessKeyAccess{}}
			for _, key := range directory.Keys {
				capabilities, err := accessKeyCapabilities(subject, directory, key, now)
				if err != nil {
					return iamv1.AccessKeyList{}, err
				}
				result.Items = append(result.Items, iamv1.AccessKeyAccess{Key: key, Capabilities: capabilities})
			}
			if iamv1.ValidateAccessKeyList(result) != nil {
				return iamv1.AccessKeyList{}, ErrUnavailable
			}
			return result, nil
		})
}

func (service *Authority) GetAccessKey(ctx context.Context, credential iamv1.Secret, user iamv1.PrincipalID, key iamv1.AccessKeyID, requestID string) (iamv1.AccessKeyAccess, error) {
	if iamv1.ValidateID("userId", string(user)) != nil || iamv1.ValidateID("accessKeyId", string(key)) != nil || iamv1.ValidateID("requestId", requestID) != nil {
		return iamv1.AccessKeyAccess{}, ErrInvalidArgument
	}
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccessKeyRead, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccessKey, ID: string(key)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.AccessKeyAccess, error) {
			if err := service.checkAccessKeyCustody(ctx, tx); err != nil {
				return iamv1.AccessKeyAccess{}, err
			}
			directory, err := tx.ReadAccessKeys(ctx, accessKeyRead(subject, decision, user, key))
			if err != nil {
				return iamv1.AccessKeyAccess{}, err
			}
			if len(directory.Keys) != 1 {
				return iamv1.AccessKeyAccess{}, ErrUnavailable
			}
			capabilities, err := accessKeyCapabilities(subject, directory, directory.Keys[0], now)
			if err != nil {
				return iamv1.AccessKeyAccess{}, err
			}
			return iamv1.AccessKeyAccess{Key: directory.Keys[0], Capabilities: capabilities}, nil
		})
}

func (service *Authority) CreateAccessKey(ctx context.Context, credential iamv1.Secret, user iamv1.PrincipalID, request iamv1.CreateAccessKeyRequest) (iamv1.CreateAccessKeyResponse, error) {
	if iamv1.ValidateID("userId", string(user)) != nil || iamv1.ValidateCreateAccessKeyRequest(request) != nil {
		return iamv1.CreateAccessKeyResponse{}, ErrInvalidArgument
	}
	digest, err := digestSanitized("access-key.create", struct {
		UserID  iamv1.PrincipalID
		Request iamv1.CreateAccessKeyRequest
	}{user, request})
	if err != nil {
		return iamv1.CreateAccessKeyResponse{}, err
	}
	var keyID string
	var secret iamv1.Secret
	var sealed authority.SealedAccessKeySecret
	var sealedScope authority.AccessKeySecretScope
	defer func() { clear(sealed.Nonce); clear(sealed.Ciphertext) }()
	return withAccountAuthorization(service, ctx, credential, iamv1.ActionIAMAccessKeyCreate, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceUser, ID: string(user)}, request.RequestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (iamv1.CreateAccessKeyResponse, error) {
			if err := service.checkAccessKeyCustody(ctx, tx); err != nil {
				return iamv1.CreateAccessKeyResponse{}, err
			}
			for collision := 0; collision < 4; collision++ {
				if keyID == "" {
					keyID, err = service.config.NewID("access-key")
					if err != nil || iamv1.ValidateID("accessKeyId", keyID) != nil {
						return iamv1.CreateAccessKeyResponse{}, ErrUnavailable
					}
				}
				read := accessKeyRead(subject, decision, user, iamv1.AccessKeyID(keyID))
				reserved, err := tx.ReserveAccessKey(ctx, AccessKeyReservation{AccessKeyRead: read, ExpectedUserVersion: request.UserResourceVersion,
					InstallationID: service.accessKeys.scope.InstallationID, WrappingKeyID: service.accessKeys.id, MaterialCommitment: service.accessKeys.commitment,
					RequestID: request.RequestID, RequestDigest: digest})
				if err != nil {
					return iamv1.CreateAccessKeyResponse{}, err
				}
				if reserved.Outcome == "EQUAL_REPLAY" {
					return iamv1.CreateAccessKeyResponse{Outcome: "EQUAL_REPLAY", Key: *reserved.Key}, nil
				}
				if reserved.Outcome == "ID_COLLISION" {
					keyID, secret = "", iamv1.Secret{}
					clear(sealed.Nonce)
					clear(sealed.Ciphertext)
					sealed = authority.SealedAccessKeySecret{}
					continue
				}
				if reserved.Outcome != "RESERVED" {
					return iamv1.CreateAccessKeyResponse{}, ErrUnavailable
				}
				scope := authority.AccessKeySecretScope{InstallationID: service.accessKeys.scope.InstallationID, AccountID: read.AccountID, UserID: user, AccessKeyID: keyID}
				if sealed.FormatVersion == 0 {
					secret, err = service.credentials.IssueAccessKeySecret()
					if err != nil {
						return iamv1.CreateAccessKeyResponse{}, ErrUnavailable
					}
					sealed, err = authority.SealAccessKeySecret(scope, service.accessKeys.id, service.accessKeys.material, secret)
					if err != nil {
						return iamv1.CreateAccessKeyResponse{}, ErrUnavailable
					}
					sealedScope = scope
				} else if scope != sealedScope {
					return iamv1.CreateAccessKeyResponse{}, ErrUnavailable
				}
				event, err := service.newManagementEvent(subject, auditv1.ActionIAMAccessKeyCreated, auditv1.TargetAccessKey, keyID, decision.ID, digest, request.RequestID, now)
				if err != nil {
					return iamv1.CreateAccessKeyResponse{}, err
				}
				stored, err := tx.CompleteAccessKey(ctx, AccessKeyCompletion{AccessKeyRead: read, Material: sealed, AuditEvent: event})
				if err != nil {
					return iamv1.CreateAccessKeyResponse{}, err
				}
				response := iamv1.CreateAccessKeyResponse{Outcome: stored.Outcome, Key: *stored.Key}
				if stored.Outcome == "APPLIED" {
					response.Secret = secret
				}
				if iamv1.ValidateCreateAccessKeyResponse(response) != nil {
					return iamv1.CreateAccessKeyResponse{}, ErrUnavailable
				}
				return response, nil
			}
			return iamv1.CreateAccessKeyResponse{}, ErrUnavailable
		})
}

func (service *Authority) changeAccessKey(ctx context.Context, credential iamv1.Secret, user iamv1.PrincipalID, key iamv1.AccessKeyID,
	version uint64, status iamv1.AccessKeyStatus, requestID string) (AccessKeyMutationResult, error) {
	action, fact := iamv1.ActionIAMAccessKeySetStatus, auditv1.ActionIAMAccessKeyDisabled
	if status == iamv1.AccessKeyEnabled {
		fact = auditv1.ActionIAMAccessKeyEnabled
	}
	if status == "" {
		action, fact = iamv1.ActionIAMAccessKeyDelete, auditv1.ActionIAMAccessKeyDeleted
	}
	digest, err := digestSanitized(string(action), struct {
		UserID          iamv1.PrincipalID
		KeyID           iamv1.AccessKeyID
		ResourceVersion uint64
		Status          iamv1.AccessKeyStatus
		RequestID       string
	}{user, key, version, status, requestID})
	if err != nil {
		return AccessKeyMutationResult{}, err
	}
	return withAccountAuthorization(service, ctx, credential, action, iamv1.AuthorizationResourceInstance, "",
		iamv1.ResourceReference{Kind: iamv1.ResourceAccessKey, ID: string(key)}, requestID,
		func(ctx context.Context, tx Transaction, subject SessionCredential, decision iamv1.AuthorizationDecision, now time.Time) (AccessKeyMutationResult, error) {
			if err := service.checkAccessKeyCustody(ctx, tx); err != nil {
				return AccessKeyMutationResult{}, err
			}
			event, err := service.newManagementEvent(subject, fact, auditv1.TargetAccessKey, string(key), decision.ID, digest, requestID, now)
			if err != nil {
				return AccessKeyMutationResult{}, err
			}
			return tx.ChangeAccessKey(ctx, AccessKeyChange{AccessKeyRead: accessKeyRead(subject, decision, user, key),
				ExpectedVersion: version, Status: status, AuditEvent: event})
		})
}

func (service *Authority) SetAccessKeyStatus(ctx context.Context, credential iamv1.Secret, user iamv1.PrincipalID, key iamv1.AccessKeyID, request iamv1.SetAccessKeyStatusRequest) (iamv1.SetAccessKeyStatusResponse, error) {
	if iamv1.ValidateID("userId", string(user)) != nil || iamv1.ValidateID("accessKeyId", string(key)) != nil || iamv1.ValidateSetAccessKeyStatusRequest(request) != nil {
		return iamv1.SetAccessKeyStatusResponse{}, ErrInvalidArgument
	}
	result, err := service.changeAccessKey(ctx, credential, user, key, request.AccessKeyResourceVersion, request.Status, request.RequestID)
	if err != nil {
		return iamv1.SetAccessKeyStatusResponse{}, err
	}
	return iamv1.SetAccessKeyStatusResponse{Outcome: result.Outcome, Key: *result.Key}, nil
}

func (service *Authority) DeleteAccessKey(ctx context.Context, credential iamv1.Secret, user iamv1.PrincipalID, key iamv1.AccessKeyID, request iamv1.DeleteAccessKeyRequest) (iamv1.DeleteAccessKeyResponse, error) {
	if iamv1.ValidateID("userId", string(user)) != nil || iamv1.ValidateID("accessKeyId", string(key)) != nil || iamv1.ValidateDeleteAccessKeyRequest(request) != nil {
		return iamv1.DeleteAccessKeyResponse{}, ErrInvalidArgument
	}
	result, err := service.changeAccessKey(ctx, credential, user, key, request.AccessKeyResourceVersion, "", request.RequestID)
	if err != nil {
		return iamv1.DeleteAccessKeyResponse{}, err
	}
	return iamv1.DeleteAccessKeyResponse{Outcome: result.Outcome, Deletion: *result.Deletion}, nil
}
