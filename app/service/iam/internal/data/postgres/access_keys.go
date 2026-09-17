package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/authority"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func (value *transaction) LookupAccessKey(ctx context.Context, serviceDigest string, key iamv1.AccessKeyID, installation string, audience iamv1.ProductID) (identityaccess.AccessKeyCredential, bool, error) {
	if iamv1.ValidateDigest("serviceDigest", serviceDigest) != nil || iamv1.ValidateID("accessKeyId", string(key)) != nil ||
		iamv1.ValidateID("installationId", installation) != nil {
		return identityaccess.AccessKeyCredential{}, false, identityaccess.ErrInvalidArgument
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.lookup_access_key($1,$2,$3,$4)", serviceDigest, key, installation, audience).Scan(&encoded); err != nil {
		return identityaccess.AccessKeyCredential{}, false, mapDatabaseError("lookup IAM access key", err)
	}
	defer clear(encoded)
	if encoded == nil {
		return identityaccess.AccessKeyCredential{}, false, nil
	}
	var stored struct {
		Account                        iamv1.Account   `json:"account"`
		User                           iamv1.User      `json:"user"`
		Key                            iamv1.AccessKey `json:"key"`
		InstallationID                 string          `json:"installationId"`
		Policies                       json.RawMessage `json:"policies"`
		Boundary                       json.RawMessage `json:"boundary"`
		HasUnrevokedPlatformAttachment *bool           `json:"hasUnrevokedPlatformAttachment"`
		Material                       struct {
			FormatVersion      uint8  `json:"formatVersion"`
			WrappingKeyID      string `json:"wrappingKeyId"`
			MaterialCommitment string `json:"materialCommitment"`
			Nonce              string `json:"nonce"`
			Ciphertext         string `json:"ciphertext"`
		} `json:"material"`
	}
	if contractjson.DecodeObjectBytes(encoded, (maxStoredPolicyVersionBytes+4096)*(authority.MaxEvaluationPolicies+1)+8192, &stored) != nil {
		return identityaccess.AccessKeyCredential{}, false, identityaccess.ErrUnavailable
	}
	normalizeAccount(&stored.Account)
	normalizeUser(&stored.User)
	normalizeAccessKey(&stored.Key)
	if iamv1.ValidateAccount(stored.Account) != nil || iamv1.ValidateUser(stored.User) != nil || iamv1.ValidateAccessKey(stored.Key) != nil ||
		stored.InstallationID != installation || stored.Key.ID != key || stored.Key.AccountID != stored.Account.ID ||
		stored.User.AccountID != stored.Account.ID || stored.Key.UserID != stored.User.ID || stored.HasUnrevokedPlatformAttachment == nil ||
		stored.Material.FormatVersion != 1 || iamv1.ValidateID("wrappingKeyId", stored.Material.WrappingKeyID) != nil ||
		iamv1.ValidateDigest("materialCommitment", stored.Material.MaterialCommitment) != nil || len(stored.Material.Nonce) != 24 || len(stored.Material.Ciphertext) != 96 {
		return identityaccess.AccessKeyCredential{}, false, identityaccess.ErrUnavailable
	}
	result := identityaccess.AccessKeyCredential{MaterialCommitment: stored.Material.MaterialCommitment,
		Material: authority.SealedAccessKeySecret{FormatVersion: stored.Material.FormatVersion, WrappingKeyID: stored.Material.WrappingKeyID},
		Subject: authority.AccessKeyContext{InstallationID: installation, RootUserID: stored.Account.RootIdentity.PrincipalID,
			Key: stored.Key, HasUnrevokedPlatformAttachment: *stored.HasUnrevokedPlatformAttachment,
			Organization: iamv1.Organization{APIVersion: iamv1.APIVersion, Kind: "Organization", ID: stored.Account.ID,
				DisplayName: stored.Account.DisplayName, Status: stored.Account.Status, ResourceVersion: stored.Account.ResourceVersion,
				CreatedAt: stored.Account.CreatedAt, UpdatedAt: stored.Account.UpdatedAt},
			Principal: iamv1.Principal{APIVersion: iamv1.APIVersion, Kind: "Principal", ID: stored.User.ID, AccountID: stored.User.AccountID,
				Type: iamv1.PrincipalUser, LoginName: stored.User.LoginName, DisplayName: stored.User.DisplayName, Status: stored.User.Status,
				MustChangePassword: stored.User.MustChangePassword, ResourceVersion: stored.User.ResourceVersion, CreatedAt: stored.User.CreatedAt, UpdatedAt: stored.User.UpdatedAt}}}
	var err error
	result.Material.Nonce, err = hex.DecodeString(stored.Material.Nonce)
	if err != nil || hex.EncodeToString(result.Material.Nonce) != stored.Material.Nonce {
		return identityaccess.AccessKeyCredential{}, false, identityaccess.ErrUnavailable
	}
	result.Material.Ciphertext, err = hex.DecodeString(stored.Material.Ciphertext)
	if err != nil || hex.EncodeToString(result.Material.Ciphertext) != stored.Material.Ciphertext {
		return identityaccess.AccessKeyCredential{}, false, identityaccess.ErrUnavailable
	}
	result.Subject.Policies, err = value.decodeAttachedPolicies(ctx, stored.Policies)
	if err != nil {
		return identityaccess.AccessKeyCredential{}, false, err
	}
	result.Subject.Boundary, err = value.decodeUserBoundary(ctx, stored.Boundary, stored.Account.ID, stored.User.ID, stored.User.ResourceVersion)
	if err != nil {
		return identityaccess.AccessKeyCredential{}, false, err
	}
	return result, true, nil
}

func (value *transaction) ReadAccessKeyCustody(ctx context.Context) (identityaccess.AccessKeyCustody, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_access_key_custody()").Scan(&encoded); err != nil {
		return identityaccess.AccessKeyCustody{}, mapDatabaseError("read IAM access key custody", err)
	}
	defer clear(encoded)
	var result identityaccess.AccessKeyCustody
	if contractjson.DecodeObjectBytes(encoded, 4096, &result) != nil ||
		iamv1.ValidateID("installationId", result.InstallationID) != nil ||
		iamv1.ValidateDigest("bootstrapDigest", result.BootstrapDigest) != nil || result.Keys == nil || len(result.Keys) > 1 {
		return identityaccess.AccessKeyCustody{}, identityaccess.ErrUnavailable
	}
	for _, key := range result.Keys {
		if iamv1.ValidateID("wrappingKeyId", key.WrappingKeyID) != nil || iamv1.ValidateDigest("materialCommitment", key.MaterialCommitment) != nil {
			return identityaccess.AccessKeyCustody{}, identityaccess.ErrUnavailable
		}
	}
	return result, nil
}

func normalizeAccessKey(key *iamv1.AccessKey) {
	key.CreatedAt, key.UpdatedAt = key.CreatedAt.UTC(), key.UpdatedAt.UTC()
}

func (value *transaction) ReadAccessKeys(ctx context.Context, read identityaccess.AccessKeyRead) (identityaccess.AccessKeyDirectory, error) {
	query := "SELECT iam.list_access_keys($1,$2,$3,$4,$5)"
	args := []any{read.AccountID, read.ActorID, read.ActorSessionID, read.UserID, read.DecisionID}
	if read.KeyID != "" {
		query, args = "SELECT iam.read_access_key($1,$2,$3,$4,$5,$6)", []any{read.AccountID, read.ActorID, read.ActorSessionID, read.UserID, read.KeyID, read.DecisionID}
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, query, args...).Scan(&encoded); err != nil {
		return identityaccess.AccessKeyDirectory{}, mapAuthorizationDatabaseError("read IAM access keys", err)
	}
	defer clear(encoded)
	var result identityaccess.AccessKeyDirectory
	if contractjson.DecodeObjectBytes(encoded, 4096, &result) != nil || result.UserResourceVersion == 0 || result.UserResourceVersion > 9007199254740991 ||
		(result.UserStatus != iamv1.PrincipalActive && result.UserStatus != iamv1.PrincipalDisabled) || result.Keys == nil || len(result.Keys) > iamv1.MaxUserAccessKeys ||
		(read.KeyID != "" && len(result.Keys) != 1) {
		return identityaccess.AccessKeyDirectory{}, identityaccess.ErrUnavailable
	}
	for index := range result.Keys {
		key := &result.Keys[index]
		normalizeAccessKey(key)
		if iamv1.ValidateAccessKey(*key) != nil || key.AccountID != read.AccountID || key.UserID != read.UserID ||
			(read.KeyID != "" && key.ID != read.KeyID) || (index > 0 && result.Keys[index-1].ID >= key.ID) {
			return identityaccess.AccessKeyDirectory{}, identityaccess.ErrUnavailable
		}
	}
	return result, nil
}

func (value *transaction) ReserveAccessKey(ctx context.Context, mutation identityaccess.AccessKeyReservation) (identityaccess.AccessKeyReservationResult, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.reserve_access_key($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
		mutation.AccountID, mutation.ActorID, mutation.ActorSessionID, mutation.UserID, mutation.DecisionID, mutation.KeyID,
		mutation.ExpectedUserVersion, mutation.InstallationID, mutation.WrappingKeyID, mutation.MaterialCommitment, mutation.RequestID, mutation.RequestDigest).Scan(&encoded); err != nil {
		return identityaccess.AccessKeyReservationResult{}, mapAuthorizationDatabaseError("reserve IAM access key", err)
	}
	defer clear(encoded)
	var result identityaccess.AccessKeyReservationResult
	if contractjson.DecodeObjectBytes(encoded, 4096, &result) != nil {
		return identityaccess.AccessKeyReservationResult{}, identityaccess.ErrUnavailable
	}
	switch result.Outcome {
	case "ID_COLLISION", "RESERVED":
		if result.Key != nil {
			return identityaccess.AccessKeyReservationResult{}, identityaccess.ErrUnavailable
		}
	case "EQUAL_REPLAY":
		if result.Key == nil {
			return identityaccess.AccessKeyReservationResult{}, identityaccess.ErrUnavailable
		}
		normalizeAccessKey(result.Key)
		if iamv1.ValidateCreateAccessKeyResponse(iamv1.CreateAccessKeyResponse{Outcome: "EQUAL_REPLAY", Key: *result.Key}) != nil ||
			result.Key.AccountID != mutation.AccountID || result.Key.UserID != mutation.UserID {
			return identityaccess.AccessKeyReservationResult{}, identityaccess.ErrUnavailable
		}
	default:
		return identityaccess.AccessKeyReservationResult{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) CompleteAccessKey(ctx context.Context, mutation identityaccess.AccessKeyCompletion) (identityaccess.AccessKeyMutationResult, error) {
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return identityaccess.AccessKeyMutationResult{}, err
	}
	defer clear(event)
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.complete_access_key($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb)",
		mutation.AccountID, mutation.ActorID, mutation.ActorSessionID, mutation.UserID, mutation.DecisionID, mutation.KeyID,
		mutation.Material.FormatVersion, mutation.Material.Nonce, mutation.Material.Ciphertext, event).Scan(&encoded); err != nil {
		return identityaccess.AccessKeyMutationResult{}, mapAuthorizationDatabaseError("complete IAM access key", err)
	}
	result, err := decodeAccessKeyMutation(encoded, mutation.AccessKeyRead, false)
	if err != nil {
		return identityaccess.AccessKeyMutationResult{}, err
	}
	if result.Key.ResourceVersion != 1 || result.Key.Status != iamv1.AccessKeyEnabled {
		return identityaccess.AccessKeyMutationResult{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func (value *transaction) ChangeAccessKey(ctx context.Context, mutation identityaccess.AccessKeyChange) (identityaccess.AccessKeyMutationResult, error) {
	event, err := marshalManagementEvent(mutation.AuditEvent)
	if err != nil {
		return identityaccess.AccessKeyMutationResult{}, err
	}
	defer clear(event)
	var status any
	if mutation.Status != "" {
		status = string(mutation.Status)
	}
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.change_access_key($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)",
		mutation.AccountID, mutation.ActorID, mutation.ActorSessionID, mutation.UserID, mutation.DecisionID, mutation.KeyID,
		mutation.ExpectedVersion, status, event).Scan(&encoded); err != nil {
		return identityaccess.AccessKeyMutationResult{}, mapAuthorizationDatabaseError("change IAM access key", err)
	}
	result, err := decodeAccessKeyMutation(encoded, mutation.AccessKeyRead, mutation.Status == "")
	if err != nil {
		return identityaccess.AccessKeyMutationResult{}, err
	}
	if (result.Key != nil && (result.Key.ResourceVersion != mutation.ExpectedVersion+1 || result.Key.Status != mutation.Status)) ||
		(result.Deletion != nil && result.Deletion.ResourceVersion != mutation.ExpectedVersion+1) {
		return identityaccess.AccessKeyMutationResult{}, identityaccess.ErrUnavailable
	}
	return result, nil
}

func decodeAccessKeyMutation(encoded []byte, read identityaccess.AccessKeyRead, deletion bool) (identityaccess.AccessKeyMutationResult, error) {
	defer clear(encoded)
	var result identityaccess.AccessKeyMutationResult
	if contractjson.DecodeObjectBytes(encoded, 4096, &result) != nil || (result.Outcome != "APPLIED" && result.Outcome != "EQUAL_REPLAY") {
		return identityaccess.AccessKeyMutationResult{}, identityaccess.ErrUnavailable
	}
	if deletion {
		if result.Key != nil || result.Deletion == nil {
			return identityaccess.AccessKeyMutationResult{}, identityaccess.ErrUnavailable
		}
		result.Deletion.DeletedAt = result.Deletion.DeletedAt.UTC()
		if iamv1.ValidateAccessKeyDeletion(*result.Deletion) != nil || result.Deletion.AccountID != read.AccountID || result.Deletion.UserID != read.UserID || result.Deletion.ID != read.KeyID {
			return identityaccess.AccessKeyMutationResult{}, identityaccess.ErrUnavailable
		}
	} else {
		if result.Key == nil || result.Deletion != nil {
			return identityaccess.AccessKeyMutationResult{}, identityaccess.ErrUnavailable
		}
		normalizeAccessKey(result.Key)
		if iamv1.ValidateAccessKey(*result.Key) != nil || result.Key.AccountID != read.AccountID || result.Key.UserID != read.UserID || result.Key.ID != read.KeyID {
			return identityaccess.AccessKeyMutationResult{}, identityaccess.ErrUnavailable
		}
	}
	return result, nil
}
