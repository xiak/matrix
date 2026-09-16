package iamv1

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/xiak/matrix/api/contractjson"
)

type RoleID string
type RoleTrustVersionID string

const (
	TrustPolicyLanguageVersion          = "1"
	MaxTrustPolicyStatements            = 8
	MaxTrustStatementPrincipals         = 32
	MaxTrustPolicyPrincipalVisits       = 256
	MaxTrustPolicyBytes           int64 = 16 * 1024
)

var ErrInvalidTrustPolicy = errors.New("IAM role trust policy is invalid")

// TrustPolicyDocument declares carrier admission, not identity permissions.
// Its owning Role supplies the account. Valid syntax proves neither that a
// USER exists in that account nor that the USER may assume or use the Role.
type TrustPolicyDocument struct {
	LanguageVersion string                 `json:"languageVersion"`
	Statements      []TrustPolicyStatement `json:"statements"`
}

type TrustPolicyStatement struct {
	SID        string           `json:"sid"`
	Effect     PolicyEffect     `json:"effect"`
	Principals []TrustPrincipal `json:"principals"`
}

// R1 accepts only the exact USER discriminator. Role, Group, service and
// provider carriers require their own admission contracts before acceptance.
type TrustPrincipal struct {
	Type PrincipalType `json:"type"`
	ID   PrincipalID   `json:"id"`
}

// RoleTrustVersion is immutable content bound to an account and one Role.
// A valid content digest is not evidence that it is selected or authorized.
type RoleTrustVersion struct {
	APIVersion    string              `json:"apiVersion"`
	Kind          string              `json:"kind"`
	ID            RoleTrustVersionID  `json:"id"`
	AccountID     AccountID           `json:"accountId"`
	RoleID        RoleID              `json:"roleId"`
	Document      TrustPolicyDocument `json:"document"`
	ContentDigest string              `json:"contentDigest"`
	CreatedAt     time.Time           `json:"createdAt"`
}

func (document *TrustPolicyDocument) UnmarshalJSON(source []byte) error {
	type wire TrustPolicyDocument
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxTrustPolicyBytes, &decoded) != nil ||
		ValidateTrustPolicyDocument(TrustPolicyDocument(decoded)) != nil {
		return ErrInvalidTrustPolicy
	}
	*document = TrustPolicyDocument(decoded)
	return nil
}

func DecodeTrustPolicyDocument(reader io.Reader) (TrustPolicyDocument, error) {
	var document TrustPolicyDocument
	if contractjson.DecodeObject(reader, MaxTrustPolicyBytes, &document) != nil {
		return TrustPolicyDocument{}, ErrInvalidTrustPolicy
	}
	return document, nil
}

func DecodeRoleTrustVersion(reader io.Reader) (RoleTrustVersion, error) {
	var version RoleTrustVersion
	if contractjson.DecodeObject(reader, MaxRequestBytes, &version) != nil || ValidateRoleTrustVersion(version) != nil {
		return RoleTrustVersion{}, ErrInvalidTrustPolicy
	}
	return version, nil
}

func ValidateTrustPolicyDocument(document TrustPolicyDocument) error {
	if document.LanguageVersion != TrustPolicyLanguageVersion || document.Statements == nil ||
		len(document.Statements) > MaxTrustPolicyStatements {
		return ErrInvalidTrustPolicy
	}
	sids := make(map[string]bool, len(document.Statements))
	visits := 0
	for _, statement := range document.Statements {
		if ValidateID("sid", statement.SID) != nil || sids[statement.SID] ||
			(statement.Effect != PolicyAllow && statement.Effect != PolicyDeny) ||
			len(statement.Principals) == 0 || len(statement.Principals) > MaxTrustStatementPrincipals {
			return ErrInvalidTrustPolicy
		}
		sids[statement.SID] = true
		visits += len(statement.Principals)
		if visits > MaxTrustPolicyPrincipalVisits {
			return ErrInvalidTrustPolicy
		}
		principals := make(map[PrincipalID]bool, len(statement.Principals))
		for _, principal := range statement.Principals {
			if principal.Type != PrincipalUser || ValidateID("principal.id", string(principal.ID)) != nil || principals[principal.ID] {
				return ErrInvalidTrustPolicy
			}
			principals[principal.ID] = true
		}
	}
	encoded, err := json.Marshal(document)
	if err != nil || int64(len(encoded)) > MaxTrustPolicyBytes {
		return ErrInvalidTrustPolicy
	}
	return nil
}

// CanonicalizeTrustPolicyDocument is the sole role-trust content encoder.
// Order is not authority. Normalize copies and preserve explicit empty [].
// Neither this digest nor identity-policy digests replace Audit encoding.
func CanonicalizeTrustPolicyDocument(document TrustPolicyDocument) (string, string, error) {
	if ValidateTrustPolicyDocument(document) != nil {
		return "", "", ErrInvalidTrustPolicy
	}
	statements := make([]TrustPolicyStatement, len(document.Statements))
	copy(statements, document.Statements)
	for index := range statements {
		statement := &statements[index]
		statement.Principals = slices.Clone(statement.Principals)
		slices.SortFunc(statement.Principals, func(left, right TrustPrincipal) int {
			return cmp.Compare(left.ID, right.ID)
		})
	}
	slices.SortFunc(statements, func(left, right TrustPolicyStatement) int { return cmp.Compare(left.SID, right.SID) })
	document.Statements = statements
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", "", ErrInvalidTrustPolicy
	}
	digest := sha256.Sum256(append([]byte("matrix.iam.role-trust.v1\x00"), encoded...))
	return string(encoded), "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ValidateRoleTrustVersion(value RoleTrustVersion) error {
	if value.APIVersion != APIVersion || value.Kind != "RoleTrustVersion" ||
		ValidateID("trustVersion.id", string(value.ID)) != nil ||
		ValidateID("trustVersion.accountId", string(value.AccountID)) != nil ||
		ValidateID("trustVersion.roleId", string(value.RoleID)) != nil ||
		validateTime("trustVersion.createdAt", value.CreatedAt) != nil {
		return ErrInvalidTrustPolicy
	}
	_, digest, err := CanonicalizeTrustPolicyDocument(value.Document)
	if err != nil || value.ContentDigest != digest {
		return ErrInvalidTrustPolicy
	}
	return nil
}
