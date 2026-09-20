package postgres

import (
	"context"
	"encoding/json"

	"github.com/xiak/matrix/api/contractjson"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/iam/internal/usecase/identityaccess"
)

func (value *transaction) RegisterTOTPKeyset(ctx context.Context, registration identityaccess.TOTPKeysetRegistration) error {
	encoded, err := json.Marshal(registration)
	if err != nil {
		return identityaccess.ErrUnavailable
	}
	_, err = value.tx.Exec(ctx, "SELECT iam.register_totp_keyset($1::jsonb)", string(encoded))
	return mapDatabaseError("register IAM TOTP custody", err)
}

func (value *transaction) ReadTOTPCustody(ctx context.Context) (identityaccess.TOTPCustody, error) {
	var encoded []byte
	if err := value.tx.QueryRow(ctx, "SELECT iam.read_totp_custody()").Scan(&encoded); err != nil {
		return identityaccess.TOTPCustody{}, mapDatabaseError("read IAM TOTP custody", err)
	}
	var stored struct {
		Keyset            *identityaccess.TOTPKeysetRegistration `json:"keyset"`
		HasAuthenticators *bool                                  `json:"hasAuthenticators"`
	}
	if contractjson.DecodeObjectBytes(encoded, iamv1.MaxTOTPKeyringBytes, &stored) != nil ||
		stored.Keyset == nil || stored.HasAuthenticators == nil ||
		stored.Keyset.Keys == nil || len(stored.Keyset.Keys) == 0 || len(stored.Keyset.Keys) > iamv1.MaxTOTPWrappingKeys {
		return identityaccess.TOTPCustody{}, identityaccess.ErrUnavailable
	}
	// The use case compares every registration field with validated material.
	return identityaccess.TOTPCustody{Keyset: *stored.Keyset, HasAuthenticators: *stored.HasAuthenticators}, nil
}
