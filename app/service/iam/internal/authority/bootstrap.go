package authority

import (
	"errors"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

var ErrBootstrapConflict = errors.New("IAM bootstrap conflicts with installed authority")

type BootstrapOutcome string

const (
	BootstrapApply       BootstrapOutcome = "APPLY"
	BootstrapEqualReplay BootstrapOutcome = "EQUAL_REPLAY"
)

type BootstrapReceipt struct {
	InstallationID string
	ContentDigest  string
}

func ClassifyBootstrap(
	existing *BootstrapReceipt,
	document iamv1.BootstrapDocument,
) (BootstrapOutcome, BootstrapReceipt, error) {
	digest, err := iamv1.BootstrapDigest(document)
	if err != nil {
		return "", BootstrapReceipt{}, err
	}
	receipt := BootstrapReceipt{
		InstallationID: document.InstallationID,
		ContentDigest:  digest,
	}
	if existing == nil {
		return BootstrapApply, receipt, nil
	}
	if iamv1.ValidateID("bootstrap.installationId", existing.InstallationID) != nil ||
		iamv1.ValidateDigest("bootstrap.contentDigest", existing.ContentDigest) != nil {
		return "", BootstrapReceipt{}, ErrBootstrapConflict
	}
	if *existing != receipt {
		return "", BootstrapReceipt{}, ErrBootstrapConflict
	}
	return BootstrapEqualReplay, receipt, nil
}
