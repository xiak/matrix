package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"

	paasv1 "matrix/api/paas/v1"
)

type CommandIdentityInput struct {
	OperationID     paasv1.OperationID
	Action          paasv1.AdapterAction
	RuntimeTargetID paasv1.ResourceID
	WorkloadID      paasv1.ResourceID
	ReleaseID       paasv1.ResourceID
}

func DeriveCommandID(input CommandIdentityInput) (paasv1.CommandID, error) {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("operationId", string(input.OperationID)),
		paasv1.ValidateID("runtimeTargetId", string(input.RuntimeTargetID)),
	)
	if input.Action == "" {
		problems = append(problems, errors.New("adapter action is required"))
	}
	if input.WorkloadID != "" {
		problems = append(problems, paasv1.ValidateID("workloadId", string(input.WorkloadID)))
	}
	if input.ReleaseID != "" {
		problems = append(problems, paasv1.ValidateID("releaseId", string(input.ReleaseID)))
	}
	if err := errors.Join(problems...); err != nil {
		return "", err
	}

	digest := sha256.New()
	writeIdentityPart(digest, string(input.OperationID))
	writeIdentityPart(digest, string(input.Action))
	writeIdentityPart(digest, string(input.RuntimeTargetID))
	writeIdentityPart(digest, string(input.WorkloadID))
	writeIdentityPart(digest, string(input.ReleaseID))
	return paasv1.CommandID("cmd_" + hex.EncodeToString(digest.Sum(nil))), nil
}

func DigestPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeIdentityPart(target hash.Hash, value string) {
	_, _ = fmt.Fprintf(target, "%d:", len(value))
	_, _ = target.Write([]byte(value))
}
