package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

type CommandIdentityInput struct {
	OperationID           paasv1.OperationID
	Action                paasv1.AdapterAction
	ExecutionTargetID     paasv1.ResourceID
	DeploymentID          paasv1.ResourceID
	ApplicationRevisionID paasv1.ResourceID
}

func DeriveCommandID(input CommandIdentityInput) (paasv1.CommandID, error) {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("operationId", string(input.OperationID)),
		paasv1.ValidateID("executionTargetId", string(input.ExecutionTargetID)),
	)
	if input.Action == "" {
		problems = append(problems, errors.New("adapter action is required"))
	}
	if input.DeploymentID != "" {
		problems = append(problems, paasv1.ValidateID("deploymentId", string(input.DeploymentID)))
	}
	if input.ApplicationRevisionID != "" {
		problems = append(
			problems,
			paasv1.ValidateID(
				"applicationRevisionId",
				string(input.ApplicationRevisionID),
			),
		)
	}
	if err := errors.Join(problems...); err != nil {
		return "", err
	}

	digest := sha256.New()
	writeIdentityPart(digest, string(input.OperationID))
	writeIdentityPart(digest, string(input.Action))
	writeIdentityPart(digest, string(input.ExecutionTargetID))
	writeIdentityPart(digest, string(input.DeploymentID))
	writeIdentityPart(digest, string(input.ApplicationRevisionID))
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
