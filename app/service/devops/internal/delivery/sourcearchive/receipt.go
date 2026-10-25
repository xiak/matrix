package sourcearchive

import (
	"errors"
	"strconv"
	"strings"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
)

// Receipt is non-secret evidence for one immutable source archive. A host path
// is deliberately absent so acquisition, execution, and persistence share
// identity without sharing filesystem layout.
type Receipt struct {
	TenantID          devopsv1.TenantID   `json:"tenantId"`
	RunID             devopsv1.ResourceID `json:"runId"`
	CommandID         string              `json:"commandId"`
	InputDigest       string              `json:"inputDigest"`
	HeadCommit        string              `json:"headCommit"`
	TrustedBaseCommit string              `json:"trustedBaseCommit"`
	MediaType         string              `json:"mediaType"`
	ArchiveDigest     string              `json:"archiveDigest"`
	ArchiveBytes      int64               `json:"archiveBytes"`
	ExpandedBytes     int64               `json:"expandedBytes"`
	PathCount         uint64              `json:"pathCount"`
}

// ValidateReceipt proves the portable archive identity and closed size/type
// limits without relying on an acquisition command or a filesystem layout.
func ValidateReceipt(value Receipt) error {
	var problems []error
	problems = append(problems,
		devopsv1.ValidateID("sourceArchive.tenantId", string(value.TenantID)),
		devopsv1.ValidatePipelineRunID("sourceArchive.runId", value.RunID),
		devopsv1.ValidateID("sourceArchive.commandId", value.CommandID),
		devopsv1.ValidateDigest("sourceArchive.inputDigest", value.InputDigest),
		devopsv1.ValidateDigest("sourceArchive.archiveDigest", value.ArchiveDigest),
	)
	prefix := string(value.RunID) + ":fetch:"
	attemptText := strings.TrimPrefix(value.CommandID, prefix)
	attempt, err := strconv.ParseUint(attemptText, 10, 64)
	if err != nil || attempt < 1 || attempt > 100 ||
		strconv.FormatUint(attempt, 10) != attemptText ||
		value.CommandID != prefix+attemptText {
		problems = append(problems, errors.New("source archive command identity is invalid"))
	}
	if !validGitObjectID(value.HeadCommit) ||
		!validGitObjectID(value.TrustedBaseCommit) {
		problems = append(problems, errors.New("source archive commit identity is invalid"))
	}
	if value.MediaType != MediaType || value.ArchiveBytes < 1 ||
		value.ArchiveBytes > MaximumArchiveBytes || value.ExpandedBytes < 0 ||
		value.ExpandedBytes > MaximumExpandedBytes || value.PathCount > MaximumPathCount {
		problems = append(problems, errors.New("source archive limits are invalid"))
	}
	if err := errors.Join(problems...); err != nil {
		return errors.Join(ErrInvalid, err)
	}
	return nil
}

func validGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') &&
			(character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
