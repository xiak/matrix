package sourcearchive

import devopsv1 "github.com/xiak/matrix/api/devops/v1"

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
