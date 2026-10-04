package iamv1

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
)

type SecurityReportID string
type SecurityReportObservationState string
type SecurityReportCoverageState string

const (
	SecurityReportFormatVersion uint32 = 1
	MaxSecurityReportUsers             = 1000
	MaxSecurityReportAccessKeys        = MaxSecurityReportUsers * MaxUserAccessKeys
	MaxSecurityReportRows              = 1 + MaxSecurityReportUsers + MaxSecurityReportAccessKeys
	MaxSecurityReportCSVBytes          = 4 * 1024 * 1024
	MaxActiveSecurityReports           = 20
	SecurityReportRetention            = 7 * 24 * time.Hour

	SecurityReportObserved                      SecurityReportObservationState = "OBSERVED"
	SecurityReportNotObservedInRetainedIAMState SecurityReportObservationState = "NOT_OBSERVED_IN_RETAINED_IAM_STATE"
	SecurityReportUnknown                       SecurityReportObservationState = "UNKNOWN"

	SecurityReportCoverageComplete    SecurityReportCoverageState = "COMPLETE"
	SecurityReportCoverageNotIncluded SecurityReportCoverageState = "NOT_INCLUDED"
)

var securityReportCoverageSources = [...]struct {
	Source string
	State  SecurityReportCoverageState
}{
	{Source: "IAM_ACCOUNT", State: SecurityReportCoverageComplete},
	{Source: "IAM_USERS", State: SecurityReportCoverageComplete},
	{Source: "IAM_LOGIN_SESSIONS", State: SecurityReportCoverageComplete},
	{Source: "IAM_ACCESS_KEYS", State: SecurityReportCoverageComplete},
	{Source: "IAM_ROLE_ACTIVITY", State: SecurityReportCoverageNotIncluded},
	{Source: "PAAS_RESULTS", State: SecurityReportCoverageNotIncluded},
	{Source: "AUDIT_STATISTICS", State: SecurityReportCoverageNotIncluded},
	{Source: "NOTIFICATION_DELIVERY", State: SecurityReportCoverageNotIncluded},
	{Source: "EXTERNAL_RISK", State: SecurityReportCoverageNotIncluded},
}

type SecurityReportCoverage struct {
	Source string                      `json:"source"`
	State  SecurityReportCoverageState `json:"state"`
}

type SecurityReportTimeObservation struct {
	State      SecurityReportObservationState `json:"state"`
	ObservedAt *time.Time                     `json:"observedAt,omitempty"`
}

type SecurityReportMFAState struct {
	EnrollmentState string `json:"enrollmentState"`
	FactorRevision  uint64 `json:"factorRevision,omitempty"`
}

type SecurityReportUser struct {
	ID                 PrincipalID                   `json:"id"`
	LoginName          string                        `json:"loginName"`
	DisplayName        string                        `json:"displayName"`
	Status             PrincipalStatus               `json:"status"`
	Root               bool                          `json:"root"`
	MustChangePassword bool                          `json:"mustChangePassword,omitempty"`
	ResourceVersion    uint64                        `json:"resourceVersion"`
	CreatedAt          time.Time                     `json:"createdAt"`
	MFA                SecurityReportMFAState        `json:"mfa"`
	LastPasswordLogin  SecurityReportTimeObservation `json:"lastPasswordLogin"`
}

type SecurityReportAccessKey struct {
	ID                  AccessKeyID                        `json:"id"`
	UserID              PrincipalID                        `json:"userId"`
	Status              AccessKeyStatus                    `json:"status"`
	NetworkRestrictions AccessKeyNetworkRestrictions       `json:"networkRestrictions"`
	ResourceVersion     uint64                             `json:"resourceVersion"`
	CreatedAt           time.Time                          `json:"createdAt"`
	LastAuthorization   *AccessKeyAuthorizationObservation `json:"lastAuthorization,omitempty"`
}

type AccountSecurityReportMetadata struct {
	APIVersion       string           `json:"apiVersion"`
	Kind             string           `json:"kind"`
	ID               SecurityReportID `json:"id"`
	AccountID        AccountID        `json:"accountId"`
	FormatVersion    uint32           `json:"formatVersion"`
	ObservedAt       time.Time        `json:"observedAt"`
	ExpiresAt        time.Time        `json:"expiresAt"`
	DocumentDigest   string           `json:"documentDigest"`
	CSVContentDigest string           `json:"csvContentDigest"`
	UserCount        uint32           `json:"userCount"`
	AccessKeyCount   uint32           `json:"accessKeyCount"`
	RowCount         uint32           `json:"rowCount"`
	CSVBytes         uint32           `json:"csvBytes"`
}

type AccountSecurityReport struct {
	Metadata                       AccountSecurityReportMetadata `json:"metadata"`
	AccountSecuritySettingsVersion uint64                        `json:"accountSecuritySettingsVersion"`
	Coverage                       []SecurityReportCoverage      `json:"coverage"`
	Users                          []SecurityReportUser          `json:"users"`
	AccessKeys                     []SecurityReportAccessKey     `json:"accessKeys"`
}

type CreateAccountSecurityReportRequest struct {
	FormatVersion uint32 `json:"formatVersion"`
	RequestID     string `json:"requestId"`
}

type CreateAccountSecurityReportResponse struct {
	Outcome  string                        `json:"outcome"`
	Metadata AccountSecurityReportMetadata `json:"metadata"`
}

func ValidateSecurityReportCoverage(value []SecurityReportCoverage) error {
	if len(value) != len(securityReportCoverageSources) {
		return errors.New("security report coverage is incomplete")
	}
	for index, expected := range securityReportCoverageSources {
		if value[index].Source != expected.Source || value[index].State != expected.State {
			return errors.New("security report coverage is invalid")
		}
	}
	return nil
}

func ValidateSecurityReportTimeObservation(value SecurityReportTimeObservation) error {
	switch value.State {
	case SecurityReportObserved:
		if value.ObservedAt == nil || validateTime("securityReport.observedAt", *value.ObservedAt) != nil {
			return errors.New("security report observation is invalid")
		}
	case SecurityReportNotObservedInRetainedIAMState, SecurityReportUnknown:
		if value.ObservedAt != nil {
			return errors.New("security report observation has an invented time")
		}
	default:
		return errors.New("security report observation state is invalid")
	}
	return nil
}

func ValidateSecurityReportMFAState(value SecurityReportMFAState) error {
	switch value.EnrollmentState {
	case "NEVER_BOUND":
		if value.FactorRevision != 1 {
			return errors.New("never-bound MFA report state is invalid")
		}
	case "BOUND", "RECOVERY_REQUIRED", "REMOVED":
		if validatePositiveVersion(value.FactorRevision) != nil {
			return errors.New("MFA report revision is invalid")
		}
	case "UNKNOWN":
		if value.FactorRevision != 0 {
			return errors.New("unknown MFA report state has an invented revision")
		}
	default:
		return errors.New("MFA report state is invalid")
	}
	return nil
}

func ValidateSecurityReportUser(value SecurityReportUser, observedAt time.Time) error {
	if (value.Status != PrincipalActive && value.Status != PrincipalDisabled) ||
		ValidateID("securityReport.user.id", string(value.ID)) != nil || validateLoginName(value.LoginName) != nil ||
		validateText("securityReport.user.displayName", value.DisplayName, 1, 128) != nil ||
		validatePositiveVersion(value.ResourceVersion) != nil || validateTime("securityReport.user.createdAt", value.CreatedAt) != nil ||
		value.CreatedAt.After(observedAt) || ValidateSecurityReportMFAState(value.MFA) != nil ||
		ValidateSecurityReportTimeObservation(value.LastPasswordLogin) != nil ||
		(value.LastPasswordLogin.ObservedAt != nil && (value.LastPasswordLogin.ObservedAt.Before(value.CreatedAt) || value.LastPasswordLogin.ObservedAt.After(observedAt))) {
		return errors.New("security report user is invalid")
	}
	return nil
}

func ValidateSecurityReportAccessKey(value SecurityReportAccessKey, observedAt time.Time) error {
	if (value.Status != AccessKeyEnabled && value.Status != AccessKeyDisabled) ||
		ValidateID("securityReport.accessKey.id", string(value.ID)) != nil || ValidateID("securityReport.accessKey.userId", string(value.UserID)) != nil ||
		ValidateAccessKeyNetworkRestrictions(value.NetworkRestrictions) != nil || validatePositiveVersion(value.ResourceVersion) != nil ||
		validateTime("securityReport.accessKey.createdAt", value.CreatedAt) != nil || value.CreatedAt.After(observedAt) {
		return errors.New("security report access key is invalid")
	}
	if value.LastAuthorization != nil {
		observation := AccessKeyUsageSummary{ObservedAt: observedAt, LastAuthorization: value.LastAuthorization}
		if ValidateAccessKeyUsageSummary(observation) != nil || value.LastAuthorization.EvaluatedAt.Before(value.CreatedAt) {
			return errors.New("security report access key observation is invalid")
		}
	}
	return nil
}

func ValidateAccountSecurityReportMetadata(value AccountSecurityReportMetadata) error {
	if value.APIVersion != APIVersion || value.Kind != "AccountSecurityReportMetadata" || value.FormatVersion != SecurityReportFormatVersion ||
		ValidateID("securityReport.id", string(value.ID)) != nil || ValidateID("securityReport.accountId", string(value.AccountID)) != nil ||
		validateTime("securityReport.observedAt", value.ObservedAt) != nil || validateTime("securityReport.expiresAt", value.ExpiresAt) != nil ||
		!value.ExpiresAt.Equal(value.ObservedAt.Add(SecurityReportRetention)) ||
		ValidateDigest("securityReport.documentDigest", value.DocumentDigest) != nil || ValidateDigest("securityReport.csvContentDigest", value.CSVContentDigest) != nil ||
		value.UserCount > MaxSecurityReportUsers || value.AccessKeyCount > MaxSecurityReportAccessKeys ||
		value.RowCount != 1+value.UserCount+value.AccessKeyCount || value.RowCount > MaxSecurityReportRows ||
		value.CSVBytes == 0 || value.CSVBytes > MaxSecurityReportCSVBytes {
		return errors.New("security report metadata is invalid")
	}
	return nil
}

func ValidateAccountSecurityReport(value AccountSecurityReport) error {
	if err := validateAccountSecurityReportWithoutCommitments(value); err != nil {
		return err
	}
	document, digest, err := CanonicalizeAccountSecurityReportDocument(value)
	if err != nil || document == "" || digest != value.Metadata.DocumentDigest {
		return errors.New("account security report document commitment is invalid")
	}
	csvDocument, csvDigest, err := EncodeAccountSecurityReportCSV(value)
	if err != nil || csvDigest != value.Metadata.CSVContentDigest || len(csvDocument) != int(value.Metadata.CSVBytes) {
		return errors.New("account security report CSV commitment is invalid")
	}
	return nil
}

func validateAccountSecurityReportContent(value AccountSecurityReport) error {
	metadata := value.Metadata
	metadata.DocumentDigest = "sha256:" + strings.Repeat("0", 64)
	metadata.CSVContentDigest = "sha256:" + strings.Repeat("0", 64)
	metadata.CSVBytes = 1
	value.Metadata = metadata
	if err := validateAccountSecurityReportWithoutCommitments(value); err != nil {
		return err
	}
	return nil
}

func validateAccountSecurityReportWithoutCommitments(value AccountSecurityReport) error {
	if ValidateAccountSecurityReportMetadata(value.Metadata) != nil || validatePositiveVersion(value.AccountSecuritySettingsVersion) != nil ||
		ValidateSecurityReportCoverage(value.Coverage) != nil || value.Users == nil || value.AccessKeys == nil ||
		len(value.Users) != int(value.Metadata.UserCount) || len(value.AccessKeys) != int(value.Metadata.AccessKeyCount) {
		return errors.New("account security report is invalid")
	}
	rootCount := 0
	userIDs := make(map[PrincipalID]struct{}, len(value.Users))
	var previous PrincipalID
	for _, user := range value.Users {
		if ValidateSecurityReportUser(user, value.Metadata.ObservedAt) != nil || user.ID <= previous {
			return errors.New("account security report users are invalid")
		}
		if user.Root {
			rootCount++
		}
		userIDs[user.ID] = struct{}{}
		previous = user.ID
	}
	if rootCount != 1 {
		return errors.New("account security report lacks its one root USER")
	}
	var previousKey AccessKeyID
	for _, key := range value.AccessKeys {
		_, userExists := userIDs[key.UserID]
		if !userExists || ValidateSecurityReportAccessKey(key, value.Metadata.ObservedAt) != nil || key.ID <= previousKey {
			return errors.New("account security report access keys are invalid")
		}
		previousKey = key.ID
	}
	return nil
}

func CanonicalizeAccountSecurityReportDocument(value AccountSecurityReport) (string, string, error) {
	if err := validateAccountSecurityReportContent(value); err != nil {
		return "", "", err
	}
	wire := struct {
		AccountID                      AccountID                 `json:"accountId"`
		FormatVersion                  uint32                    `json:"formatVersion"`
		ObservedAt                     time.Time                 `json:"observedAt"`
		ExpiresAt                      time.Time                 `json:"expiresAt"`
		AccountSecuritySettingsVersion uint64                    `json:"accountSecuritySettingsVersion"`
		Coverage                       []SecurityReportCoverage  `json:"coverage"`
		Users                          []SecurityReportUser      `json:"users"`
		AccessKeys                     []SecurityReportAccessKey `json:"accessKeys"`
	}{
		AccountID: value.Metadata.AccountID, FormatVersion: value.Metadata.FormatVersion,
		ObservedAt: value.Metadata.ObservedAt, ExpiresAt: value.Metadata.ExpiresAt,
		AccountSecuritySettingsVersion: value.AccountSecuritySettingsVersion,
		Coverage:                       value.Coverage, Users: value.Users, AccessKeys: value.AccessKeys,
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > MaxSecurityReportCSVBytes {
		return "", "", errors.New("account security report document is invalid")
	}
	digest := sha256.Sum256(encoded)
	return string(encoded), "sha256:" + hex.EncodeToString(digest[:]), nil
}

var accountSecurityReportCSVColumns = []string{
	"resource_type", "resource_id", "user_id", "login_name", "status", "root", "must_change_password",
	"resource_version", "created_at", "mfa_state", "factor_revision", "observation_state", "observed_at",
	"allowed_source_cidrs", "authorization_allowed", "authorization_product", "authorization_action", "authorization_source_ip",
}

func EncodeAccountSecurityReportCSV(value AccountSecurityReport) ([]byte, string, error) {
	if err := validateAccountSecurityReportContent(value); err != nil {
		return nil, "", err
	}
	var output bytes.Buffer
	writer := csv.NewWriter(&output)
	writer.UseCRLF = false
	if err := writer.Write(accountSecurityReportCSVColumns); err != nil {
		return nil, "", err
	}
	write := func(fields []string) error {
		for _, field := range fields {
			if strings.ContainsAny(field, "\r\n") || strings.HasPrefix(field, "=") || strings.HasPrefix(field, "+") ||
				strings.HasPrefix(field, "-") || strings.HasPrefix(field, "@") || strings.HasPrefix(field, "\t") {
				return errors.New("security report CSV field is unsafe")
			}
		}
		return writer.Write(fields)
	}
	empty := func() []string { return make([]string, len(accountSecurityReportCSVColumns)) }
	account := empty()
	account[0], account[1], account[7], account[8] = "ACCOUNT", string(value.Metadata.AccountID), strconv.FormatUint(value.AccountSecuritySettingsVersion, 10), value.Metadata.ObservedAt.Format(time.RFC3339Nano)
	if err := write(account); err != nil {
		return nil, "", err
	}
	for _, user := range value.Users {
		row := empty()
		row[0], row[1], row[2], row[3], row[4] = "USER", string(user.ID), string(user.ID), user.LoginName, string(user.Status)
		row[5], row[6], row[7], row[8] = strconv.FormatBool(user.Root), strconv.FormatBool(user.MustChangePassword), strconv.FormatUint(user.ResourceVersion, 10), user.CreatedAt.Format(time.RFC3339Nano)
		row[9] = user.MFA.EnrollmentState
		if user.MFA.FactorRevision != 0 {
			row[10] = strconv.FormatUint(user.MFA.FactorRevision, 10)
		}
		row[11] = string(user.LastPasswordLogin.State)
		if user.LastPasswordLogin.ObservedAt != nil {
			row[12] = user.LastPasswordLogin.ObservedAt.Format(time.RFC3339Nano)
		}
		if err := write(row); err != nil {
			return nil, "", err
		}
	}
	for _, key := range value.AccessKeys {
		row := empty()
		row[0], row[1], row[2], row[4] = "ACCESS_KEY", string(key.ID), string(key.UserID), string(key.Status)
		row[7], row[8], row[11], row[13] = strconv.FormatUint(key.ResourceVersion, 10), key.CreatedAt.Format(time.RFC3339Nano), string(SecurityReportNotObservedInRetainedIAMState), strings.Join(key.NetworkRestrictions.AllowedSourceCIDRs, "|")
		if key.LastAuthorization != nil {
			row[11], row[12] = string(SecurityReportObserved), key.LastAuthorization.EvaluatedAt.Format(time.RFC3339Nano)
			row[14], row[15], row[16], row[17] = strconv.FormatBool(key.LastAuthorization.Allowed), string(key.LastAuthorization.Product), string(key.LastAuthorization.Action), key.LastAuthorization.SourceIP
		}
		if err := write(row); err != nil {
			return nil, "", err
		}
	}
	writer.Flush()
	if writer.Error() != nil || output.Len() == 0 || output.Len() > MaxSecurityReportCSVBytes {
		return nil, "", errors.New("security report CSV exceeds its contract")
	}
	encoded := output.Bytes()
	digest := sha256.Sum256(encoded)
	return slices.Clone(encoded), "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ValidateAccountSecurityReportCSV(metadata AccountSecurityReportMetadata, document []byte) error {
	if ValidateAccountSecurityReportMetadata(metadata) != nil || len(document) != int(metadata.CSVBytes) || len(document) == 0 || len(document) > MaxSecurityReportCSVBytes {
		return errors.New("security report CSV metadata is invalid")
	}
	digest := sha256.Sum256(document)
	if "sha256:"+hex.EncodeToString(digest[:]) != metadata.CSVContentDigest {
		return errors.New("security report CSV digest is invalid")
	}
	return nil
}

func ValidateCreateAccountSecurityReportRequest(value CreateAccountSecurityReportRequest) error {
	if value.FormatVersion != SecurityReportFormatVersion || ValidateID("requestId", value.RequestID) != nil {
		return errors.New("security report creation request is invalid")
	}
	return nil
}

func ValidateCreateAccountSecurityReportResponse(value CreateAccountSecurityReportResponse) error {
	if (value.Outcome != "APPLIED" && value.Outcome != "EQUAL_REPLAY") || ValidateAccountSecurityReportMetadata(value.Metadata) != nil {
		return errors.New("security report creation response is invalid")
	}
	return nil
}

func SecurityReportCoverageContract() []SecurityReportCoverage {
	result := make([]SecurityReportCoverage, len(securityReportCoverageSources))
	for index, source := range securityReportCoverageSources {
		result[index] = SecurityReportCoverage{Source: source.Source, State: source.State}
	}
	return slices.Clone(result)
}
