package iamv1

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"

	"github.com/xiak/matrix/api/contractjson"
)

type ServiceRoleTemplateID string
type ServiceRoleTemplateStatus string

const (
	ServiceRoleTemplateActive           ServiceRoleTemplateStatus = "ACTIVE"
	ServiceRoleTemplateRetired          ServiceRoleTemplateStatus = "RETIRED"
	MaxServiceRoleTemplateWorkloadKinds                           = 16
	MaxServiceRoleTemplateListBytes     int64                     = 256 * 1024
)

// ServiceRoleTemplateSpec is release-owned authority, not a tenant policy or
// a caller-selected service name. The exact immutable PolicyVersion is the
// permission ceiling; workload kinds only constrain where that ceiling may be
// delegated and never grant those permissions by themselves.
type ServiceRoleTemplateSpec struct {
	Product                   ProductID              `json:"product"`
	ServicePurpose            ServicePurpose         `json:"servicePurpose"`
	PolicyVersion             PolicyVersionReference `json:"policyVersion"`
	WorkloadResourceKinds     []ResourceKind         `json:"workloadResourceKinds"`
	MaxSessionDurationSeconds uint32                 `json:"maxSessionDurationSeconds"`
}

// ServiceRoleTemplate is an immutable template version. Retirement prevents
// new bindings and sessions without rewriting an existing consent or history.
type ServiceRoleTemplate struct {
	APIVersion    string                    `json:"apiVersion"`
	Kind          string                    `json:"kind"`
	ID            ServiceRoleTemplateID     `json:"id"`
	Version       uint64                    `json:"version"`
	Spec          ServiceRoleTemplateSpec   `json:"spec"`
	ContentDigest string                    `json:"contentDigest"`
	Status        ServiceRoleTemplateStatus `json:"status"`
}

type ServiceRoleTemplateReference struct {
	ID            ServiceRoleTemplateID `json:"id"`
	Version       uint64                `json:"version"`
	ContentDigest string                `json:"contentDigest"`
}

type ServiceRoleTemplateList struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Items      []ServiceRoleTemplate `json:"items"`
}

func ValidateServiceRoleTemplateSpec(value ServiceRoleTemplateSpec) error {
	if !profileIdentifier(string(value.Product), false) || !knownServicePurpose(value.ServicePurpose) ||
		ValidateID("policyVersion.policyId", string(value.PolicyVersion.PolicyID)) != nil ||
		ValidateID("policyVersion.versionId", string(value.PolicyVersion.VersionID)) != nil ||
		ValidateDigest("policyVersion.contentDigest", value.PolicyVersion.ContentDigest) != nil ||
		value.WorkloadResourceKinds == nil || len(value.WorkloadResourceKinds) == 0 ||
		len(value.WorkloadResourceKinds) > MaxServiceRoleTemplateWorkloadKinds ||
		value.MaxSessionDurationSeconds < MinRoleSessionDurationSeconds ||
		value.MaxSessionDurationSeconds > MaxRoleSessionDurationSeconds {
		return errors.New("service role template spec is invalid")
	}
	seen := make(map[ResourceKind]bool, len(value.WorkloadResourceKinds))
	for _, kind := range value.WorkloadResourceKinds {
		if !profileIdentifier(string(kind), true) || seen[kind] {
			return errors.New("service role template workload kind is invalid")
		}
		seen[kind] = true
	}
	return nil
}

// CanonicalizeServiceRoleTemplateSpec is the single content encoder for a
// template version. Array order is not authority and is normalized before the
// domain-separated digest is calculated.
func CanonicalizeServiceRoleTemplateSpec(value ServiceRoleTemplateSpec) (string, string, error) {
	if ValidateServiceRoleTemplateSpec(value) != nil {
		return "", "", errors.New("service role template spec is invalid")
	}
	value.WorkloadResourceKinds = slices.Clone(value.WorkloadResourceKinds)
	slices.SortFunc(value.WorkloadResourceKinds, func(left, right ResourceKind) int {
		return cmp.Compare(left, right)
	})
	document, err := json.Marshal(value)
	if err != nil {
		return "", "", errors.New("service role template spec is invalid")
	}
	digest := sha256.Sum256(append([]byte("matrix.iam.service-role-template.v1\x00"), document...))
	return string(document), "sha256:" + hex.EncodeToString(digest[:]), nil
}

func ValidateServiceRoleTemplateReference(value ServiceRoleTemplateReference) error {
	return errors.Join(ValidateID("serviceRoleTemplate.id", string(value.ID)), validatePositiveVersion(value.Version),
		ValidateDigest("serviceRoleTemplate.contentDigest", value.ContentDigest))
}

func ValidateServiceRoleTemplate(value ServiceRoleTemplate) error {
	if value.APIVersion != APIVersion || value.Kind != "ServiceRoleTemplate" ||
		(value.Status != ServiceRoleTemplateActive && value.Status != ServiceRoleTemplateRetired) {
		return errors.New("service role template is invalid")
	}
	_, digest, err := CanonicalizeServiceRoleTemplateSpec(value.Spec)
	if err != nil || digest != value.ContentDigest {
		return errors.New("service role template is invalid")
	}
	return errors.Join(ValidateID("serviceRoleTemplate.id", string(value.ID)), validatePositiveVersion(value.Version))
}

func (value ServiceRoleTemplate) Reference() ServiceRoleTemplateReference {
	return ServiceRoleTemplateReference{ID: value.ID, Version: value.Version, ContentDigest: value.ContentDigest}
}

func ValidateServiceRoleTemplateList(value ServiceRoleTemplateList) error {
	if value.APIVersion != APIVersion || value.Kind != "ServiceRoleTemplateList" || value.Items == nil ||
		len(value.Items) > DirectoryPageSize {
		return errors.New("service role template list is invalid")
	}
	var previous ServiceRoleTemplateID
	for _, item := range value.Items {
		if ValidateServiceRoleTemplate(item) != nil || item.ID <= previous {
			return errors.New("service role template list item is invalid")
		}
		previous = item.ID
	}
	encoded, err := json.Marshal(value)
	if err != nil || int64(len(encoded)) > MaxServiceRoleTemplateListBytes {
		return errors.New("service role template list exceeds its byte budget")
	}
	return nil
}

func (value *ServiceRoleTemplateSpec) UnmarshalJSON(source []byte) error {
	type wire ServiceRoleTemplateSpec
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateServiceRoleTemplateSpec(ServiceRoleTemplateSpec(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ServiceRoleTemplateSpec(decoded)
	return nil
}

func (value *ServiceRoleTemplate) UnmarshalJSON(source []byte) error {
	type wire ServiceRoleTemplate
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateServiceRoleTemplate(ServiceRoleTemplate(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ServiceRoleTemplate(decoded)
	return nil
}

func (value *ServiceRoleTemplateReference) UnmarshalJSON(source []byte) error {
	type wire ServiceRoleTemplateReference
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxRequestBytes, &decoded) != nil ||
		ValidateServiceRoleTemplateReference(ServiceRoleTemplateReference(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ServiceRoleTemplateReference(decoded)
	return nil
}

func (value *ServiceRoleTemplateList) UnmarshalJSON(source []byte) error {
	type wire ServiceRoleTemplateList
	var decoded wire
	if contractjson.DecodeObjectBytes(source, MaxServiceRoleTemplateListBytes, &decoded) != nil ||
		ValidateServiceRoleTemplateList(ServiceRoleTemplateList(decoded)) != nil {
		return contractjson.ErrInvalidDocument
	}
	*value = ServiceRoleTemplateList(decoded)
	return nil
}
