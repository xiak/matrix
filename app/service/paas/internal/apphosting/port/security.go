package port

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

var (
	ErrUnauthenticated          = errors.New("IAM authentication failed")
	ErrPermissionDenied         = errors.New("IAM authorization denied")
	ErrAuthorizationReplay      = errors.New("IAM signed request was already consumed")
	ErrAuthorizationUnavailable = errors.New("IAM authorization unavailable")
)

const (
	AuthorizeApplicationCreate           = iamv1.ActionPaaSApplicationCreate
	AuthorizeApplicationRead             = iamv1.ActionPaaSApplicationRead
	AuthorizeApplicationLabelSet         = iamv1.ActionPaaSApplicationLabelSet
	AuthorizeApplicationLabelDelete      = iamv1.ActionPaaSApplicationLabelDelete
	AuthorizeConfigurationCreate         = iamv1.ActionPaaSConfigurationCreate
	AuthorizeConfigurationRead           = iamv1.ActionPaaSConfigurationRead
	AuthorizeConfigurationRevisionCreate = iamv1.ActionPaaSConfigurationRevisionCreate
	AuthorizeConfigurationRevisionRead   = iamv1.ActionPaaSConfigurationRevisionRead
	AuthorizeApplicationRevisionCreate   = iamv1.ActionPaaSApplicationRevisionCreate
	AuthorizeApplicationRevisionRead     = iamv1.ActionPaaSApplicationRevisionRead
	AuthorizeDeploymentCreate            = iamv1.ActionPaaSDeploymentCreate
	AuthorizeDeploymentUpdate            = iamv1.ActionPaaSDeploymentUpdate
	AuthorizeDeploymentStop              = iamv1.ActionPaaSDeploymentStop
	AuthorizeDeploymentRollback          = iamv1.ActionPaaSDeploymentRollback
	AuthorizeDeploymentRead              = iamv1.ActionPaaSDeploymentRead
	AuthorizeOperationRead               = iamv1.ActionPaaSOperationRead
)

const (
	ResourceApplication           = "Application"
	ResourceConfiguration         = "Configuration"
	ResourceConfigurationRevision = "ConfigurationRevision"
	ResourceApplicationRevision   = "ApplicationRevision"
	ResourceDeployment            = "Deployment"
	ResourceOperation             = "Operation"
)

// AuthorizationRequest carries transient credential material to the IAM
// boundary. Credential must never be persisted, logged, or copied into Audit.
type AuthorizationRequest struct {
	Credential      string
	Action          iamv1.Action
	Resource        paasv1.ResourceRef
	ResourceMode    iamv1.AuthorizationResourceMode
	CollectionUsage iamv1.AuthorizationCollectionUsage
	SourceIP        string
	RequestLabels   map[string]string
	ResourceLabels  map[string]string
	RequestID       string
}

// AccessKeyAuthorizationRequest carries the exact external request extracted
// by the product HTTP boundary. It is neither a bearer credential nor a
// reusable permit and must be sent to IAM at most once.
type AccessKeyAuthorizationRequest struct {
	Action          iamv1.Action
	Resource        paasv1.ResourceRef
	ResourceMode    iamv1.AuthorizationResourceMode
	CollectionUsage iamv1.AuthorizationCollectionUsage
	SourceIP        string
	RequestLabels   map[string]string
	ResourceLabels  map[string]string
	RequestID       string
	SignedRequest   iamv1.AccessKeySignedRequest
}

// Authorization is the trusted IAM result consumed by apphosting. Tenant and
// subject are never reconstructed from HTTP headers or request documents.
type Authorization struct {
	TenantID     paasv1.TenantID
	Subject      paasv1.SubjectRef
	DecisionID   string
	RequestID    string
	RequestTags  []iamv1.AuthorizationTag
	ResourceTags []iamv1.AuthorizationTag
	AuditID      string
	TraceParent  string
}

// SubjectResolutionRequest carries only the transient bearer. The adapter
// supplies the exact current PaaS Profile; no caller-controlled Account,
// Subject, Action, resource or tag selector crosses this boundary.
type SubjectResolutionRequest struct {
	Credential string
}

// AuthorizationSubjectContext is sufficient to open an Account-scoped
// resource lookup. It is not an authorization result and must never be used
// to return or mutate a resource without a subsequent decision.
type AuthorizationSubjectContext struct {
	TenantID paasv1.TenantID
	Subject  paasv1.SubjectRef
	Profile  iamv1.AuthorizationProfileReference
}

// Authorizer is implemented by the independently deployable IAM boundary.
// Implementations must fail closed when identity or current policy cannot be
// established.
type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) (Authorization, error)
	ResolveSubject(context.Context, SubjectResolutionRequest) (AuthorizationSubjectContext, error)
}

// AccessKeyAuthorizer is a separate capability so products cannot silently
// reinterpret a signed request as a login bearer.
type AccessKeyAuthorizer interface {
	ResolveAccessKeySubject(context.Context, iamv1.AccessKeySignedRequest) (AuthorizationSubjectContext, error)
	AuthorizeAccessKey(context.Context, AccessKeyAuthorizationRequest) (Authorization, error)
}

func ValidateAuthorizationRequest(value AuthorizationRequest) error {
	var problems []error
	if value.Credential == "" || strings.TrimSpace(value.Credential) != value.Credential ||
		len([]byte(value.Credential)) > 16*1024 {
		problems = append(problems, errors.New("authorization credential is invalid"))
	}
	_, requestErr := NewIAMAuthorizationRequest(value)
	problems = append(problems, requestErr)
	return errors.Join(problems...)
}

func ValidateAccessKeyAuthorizationRequest(value AccessKeyAuthorizationRequest) error {
	_, err := NewIAMAccessKeyAuthorizationRequest(value)
	if err != nil {
		return errors.New("access-key authorization request is invalid")
	}
	return nil
}

// NewIAMAccessKeyAuthorizationRequest maps the product-owned business shape
// without inventing a bearer credential. The SignedRequest remains a distinct
// authentication proof in IAM's AccessKey request.
func NewIAMAccessKeyAuthorizationRequest(value AccessKeyAuthorizationRequest) (iamv1.AuthorizationRequest, error) {
	request, err := newIAMAuthorizationRequest(value.Action, value.Resource, value.ResourceMode,
		value.CollectionUsage, value.SourceIP, value.RequestLabels, value.ResourceLabels, value.RequestID)
	if err != nil || iamv1.ValidateAccessKeySignedRequest(value.SignedRequest) != nil ||
		request.Profile.Product != value.SignedRequest.Parameters.Audience ||
		iamv1.CheckAuthorizationProfileUserAuthentication(
			authorizationProfile(), request.Profile, value.Action, iamv1.UserAuthenticationAccessKey,
		) != nil {
		return iamv1.AuthorizationRequest{}, errors.New("access-key authorization request is invalid")
	}
	return request, nil
}

func ValidateAccessKeyAuthorizationForRequest(value Authorization, request AccessKeyAuthorizationRequest) error {
	problems := []error{ValidateAuthorization(value), ValidateAccessKeyAuthorizationRequest(request)}
	if value.RequestID != request.RequestID || value.Subject.AccessKeyID == "" ||
		value.Subject.AccessKeyID != string(request.SignedRequest.Parameters.AccessKeyID) {
		problems = append(problems, errors.New("IAM access-key authorization binding mismatch"))
	}
	iamRequest, err := NewIAMAccessKeyAuthorizationRequest(request)
	if err != nil || !slices.Equal(value.RequestTags, iamRequest.RequestTags) ||
		!slices.Equal(value.ResourceTags, iamRequest.ResourceTags) {
		problems = append(problems, errors.New("IAM access-key authorization tags mismatch"))
	}
	return errors.Join(problems...)
}

func authorizationProfile() iamv1.AuthorizationProfile {
	profile, _ := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	return profile
}

// NewIAMAuthorizationRequest is the single PaaS-to-IAM vocabulary adapter.
// The release-owned Profile remains the authority for actions, shapes,
// conditions and caller purpose; this function only translates PaaS resource
// names and binds the network fact observed by the PEP.
func NewIAMAuthorizationRequest(value AuthorizationRequest) (iamv1.AuthorizationRequest, error) {
	return newIAMAuthorizationRequest(value.Action, value.Resource, value.ResourceMode,
		value.CollectionUsage, value.SourceIP, value.RequestLabels, value.ResourceLabels, value.RequestID)
}

func newIAMAuthorizationRequest(
	action iamv1.Action,
	resource paasv1.ResourceRef,
	resourceMode iamv1.AuthorizationResourceMode,
	collectionUsage iamv1.AuthorizationCollectionUsage,
	sourceIP string,
	requestLabels map[string]string,
	resourceLabels map[string]string,
	requestID string,
) (iamv1.AuthorizationRequest, error) {
	if !isAppHostingAction(action) {
		return iamv1.AuthorizationRequest{}, errors.New("authorization action is outside apphosting")
	}
	if requestLabels != nil && action != AuthorizeApplicationCreate &&
		action != AuthorizeApplicationLabelSet && action != AuthorizeApplicationLabelDelete {
		return iamv1.AuthorizationRequest{}, errors.New("authorization labels are outside application creation")
	}
	if resourceLabels != nil && action != AuthorizeApplicationRead &&
		action != AuthorizeApplicationLabelSet && action != AuthorizeApplicationLabelDelete {
		return iamv1.AuthorizationRequest{}, errors.New("authorization resource labels are outside application read")
	}
	if err := paasv1.ValidateLabels(requestLabels); err != nil {
		return iamv1.AuthorizationRequest{}, errors.New("authorization labels are invalid")
	}
	if err := paasv1.ValidateLabels(resourceLabels); err != nil {
		return iamv1.AuthorizationRequest{}, errors.New("authorization resource labels are invalid")
	}
	iamResource, err := iamResourceReference(resource)
	if err != nil {
		return iamv1.AuthorizationRequest{}, err
	}
	request, err := iamv1.NewAuthorizationRequest(action, iamResource,
		resourceMode, collectionUsage, requestID, requestID)
	profile, known := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	if err != nil || !known || iamv1.CheckAuthorizationProfileReference(profile, request.Profile) != nil ||
		profile.CallingService != iamv1.ServicePaaS {
		return iamv1.AuthorizationRequest{}, errors.New("authorization request is outside the PaaS profile")
	}
	request, err = iamv1.BindAuthorizationSourceIP(request, sourceIP)
	if err != nil {
		return iamv1.AuthorizationRequest{}, errors.New("authorization network context is invalid")
	}
	request, err = iamv1.BindAuthorizationRequestTags(request, requestLabels)
	if err != nil {
		return iamv1.AuthorizationRequest{}, errors.New("authorization request tags are invalid")
	}
	request, err = iamv1.BindAuthorizationResourceTags(request, resourceLabels)
	if err != nil {
		return iamv1.AuthorizationRequest{}, errors.New("authorization resource tags are invalid")
	}
	return request, nil
}

// isAppHostingAction is the PEP route boundary within the wider PaaS product
// Profile. Platform host and installation actions intentionally remain in the
// same release-owned product declaration but are not accepted by this HTTP
// adapter.
func isAppHostingAction(value iamv1.Action) bool {
	switch value {
	case AuthorizeApplicationCreate, AuthorizeApplicationRead,
		AuthorizeApplicationLabelSet, AuthorizeApplicationLabelDelete,
		AuthorizeConfigurationCreate, AuthorizeConfigurationRead,
		AuthorizeConfigurationRevisionCreate, AuthorizeConfigurationRevisionRead,
		AuthorizeApplicationRevisionCreate, AuthorizeApplicationRevisionRead,
		AuthorizeDeploymentCreate, AuthorizeDeploymentUpdate,
		AuthorizeDeploymentStop, AuthorizeDeploymentRollback,
		AuthorizeDeploymentRead, AuthorizeOperationRead:
		return true
	default:
		return false
	}
}

func iamResourceReference(value paasv1.ResourceRef) (iamv1.ResourceReference, error) {
	kinds := map[string]iamv1.ResourceKind{
		ResourceApplication:           iamv1.ResourceApplication,
		ResourceConfiguration:         iamv1.ResourceConfiguration,
		ResourceConfigurationRevision: iamv1.ResourceConfigurationRevision,
		ResourceApplicationRevision:   iamv1.ResourceApplicationRevision,
		ResourceDeployment:            iamv1.ResourceDeployment,
		ResourceOperation:             iamv1.ResourceOperation,
	}
	kind, known := kinds[value.Kind]
	if !known {
		return iamv1.ResourceReference{}, fmt.Errorf("unknown PaaS resource kind %q", value.Kind)
	}
	return iamv1.ResourceReference{Kind: kind, ID: string(value.ID)}, nil
}

func ValidateAuthorizationForRequest(
	value Authorization,
	request AuthorizationRequest,
) error {
	problems := []error{ValidateAuthorization(value)}
	if value.RequestID != request.RequestID {
		problems = append(problems, errors.New("IAM authorization request correlation mismatch"))
	}
	iamRequest, err := NewIAMAuthorizationRequest(request)
	if err != nil || !slices.Equal(value.RequestTags, iamRequest.RequestTags) ||
		!slices.Equal(value.ResourceTags, iamRequest.ResourceTags) {
		problems = append(problems, errors.New("IAM authorization request tags mismatch"))
	}
	return errors.Join(problems...)
}

// ValidateAuthorizationTagsForAction re-binds a product command immediately
// before the use case mutates state. A handler decision cannot be paired with
// changed labels by an in-process caller.
func ValidateAuthorizationTagsForAction(value Authorization, action iamv1.Action, labels map[string]string) error {
	if err := paasv1.ValidateLabels(labels); err != nil || iamv1.CheckAuthorizationTagsForAction(value.RequestTags, action, labels) != nil {
		return errors.New("IAM authorization request tags mismatch")
	}
	return nil
}

func ValidateAuthorizationResourceTagsForAction(value Authorization, action iamv1.Action, labels map[string]string) error {
	if err := paasv1.ValidateLabels(labels); err != nil || iamv1.CheckAuthorizationResourceTagsForAction(value.ResourceTags, action, labels) != nil {
		return errors.New("IAM authorization resource tags mismatch")
	}
	return nil
}

func ValidateApplicationLabelKeyForAction(action iamv1.Action, key string) error {
	if action != AuthorizeApplicationLabelSet && action != AuthorizeApplicationLabelDelete {
		return errors.New("action is not an application label mutation")
	}
	requestKey, requestErr := iamv1.NewRequestTagConditionKey(key)
	resourceKey, resourceErr := iamv1.NewResourceTagConditionKey(key)
	requestDefinition, requestDeclared := iamv1.LookupActionConditionDefinition(action, requestKey)
	resourceDefinition, resourceDeclared := iamv1.LookupActionConditionDefinition(action, resourceKey)
	if requestErr != nil || resourceErr != nil || !requestDeclared || !resourceDeclared ||
		requestDefinition.Source != iamv1.ConditionCallingServiceRequestTag ||
		resourceDefinition.Source != iamv1.ConditionCallingServiceResourceTag ||
		requestDefinition.ValueType != iamv1.ConditionString || resourceDefinition.ValueType != iamv1.ConditionString {
		return errors.New("application label key is not declared by the PaaS Profile")
	}
	return nil
}

func ValidateSubjectResolutionRequest(value SubjectResolutionRequest) error {
	if value.Credential == "" || strings.TrimSpace(value.Credential) != value.Credential || len([]byte(value.Credential)) > 16*1024 {
		return errors.New("subject credential is invalid")
	}
	return nil
}

func ValidateAuthorizationSubjectContext(value AuthorizationSubjectContext) error {
	profile, known := iamv1.LookupAuthorizationProfile(iamv1.ProductPaaS)
	if !known || iamv1.CheckAuthorizationProfileReference(profile, value.Profile) != nil ||
		paasv1.ValidateID("authorizationSubject.tenantId", string(value.TenantID)) != nil ||
		paasv1.ValidateSubjectRef(value.Subject) != nil ||
		(value.Subject.Type != paasv1.SubjectUser && value.Subject.Type != paasv1.SubjectRole) {
		return errors.New("authorization subject context is invalid")
	}
	return nil
}

func ValidateAuthorizationForSubjectContext(value Authorization, subject AuthorizationSubjectContext) error {
	if ValidateAuthorization(value) != nil || ValidateAuthorizationSubjectContext(subject) != nil ||
		value.TenantID != subject.TenantID || !value.Subject.Equal(subject.Subject) {
		return errors.New("authorization subject context changed")
	}
	return nil
}

func ValidateAuthorization(value Authorization) error {
	var problems []error
	problems = append(problems,
		paasv1.ValidateID("authorization.tenantId", string(value.TenantID)),
		paasv1.ValidateSubjectRef(value.Subject),
		paasv1.ValidateID("authorization.decisionId", value.DecisionID),
		paasv1.ValidateID("authorization.requestId", value.RequestID),
	)
	if value.AuditID != "" {
		problems = append(problems, paasv1.ValidateID("authorization.auditId", value.AuditID))
	}
	if value.TraceParent != "" {
		problems = append(problems,
			paasv1.ValidateSafeExternalText("authorization.traceparent", value.TraceParent, 55, false),
		)
	}
	if value.RequestTags != nil && (len(value.RequestTags) < 1 || len(value.RequestTags) > iamv1.MaxAuthorizationTags) {
		problems = append(problems, errors.New("authorization request tags are invalid"))
	}
	previous := ""
	for _, tag := range value.RequestTags {
		if iamv1.ValidateAuthorizationTag(tag) != nil || tag.Key <= previous {
			problems = append(problems, errors.New("authorization request tags are invalid"))
			break
		}
		previous = tag.Key
	}
	if value.ResourceTags != nil && (len(value.ResourceTags) < 1 || len(value.ResourceTags) > iamv1.MaxAuthorizationTags) {
		problems = append(problems, errors.New("authorization resource tags are invalid"))
	}
	previous = ""
	for _, tag := range value.ResourceTags {
		if iamv1.ValidateAuthorizationTag(tag) != nil || tag.Key <= previous {
			problems = append(problems, errors.New("authorization resource tags are invalid"))
			break
		}
		previous = tag.Key
	}
	return errors.Join(problems...)
}
