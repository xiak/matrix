// Package port owns delivery's boundaries to side effects and independently
// deployed services.
package port

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

var traceParentPattern = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

var (
	ErrUnauthenticated          = errors.New("IAM authentication failed")
	ErrPermissionDenied         = errors.New("IAM authorization denied")
	ErrAuthorizationUnavailable = errors.New("IAM authorization unavailable")
)

// AuthorizationRequest carries a transient caller credential to IAM. Delivery
// must never persist or log Credential.
type AuthorizationRequest struct {
	Credential    string
	Action        iamv1.Action
	Resource      iamv1.ResourceReference
	RequestID     string
	CorrelationID string
	TraceParent   string
}

// Authorization is the trusted, action-bound IAM result used by delivery.
// Tenant and subject are never reconstructed from HTTP headers or documents.
type Authorization struct {
	TenantID      devopsv1.TenantID
	Subject       devopsv1.SubjectRef
	DecisionID    string
	Action        iamv1.Action
	Resource      iamv1.ResourceReference
	RequestID     string
	CorrelationID string
	TraceParent   string
}

type Authorizer interface {
	Authorize(context.Context, AuthorizationRequest) (Authorization, error)
}

func ValidateAuthorizationRequest(value AuthorizationRequest) error {
	var problems []error
	if value.Credential == "" || strings.TrimSpace(value.Credential) != value.Credential ||
		len([]byte(value.Credential)) > 16*1024 {
		problems = append(problems, errors.New("authorization credential is invalid"))
	}
	expectedKind, known := iamv1.ResourceKindForAction(value.Action)
	if !known {
		problems = append(problems, fmt.Errorf("unknown authorization action %q", value.Action))
	} else if value.Resource.Kind != expectedKind {
		problems = append(problems, errors.New("authorization action and resource kind differ"))
	}
	problems = append(problems,
		devopsv1.ValidateID("authorization.resource.id", value.Resource.ID),
		devopsv1.ValidateID("authorization.requestId", value.RequestID),
		devopsv1.ValidateID("authorization.correlationId", value.CorrelationID),
	)
	problems = append(problems, ValidateTraceParent(value.TraceParent))
	return errors.Join(problems...)
}

func ValidateAuthorization(value Authorization) error {
	var problems []error
	problems = append(problems,
		devopsv1.ValidateID("authorization.tenantId", string(value.TenantID)),
		devopsv1.ValidateSubjectRef(value.Subject),
		devopsv1.ValidateID("authorization.decisionId", value.DecisionID),
		devopsv1.ValidateID("authorization.resource.id", value.Resource.ID),
		devopsv1.ValidateID("authorization.requestId", value.RequestID),
		devopsv1.ValidateID("authorization.correlationId", value.CorrelationID),
	)
	expectedKind, known := iamv1.ResourceKindForAction(value.Action)
	if !known {
		problems = append(problems, fmt.Errorf("unknown authorization action %q", value.Action))
	} else if value.Resource.Kind != expectedKind {
		problems = append(problems, errors.New("authorization action and resource kind differ"))
	}
	problems = append(problems, ValidateTraceParent(value.TraceParent))
	return errors.Join(problems...)
}

func ValidateTraceParent(value string) error {
	if value != "" && !traceParentPattern.MatchString(value) {
		return errors.New("traceparent is invalid")
	}
	return nil
}

func ValidateAuthorizationForRequest(
	value Authorization,
	action iamv1.Action,
	resourceKind iamv1.ResourceKind,
	resourceID devopsv1.ResourceID,
) error {
	var problems []error
	problems = append(problems, ValidateAuthorization(value))
	if value.Action != action || value.Resource.Kind != resourceKind ||
		value.Resource.ID != string(resourceID) {
		problems = append(problems, errors.New("IAM decision does not authorize this request"))
	}
	return errors.Join(problems...)
}
