package authority

import (
	"cmp"
	"slices"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
)

// CurrentAccessDiagnosis projects the exact private evaluation already used by
// authorization. It never reinterprets policy content and never emits decision
// or historical proof material.
func CurrentAccessDiagnosis(evaluation AuthorizationEvaluation, tenantID iamv1.AccountID, installationID string,
	subject iamv1.Subject, request iamv1.AuthorizationRequest,
) (iamv1.CurrentAccessDiagnosis, error) {
	if iamv1.CheckAuthorizationDecisionForRequest(evaluation.AuthorizationDecision, request) != nil || iamv1.ValidateSubject(subject) != nil {
		return iamv1.CurrentAccessDiagnosis{}, ErrAuthorityUnavailable
	}
	// The evaluator's denied decision intentionally redacts its authority scope
	// and subject. Diagnosis restores only the already authenticated actor.
	result := iamv1.CurrentAccessDiagnosis{
		APIVersion: iamv1.APIVersion, Kind: "CurrentAccessDiagnosis", Outcome: iamv1.AccessDiagnosisDenied,
		Subject: subject, Action: request.Action, Resource: request.Resource, Profile: request.Profile,
		ResourceMode: request.ResourceMode, CollectionUsage: request.CollectionUsage,
		RequestTags: slices.Clone(request.RequestTags), ResourceTags: slices.Clone(request.ResourceTags),
		RequestID: request.RequestID, CorrelationID: request.CorrelationID, EvaluatedAt: evaluation.DecidedAt,
		Sources: []iamv1.AccessDiagnosisSource{}, Restrictions: []iamv1.AccessDiagnosisRestriction{},
		ResourceExistence: iamv1.AccessDiagnosisNotEvaluated, BusinessOutcome: iamv1.AccessDiagnosisNotEvaluated,
	}
	if request.NetworkContext != nil {
		network := *request.NetworkContext
		result.NetworkContext = &network
	}
	definition, known := iamv1.LookupActionDefinition(request.Action)
	if !known {
		return iamv1.CurrentAccessDiagnosis{}, ErrAuthorityUnavailable
	}
	if definition.AuthorityScope == iamv1.AuthorityScopeTenant {
		result.TenantID = tenantID
	} else {
		result.InstallationID = installationID
	}
	if evaluation.Allowed {
		result.Outcome = iamv1.AccessDiagnosisAllowed
	} else {
		result.Reasons = diagnosisReasons(evaluation)
	}
	sources, err := diagnosisSources(evaluation, subject.Type)
	if err != nil {
		return iamv1.CurrentAccessDiagnosis{}, err
	}
	result.Sources = sources
	result.Restrictions = diagnosisRestrictions(evaluation, subject.Type)
	if iamv1.ValidateCurrentAccessDiagnosis(result) != nil {
		return iamv1.CurrentAccessDiagnosis{}, ErrAuthorityUnavailable
	}
	return result, nil
}

func diagnosisReasons(value AuthorizationEvaluation) []iamv1.AccessDiagnosisReason {
	reasons := make([]iamv1.AccessDiagnosisReason, 0, 9)
	if value.PolicyEvaluation.ExplicitDeny || value.UserBoundaryEvaluation != nil && value.UserBoundaryEvaluation.ExplicitDeny ||
		value.RoleBoundaryEvaluation != nil && value.RoleBoundaryEvaluation.ExplicitDeny ||
		value.SessionPolicyEvaluation != nil && value.SessionPolicyEvaluation.ExplicitDeny {
		reasons = append(reasons, iamv1.AccessDiagnosisExplicitDeny)
	}
	if len(value.PolicyEvaluation.MatchedAllowVersions) == 0 {
		reasons = append(reasons, iamv1.AccessDiagnosisNoMatchingAllow)
	}
	if value.UserBoundaryEvaluation != nil && !value.UserBoundaryEvaluation.Allowed {
		reasons = append(reasons, iamv1.AccessDiagnosisUserPermissionBoundary)
	}
	if value.RoleBoundaryEvaluation != nil && !value.RoleBoundaryEvaluation.Allowed {
		reasons = append(reasons, iamv1.AccessDiagnosisRolePermissionBoundary)
	}
	if value.SessionPolicyEvaluation != nil && !value.SessionPolicyEvaluation.Allowed {
		reasons = append(reasons, iamv1.AccessDiagnosisSessionPolicy)
	}
	if value.CredentialRestricted {
		reasons = append(reasons, iamv1.AccessDiagnosisCredentialRestricted)
	}
	if !value.SubjectSupported {
		reasons = append(reasons, iamv1.AccessDiagnosisSubjectUnsupported)
	}
	if !value.CallingServiceSupported {
		reasons = append(reasons, iamv1.AccessDiagnosisCallingServiceUnsupported)
	}
	if !value.ResourceContextSupported {
		reasons = append(reasons, iamv1.AccessDiagnosisResourceContextUnsupported)
	}
	slices.Sort(reasons)
	return reasons
}

func diagnosisSources(value AuthorizationEvaluation, subjectType iamv1.SubjectType) ([]iamv1.AccessDiagnosisSource, error) {
	result := make([]iamv1.AccessDiagnosisSource, 0, len(value.PolicyEvidence)*2)
	if value.RoleEvidence != nil && value.RoleEvidence.Service != nil {
		version := value.RoleEvidence.Service.PermissionVersion
		result = appendPolicyEffects(result, iamv1.AccessDiagnosisSourceServiceRole, version, "", "", value.PolicyEvaluation)
	} else {
		for _, evidence := range value.PolicyEvidence {
			kind := iamv1.AccessDiagnosisSourceDirect
			if subjectType == iamv1.SubjectRole {
				kind = iamv1.AccessDiagnosisSourceRole
			} else if evidence.MembershipID != "" {
				kind = iamv1.AccessDiagnosisSourceGroup
			}
			result = appendPolicyEffects(result, kind, evidence.Version, evidence.AttachmentID, evidence.MembershipID, value.PolicyEvaluation)
		}
	}
	slices.SortFunc(result, func(left, right iamv1.AccessDiagnosisSource) int {
		if order := cmp.Compare(left.Kind, right.Kind); order != 0 {
			return order
		}
		if order := cmp.Compare(left.Effect, right.Effect); order != 0 {
			return order
		}
		if order := cmp.Compare(left.Version.PolicyID, right.Version.PolicyID); order != 0 {
			return order
		}
		if order := cmp.Compare(left.Version.VersionID, right.Version.VersionID); order != 0 {
			return order
		}
		if order := cmp.Compare(left.AttachmentID, right.AttachmentID); order != 0 {
			return order
		}
		return cmp.Compare(left.MembershipID, right.MembershipID)
	})
	for _, expected := range append(slices.Clone(value.PolicyEvaluation.MatchedAllowVersions), value.PolicyEvaluation.MatchedDenyVersions...) {
		found := false
		for _, source := range result {
			found = found || source.Version == expected
		}
		if !found {
			return nil, ErrAuthorityUnavailable
		}
	}
	return result, nil
}

func appendPolicyEffects(result []iamv1.AccessDiagnosisSource, kind iamv1.AccessDiagnosisSourceKind,
	version iamv1.PolicyVersionReference, attachment iamv1.PolicyAttachmentID, membership iamv1.GroupMembershipID,
	evaluation PolicyEvaluation,
) []iamv1.AccessDiagnosisSource {
	for _, candidate := range evaluation.MatchedAllowVersions {
		if candidate == version {
			result = append(result, iamv1.AccessDiagnosisSource{Kind: kind, Effect: iamv1.AccessDiagnosisEffectAllow,
				Version: version, AttachmentID: attachment, MembershipID: membership})
		}
	}
	for _, candidate := range evaluation.MatchedDenyVersions {
		if candidate == version {
			result = append(result, iamv1.AccessDiagnosisSource{Kind: kind, Effect: iamv1.AccessDiagnosisEffectDeny,
				Version: version, AttachmentID: attachment, MembershipID: membership})
		}
	}
	return result
}

func diagnosisRestrictions(value AuthorizationEvaluation, subjectType iamv1.SubjectType) []iamv1.AccessDiagnosisRestriction {
	result := make([]iamv1.AccessDiagnosisRestriction, 0, 3)
	if subjectType == iamv1.SubjectUser {
		item := iamv1.AccessDiagnosisRestriction{Kind: iamv1.AccessDiagnosisRestrictionUserBoundary,
			State: iamv1.AccessDiagnosisRestrictionNotApplicable}
		if value.BoundaryEvidence.State == "BOUND" && value.BoundaryEvidence.Version != nil && value.UserBoundaryEvaluation != nil {
			item.Version = value.BoundaryEvidence.Version
			item.State = restrictionState(*value.UserBoundaryEvaluation)
		}
		result = append(result, item)
	}
	if subjectType == iamv1.SubjectRole && value.RoleEvidence != nil && value.RoleEvidence.Service == nil {
		boundary := iamv1.AccessDiagnosisRestriction{Kind: iamv1.AccessDiagnosisRestrictionRoleBoundary,
			State: iamv1.AccessDiagnosisRestrictionNotApplicable}
		if value.RoleBoundaryEvaluation != nil {
			version := value.RoleEvidence.Boundary.Version
			boundary.Version, boundary.State = &version, restrictionState(*value.RoleBoundaryEvaluation)
		}
		session := iamv1.AccessDiagnosisRestriction{Kind: iamv1.AccessDiagnosisRestrictionSessionPolicy,
			State: iamv1.AccessDiagnosisRestrictionNotApplicable}
		if value.SessionPolicyEvaluation != nil && value.RoleEvidence.SessionPolicy != nil {
			session.ContentDigest = value.RoleEvidence.SessionPolicy.ContentDigest
			session.State = restrictionState(*value.SessionPolicyEvaluation)
		}
		result = append(result, boundary, session)
	}
	slices.SortFunc(result, func(left, right iamv1.AccessDiagnosisRestriction) int { return cmp.Compare(left.Kind, right.Kind) })
	return result
}

func restrictionState(value PolicyEvaluation) iamv1.AccessDiagnosisRestrictionState {
	if value.Allowed {
		return iamv1.AccessDiagnosisRestrictionMatched
	}
	return iamv1.AccessDiagnosisRestrictionBlocked
}
