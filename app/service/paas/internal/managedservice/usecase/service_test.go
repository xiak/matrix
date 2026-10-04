package usecase

import (
	"context"
	"errors"
	"maps"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/domain"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/port"
)

func TestQuotaActivationEqualReplayAndChangedConflict(t *testing.T) {
	repository := newMemoryRepository()
	service := newTestService(t, repository)
	command := ActivateQuotaCommand{
		Authorization: testAuthorization(), IdempotencyKey: "quota-request-1",
		Request: managedservicev1.ActivateQuotaRequest{
			OfferingID: domain.PostgreSQLOfferingID, QuotaShapeID: "pg-small", InstanceCount: 1,
		},
	}
	created, replayed, err := service.ActivateQuota(context.Background(), command)
	if err != nil || replayed {
		t.Fatalf("activate quota = %#v replayed=%v err=%v", created, replayed, err)
	}
	replay, replayed, err := service.ActivateQuota(context.Background(), command)
	if err != nil || !replayed || replay.ID != created.ID {
		t.Fatalf("quota replay = %#v replayed=%v err=%v", replay, replayed, err)
	}
	command.Request.InstanceCount = 2
	if _, _, err := service.ActivateQuota(context.Background(), command); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error=%v", err)
	}
	if len(repository.events) != 1 || repository.events[0].Action != audit.QuotaEntitlementActivated ||
		repository.events[0].Target.ID != audit.ResourceID(created.ID) {
		t.Fatalf("quota Audit events = %#v", repository.events)
	}
}

func TestConcurrentInstallationsCannotExceedQuota(t *testing.T) {
	repository := newMemoryRepository()
	service := newTestService(t, repository)
	entitlement, _, err := service.ActivateQuota(context.Background(), ActivateQuotaCommand{
		Authorization: testAuthorization(), IdempotencyKey: "quota-request-2",
		Request: managedservicev1.ActivateQuotaRequest{
			OfferingID: domain.PostgreSQLOfferingID, QuotaShapeID: "pg-small", InstanceCount: 1,
		},
	})
	if err != nil {
		t.Fatalf("activate quota: %v", err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for index, id := range []string{"postgres-one", "postgres-two"} {
		go func(index int, id string) {
			<-start
			_, _, createErr := service.CreateInstallation(context.Background(), CreateInstallationCommand{
				Authorization: testAuthorization(), IdempotencyKey: "install-request-" + id,
				Request: managedservicev1.CreateInstallationRequest{
					ID: id, Name: id, OfferingID: domain.PostgreSQLOfferingID,
					QuotaEntitlementID: entitlement.ID, RegionID: "local-primary",
				},
			})
			_ = index
			results <- createErr
		}(index, id)
	}
	close(start)
	var succeeded, exhausted int
	for range 2 {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrQuotaExhausted):
			exhausted++
		default:
			t.Fatalf("unexpected create error: %v", err)
		}
	}
	if succeeded != 1 || exhausted != 1 {
		t.Fatalf("succeeded=%d exhausted=%d", succeeded, exhausted)
	}
	if len(repository.events) != 2 || repository.events[1].Action != audit.ServiceInstallationCreated {
		t.Fatalf("transactional Audit events = %#v", repository.events)
	}
}

func TestInstallationRejectsUnavailableRegionBeforePersistence(t *testing.T) {
	repository := newMemoryRepository()
	region := testRegion()
	region.State = managedservicev1.RegionStale
	authority := &stubWorkloadRoleBinder{}
	service, err := NewService(repository, Config{
		Catalog: domain.DefaultCatalog(), Region: region,
		WorkloadRoleAuthority: authority, WorkloadRoleRuntime: authority,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	_, _, err = service.CreateInstallation(context.Background(), CreateInstallationCommand{
		Authorization: testAuthorization(), IdempotencyKey: "install-stale-region",
		Request: managedservicev1.CreateInstallationRequest{
			ID: "postgres-stale", Name: "Postgres stale",
			OfferingID:         domain.PostgreSQLOfferingID,
			QuotaEntitlementID: "quota-stale", RegionID: "local-primary",
		},
	})
	if !errors.Is(err, ErrRegionUnavailable) {
		t.Fatalf("stale region error=%v", err)
	}
}

func TestSingleResourceReadsReturnCurrentStateAndNotFound(t *testing.T) {
	repository := newMemoryRepository()
	service := newTestService(t, repository)
	authorization := testAuthorization()
	offering, err := service.GetOffering(context.Background(), authorization, domain.PostgreSQLOfferingID)
	if err != nil || offering.ID != domain.PostgreSQLOfferingID {
		t.Fatalf("get offering=%#v err=%v", offering, err)
	}
	region, err := service.GetRegion(context.Background(), authorization, "local-primary")
	if err != nil || region.Profile != managedservicev1.RegionLocalMachine {
		t.Fatalf("get region=%#v err=%v", region, err)
	}
	quota, _, err := service.ActivateQuota(context.Background(), ActivateQuotaCommand{
		Authorization: authorization, IdempotencyKey: "quota-single-read",
		Request: managedservicev1.ActivateQuotaRequest{
			OfferingID: domain.PostgreSQLOfferingID, QuotaShapeID: "pg-small", InstanceCount: 1,
		},
	})
	if err != nil {
		t.Fatalf("activate quota: %v", err)
	}
	readQuota, err := service.GetQuotaEntitlement(context.Background(), authorization, quota.ID)
	if err != nil || readQuota != quota {
		t.Fatalf("get quota=%#v want=%#v err=%v", readQuota, quota, err)
	}
	installation, _, err := service.CreateInstallation(context.Background(), CreateInstallationCommand{
		Authorization: authorization, IdempotencyKey: "installation-single-read",
		Request: managedservicev1.CreateInstallationRequest{
			ID: "postgres-single", Name: "Postgres single",
			OfferingID: domain.PostgreSQLOfferingID, QuotaEntitlementID: quota.ID,
			RegionID: "local-primary",
		},
	})
	if err != nil {
		t.Fatalf("create installation: %v", err)
	}
	readInstallation, err := service.GetServiceInstallation(context.Background(), authorization, installation.ID)
	if err != nil || readInstallation.ID != installation.ID {
		t.Fatalf("get installation=%#v err=%v", readInstallation, err)
	}
	operation, err := service.GetInstallationOperation(context.Background(), authorization, installation.ID)
	if err != nil || operation.ID != installation.Operation.ID {
		t.Fatalf("get operation=%#v err=%v", operation, err)
	}
	if _, err := service.GetQuotaEntitlement(context.Background(), authorization, "quota-absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent quota error=%v", err)
	}
	if _, err := service.GetServiceInstallation(context.Background(), authorization, "postgres-absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent installation error=%v", err)
	}
}

func TestBindServiceRoleUsesVerifiedInstallationAndStableCommandIdentity(t *testing.T) {
	repository := newMemoryRepository()
	binder := &stubWorkloadRoleBinder{}
	service := newTestService(t, repository)
	service.workloadRoleAuthority = binder
	service.workloadRoleRuntime = binder
	authorization := testAuthorization()
	quota, _, err := service.ActivateQuota(context.Background(), ActivateQuotaCommand{
		Authorization: authorization, IdempotencyKey: "quota-role-binding",
		Request: managedservicev1.ActivateQuotaRequest{
			OfferingID: domain.PostgreSQLOfferingID, QuotaShapeID: "pg-small", InstanceCount: 1,
		},
	})
	if err != nil {
		t.Fatalf("activate quota: %v", err)
	}
	installation, _, err := service.CreateInstallation(context.Background(), CreateInstallationCommand{
		Authorization: authorization, IdempotencyKey: "installation-role-binding",
		Request: managedservicev1.CreateInstallationRequest{
			ID: "postgres-role-binding", Name: "Postgres role binding",
			OfferingID: domain.PostgreSQLOfferingID, QuotaEntitlementID: quota.ID, RegionID: "local-primary",
		},
	})
	if err != nil {
		t.Fatalf("create installation: %v", err)
	}
	template := testServiceRoleTemplateReference()
	binder.result = testServiceLinkedRoleAccess(t, authorization.TenantID, installation.ID, template)
	command := BindServiceRoleCommand{
		Authorization: authorization, Credential: "Bearer user-session",
		InstallationID: installation.ID, Request: managedservicev1.BindServiceRoleRequest{Template: template},
		IdempotencyKey: "bind-role-request",
	}
	beginCount := len(repository.beginTenants)
	receipt, err := service.BindServiceRole(context.Background(), command)
	if err != nil || receipt.ServiceInstallationID != installation.ID || receipt.Template != template ||
		receipt.BindingID != binder.result.Bindings[0].ID {
		t.Fatalf("binding receipt=%#v err=%v", receipt, err)
	}
	wantRequestID := serviceRoleBindingRequestID(command.IdempotencyKey)
	if binder.calls != 1 || binder.request.Action != port.AuthorizeInstallationRoleBind ||
		binder.request.Resource != (port.ResourceReference{Kind: port.ResourceServiceInstallation, ID: installation.ID}) ||
		binder.request.RequestID != wantRequestID || binder.request.Credential != command.Credential {
		t.Fatalf("binding request=%#v calls=%d", binder.request, binder.calls)
	}
	wantAssumeRequestID := serviceRoleSessionRequestID(binder.result.Bindings[0].ID, command.Authorization.RequestID)
	wantReadRequestID := serviceRoleBusinessReadRequestID(binder.result.Bindings[0].ID, command.Authorization.RequestID)
	if binder.runtimeCalls != 1 || binder.runtimeBindingID != binder.result.Bindings[0].ID ||
		binder.runtimeAssumeRequestID != wantAssumeRequestID || binder.runtimeRequest.RequestID != wantReadRequestID ||
		binder.runtimeRequest.Action != port.AuthorizeInstallationRead || binder.releaseCalls != 1 {
		t.Fatalf("runtime binding=%s assume=%s request=%#v calls=%d releases=%d", binder.runtimeBindingID,
			binder.runtimeAssumeRequestID, binder.runtimeRequest, binder.runtimeCalls, binder.releaseCalls)
	}
	if len(repository.beginTenants) != beginCount+2 || repository.beginTenants[beginCount] != authorization.TenantID ||
		repository.beginTenants[beginCount+1] != authorization.TenantID {
		t.Fatalf("service Role verification reads=%v", repository.beginTenants[beginCount:])
	}
	command.Authorization.RequestID = "request-bind-role-replay"
	if _, err := service.BindServiceRole(context.Background(), command); err != nil ||
		binder.request.RequestID != wantRequestID || binder.runtimeAssumeRequestID == wantAssumeRequestID {
		t.Fatalf("equal replay did not keep command identity: request=%#v err=%v", binder.request, err)
	}
	binding := binder.result.Bindings[0]
	binder.runtimeAuthorization = port.WorkloadRoleAuthorization{
		TenantID: "organization-other", BindingID: binding.ID, RoleID: binding.RoleID,
		RoleSessionID: "role-session-forged-account", SourceServicePrincipalID: binder.result.Relation.ServicePrincipal.PrincipalID,
		DecisionID: "decision-forged-account", RequestID: "placeholder",
	}
	command.Authorization.RequestID = "request-bind-role-forged-runtime"
	binder.runtimeAuthorization.RequestID = serviceRoleBusinessReadRequestID(binding.ID, command.Authorization.RequestID)
	previousReleases := binder.releaseCalls
	if _, err := service.BindServiceRole(context.Background(), command); !errors.Is(err, port.ErrAuthorizationUnavailable) ||
		binder.releaseCalls != previousReleases+1 {
		t.Fatalf("forged runtime Account was accepted or not released: releases=%d err=%v", binder.releaseCalls, err)
	}
	binder.runtimeAuthorization = port.WorkloadRoleAuthorization{}
	binder.releaseErr = port.ErrAuthorizationUnavailable
	command.Authorization.RequestID = "request-bind-role-release-unavailable"
	previousReleases = binder.releaseCalls
	if _, err := service.BindServiceRole(context.Background(), command); !errors.Is(err, port.ErrAuthorizationUnavailable) ||
		binder.releaseCalls != previousReleases+1 {
		t.Fatalf("failed RoleSession exit was hidden: releases=%d err=%v", binder.releaseCalls, err)
	}
	binder.releaseErr = nil
	before := binder.calls
	command.InstallationID = "postgres-absent"
	if _, err := service.BindServiceRole(context.Background(), command); !errors.Is(err, ErrNotFound) || binder.calls != before {
		t.Fatalf("absent resource reached IAM: calls=%d before=%d err=%v", binder.calls, before, err)
	}
	command.InstallationID = installation.ID
	command.Authorization.SubjectType = port.SubjectServiceAccount
	if _, err := service.BindServiceRole(context.Background(), command); !errors.Is(err, ErrInvalidArgument) || binder.calls != before {
		t.Fatalf("service subject reached USER consent: calls=%d before=%d err=%v", binder.calls, before, err)
	}
}

func TestUnbindServiceRoleUsesVerifiedInstallationAndStableCommandIdentity(t *testing.T) {
	repository := newMemoryRepository()
	authority := &stubWorkloadRoleBinder{}
	service := newTestService(t, repository)
	service.workloadRoleAuthority = authority
	authorization := testAuthorization()
	quota, _, err := service.ActivateQuota(context.Background(), ActivateQuotaCommand{
		Authorization: authorization, IdempotencyKey: "quota-role-unbinding",
		Request: managedservicev1.ActivateQuotaRequest{
			OfferingID: domain.PostgreSQLOfferingID, QuotaShapeID: "pg-small", InstanceCount: 1,
		},
	})
	if err != nil {
		t.Fatalf("activate quota: %v", err)
	}
	installation, _, err := service.CreateInstallation(context.Background(), CreateInstallationCommand{
		Authorization: authorization, IdempotencyKey: "installation-role-unbinding",
		Request: managedservicev1.CreateInstallationRequest{
			ID: "postgres-role-unbinding", Name: "Postgres role unbinding",
			OfferingID: domain.PostgreSQLOfferingID, QuotaEntitlementID: quota.ID, RegionID: "local-primary",
		},
	})
	if err != nil {
		t.Fatalf("create installation: %v", err)
	}
	template := testServiceRoleTemplateReference()
	access := testServiceLinkedRoleAccess(t, authorization.TenantID, installation.ID, template)
	revoked := access.Bindings[0]
	revokedAt := revoked.CreatedAt.Add(time.Second)
	revoked.Status, revoked.ResourceVersion, revoked.UpdatedAt, revoked.RevokedAt =
		iamv1.WorkloadRoleBindingRevoked, 2, revokedAt, &revokedAt
	authority.revokeResult = revoked
	command := UnbindServiceRoleCommand{
		Authorization: authorization, Credential: "Bearer user-session",
		InstallationID: installation.ID, BindingID: revoked.ID,
		Request:        managedservicev1.UnbindServiceRoleRequest{ResourceVersion: 1},
		IdempotencyKey: "unbind-role-request",
	}
	receipt, err := service.UnbindServiceRole(context.Background(), command)
	if err != nil || receipt.ServiceInstallationID != installation.ID || receipt.Template != template ||
		receipt.BindingID != revoked.ID || receipt.RoleID != revoked.RoleID || receipt.Status != iamv1.WorkloadRoleBindingRevoked ||
		receipt.ResourceVersion != 2 || !receipt.RevokedAt.Equal(revokedAt) {
		t.Fatalf("unbinding receipt=%#v err=%v", receipt, err)
	}
	wantRequestID := serviceRoleUnbindingRequestID(command.IdempotencyKey)
	if authority.revokeCalls != 1 || authority.revokeBindingID != revoked.ID || authority.revokeVersion != 1 ||
		authority.revokeRequest.Action != port.AuthorizeInstallationRoleUnbind ||
		authority.revokeRequest.Resource != (port.ResourceReference{Kind: port.ResourceServiceInstallation, ID: installation.ID}) ||
		authority.revokeRequest.RequestID != wantRequestID || authority.revokeRequest.Credential != command.Credential {
		t.Fatalf("unbinding request=%#v calls=%d", authority.revokeRequest, authority.revokeCalls)
	}
	if _, err := service.UnbindServiceRole(context.Background(), command); err != nil || authority.revokeRequest.RequestID != wantRequestID {
		t.Fatalf("equal unbinding replay did not keep command identity: request=%#v err=%v", authority.revokeRequest, err)
	}
	before := authority.revokeCalls
	command.InstallationID = "postgres-absent"
	if _, err := service.UnbindServiceRole(context.Background(), command); !errors.Is(err, ErrNotFound) || authority.revokeCalls != before {
		t.Fatalf("absent unbinding resource reached IAM: calls=%d before=%d err=%v", authority.revokeCalls, before, err)
	}
	command.InstallationID = installation.ID
	command.Authorization.SubjectType = port.SubjectServiceAccount
	if _, err := service.UnbindServiceRole(context.Background(), command); !errors.Is(err, ErrInvalidArgument) || authority.revokeCalls != before {
		t.Fatalf("service subject reached USER unbinding: calls=%d before=%d err=%v", authority.revokeCalls, before, err)
	}
}

func newTestService(t *testing.T, repository Repository) *Service {
	t.Helper()
	var operationSequence atomic.Uint32
	authority := &stubWorkloadRoleBinder{}
	service, err := NewService(repository, Config{
		Catalog: domain.DefaultCatalog(), Region: testRegion(),
		WorkloadRoleAuthority: authority, WorkloadRoleRuntime: authority,
		NewQuotaID: func() (string, error) { return "quota-test", nil },
		NewOperationID: func() (string, error) {
			if operationSequence.Add(1) == 1 {
				return "operation-one", nil
			}
			return "operation-two", nil
		},
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return service
}

type stubWorkloadRoleBinder struct {
	calls                  int
	template               iamv1.ServiceRoleTemplateReference
	request                port.AuthorizationRequest
	result                 iamv1.ServiceLinkedRoleAccess
	revokeCalls            int
	revokeBindingID        iamv1.WorkloadRoleBindingID
	revokeVersion          uint64
	revokeRequest          port.AuthorizationRequest
	revokeResult           iamv1.WorkloadRoleBinding
	err                    error
	runtimeCalls           int
	runtimeBindingID       iamv1.WorkloadRoleBindingID
	runtimeAssumeRequestID string
	runtimeRequest         port.WorkloadRoleAuthorizationRequest
	runtimeAuthorization   port.WorkloadRoleAuthorization
	runtimeErr             error
	releaseCalls           int
	releaseErr             error
}

func (binder *stubWorkloadRoleBinder) AssumeWorkloadRole(
	_ context.Context,
	bindingID iamv1.WorkloadRoleBindingID,
	assumeRequestID string,
	request port.WorkloadRoleAuthorizationRequest,
) (port.WorkloadRoleLease, error) {
	binder.runtimeCalls++
	binder.runtimeBindingID, binder.runtimeAssumeRequestID, binder.runtimeRequest = bindingID, assumeRequestID, request
	if binder.runtimeErr != nil {
		return nil, binder.runtimeErr
	}
	authorization := binder.runtimeAuthorization
	if authorization.TenantID == "" && len(binder.result.Bindings) == 1 {
		binding := binder.result.Bindings[0]
		authorization = port.WorkloadRoleAuthorization{
			TenantID: string(binding.AccountID), BindingID: binding.ID, RoleID: binding.RoleID,
			RoleSessionID: "role-session-managedservice", SourceServicePrincipalID: binder.result.Relation.ServicePrincipal.PrincipalID,
			DecisionID: "decision-managedservice-read", RequestID: request.RequestID,
		}
	}
	return &stubWorkloadRoleLease{binder: binder, authorization: authorization}, nil
}

type stubWorkloadRoleLease struct {
	binder        *stubWorkloadRoleBinder
	authorization port.WorkloadRoleAuthorization
}

func (lease *stubWorkloadRoleLease) Authorization() port.WorkloadRoleAuthorization {
	return lease.authorization
}

func (lease *stubWorkloadRoleLease) Release(context.Context) error {
	lease.binder.releaseCalls++
	return lease.binder.releaseErr
}

func (binder *stubWorkloadRoleBinder) BindWorkloadRole(
	_ context.Context,
	template iamv1.ServiceRoleTemplateReference,
	request port.AuthorizationRequest,
) (iamv1.ServiceLinkedRoleAccess, error) {
	binder.calls++
	binder.template = template
	binder.request = request
	return binder.result, binder.err
}

func (binder *stubWorkloadRoleBinder) RevokeWorkloadRole(
	_ context.Context,
	bindingID iamv1.WorkloadRoleBindingID,
	resourceVersion uint64,
	request port.AuthorizationRequest,
) (iamv1.WorkloadRoleBinding, error) {
	binder.revokeCalls++
	binder.revokeBindingID, binder.revokeVersion, binder.revokeRequest = bindingID, resourceVersion, request
	return binder.revokeResult, binder.err
}

func testServiceRoleTemplateReference() iamv1.ServiceRoleTemplateReference {
	return iamv1.ServiceRoleTemplateReference{
		ID: "managedservice.installation-reader", Version: 1,
		ContentDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
}

func testServiceLinkedRoleAccess(
	t *testing.T,
	accountID string,
	installationID string,
	template iamv1.ServiceRoleTemplateReference,
) iamv1.ServiceLinkedRoleAccess {
	t.Helper()
	createdAt := time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)
	policyVersion := iamv1.PolicyVersionReference{
		PolicyID:      "policy-managedservice-reader",
		VersionID:     "version-managedservice-reader",
		ContentDigest: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
	}
	relation := iamv1.ServiceLinkedRole{
		APIVersion: iamv1.APIVersion, Kind: "ServiceLinkedRole",
		Role: iamv1.Role{
			APIVersion: iamv1.APIVersion, Kind: "Role", ID: "role-managedservice-reader",
			AccountID: iamv1.AccountID(accountID), Name: "ManagedServiceInstallationReader",
			Description: "Managed service installation reader", Tags: []iamv1.RoleTag{},
			Management: iamv1.RoleServiceLinked, Status: iamv1.RoleActive,
			MaxSessionDurationSeconds: 900, ResourceVersion: 1,
			CurrentTrustVersionID: "trust-managedservice-reader", CreatedAt: createdAt, UpdatedAt: createdAt,
		},
		Template: template,
		ServicePrincipal: iamv1.ServicePrincipalReference{
			InstallationID: "installation-platform", PrincipalID: "service-paas", Purpose: iamv1.ServicePaaS,
		},
		PermissionCeiling: policyVersion,
	}
	binding := iamv1.WorkloadRoleBinding{
		APIVersion: iamv1.APIVersion, Kind: "WorkloadRoleBinding", ID: "binding-managedservice-reader",
		AccountID: relation.Role.AccountID, RoleID: relation.Role.ID, Template: template,
		Workload: iamv1.ResourceReference{Kind: iamv1.ResourceServiceInstallation, ID: installationID},
		Status:   iamv1.WorkloadRoleBindingActive, ResourceVersion: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
	}
	result := iamv1.ServiceLinkedRoleAccess{
		APIVersion: iamv1.APIVersion, Kind: "ServiceLinkedRoleAccess", Relation: relation,
		Bindings: []iamv1.WorkloadRoleBinding{binding},
	}
	if iamv1.ValidateServiceLinkedRoleAccess(result) != nil {
		t.Fatal("test service-linked Role access is invalid")
	}
	return result
}

func testAuthorization() port.Authorization {
	return port.Authorization{
		TenantID: "organization-test", SubjectType: port.SubjectUser,
		SubjectID:  "principal-test",
		DecisionID: "decision-test", RequestID: "request-test",
	}
}

func testRegion() managedservicev1.Region {
	inspectedAt := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	return managedservicev1.Region{
		ID: "local-primary", DisplayName: "本机主区域",
		Profile: managedservicev1.RegionLocalMachine,
		State:   managedservicev1.RegionReady, InspectedAt: &inspectedAt,
		Capacity: managedservicev1.RegionCapacity{
			CPUMillicores: 4000, MemoryMiB: 8192, StorageGiB: 100,
		},
	}
}

type memoryRepository struct {
	mu            sync.Mutex
	quotas        map[string]managedservicev1.QuotaEntitlement
	quotaKeys     map[string]memoryReplay
	installations map[string]managedservicev1.ServiceInstallation
	installKeys   map[string]memoryReplay
	events        []audit.Event
	beginTenants  []string
}

type memoryReplay struct {
	id     string
	digest string
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{
		quotas: map[string]managedservicev1.QuotaEntitlement{}, quotaKeys: map[string]memoryReplay{},
		installations: map[string]managedservicev1.ServiceInstallation{}, installKeys: map[string]memoryReplay{},
	}
}

func (repository *memoryRepository) Begin(
	_ context.Context,
	tenantID string,
	_ TransactionMode,
) (Transaction, error) {
	repository.mu.Lock()
	repository.beginTenants = append(repository.beginTenants, tenantID)
	return &memoryTransaction{
		repository: repository,
		quotas:     maps.Clone(repository.quotas), quotaKeys: maps.Clone(repository.quotaKeys),
		installations: maps.Clone(repository.installations), installKeys: maps.Clone(repository.installKeys),
		events: append([]audit.Event(nil), repository.events...),
	}, nil
}

type memoryTransaction struct {
	repository    *memoryRepository
	quotas        map[string]managedservicev1.QuotaEntitlement
	quotaKeys     map[string]memoryReplay
	installations map[string]managedservicev1.ServiceInstallation
	installKeys   map[string]memoryReplay
	events        []audit.Event
	closed        bool
}

func (transaction *memoryTransaction) ListQuotaEntitlements(context.Context) ([]managedservicev1.QuotaEntitlement, error) {
	result := make([]managedservicev1.QuotaEntitlement, 0, len(transaction.quotas))
	for _, item := range transaction.quotas {
		result = append(result, item)
	}
	return result, nil
}

func (transaction *memoryTransaction) GetQuotaEntitlement(
	_ context.Context,
	id string,
) (managedservicev1.QuotaEntitlement, error) {
	item, found := transaction.quotas[id]
	if !found {
		return managedservicev1.QuotaEntitlement{}, ErrNotFound
	}
	return item, nil
}

func (transaction *memoryTransaction) ListServiceInstallations(context.Context) ([]managedservicev1.ServiceInstallation, error) {
	result := make([]managedservicev1.ServiceInstallation, 0, len(transaction.installations))
	for _, item := range transaction.installations {
		result = append(result, item)
	}
	return result, nil
}

func (transaction *memoryTransaction) GetServiceInstallation(
	_ context.Context,
	id string,
) (managedservicev1.ServiceInstallation, error) {
	item, found := transaction.installations[id]
	if !found {
		return managedservicev1.ServiceInstallation{}, ErrNotFound
	}
	return item, nil
}

func (transaction *memoryTransaction) FindQuotaReplay(
	_ context.Context,
	key string,
) (managedservicev1.QuotaEntitlement, string, bool, error) {
	replay, found := transaction.quotaKeys[key]
	return transaction.quotas[replay.id], replay.digest, found, nil
}

func (transaction *memoryTransaction) InsertQuotaEntitlement(
	_ context.Context,
	draft QuotaDraft,
) (managedservicev1.QuotaEntitlement, error) {
	item := managedservicev1.QuotaEntitlement{
		ID: draft.ID, OfferingID: draft.OfferingID, QuotaShapeID: draft.QuotaShapeID,
		PurchasedCount: draft.PurchasedCount, ResourceVersion: 1,
		ActivatedAt: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC),
	}
	transaction.quotas[item.ID] = item
	transaction.quotaKeys[draft.IdempotencyKey] = memoryReplay{id: item.ID, digest: draft.RequestDigest}
	return item, nil
}

func (transaction *memoryTransaction) FindInstallationReplay(
	_ context.Context,
	key string,
) (managedservicev1.ServiceInstallation, string, bool, error) {
	replay, found := transaction.installKeys[key]
	return transaction.installations[replay.id], replay.digest, found, nil
}

func (transaction *memoryTransaction) GetQuotaEntitlementForUpdate(
	_ context.Context,
	id string,
) (managedservicev1.QuotaEntitlement, error) {
	item, found := transaction.quotas[id]
	if !found {
		return managedservicev1.QuotaEntitlement{}, ErrNotFound
	}
	return item, nil
}

func (transaction *memoryTransaction) ReserveInstallation(
	_ context.Context,
	draft InstallationDraft,
	expectedQuotaVersion uint64,
) (managedservicev1.ServiceInstallation, error) {
	if _, found := transaction.installations[draft.ID]; found {
		return managedservicev1.ServiceInstallation{}, ErrAlreadyExists
	}
	quota := transaction.quotas[draft.QuotaEntitlementID]
	if quota.ResourceVersion != expectedQuotaVersion ||
		quota.PurchasedCount <= quota.ReservedCount+quota.ConsumedCount {
		return managedservicev1.ServiceInstallation{}, ErrQuotaExhausted
	}
	quota.ReservedCount++
	quota.ResourceVersion++
	transaction.quotas[quota.ID] = quota
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	item := managedservicev1.ServiceInstallation{
		ID: draft.ID, Name: draft.Name, OfferingID: draft.OfferingID,
		EngineVersion: draft.EngineVersion, QuotaEntitlementID: draft.QuotaEntitlementID,
		RegionID: draft.RegionID, Phase: managedservicev1.InstallationPending, CreatedAt: now,
		Operation: managedservicev1.InstallationOperation{
			ID: draft.OperationID, Phase: managedservicev1.InstallationPending, ObservedAt: now,
		},
	}
	transaction.installations[item.ID] = item
	transaction.installKeys[draft.IdempotencyKey] = memoryReplay{id: item.ID, digest: draft.RequestDigest}
	return item, nil
}

func (transaction *memoryTransaction) AppendAuditEvent(_ context.Context, event audit.Event) error {
	if err := audit.ValidateEvent(event); err != nil {
		return err
	}
	transaction.events = append(transaction.events, event)
	return nil
}

func (transaction *memoryTransaction) Commit(context.Context) error {
	if transaction.closed {
		return errors.New("transaction already closed")
	}
	transaction.repository.quotas = transaction.quotas
	transaction.repository.quotaKeys = transaction.quotaKeys
	transaction.repository.installations = transaction.installations
	transaction.repository.installKeys = transaction.installKeys
	transaction.repository.events = transaction.events
	transaction.closed = true
	transaction.repository.mu.Unlock()
	return nil
}

func (transaction *memoryTransaction) Rollback(context.Context) error {
	if transaction.closed {
		return nil
	}
	transaction.closed = true
	transaction.repository.mu.Unlock()
	return nil
}
