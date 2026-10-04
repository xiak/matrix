package usecase

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/audit"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/domain"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/port"
)

var (
	ErrInvalidArgument       = errors.New("managed-service request is invalid")
	ErrNotFound              = errors.New("managed-service resource is absent")
	ErrAlreadyExists         = errors.New("managed-service resource already exists")
	ErrIdempotencyConflict   = errors.New("managed-service idempotency key conflicts")
	ErrQuotaExhausted        = errors.New("managed-service quota is exhausted")
	ErrRegionUnavailable     = errors.New("managed-service region is unavailable")
	ErrTransactionRetry      = errors.New("managed-service transaction must retry")
	ErrRepositoryUnavailable = errors.New("managed-service repository is unavailable")
)

type TransactionMode uint8

const (
	ReadOnly TransactionMode = iota + 1
	ReadWrite
)

type Repository interface {
	Begin(context.Context, string, TransactionMode) (Transaction, error)
}

type Transaction interface {
	ListQuotaEntitlements(context.Context) ([]managedservicev1.QuotaEntitlement, error)
	GetQuotaEntitlement(context.Context, string) (managedservicev1.QuotaEntitlement, error)
	ListServiceInstallations(context.Context) ([]managedservicev1.ServiceInstallation, error)
	GetServiceInstallation(context.Context, string) (managedservicev1.ServiceInstallation, error)
	FindQuotaReplay(context.Context, string) (managedservicev1.QuotaEntitlement, string, bool, error)
	InsertQuotaEntitlement(context.Context, QuotaDraft) (managedservicev1.QuotaEntitlement, error)
	FindInstallationReplay(context.Context, string) (managedservicev1.ServiceInstallation, string, bool, error)
	GetQuotaEntitlementForUpdate(context.Context, string) (managedservicev1.QuotaEntitlement, error)
	ReserveInstallation(context.Context, InstallationDraft, uint64) (managedservicev1.ServiceInstallation, error)
	AppendAuditEvent(context.Context, audit.Event) error
	Commit(context.Context) error
	Rollback(context.Context) error
}

type QuotaDraft struct {
	ID             string
	OfferingID     string
	QuotaShapeID   string
	PurchasedCount uint32
	IdempotencyKey string
	RequestDigest  string
	ActorType      port.SubjectType
	ActorID        string
	IAMDecisionID  string
	RequestID      string
}

type InstallationDraft struct {
	ID                 string
	Name               string
	OfferingID         string
	EngineVersion      string
	QuotaEntitlementID string
	RegionID           string
	OperationID        string
	IdempotencyKey     string
	RequestDigest      string
	ActorType          port.SubjectType
	ActorID            string
	IAMDecisionID      string
	RequestID          string
}

type ActivateQuotaCommand struct {
	Authorization  port.Authorization
	Request        managedservicev1.ActivateQuotaRequest
	IdempotencyKey string
}

type CreateInstallationCommand struct {
	Authorization  port.Authorization
	Request        managedservicev1.CreateInstallationRequest
	IdempotencyKey string
}

type BindServiceRoleCommand struct {
	Authorization  port.Authorization
	Credential     string
	InstallationID string
	Request        managedservicev1.BindServiceRoleRequest
	IdempotencyKey string
}

type UnbindServiceRoleCommand struct {
	Authorization  port.Authorization
	Credential     string
	InstallationID string
	BindingID      iamv1.WorkloadRoleBindingID
	Request        managedservicev1.UnbindServiceRoleRequest
	IdempotencyKey string
}

type Config struct {
	Catalog               domain.Catalog
	Region                managedservicev1.Region
	WorkloadRoleAuthority port.WorkloadRoleAuthority
	WorkloadRoleRuntime   port.WorkloadRoleRuntime
	MaximumWriteAttempts  int
	NewQuotaID            func() (string, error)
	NewOperationID        func() (string, error)
}

type Service struct {
	repository            Repository
	workloadRoleAuthority port.WorkloadRoleAuthority
	workloadRoleRuntime   port.WorkloadRoleRuntime
	catalog               domain.Catalog
	region                managedservicev1.Region
	maximumWriteAttempts  int
	newQuotaID            func() (string, error)
	newOperationID        func() (string, error)
}

func NewService(repository Repository, config Config) (*Service, error) {
	if repository == nil || config.WorkloadRoleAuthority == nil || config.WorkloadRoleRuntime == nil ||
		managedservicev1.ValidateRegion(config.Region) != nil {
		return nil, errors.New("managed-service use case configuration is invalid")
	}
	if len(config.Catalog.List()) == 0 {
		config.Catalog = domain.DefaultCatalog()
	}
	if config.MaximumWriteAttempts == 0 {
		config.MaximumWriteAttempts = 5
	}
	if config.MaximumWriteAttempts < 1 || config.MaximumWriteAttempts > 10 {
		return nil, errors.New("managed-service transaction attempt count is invalid")
	}
	if config.NewQuotaID == nil {
		config.NewQuotaID = func() (string, error) { return newID("quota-") }
	}
	if config.NewOperationID == nil {
		config.NewOperationID = func() (string, error) { return newID("operation-") }
	}
	return &Service{
		repository: repository, workloadRoleAuthority: config.WorkloadRoleAuthority,
		workloadRoleRuntime: config.WorkloadRoleRuntime,
		catalog:             config.Catalog, region: config.Region,
		maximumWriteAttempts: config.MaximumWriteAttempts,
		newQuotaID:           config.NewQuotaID, newOperationID: config.NewOperationID,
	}, nil
}

func (service *Service) ListOfferings(
	_ context.Context,
	authorization port.Authorization,
) (managedservicev1.ServiceOfferingList, error) {
	if port.ValidateAuthorization(authorization) != nil {
		return managedservicev1.ServiceOfferingList{}, ErrInvalidArgument
	}
	return managedservicev1.ServiceOfferingList{Kind: "ServiceOfferingList", Items: service.catalog.List()}, nil
}

func (service *Service) GetOffering(
	ctx context.Context,
	authorization port.Authorization,
	id string,
) (managedservicev1.ServiceOffering, error) {
	if ctx == nil || port.ValidateAuthorization(authorization) != nil ||
		managedservicev1.ValidateID("offeringId", id) != nil {
		return managedservicev1.ServiceOffering{}, ErrInvalidArgument
	}
	for _, offering := range service.catalog.List() {
		if offering.ID == id {
			return offering, nil
		}
	}
	return managedservicev1.ServiceOffering{}, ErrNotFound
}

func (service *Service) ListRegions(
	_ context.Context,
	authorization port.Authorization,
) (managedservicev1.RegionList, error) {
	if port.ValidateAuthorization(authorization) != nil {
		return managedservicev1.RegionList{}, ErrInvalidArgument
	}
	return managedservicev1.RegionList{Kind: "RegionList", Items: []managedservicev1.Region{service.region}}, nil
}

func (service *Service) GetRegion(
	ctx context.Context,
	authorization port.Authorization,
	id string,
) (managedservicev1.Region, error) {
	if ctx == nil || port.ValidateAuthorization(authorization) != nil ||
		managedservicev1.ValidateID("regionId", id) != nil {
		return managedservicev1.Region{}, ErrInvalidArgument
	}
	if id != service.region.ID {
		return managedservicev1.Region{}, ErrNotFound
	}
	return service.region, nil
}

func (service *Service) ListQuotaEntitlements(
	ctx context.Context,
	authorization port.Authorization,
) (managedservicev1.QuotaEntitlementList, error) {
	if ctx == nil || port.ValidateAuthorization(authorization) != nil {
		return managedservicev1.QuotaEntitlementList{}, ErrInvalidArgument
	}
	var items []managedservicev1.QuotaEntitlement
	err := service.withTransaction(ctx, authorization.TenantID, ReadOnly, func(transaction Transaction) error {
		var err error
		items, err = transaction.ListQuotaEntitlements(ctx)
		return err
	})
	if err != nil {
		return managedservicev1.QuotaEntitlementList{}, err
	}
	return managedservicev1.QuotaEntitlementList{Kind: "QuotaEntitlementList", Items: items}, nil
}

func (service *Service) GetQuotaEntitlement(
	ctx context.Context,
	authorization port.Authorization,
	id string,
) (managedservicev1.QuotaEntitlement, error) {
	if ctx == nil || port.ValidateAuthorization(authorization) != nil ||
		managedservicev1.ValidateID("quotaEntitlementId", id) != nil {
		return managedservicev1.QuotaEntitlement{}, ErrInvalidArgument
	}
	var result managedservicev1.QuotaEntitlement
	err := service.withTransaction(ctx, authorization.TenantID, ReadOnly, func(transaction Transaction) error {
		var err error
		result, err = transaction.GetQuotaEntitlement(ctx, id)
		return err
	})
	if err != nil {
		return managedservicev1.QuotaEntitlement{}, err
	}
	return result, nil
}

func (service *Service) ListServiceInstallations(
	ctx context.Context,
	authorization port.Authorization,
) (managedservicev1.ServiceInstallationList, error) {
	if ctx == nil || port.ValidateAuthorization(authorization) != nil {
		return managedservicev1.ServiceInstallationList{}, ErrInvalidArgument
	}
	var items []managedservicev1.ServiceInstallation
	err := service.withTransaction(ctx, authorization.TenantID, ReadOnly, func(transaction Transaction) error {
		var err error
		items, err = transaction.ListServiceInstallations(ctx)
		return err
	})
	if err != nil {
		return managedservicev1.ServiceInstallationList{}, err
	}
	return managedservicev1.ServiceInstallationList{Kind: "ServiceInstallationList", Items: items}, nil
}

func (service *Service) GetServiceInstallation(
	ctx context.Context,
	authorization port.Authorization,
	id string,
) (managedservicev1.ServiceInstallation, error) {
	if ctx == nil || port.ValidateAuthorization(authorization) != nil ||
		managedservicev1.ValidateInstallationID(id) != nil {
		return managedservicev1.ServiceInstallation{}, ErrInvalidArgument
	}
	var result managedservicev1.ServiceInstallation
	err := service.withTransaction(ctx, authorization.TenantID, ReadOnly, func(transaction Transaction) error {
		var err error
		result, err = transaction.GetServiceInstallation(ctx, id)
		return err
	})
	if err != nil {
		return managedservicev1.ServiceInstallation{}, err
	}
	return result, nil
}

func (service *Service) GetInstallationOperation(
	ctx context.Context,
	authorization port.Authorization,
	installationID string,
) (managedservicev1.InstallationOperation, error) {
	installation, err := service.GetServiceInstallation(ctx, authorization, installationID)
	if err != nil {
		return managedservicev1.InstallationOperation{}, err
	}
	return installation.Operation, nil
}

// BindServiceRole proves the path resource exists in the IAM-derived Account
// before forwarding one normalized, idempotent workload consent command. The
// caller cannot select the Account, Role, service principal or purpose.
func (service *Service) BindServiceRole(
	ctx context.Context,
	command BindServiceRoleCommand,
) (managedservicev1.ServiceRoleBindingReceipt, error) {
	if ctx == nil || port.ValidateAuthorization(command.Authorization) != nil ||
		command.Authorization.SubjectType != port.SubjectUser || command.Credential == "" ||
		managedservicev1.ValidateInstallationID(command.InstallationID) != nil ||
		managedservicev1.ValidateBindServiceRoleRequest(command.Request) != nil ||
		managedservicev1.ValidateIdempotencyKey(command.IdempotencyKey) != nil {
		return managedservicev1.ServiceRoleBindingReceipt{}, ErrInvalidArgument
	}
	var installation managedservicev1.ServiceInstallation
	err := service.withTransaction(ctx, command.Authorization.TenantID, ReadOnly, func(transaction Transaction) error {
		var readErr error
		installation, readErr = transaction.GetServiceInstallation(ctx, command.InstallationID)
		return readErr
	})
	if err != nil {
		return managedservicev1.ServiceRoleBindingReceipt{}, err
	}
	if managedservicev1.ValidateServiceInstallation(installation) != nil || installation.ID != command.InstallationID {
		return managedservicev1.ServiceRoleBindingReceipt{}, ErrRepositoryUnavailable
	}
	requestID := serviceRoleBindingRequestID(command.IdempotencyKey)
	request := port.AuthorizationRequest{
		Credential: command.Credential, Action: port.AuthorizeInstallationRoleBind,
		Resource:     port.ResourceReference{Kind: port.ResourceServiceInstallation, ID: installation.ID},
		ResourceMode: iamv1.AuthorizationResourceInstance, RequestID: requestID,
	}
	result, err := service.workloadRoleAuthority.BindWorkloadRole(ctx, command.Request.Template, request)
	if err != nil {
		return managedservicev1.ServiceRoleBindingReceipt{}, err
	}
	if iamv1.ValidateServiceLinkedRoleAccess(result) != nil || len(result.Bindings) != 1 ||
		result.Relation.Role.AccountID != iamv1.AccountID(command.Authorization.TenantID) ||
		result.Relation.Template != command.Request.Template ||
		result.Bindings[0].AccountID != iamv1.AccountID(command.Authorization.TenantID) ||
		result.Bindings[0].RoleID != result.Relation.Role.ID ||
		result.Bindings[0].Template != command.Request.Template ||
		result.Bindings[0].Workload != (iamv1.ResourceReference{
			Kind: iamv1.ResourceServiceInstallation, ID: installation.ID,
		}) {
		return managedservicev1.ServiceRoleBindingReceipt{}, port.ErrAuthorizationUnavailable
	}
	binding := result.Bindings[0]
	assumeRequestID := serviceRoleSessionRequestID(binding.ID, command.Authorization.RequestID)
	readRequest := port.WorkloadRoleAuthorizationRequest{
		Action:       port.AuthorizeInstallationRead,
		Resource:     port.ResourceReference{Kind: port.ResourceServiceInstallation, ID: installation.ID},
		ResourceMode: iamv1.AuthorizationResourceInstance,
		RequestID:    serviceRoleBusinessReadRequestID(binding.ID, command.Authorization.RequestID),
	}
	lease, err := service.workloadRoleRuntime.AssumeWorkloadRole(ctx, binding.ID, assumeRequestID, readRequest)
	if err != nil {
		return managedservicev1.ServiceRoleBindingReceipt{}, err
	}
	runtimeAuthorization := lease.Authorization()
	if port.ValidateWorkloadRoleAuthorizationForRequest(runtimeAuthorization, binding.ID, readRequest) != nil ||
		runtimeAuthorization.TenantID != command.Authorization.TenantID || runtimeAuthorization.RoleID != binding.RoleID ||
		runtimeAuthorization.SourceServicePrincipalID != result.Relation.ServicePrincipal.PrincipalID {
		_ = lease.Release(ctx)
		return managedservicev1.ServiceRoleBindingReceipt{}, port.ErrAuthorizationUnavailable
	}
	var serviceRead managedservicev1.ServiceInstallation
	readErr := service.withTransaction(ctx, runtimeAuthorization.TenantID, ReadOnly, func(transaction Transaction) error {
		var transactionErr error
		serviceRead, transactionErr = transaction.GetServiceInstallation(ctx, installation.ID)
		return transactionErr
	})
	releaseErr := lease.Release(ctx)
	if readErr != nil {
		if releaseErr != nil {
			return managedservicev1.ServiceRoleBindingReceipt{}, errors.Join(readErr, releaseErr)
		}
		return managedservicev1.ServiceRoleBindingReceipt{}, readErr
	}
	if releaseErr != nil {
		return managedservicev1.ServiceRoleBindingReceipt{}, releaseErr
	}
	if managedservicev1.ValidateServiceInstallation(serviceRead) != nil || !reflect.DeepEqual(serviceRead, installation) {
		return managedservicev1.ServiceRoleBindingReceipt{}, ErrRepositoryUnavailable
	}
	receipt := managedservicev1.ServiceRoleBindingReceipt{
		Kind: "ServiceRoleBindingReceipt", ServiceInstallationID: installation.ID,
		BindingID: binding.ID, RoleID: binding.RoleID, Template: binding.Template,
		Status: binding.Status, ResourceVersion: binding.ResourceVersion, CreatedAt: binding.CreatedAt,
	}
	if managedservicev1.ValidateServiceRoleBindingReceipt(receipt) != nil {
		return managedservicev1.ServiceRoleBindingReceipt{}, port.ErrAuthorizationUnavailable
	}
	return receipt, nil
}

// UnbindServiceRole proves both path resources without treating either as an
// authority selector. IAM recovers the Account, Role, template, workload and
// service principal from the existing binding and performs its single
// terminal transition under the same USER and service credentials.
func (service *Service) UnbindServiceRole(
	ctx context.Context,
	command UnbindServiceRoleCommand,
) (managedservicev1.ServiceRoleUnbindingReceipt, error) {
	if ctx == nil || port.ValidateAuthorization(command.Authorization) != nil ||
		command.Authorization.SubjectType != port.SubjectUser || command.Credential == "" ||
		managedservicev1.ValidateInstallationID(command.InstallationID) != nil ||
		iamv1.ValidateID("bindingId", string(command.BindingID)) != nil ||
		managedservicev1.ValidateUnbindServiceRoleRequest(command.Request) != nil ||
		managedservicev1.ValidateIdempotencyKey(command.IdempotencyKey) != nil {
		return managedservicev1.ServiceRoleUnbindingReceipt{}, ErrInvalidArgument
	}
	var installation managedservicev1.ServiceInstallation
	err := service.withTransaction(ctx, command.Authorization.TenantID, ReadOnly, func(transaction Transaction) error {
		var readErr error
		installation, readErr = transaction.GetServiceInstallation(ctx, command.InstallationID)
		return readErr
	})
	if err != nil {
		return managedservicev1.ServiceRoleUnbindingReceipt{}, err
	}
	if managedservicev1.ValidateServiceInstallation(installation) != nil || installation.ID != command.InstallationID {
		return managedservicev1.ServiceRoleUnbindingReceipt{}, ErrRepositoryUnavailable
	}
	requestID := serviceRoleUnbindingRequestID(command.IdempotencyKey)
	request := port.AuthorizationRequest{
		Credential: command.Credential, Action: port.AuthorizeInstallationRoleUnbind,
		Resource:     port.ResourceReference{Kind: port.ResourceServiceInstallation, ID: installation.ID},
		ResourceMode: iamv1.AuthorizationResourceInstance, RequestID: requestID,
	}
	binding, err := service.workloadRoleAuthority.RevokeWorkloadRole(
		ctx, command.BindingID, command.Request.ResourceVersion, request,
	)
	if err != nil {
		return managedservicev1.ServiceRoleUnbindingReceipt{}, err
	}
	if iamv1.ValidateWorkloadRoleBinding(binding) != nil ||
		binding.ID != command.BindingID || binding.AccountID != iamv1.AccountID(command.Authorization.TenantID) ||
		binding.Workload != (iamv1.ResourceReference{Kind: iamv1.ResourceServiceInstallation, ID: installation.ID}) ||
		binding.Status != iamv1.WorkloadRoleBindingRevoked || binding.ResourceVersion != command.Request.ResourceVersion+1 ||
		binding.RevokedAt == nil {
		return managedservicev1.ServiceRoleUnbindingReceipt{}, port.ErrAuthorizationUnavailable
	}
	receipt := managedservicev1.ServiceRoleUnbindingReceipt{
		Kind: "ServiceRoleUnbindingReceipt", ServiceInstallationID: installation.ID,
		BindingID: binding.ID, RoleID: binding.RoleID, Template: binding.Template,
		Status: binding.Status, ResourceVersion: binding.ResourceVersion,
		CreatedAt: binding.CreatedAt, RevokedAt: *binding.RevokedAt,
	}
	if managedservicev1.ValidateServiceRoleUnbindingReceipt(receipt) != nil {
		return managedservicev1.ServiceRoleUnbindingReceipt{}, port.ErrAuthorizationUnavailable
	}
	return receipt, nil
}

func (service *Service) ActivateQuota(
	ctx context.Context,
	command ActivateQuotaCommand,
) (managedservicev1.QuotaEntitlement, bool, error) {
	if ctx == nil || port.ValidateAuthorization(command.Authorization) != nil ||
		managedservicev1.ValidateActivateQuotaRequest(command.Request) != nil ||
		managedservicev1.ValidateIdempotencyKey(command.IdempotencyKey) != nil {
		return managedservicev1.QuotaEntitlement{}, false, ErrInvalidArgument
	}
	offering, _, found := service.catalog.Resolve(command.Request.OfferingID, command.Request.QuotaShapeID)
	if !found {
		return managedservicev1.QuotaEntitlement{}, false, ErrInvalidArgument
	}
	digest, err := requestDigest(command.Request)
	if err != nil {
		return managedservicev1.QuotaEntitlement{}, false, ErrRepositoryUnavailable
	}
	id, err := service.newQuotaID()
	if err != nil || managedservicev1.ValidateID("quota.id", id) != nil {
		return managedservicev1.QuotaEntitlement{}, false, ErrRepositoryUnavailable
	}
	draft := QuotaDraft{
		ID: id, OfferingID: offering.ID, QuotaShapeID: command.Request.QuotaShapeID,
		PurchasedCount: command.Request.InstanceCount,
		IdempotencyKey: command.IdempotencyKey, RequestDigest: digest,
		ActorType:     command.Authorization.SubjectType,
		ActorID:       command.Authorization.SubjectID,
		IAMDecisionID: command.Authorization.DecisionID,
		RequestID:     command.Authorization.RequestID,
	}
	var result managedservicev1.QuotaEntitlement
	replayed := false
	err = service.withWriteRetry(ctx, command.Authorization.TenantID, func(transaction Transaction) error {
		existing, existingDigest, exists, findErr := transaction.FindQuotaReplay(ctx, command.IdempotencyKey)
		if findErr != nil {
			return findErr
		}
		if exists {
			if existingDigest != digest {
				return ErrIdempotencyConflict
			}
			result, replayed = existing, true
			return nil
		}
		created, createErr := transaction.InsertQuotaEntitlement(ctx, draft)
		if createErr != nil {
			return createErr
		}
		event, eventErr := quotaAuditEvent(command.Authorization, created, digest)
		if eventErr != nil {
			return ErrRepositoryUnavailable
		}
		if appendErr := transaction.AppendAuditEvent(ctx, event); appendErr != nil {
			return appendErr
		}
		result = created
		return nil
	})
	if err != nil {
		return managedservicev1.QuotaEntitlement{}, false, err
	}
	if managedservicev1.ValidateQuotaEntitlement(result) != nil {
		return managedservicev1.QuotaEntitlement{}, false, ErrRepositoryUnavailable
	}
	return result, replayed, nil
}

func (service *Service) CreateInstallation(
	ctx context.Context,
	command CreateInstallationCommand,
) (managedservicev1.ServiceInstallation, bool, error) {
	if ctx == nil || port.ValidateAuthorization(command.Authorization) != nil ||
		managedservicev1.ValidateCreateInstallationRequest(command.Request) != nil ||
		managedservicev1.ValidateIdempotencyKey(command.IdempotencyKey) != nil {
		return managedservicev1.ServiceInstallation{}, false, ErrInvalidArgument
	}
	if command.Request.RegionID != service.region.ID || service.region.State != managedservicev1.RegionReady {
		return managedservicev1.ServiceInstallation{}, false, ErrRegionUnavailable
	}
	digest, err := requestDigest(command.Request)
	if err != nil {
		return managedservicev1.ServiceInstallation{}, false, ErrRepositoryUnavailable
	}
	operationID, err := service.newOperationID()
	if err != nil || managedservicev1.ValidateID("operation.id", operationID) != nil {
		return managedservicev1.ServiceInstallation{}, false, ErrRepositoryUnavailable
	}
	var result managedservicev1.ServiceInstallation
	replayed := false
	err = service.withWriteRetry(ctx, command.Authorization.TenantID, func(transaction Transaction) error {
		existing, existingDigest, exists, findErr := transaction.FindInstallationReplay(ctx, command.IdempotencyKey)
		if findErr != nil {
			return findErr
		}
		if exists {
			if existingDigest != digest {
				return ErrIdempotencyConflict
			}
			result, replayed = existing, true
			return nil
		}
		entitlement, quotaErr := transaction.GetQuotaEntitlementForUpdate(ctx, command.Request.QuotaEntitlementID)
		if quotaErr != nil {
			return quotaErr
		}
		if entitlement.OfferingID != command.Request.OfferingID ||
			entitlement.PurchasedCount <= entitlement.ReservedCount+entitlement.ConsumedCount {
			return ErrQuotaExhausted
		}
		offering, _, found := service.catalog.Resolve(entitlement.OfferingID, entitlement.QuotaShapeID)
		if !found {
			return ErrInvalidArgument
		}
		created, createErr := transaction.ReserveInstallation(ctx, InstallationDraft{
			ID: command.Request.ID, Name: command.Request.Name,
			OfferingID: offering.ID, EngineVersion: offering.EngineVersion,
			QuotaEntitlementID: entitlement.ID, RegionID: service.region.ID,
			OperationID: operationID, IdempotencyKey: command.IdempotencyKey,
			RequestDigest: digest,
			ActorType:     command.Authorization.SubjectType,
			ActorID:       command.Authorization.SubjectID,
			IAMDecisionID: command.Authorization.DecisionID,
			RequestID:     command.Authorization.RequestID,
		}, entitlement.ResourceVersion)
		if createErr != nil {
			return createErr
		}
		event, eventErr := installationAuditEvent(command.Authorization, created, digest)
		if eventErr != nil {
			return ErrRepositoryUnavailable
		}
		if appendErr := transaction.AppendAuditEvent(ctx, event); appendErr != nil {
			return appendErr
		}
		result = created
		return nil
	})
	if err != nil {
		return managedservicev1.ServiceInstallation{}, false, err
	}
	if managedservicev1.ValidateServiceInstallation(result) != nil {
		return managedservicev1.ServiceInstallation{}, false, ErrRepositoryUnavailable
	}
	return result, replayed, nil
}

func quotaAuditEvent(
	authorization port.Authorization,
	quota managedservicev1.QuotaEntitlement,
	requestDigest string,
) (audit.Event, error) {
	event := audit.Event{
		SchemaVersion: "v1", EventID: managedAuditEventID(audit.QuotaEntitlementActivated, quota.ID),
		TenantID: audit.TenantID(authorization.TenantID),
		Actor:    auditActor(authorization), IAMDecisionID: authorization.DecisionID,
		Action: audit.QuotaEntitlementActivated,
		Target: audit.TargetReference{
			Kind: audit.TargetQuotaEntitlement, ID: audit.ResourceID(quota.ID),
		},
		RequestDigest: requestDigest, Result: audit.Succeeded,
		RequestID: authorization.RequestID, OccurredAt: quota.ActivatedAt,
	}
	return event, audit.ValidateEvent(event)
}

func installationAuditEvent(
	authorization port.Authorization,
	installation managedservicev1.ServiceInstallation,
	requestDigest string,
) (audit.Event, error) {
	event := audit.Event{
		SchemaVersion: "v1",
		EventID: managedAuditEventID(
			audit.ServiceInstallationCreated,
			installation.Operation.ID,
		),
		TenantID: audit.TenantID(authorization.TenantID),
		Actor:    auditActor(authorization), IAMDecisionID: authorization.DecisionID,
		Action: audit.ServiceInstallationCreated,
		Target: audit.TargetReference{
			Kind: audit.TargetServiceInstallation, ID: audit.ResourceID(installation.ID),
		},
		OperationID:   audit.OperationID(installation.Operation.ID),
		RequestDigest: requestDigest, Result: audit.Accepted,
		RequestID: authorization.RequestID, OccurredAt: installation.CreatedAt,
	}
	return event, audit.ValidateEvent(event)
}

func auditActor(authorization port.Authorization) audit.ActorReference {
	actorType := audit.ActorUser
	if authorization.SubjectType == port.SubjectServiceAccount {
		actorType = audit.ActorServiceAccount
	}
	return audit.ActorReference{Type: actorType, ID: authorization.SubjectID}
}

func managedAuditEventID(action, resourceID string) string {
	digest := sha256.Sum256([]byte(
		"matrix-managedservice-audit-event-v1\x00" + action + "\x00" + resourceID,
	))
	return "audit-" + hex.EncodeToString(digest[:])
}

func serviceRoleBindingRequestID(idempotencyKey string) string {
	digest := sha256.Sum256([]byte(
		"matrix-managedservice-service-role-binding-v1\x00" + idempotencyKey,
	))
	return "msrb-" + hex.EncodeToString(digest[:])
}

func serviceRoleUnbindingRequestID(idempotencyKey string) string {
	digest := sha256.Sum256([]byte(
		"matrix-managedservice-service-role-unbinding-v1\x00" + idempotencyKey,
	))
	return "msru-" + hex.EncodeToString(digest[:])
}

func serviceRoleSessionRequestID(bindingID iamv1.WorkloadRoleBindingID, publicRequestID string) string {
	digest := sha256.Sum256([]byte(
		"matrix-managedservice-service-role-session-v1\x00" + string(bindingID) + "\x00" + publicRequestID,
	))
	return "msrs-" + hex.EncodeToString(digest[:])
}

func serviceRoleBusinessReadRequestID(bindingID iamv1.WorkloadRoleBindingID, publicRequestID string) string {
	digest := sha256.Sum256([]byte(
		"matrix-managedservice-service-role-read-v1\x00" + string(bindingID) + "\x00" + publicRequestID,
	))
	return "msrr-" + hex.EncodeToString(digest[:])
}

func (service *Service) withWriteRetry(
	ctx context.Context,
	tenantID string,
	workflow func(Transaction) error,
) error {
	var last error
	for range service.maximumWriteAttempts {
		last = service.withTransaction(ctx, tenantID, ReadWrite, workflow)
		if !errors.Is(last, ErrTransactionRetry) {
			return last
		}
	}
	return fmt.Errorf("%w: %v", ErrRepositoryUnavailable, last)
}

func (service *Service) withTransaction(
	ctx context.Context,
	tenantID string,
	mode TransactionMode,
	workflow func(Transaction) error,
) error {
	transaction, err := service.repository.Begin(ctx, tenantID, mode)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = transaction.Rollback(context.Background())
		}
	}()
	if err := workflow(transaction); err != nil {
		return err
	}
	if err := transaction.Commit(ctx); err != nil {
		return err
	}
	committed = true
	return nil
}

func requestDigest(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func newID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}
