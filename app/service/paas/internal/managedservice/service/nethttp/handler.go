// Package nethttp exposes the authenticated managed-service browser workflow.
package nethttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"sort"
	"strings"

	iamv1 "github.com/xiak/matrix/api/iam/v1"
	managedservicev1 "github.com/xiak/matrix/api/managedservice/v1"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/port"
	"github.com/xiak/matrix/app/service/paas/internal/managedservice/usecase"
)

type Workflow interface {
	ListServices(context.Context, port.Authorization) (managedservicev1.ServiceDefinitionList, error)
	GetService(context.Context, port.Authorization, string) (managedservicev1.ServiceDefinition, error)
	ListServiceActivations(context.Context, port.Authorization) (managedservicev1.ServiceActivationList, error)
	GetServiceActivation(context.Context, port.Authorization, string) (managedservicev1.ServiceActivation, error)
	ActivateService(context.Context, usecase.ActivateServiceCommand) (managedservicev1.ServiceActivation, bool, error)
	ListOfferings(context.Context, port.Authorization) (managedservicev1.ServiceOfferingList, error)
	GetOffering(context.Context, port.Authorization, string) (managedservicev1.ServiceOffering, error)
	ListRegions(context.Context, port.Authorization) (managedservicev1.RegionList, error)
	GetRegion(context.Context, port.Authorization, string) (managedservicev1.Region, error)
	ListQuotaEntitlements(context.Context, port.Authorization) (managedservicev1.QuotaEntitlementList, error)
	GetQuotaEntitlement(context.Context, port.Authorization, string) (managedservicev1.QuotaEntitlement, error)
	ListServiceInstallations(context.Context, port.Authorization) (managedservicev1.ServiceInstallationList, error)
	GetServiceInstallation(context.Context, port.Authorization, string) (managedservicev1.ServiceInstallation, error)
	GetInstallationOperation(context.Context, port.Authorization, string) (managedservicev1.InstallationOperation, error)
	ListCommandResults(context.Context, usecase.ListCommandResultsQuery) (managedservicev1.CommandResultList, error)
	BindServiceRole(context.Context, usecase.BindServiceRoleCommand) (managedservicev1.ServiceRoleBindingReceipt, error)
	UnbindServiceRole(context.Context, usecase.UnbindServiceRoleCommand) (managedservicev1.ServiceRoleUnbindingReceipt, error)
	ActivateQuota(context.Context, usecase.ActivateQuotaCommand) (managedservicev1.QuotaEntitlement, bool, error)
	CreateInstallation(context.Context, usecase.CreateInstallationCommand) (managedservicev1.ServiceInstallation, bool, error)
	TerminateInstallation(context.Context, usecase.TerminateInstallationCommand) (managedservicev1.ServiceInstallation, bool, error)
}

type Config struct {
	NewRequestID func() (string, error)
}

type handler struct {
	authorizer port.Authorizer
	workflow   Workflow
	config     Config
}

func NewHandler(authorizer port.Authorizer, workflow Workflow, config Config) (http.Handler, error) {
	if authorizer == nil || workflow == nil {
		return nil, errors.New("managed-service HTTP dependencies are required")
	}
	if config.NewRequestID == nil {
		config.NewRequestID = func() (string, error) { return newID("request-") }
	}
	value := &handler{authorizer: authorizer, workflow: workflow, config: config}
	routes := http.NewServeMux()
	routes.HandleFunc("GET /managed-services/v1/services", value.listServices)
	routes.HandleFunc("GET /managed-services/v1/services/{serviceId}", value.getService)
	routes.HandleFunc("GET /managed-services/v1/service-activations", value.listServiceActivations)
	routes.HandleFunc("POST /managed-services/v1/service-activations", value.activateService)
	routes.HandleFunc("GET /managed-services/v1/service-activations/{serviceId}", value.getServiceActivation)
	routes.HandleFunc("GET /managed-services/v1/offerings", value.listOfferings)
	routes.HandleFunc("GET /managed-services/v1/offerings/{offeringId}", value.getOffering)
	routes.HandleFunc("GET /managed-services/v1/regions", value.listRegions)
	routes.HandleFunc("GET /managed-services/v1/regions/{regionId}", value.getRegion)
	routes.HandleFunc("GET /managed-services/v1/quota-entitlements", value.listQuotaEntitlements)
	routes.HandleFunc("POST /managed-services/v1/quota-entitlements", value.activateQuota)
	routes.HandleFunc("GET /managed-services/v1/quota-entitlements/{quotaEntitlementId}", value.getQuotaEntitlement)
	routes.HandleFunc("GET /managed-services/v1/service-installations", value.listServiceInstallations)
	routes.HandleFunc("POST /managed-services/v1/service-installations", value.createInstallation)
	routes.HandleFunc("GET /managed-services/v1/service-installations/{installationId}", value.getServiceInstallation)
	routes.HandleFunc("GET /managed-services/v1/service-installations/{installationId}/operation", value.getInstallationOperation)
	routes.HandleFunc("POST /managed-services/v1/service-installations/{installationId}/termination", value.terminateInstallation)
	routes.HandleFunc("POST /managed-services/v1/service-installations/{installationId}/service-role-bindings", value.bindServiceRole)
	routes.HandleFunc("DELETE /managed-services/v1/service-installations/{installationId}/service-role-bindings/{bindingId}", value.unbindServiceRole)
	routes.HandleFunc("GET /managed-services/v1/command-results/{commandType}", value.listCommandResults)
	return routes, nil
}

func (value *handler) listCommandResults(response http.ResponseWriter, request *http.Request) {
	commandType := managedservicev1.CommandType(request.PathValue("commandType"))
	if managedservicev1.ValidateCommandType(commandType) != nil {
		writeProblem(response, "request-invalid", http.StatusBadRequest,
			managedservicev1.ErrorInvalidArgument, "Invalid argument", "command type is invalid", false)
		return
	}
	action, resourceKind := port.AuthorizeInstallationRead, port.ResourceServiceInstallation
	if commandType == managedservicev1.CommandQuotaActivate {
		action, resourceKind = port.AuthorizeQuotaEntitlementRead, port.ResourceQuotaEntitlement
	}
	authorization, requestID, ok := value.authorizeCollection(
		response, request, action, resourceKind, iamv1.AuthorizationCollectionList,
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.ListCommandResults(request.Context(), usecase.ListCommandResultsQuery{
		Authorization: authorization, Credential: request.Header.Get("Authorization"), CommandType: commandType,
	})
	response.Header().Set("Cache-Control", "no-store")
	writeResult(response, requestID, result, err)
}

func (value *handler) listServices(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeServiceDefinitionRead, port.ResourceServiceDefinition, iamv1.AuthorizationCollectionList,
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.ListServices(request.Context(), authorization)
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	filtered, err := value.filterServices(request, requestID, authorization, result)
	if err != nil {
		writeAuthorizationError(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusOK, filtered)
}

func (value *handler) filterServices(
	request *http.Request,
	correlationID string,
	collection port.Authorization,
	result managedservicev1.ServiceDefinitionList,
) (managedservicev1.ServiceDefinitionList, error) {
	if request == nil || result.Kind != "ServiceDefinitionList" || len(result.Items) < 1 ||
		len(result.Items) > iamv1.MaxAuthorizationBatchItems || port.ValidateAuthorization(collection) != nil {
		return managedservicev1.ServiceDefinitionList{}, port.ErrAuthorizationUnavailable
	}
	items := append([]managedservicev1.ServiceDefinition(nil), result.Items...)
	sort.Slice(items, func(left, right int) bool { return items[left].ID < items[right].ID })
	batch := port.AuthorizationBatchRequest{
		Credential: request.Header.Get("Authorization"),
		Requests:   make([]port.AuthorizationRequest, len(items)),
	}
	previous := ""
	for index, definition := range items {
		if managedservicev1.ValidateServiceDefinition(definition) != nil || definition.ID <= previous {
			return managedservicev1.ServiceDefinitionList{}, port.ErrAuthorizationUnavailable
		}
		itemRequestID, err := value.config.NewRequestID()
		if err != nil || managedservicev1.ValidateID("requestId", itemRequestID) != nil {
			return managedservicev1.ServiceDefinitionList{}, port.ErrAuthorizationUnavailable
		}
		batch.Requests[index] = port.AuthorizationRequest{
			Credential: batch.Credential, Action: port.AuthorizeServiceDefinitionRead,
			Resource:     port.ResourceReference{Kind: port.ResourceServiceDefinition, ID: definition.ID},
			ResourceMode: iamv1.AuthorizationResourceInstance,
			RequestID:    itemRequestID, CorrelationID: correlationID,
		}
		previous = definition.ID
	}
	authorization, err := value.authorizer.AuthorizeBatch(request.Context(), batch)
	if err != nil || port.ValidateAuthorizationBatchForRequest(authorization, batch) != nil ||
		authorization.TenantID != collection.TenantID || !authorization.Subject.Equal(collection.Subject) {
		if err != nil {
			return managedservicev1.ServiceDefinitionList{}, err
		}
		return managedservicev1.ServiceDefinitionList{}, port.ErrAuthorizationUnavailable
	}
	allowed := make([]managedservicev1.ServiceDefinition, 0, len(items))
	for index, item := range items {
		if authorization.Items[index].Allowed {
			allowed = append(allowed, item)
		}
	}
	capabilityRequestID, err := value.config.NewRequestID()
	if err != nil || managedservicev1.ValidateID("requestId", capabilityRequestID) != nil {
		return managedservicev1.ServiceDefinitionList{}, port.ErrAuthorizationUnavailable
	}
	capabilityRequest := port.AuthorizationRequest{
		Credential: batch.Credential, Action: port.AuthorizeServiceActivationActivate,
		Resource:        port.ResourceReference{Kind: port.ResourceServiceActivation, ID: "collection"},
		ResourceMode:    iamv1.AuthorizationResourceCollection,
		CollectionUsage: iamv1.AuthorizationCollectionCreate,
		RequestID:       capabilityRequestID, CorrelationID: correlationID,
	}
	capabilityDecision, err := value.authorizer.Decide(request.Context(), capabilityRequest)
	if err != nil || port.ValidateAuthorizationDecisionForRequest(capabilityDecision, capabilityRequest) != nil ||
		capabilityDecision.Allowed && (capabilityDecision.TenantID != collection.TenantID ||
			capabilityDecision.Subject == nil || !capabilityDecision.Subject.Equal(collection.Subject)) {
		if err != nil {
			return managedservicev1.ServiceDefinitionList{}, err
		}
		return managedservicev1.ServiceDefinitionList{}, port.ErrAuthorizationUnavailable
	}
	capability := iamv1.ActionCapability{
		Action:    iamv1.ActionManagedServiceActivationActivate,
		Resource:  iamv1.ResourceReference{Kind: iamv1.ResourceServiceActivation, ID: "collection"},
		Available: capabilityDecision.Allowed,
	}
	if !capability.Available {
		capability.RestrictionReason = iamv1.CapabilityAuthorityRequired
	}
	filtered := managedservicev1.ServiceDefinitionList{
		Kind: "ServiceDefinitionList", Items: allowed, ActivationCapability: capability,
	}
	if managedservicev1.ValidateServiceDefinitionList(filtered) != nil {
		return managedservicev1.ServiceDefinitionList{}, port.ErrAuthorizationUnavailable
	}
	return filtered, nil
}

func (value *handler) getService(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("serviceId")
	authorization, requestID, ok := value.authorizeResource(
		response, request, port.AuthorizeServiceDefinitionRead, port.ResourceServiceDefinition, id,
		iamv1.AuthorizationResourceInstance, "",
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.GetService(request.Context(), authorization, id)
	writeResult(response, requestID, result, err)
}

func (value *handler) listServiceActivations(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeServiceActivationRead, port.ResourceServiceActivation, iamv1.AuthorizationCollectionList,
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.ListServiceActivations(request.Context(), authorization)
	writeResult(response, requestID, result, err)
}

func (value *handler) getServiceActivation(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("serviceId")
	authorization, requestID, ok := value.authorizeResource(
		response, request, port.AuthorizeServiceActivationRead, port.ResourceServiceActivation, id,
		iamv1.AuthorizationResourceInstance, "",
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.GetServiceActivation(request.Context(), authorization, id)
	writeResult(response, requestID, result, err)
}

func (value *handler) activateService(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeServiceActivationActivate, port.ResourceServiceActivation, iamv1.AuthorizationCollectionCreate,
	)
	if !ok {
		return
	}
	body, ok := decodeRequest[managedservicev1.ActivateServiceRequest](response, request, requestID)
	if !ok {
		return
	}
	result, replayed, err := value.workflow.ActivateService(request.Context(), usecase.ActivateServiceCommand{
		Authorization: authorization, Request: body,
		IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	response.Header().Set("Location", "/managed-services/v1/service-activations/"+result.Service.ID)
	writeJSON(response, status, result)
}

func (value *handler) listOfferings(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeOfferingRead, port.ResourceServiceOffering, iamv1.AuthorizationCollectionList,
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.ListOfferings(request.Context(), authorization)
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	filtered, err := value.filterOfferings(request, requestID, authorization, result)
	if err != nil {
		writeAuthorizationError(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusOK, filtered)
}

func (value *handler) filterOfferings(
	request *http.Request,
	correlationID string,
	collection port.Authorization,
	result managedservicev1.ServiceOfferingList,
) (managedservicev1.ServiceOfferingList, error) {
	if request == nil || result.Kind != "ServiceOfferingList" || len(result.Items) < 1 ||
		len(result.Items) > iamv1.MaxAuthorizationBatchItems || port.ValidateAuthorization(collection) != nil {
		return managedservicev1.ServiceOfferingList{}, port.ErrAuthorizationUnavailable
	}
	items := append([]managedservicev1.ServiceOffering(nil), result.Items...)
	sort.Slice(items, func(left, right int) bool { return items[left].ID < items[right].ID })
	batch := port.AuthorizationBatchRequest{
		Credential: request.Header.Get("Authorization"),
		Requests:   make([]port.AuthorizationRequest, len(items)),
	}
	previous := ""
	for index, offering := range items {
		if managedservicev1.ValidateServiceOffering(offering) != nil || offering.ID <= previous {
			return managedservicev1.ServiceOfferingList{}, port.ErrAuthorizationUnavailable
		}
		itemRequestID, err := value.config.NewRequestID()
		if err != nil || managedservicev1.ValidateID("requestId", itemRequestID) != nil {
			return managedservicev1.ServiceOfferingList{}, port.ErrAuthorizationUnavailable
		}
		batch.Requests[index] = port.AuthorizationRequest{
			Credential: batch.Credential, Action: port.AuthorizeOfferingRead,
			Resource:     port.ResourceReference{Kind: port.ResourceServiceOffering, ID: offering.ID},
			ResourceMode: iamv1.AuthorizationResourceInstance,
			RequestID:    itemRequestID, CorrelationID: correlationID,
		}
		previous = offering.ID
	}
	authorization, err := value.authorizer.AuthorizeBatch(request.Context(), batch)
	if err != nil || port.ValidateAuthorizationBatchForRequest(authorization, batch) != nil ||
		authorization.TenantID != collection.TenantID || !authorization.Subject.Equal(collection.Subject) {
		if err != nil {
			return managedservicev1.ServiceOfferingList{}, err
		}
		return managedservicev1.ServiceOfferingList{}, port.ErrAuthorizationUnavailable
	}
	allowed := make([]managedservicev1.ServiceOffering, 0, len(items))
	for index, item := range items {
		if authorization.Items[index].Allowed {
			allowed = append(allowed, item)
		}
	}
	return managedservicev1.ServiceOfferingList{Kind: "ServiceOfferingList", Items: allowed}, nil
}

func (value *handler) getOffering(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("offeringId")
	authorization, requestID, ok := value.authorizeResource(
		response, request, port.AuthorizeOfferingRead, port.ResourceServiceOffering, id, iamv1.AuthorizationResourceInstance, "",
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.GetOffering(request.Context(), authorization, id)
	writeResult(response, requestID, result, err)
}

func (value *handler) listRegions(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeRegionRead, port.ResourceRegion, iamv1.AuthorizationCollectionList,
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.ListRegions(request.Context(), authorization)
	writeResult(response, requestID, result, err)
}

func (value *handler) getRegion(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("regionId")
	authorization, requestID, ok := value.authorizeResource(
		response, request, port.AuthorizeRegionRead, port.ResourceRegion, id, iamv1.AuthorizationResourceInstance, "",
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.GetRegion(request.Context(), authorization, id)
	writeResult(response, requestID, result, err)
}

func (value *handler) listQuotaEntitlements(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeQuotaEntitlementRead, port.ResourceQuotaEntitlement, iamv1.AuthorizationCollectionList,
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.ListQuotaEntitlements(request.Context(), authorization)
	writeResult(response, requestID, result, err)
}

func (value *handler) getQuotaEntitlement(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("quotaEntitlementId")
	authorization, requestID, ok := value.authorizeResource(
		response, request, port.AuthorizeQuotaEntitlementRead, port.ResourceQuotaEntitlement, id, iamv1.AuthorizationResourceInstance, "",
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.GetQuotaEntitlement(request.Context(), authorization, id)
	writeResult(response, requestID, result, err)
}

func (value *handler) activateQuota(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeQuotaEntitlementActivate, port.ResourceQuotaEntitlement, iamv1.AuthorizationCollectionCreate,
	)
	if !ok {
		return
	}
	body, ok := decodeRequest[managedservicev1.ActivateQuotaRequest](response, request, requestID)
	if !ok {
		return
	}
	result, replayed, err := value.workflow.ActivateQuota(request.Context(), usecase.ActivateQuotaCommand{
		Authorization: authorization, Request: body,
		IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	response.Header().Set("Location", "/managed-services/v1/quota-entitlements/"+result.ID)
	writeJSON(response, status, result)
}

func (value *handler) listServiceInstallations(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeInstallationRead, port.ResourceServiceInstallation, iamv1.AuthorizationCollectionList,
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.ListServiceInstallations(request.Context(), authorization)
	writeResult(response, requestID, result, err)
}

func (value *handler) getServiceInstallation(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("installationId")
	authorization, requestID, ok := value.authorizeResource(
		response, request, port.AuthorizeInstallationRead, port.ResourceServiceInstallation, id, iamv1.AuthorizationResourceInstance, "",
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.GetServiceInstallation(request.Context(), authorization, id)
	writeResult(response, requestID, result, err)
}

func (value *handler) getInstallationOperation(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("installationId")
	authorization, requestID, ok := value.authorizeResource(
		response, request, port.AuthorizeInstallationRead, port.ResourceServiceInstallation, id, iamv1.AuthorizationResourceInstance, "",
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, err := value.workflow.GetInstallationOperation(request.Context(), authorization, id)
	writeResult(response, requestID, result, err)
}

func (value *handler) createInstallation(response http.ResponseWriter, request *http.Request) {
	authorization, requestID, ok := value.authorizeCollection(
		response, request, port.AuthorizeInstallationCreate, port.ResourceServiceInstallation, iamv1.AuthorizationCollectionCreate,
	)
	if !ok {
		return
	}
	body, ok := decodeRequest[managedservicev1.CreateInstallationRequest](response, request, requestID)
	if !ok {
		return
	}
	result, replayed, err := value.workflow.CreateInstallation(request.Context(), usecase.CreateInstallationCommand{
		Authorization: authorization, Request: body,
		IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	status := http.StatusAccepted
	if replayed {
		status = http.StatusOK
	}
	response.Header().Set("Location", "/managed-services/v1/service-installations/"+result.ID)
	writeJSON(response, status, result)
}

func (value *handler) terminateInstallation(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("installationId")
	authorization, requestID, ok := value.authorizeResource(
		response, request, port.AuthorizeInstallationTerminate,
		port.ResourceServiceInstallation, id, iamv1.AuthorizationResourceInstance, "",
	)
	if !ok || !acceptsNoInput(response, request, requestID) {
		return
	}
	result, replayed, err := value.workflow.TerminateInstallation(
		request.Context(),
		usecase.TerminateInstallationCommand{
			Authorization: authorization, InstallationID: id,
			IdempotencyKey: request.Header.Get("Idempotency-Key"),
		},
	)
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	status := http.StatusAccepted
	if replayed {
		status = http.StatusOK
	}
	response.Header().Set("Location", "/managed-services/v1/service-installations/"+result.ID+"/operation")
	writeJSON(response, status, result)
}

func (value *handler) bindServiceRole(response http.ResponseWriter, request *http.Request) {
	id := request.PathValue("installationId")
	authorization, requestID, ok := value.authorizeResource(
		response, request, port.AuthorizeInstallationRoleBind, port.ResourceServiceInstallation, id,
		iamv1.AuthorizationResourceInstance, "",
	)
	if !ok || !acceptsNoQuery(response, request, requestID) {
		return
	}
	body, ok := decodeRequest[managedservicev1.BindServiceRoleRequest](response, request, requestID)
	if !ok {
		return
	}
	result, err := value.workflow.BindServiceRole(request.Context(), usecase.BindServiceRoleCommand{
		Authorization: authorization, Credential: request.Header.Get("Authorization"),
		InstallationID: id, Request: body, IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) unbindServiceRole(response http.ResponseWriter, request *http.Request) {
	installationID, bindingID := request.PathValue("installationId"), request.PathValue("bindingId")
	authorization, requestID, ok := value.authorizeResource(
		response, request, port.AuthorizeInstallationRoleUnbind, port.ResourceServiceInstallation, installationID,
		iamv1.AuthorizationResourceInstance, "",
	)
	if !ok || !acceptsNoQuery(response, request, requestID) {
		return
	}
	body, ok := decodeRequest[managedservicev1.UnbindServiceRoleRequest](response, request, requestID)
	if !ok {
		return
	}
	result, err := value.workflow.UnbindServiceRole(request.Context(), usecase.UnbindServiceRoleCommand{
		Authorization: authorization, Credential: request.Header.Get("Authorization"),
		InstallationID: installationID, BindingID: iamv1.WorkloadRoleBindingID(bindingID),
		Request: body, IdempotencyKey: request.Header.Get("Idempotency-Key"),
	})
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (value *handler) authorizeCollection(
	response http.ResponseWriter,
	request *http.Request,
	action iamv1.Action,
	resourceKind iamv1.ResourceKind,
	usage iamv1.AuthorizationCollectionUsage,
) (port.Authorization, string, bool) {
	return value.authorizeResource(response, request, action, resourceKind, "collection", iamv1.AuthorizationResourceCollection, usage)
}

func (value *handler) authorizeResource(
	response http.ResponseWriter,
	request *http.Request,
	action iamv1.Action,
	resourceKind iamv1.ResourceKind,
	resourceID string,
	mode iamv1.AuthorizationResourceMode,
	usage iamv1.AuthorizationCollectionUsage,
) (port.Authorization, string, bool) {
	requestID, err := value.config.NewRequestID()
	if err != nil || managedservicev1.ValidateID("requestId", requestID) != nil {
		writeProblem(response, "request-unavailable", http.StatusInternalServerError,
			managedservicev1.ErrorInternal, "Internal error", "request identity could not be established", false)
		return port.Authorization{}, "", false
	}
	response.Header().Set("X-Request-ID", requestID)
	if managedservicev1.ValidateID("resourceId", resourceID) != nil {
		writeProblem(response, requestID, http.StatusBadRequest,
			managedservicev1.ErrorInvalidArgument, "Invalid argument", "resource identity is invalid", false)
		return port.Authorization{}, requestID, false
	}
	authorizationRequest := port.AuthorizationRequest{
		Credential: request.Header.Get("Authorization"), Action: action,
		Resource:     port.ResourceReference{Kind: resourceKind, ID: resourceID},
		ResourceMode: mode, CollectionUsage: usage,
		RequestID: requestID,
	}
	if port.ValidateAuthorizationRequest(authorizationRequest) != nil {
		writeProblem(response, requestID, http.StatusUnauthorized,
			managedservicev1.ErrorUnauthenticated, "Unauthenticated", "a valid IAM credential is required", false)
		return port.Authorization{}, requestID, false
	}
	authorization, err := value.authorizer.Authorize(request.Context(), authorizationRequest)
	if err != nil {
		writeAuthorizationError(response, requestID, err)
		return port.Authorization{}, requestID, false
	}
	if port.ValidateAuthorizationForRequest(authorization, authorizationRequest) != nil {
		writeProblem(response, requestID, http.StatusServiceUnavailable,
			managedservicev1.ErrorIdentityUnavailable, "Identity unavailable", "IAM returned an invalid authorization decision", true)
		return port.Authorization{}, requestID, false
	}
	return authorization, requestID, true
}

func decodeRequest[T any](
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
) (T, bool) {
	var zero T
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeProblem(response, requestID, http.StatusUnsupportedMediaType,
			managedservicev1.ErrorInvalidArgument, "Unsupported media type", "Content-Type must be application/json", false)
		return zero, false
	}
	var result T
	if managedservicev1.DecodeRequest(request.Body, &result) != nil {
		writeProblem(response, requestID, http.StatusBadRequest,
			managedservicev1.ErrorInvalidArgument, "Invalid argument", "request body is not one valid managed-service document", false)
		return zero, false
	}
	return result, true
}

func acceptsNoInput(
	response http.ResponseWriter,
	request *http.Request,
	requestID string,
) bool {
	if request.URL.RawQuery != "" || request.ContentLength != 0 || len(request.TransferEncoding) != 0 ||
		(request.Body != nil && request.Body != http.NoBody) {
		writeProblem(response, requestID, http.StatusBadRequest,
			managedservicev1.ErrorInvalidArgument, "Invalid argument", "resource read accepts no query or body", false)
		return false
	}
	return true
}

func acceptsNoQuery(response http.ResponseWriter, request *http.Request, requestID string) bool {
	if request.URL.RawQuery != "" {
		writeProblem(response, requestID, http.StatusBadRequest,
			managedservicev1.ErrorInvalidArgument, "Invalid argument", "query selectors are not accepted", false)
		return false
	}
	return true
}

func writeResult(response http.ResponseWriter, requestID string, result any, err error) {
	if err != nil {
		writeWorkflowError(response, requestID, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func writeAuthorizationError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, port.ErrUnauthenticated):
		writeProblem(response, requestID, http.StatusUnauthorized,
			managedservicev1.ErrorUnauthenticated, "Unauthenticated", "IAM authentication failed", false)
	case errors.Is(err, port.ErrPermissionDenied):
		writeProblem(response, requestID, http.StatusForbidden,
			managedservicev1.ErrorPermissionDenied, "Permission denied", "IAM denied this action", false)
	default:
		writeProblem(response, requestID, http.StatusServiceUnavailable,
			managedservicev1.ErrorIdentityUnavailable, "Identity unavailable", "IAM authorization is unavailable", true)
	}
}

func writeWorkflowError(response http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, port.ErrUnauthenticated):
		writeProblem(response, requestID, http.StatusUnauthorized,
			managedservicev1.ErrorUnauthenticated, "Unauthenticated", "IAM authentication failed", false)
	case errors.Is(err, port.ErrPermissionDenied):
		writeProblem(response, requestID, http.StatusForbidden,
			managedservicev1.ErrorPermissionDenied, "Permission denied", "IAM denied this action", false)
	case errors.Is(err, port.ErrAuthorizationUnavailable):
		writeProblem(response, requestID, http.StatusServiceUnavailable,
			managedservicev1.ErrorIdentityUnavailable, "Identity unavailable", "IAM authorization is unavailable", true)
	case errors.Is(err, port.ErrWorkloadRoleConflict):
		writeProblem(response, requestID, http.StatusConflict,
			managedservicev1.ErrorServiceRoleConflict, "Service Role conflict", "the service Role binding conflicts with current authority", false)
	case errors.Is(err, usecase.ErrInvalidArgument):
		writeProblem(response, requestID, http.StatusBadRequest,
			managedservicev1.ErrorInvalidArgument, "Invalid argument", "request violates the managed-service contract", false)
	case errors.Is(err, usecase.ErrNotFound):
		writeProblem(response, requestID, http.StatusNotFound,
			managedservicev1.ErrorNotFound, "Not found", "the requested organization resource does not exist", false)
	case errors.Is(err, usecase.ErrAlreadyExists):
		writeProblem(response, requestID, http.StatusConflict,
			managedservicev1.ErrorAlreadyExists, "Already exists", "the service installation ID already exists", false)
	case errors.Is(err, usecase.ErrIdempotencyConflict):
		writeProblem(response, requestID, http.StatusConflict,
			managedservicev1.ErrorIdempotencyConflict, "Idempotency conflict", "Idempotency-Key was used for different content", false)
	case errors.Is(err, usecase.ErrServiceDefinitionConflict):
		writeProblem(response, requestID, http.StatusConflict,
			managedservicev1.ErrorServiceDefinitionConflict, "Service definition conflict", "the service contract changed; reload the catalog before activating", false)
	case errors.Is(err, usecase.ErrServiceUnavailable):
		writeProblem(response, requestID, http.StatusConflict,
			managedservicev1.ErrorServiceUnavailable, "Service unavailable", "the service is not currently available for activation", false)
	case errors.Is(err, usecase.ErrServiceNotActivated):
		writeProblem(response, requestID, http.StatusConflict,
			managedservicev1.ErrorServiceNotActivated, "Service not activated", "activate the service for this account before allocating quota", false)
	case errors.Is(err, usecase.ErrQuotaExhausted):
		writeProblem(response, requestID, http.StatusConflict,
			managedservicev1.ErrorQuotaExhausted, "Quota exhausted", "the selected entitlement has no available instances", false)
	case errors.Is(err, usecase.ErrRegionUnavailable):
		writeProblem(response, requestID, http.StatusConflict,
			managedservicev1.ErrorRegionUnavailable, "Region unavailable", "the selected local region is not ready", true)
	case errors.Is(err, usecase.ErrInvalidState):
		writeProblem(response, requestID, http.StatusConflict,
			managedservicev1.ErrorResourceStateConflict, "Resource state conflict", "the service installation cannot perform this transition", false)
	case errors.Is(err, context.DeadlineExceeded):
		writeProblem(response, requestID, http.StatusGatewayTimeout,
			managedservicev1.ErrorInternal, "Deadline exceeded", "request deadline was exceeded", true)
	default:
		writeProblem(response, requestID, http.StatusInternalServerError,
			managedservicev1.ErrorInternal, "Internal error", "the managed-service request could not be completed", true)
	}
}

func writeProblem(
	response http.ResponseWriter,
	requestID string,
	status int,
	code managedservicev1.ErrorCode,
	title string,
	detail string,
	retryable bool,
) {
	problem := managedservicev1.Problem{
		Type:  "https://xiak.com/problems/" + strings.ToLower(strings.ReplaceAll(string(code), "_", "-")),
		Title: title, Status: status, Code: code, Detail: detail,
		TraceID: requestID, Retryable: retryable,
	}
	if managedservicev1.ValidateProblem(problem) != nil {
		problem = managedservicev1.Problem{
			Type: "https://xiak.com/problems/internal", Title: "Internal error",
			Status: http.StatusInternalServerError, Code: managedservicev1.ErrorInternal,
			Detail:  "the error response could not be normalized",
			TraceID: "request-unavailable", Retryable: false,
		}
		status = http.StatusInternalServerError
	}
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(problem)
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func newID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate managed-service ID: %w", err)
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}
