package phase1e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
)

const maximumHTTPBody = 1024 * 1024

type edgeClient struct {
	endpoint  string
	http      *http.Client
	forbidden [][]byte
}

type httpResult struct {
	status int
	header http.Header
	body   []byte
}

type executionTargetTransitionResult struct {
	Before    paasv1.ExecutionTarget
	After     paasv1.ExecutionTarget
	Operation paasv1.Operation
	Action    paasv1.OperationAction
	Path      string
	Key       string
	IfMatch   string
}

func newEdgeClient(endpoint string) *edgeClient {
	return &edgeClient{
		endpoint: endpoint,
		http: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				Proxy:                 nil,
				DisableCompression:    true,
				DisableKeepAlives:     false,
				MaxIdleConns:          4,
				IdleConnTimeout:       30 * time.Second,
				ResponseHeaderTimeout: 5 * time.Second,
			},
		},
	}
}

func (client *edgeClient) close() {
	if client != nil && client.http != nil {
		client.http.CloseIdleConnections()
	}
}

func (client *edgeClient) addForbidden(values ...[]byte) {
	for _, value := range values {
		if len(value) != 0 {
			client.forbidden = append(client.forbidden, value)
		}
	}
}

func (client *edgeClient) json(
	ctx context.Context,
	method, path string,
	bearer []byte,
	body any,
	headers map[string]string,
	wantStatus ...int,
) (httpResult, error) {
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			return httpResult{}, errors.New("encode HTTP request failed")
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, client.endpoint+path, bytes.NewReader(encoded))
	if err != nil {
		clear(encoded)
		return httpResult{}, errors.New("construct HTTP request failed")
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if len(bearer) != 0 {
		request.Header.Set("Authorization", "Bearer "+string(bearer))
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.http.Do(request)
	clear(encoded)
	if err != nil {
		return httpResult{}, errors.New("HTTP request failed")
	}
	defer response.Body.Close()
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	content, readErr := io.ReadAll(io.LimitReader(response.Body, maximumHTTPBody+1))
	if readErr != nil || len(content) > maximumHTTPBody || mediaErr != nil ||
		(mediaType != "application/json" && (mediaType != "application/problem+json" || response.StatusCode < 400)) || response.Header.Get("Content-Encoding") != "" ||
		containsAny(content, client.forbidden) {
		clear(content)
		return httpResult{}, errors.New("HTTP response contract failed")
	}
	accepted := false
	for _, status := range wantStatus {
		accepted = accepted || response.StatusCode == status
	}
	if !accepted {
		clear(content)
		return httpResult{}, errors.New("HTTP response status failed")
	}
	return httpResult{status: response.StatusCode, header: response.Header.Clone(), body: content}, nil
}

type loginWire struct {
	LoginName string `json:"loginName"`
	Password  string `json:"password"`
	RequestID string `json:"requestId"`
}

type changePasswordWire struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
	RequestID       string `json:"requestId"`
}

func (client *edgeClient) login(ctx context.Context, password []byte, requestID string) ([]byte, error) {
	response, err := client.json(
		ctx, http.MethodPost, "/api/iam/v1/auth/login", nil,
		loginWire{LoginName: "admin", Password: string(password), RequestID: requestID},
		nil, http.StatusOK,
	)
	if err != nil {
		return nil, err
	}
	defer clear(response.body)
	var result iamv1.LoginResponse
	if decodeOne(response.body, &result) != nil || iamv1.ValidateLoginResponse(result) != nil ||
		result.Session.PrincipalID != "principal-admin" || result.Session.OrganizationID != "organization-default" ||
		result.Session.Status != iamv1.SessionActive {
		return nil, errors.New("IAM login response failed")
	}
	credential := result.Credential.CopyBytes()
	if len(credential) == 0 {
		return nil, errors.New("IAM login credential failed")
	}
	return credential, nil
}

func (client *edgeClient) changePassword(
	ctx context.Context,
	bearer, current, next []byte,
) error {
	response, err := client.json(
		ctx, http.MethodPost, "/api/iam/v1/auth/password", bearer,
		changePasswordWire{
			CurrentPassword: string(current), NewPassword: string(next),
			RequestID: "phase1-change-password",
		},
		nil, http.StatusOK,
	)
	if err != nil {
		return err
	}
	defer clear(response.body)
	var result iamv1.ChangePasswordResponse
	if decodeOne(response.body, &result) != nil ||
		iamv1.ValidateChangePasswordResponse(result) != nil || !result.BootstrapFileRetirable {
		return errors.New("IAM password change response failed")
	}
	return nil
}

func (client *edgeClient) logout(ctx context.Context, bearer []byte) error {
	response, err := client.json(
		ctx, http.MethodPost, "/api/iam/v1/auth/logout", bearer,
		iamv1.LogoutRequest{RequestID: "phase1-logout"}, nil, http.StatusOK,
	)
	if err != nil {
		return err
	}
	defer clear(response.body)
	var result iamv1.LogoutResponse
	if decodeOne(response.body, &result) != nil || result.RevokedAt.IsZero() {
		return errors.New("IAM logout response failed")
	}
	return nil
}

func (client *edgeClient) createResource(
	ctx context.Context,
	path, idempotency string,
	bearer []byte,
	body any,
	action paasv1.OperationAction,
	target paasv1.ResourceRef,
) (paasv1.Operation, error) {
	response, err := client.json(
		ctx, http.MethodPost, path, bearer, body,
		map[string]string{"Idempotency-Key": idempotency}, http.StatusCreated,
	)
	if err != nil {
		return paasv1.Operation{}, err
	}
	defer clear(response.body)
	var operation paasv1.Operation
	if decodeOne(response.body, &operation) != nil || paasv1.ValidateOperation(operation) != nil ||
		operation.Action != action || operation.Target != target || operation.State != paasv1.OperationSucceeded ||
		response.header.Get("Operation-Location") == "" || response.header.Get("ETag") == "" {
		return paasv1.Operation{}, errors.New("PaaS resource creation response failed")
	}
	return operation, nil
}

func executionTargetLifecycleContract(action paasv1.OperationAction) (string, paasv1.ExecutionTargetDesiredState, paasv1.ExecutionTargetDesiredState, bool) {
	switch action {
	case paasv1.OperationDrainExecutionTarget:
		return "drain", paasv1.ExecutionTargetActive, paasv1.ExecutionTargetDraining, true
	case paasv1.OperationActivateExecutionTarget:
		return "activate", paasv1.ExecutionTargetDraining, paasv1.ExecutionTargetActive, true
	case paasv1.OperationRemoveExecutionTarget:
		return "remove", paasv1.ExecutionTargetDraining, paasv1.ExecutionTargetRemoved, true
	default:
		return "", "", "", false
	}
}

func (client *edgeClient) executionTarget(
	ctx context.Context,
	bearer []byte,
	targetID paasv1.ResourceID,
) (paasv1.ExecutionTarget, string, error) {
	var target paasv1.ExecutionTarget
	header, err := client.get(ctx, "/api/paas/v1/execution-targets/"+string(targetID), bearer, &target)
	etag := header.Get("ETag")
	if err != nil || paasv1.ValidateExecutionTarget(target) != nil || target.Metadata.ID != targetID ||
		etag != formatResourceVersion(target.Metadata.ResourceVersion) {
		return paasv1.ExecutionTarget{}, "", errors.New("PaaS ExecutionTarget read response failed")
	}
	return target, etag, nil
}

func (client *edgeClient) transitionExecutionTarget(
	ctx context.Context,
	bearer []byte,
	targetID paasv1.ResourceID,
	action paasv1.OperationAction,
	key string,
) (executionTargetTransitionResult, error) {
	segment, source, destination, ok := executionTargetLifecycleContract(action)
	if !ok {
		return executionTargetTransitionResult{}, errors.New("PaaS ExecutionTarget action failed")
	}
	before, ifMatch, err := client.executionTarget(ctx, bearer, targetID)
	if err != nil || before.Spec.DesiredState != source {
		return executionTargetTransitionResult{}, errors.New("PaaS ExecutionTarget source state failed")
	}
	path := "/api/paas/v1/execution-targets/" + string(targetID) + "/" + segment
	response, err := client.json(
		ctx, http.MethodPost, path, bearer, nil,
		map[string]string{"Idempotency-Key": key, "If-Match": ifMatch}, http.StatusOK,
	)
	if err != nil {
		return executionTargetTransitionResult{}, err
	}
	defer clear(response.body)
	var operation paasv1.Operation
	nextVersion := before.Metadata.ResourceVersion + 1
	if decodeOne(response.body, &operation) != nil || paasv1.ValidateOperation(operation) != nil ||
		operation.Action != action || operation.Target != (paasv1.ResourceRef{Kind: "ExecutionTarget", ID: targetID}) ||
		operation.State != paasv1.OperationSucceeded || response.header.Get("ETag") != formatResourceVersion(nextVersion) ||
		response.header.Get("Location") != "/v1/execution-targets/"+string(targetID) ||
		response.header.Get("Operation-Location") != "/v1/platform/operations/"+string(operation.ID) {
		return executionTargetTransitionResult{}, errors.New("PaaS ExecutionTarget transition response failed")
	}
	var stored paasv1.Operation
	if _, err = client.get(ctx, "/api/paas/v1/platform/operations/"+string(operation.ID), bearer, &stored); err != nil ||
		!reflect.DeepEqual(stored, operation) {
		return executionTargetTransitionResult{}, errors.New("PaaS ExecutionTarget Operation failed")
	}
	after, _, err := client.executionTarget(ctx, bearer, targetID)
	if err != nil || after.Spec.DesiredState != destination || after.Metadata.ResourceVersion < nextVersion {
		return executionTargetTransitionResult{}, errors.New("PaaS ExecutionTarget result failed")
	}
	return executionTargetTransitionResult{
		Before: before, After: after, Operation: operation,
		Action: action, Path: path, Key: key, IfMatch: ifMatch,
	}, nil
}

func (client *edgeClient) replayExecutionTargetTransition(
	ctx context.Context,
	bearer []byte,
	transition executionTargetTransitionResult,
) error {
	response, err := client.json(
		ctx, http.MethodPost, transition.Path, bearer, nil,
		map[string]string{"Idempotency-Key": transition.Key, "If-Match": transition.IfMatch}, http.StatusOK,
	)
	if err != nil {
		return err
	}
	defer clear(response.body)
	var operation paasv1.Operation
	if decodeOne(response.body, &operation) != nil || !reflect.DeepEqual(operation, transition.Operation) ||
		response.header.Get("Location") != "/v1/execution-targets/"+string(transition.Before.Metadata.ID) ||
		response.header.Get("Operation-Location") != "/v1/platform/operations/"+string(operation.ID) {
		return errors.New("PaaS ExecutionTarget replay response failed")
	}
	version, err := strconv.ParseUint(strings.Trim(response.header.Get("ETag"), `"`), 10, 64)
	if err != nil || response.header.Get("ETag") != formatResourceVersion(version) ||
		version < transition.Before.Metadata.ResourceVersion+1 {
		return errors.New("PaaS ExecutionTarget replay ETag failed")
	}
	return nil
}

func (client *edgeClient) rejectExecutionTargetTransition(
	ctx context.Context,
	bearer []byte,
	targetID paasv1.ResourceID,
	action paasv1.OperationAction,
	key, ifMatch string,
	expectedCode paasv1.ErrorCode,
) (paasv1.Problem, error) {
	segment, _, _, ok := executionTargetLifecycleContract(action)
	if !ok {
		return paasv1.Problem{}, errors.New("PaaS ExecutionTarget rejected action failed")
	}
	response, err := client.json(
		ctx, http.MethodPost,
		"/api/paas/v1/execution-targets/"+string(targetID)+"/"+segment,
		bearer, nil, map[string]string{"Idempotency-Key": key, "If-Match": ifMatch},
		http.StatusConflict,
	)
	if err != nil {
		return paasv1.Problem{}, err
	}
	defer clear(response.body)
	var problem paasv1.Problem
	if decodeOne(response.body, &problem) != nil || paasv1.ValidateProblem(problem) != nil ||
		problem.Status != http.StatusConflict || problem.Code != expectedCode ||
		response.header.Get("ETag") != "" || response.header.Get("Operation-Location") != "" {
		return paasv1.Problem{}, errors.New("PaaS ExecutionTarget rejection response failed")
	}
	return problem, nil
}

func (client *edgeClient) mutateDeployment(
	ctx context.Context,
	method, path, idempotency, ifMatch string,
	bearer []byte,
	body any,
	action paasv1.OperationAction,
	deploymentID paasv1.ResourceID,
) (paasv1.Operation, error) {
	headers := map[string]string{"Idempotency-Key": idempotency}
	if ifMatch != "" {
		headers["If-Match"] = ifMatch
	}
	response, err := client.json(
		ctx, method, path, bearer, body, headers, http.StatusAccepted, http.StatusOK,
	)
	if err != nil {
		return paasv1.Operation{}, err
	}
	defer clear(response.body)
	var operation paasv1.Operation
	if decodeOne(response.body, &operation) != nil || paasv1.ValidateOperation(operation) != nil ||
		operation.Action != action || operation.Target != (paasv1.ResourceRef{Kind: "Deployment", ID: deploymentID}) ||
		(response.status == http.StatusAccepted && operation.State != paasv1.OperationAccepted) ||
		response.header.Get("Operation-Location") == "" || response.header.Get("ETag") == "" {
		return paasv1.Operation{}, errors.New("PaaS Deployment mutation response failed")
	}
	return operation, nil
}

func (client *edgeClient) get(
	ctx context.Context,
	path string,
	bearer []byte,
	destination any,
) (http.Header, error) {
	response, err := client.json(ctx, http.MethodGet, path, bearer, nil, nil, http.StatusOK)
	if err != nil {
		return nil, err
	}
	defer clear(response.body)
	if decodeOne(response.body, destination) != nil {
		return nil, errors.New("PaaS read response failed")
	}
	return response.header, nil
}

func (client *edgeClient) waitOperation(
	ctx context.Context,
	bearer []byte,
	id paasv1.OperationID,
) (paasv1.Operation, error) {
	poll, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for poll.Err() == nil {
		var operation paasv1.Operation
		_, err := client.get(poll, "/api/paas/v1/operations/"+string(id), bearer, &operation)
		if err == nil && paasv1.ValidateOperation(operation) == nil {
			switch operation.State {
			case paasv1.OperationSucceeded:
				return operation, nil
			case paasv1.OperationFailed, paasv1.OperationCancelled, paasv1.OperationManualIntervention:
				return paasv1.Operation{}, errors.New("PaaS Operation failed")
			}
		}
		if !waitPoll(poll, 200*time.Millisecond) {
			break
		}
	}
	return paasv1.Operation{}, errors.New("PaaS Operation did not complete")
}

func (client *edgeClient) waitDeployment(
	ctx context.Context,
	bearer []byte,
	id paasv1.ResourceID,
	generation uint64,
	phase paasv1.DeploymentPhase,
) (paasv1.Deployment, error) {
	poll, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for poll.Err() == nil {
		var deployment paasv1.Deployment
		_, err := client.get(poll, "/api/paas/v1/deployments/"+string(id), bearer, &deployment)
		if err == nil && paasv1.ValidateDeployment(deployment) == nil {
			if deployment.Generation == generation && deployment.Status.ObservedGeneration == generation &&
				deployment.Status.Phase == phase {
				return deployment, nil
			}
			if deployment.Status.Phase == paasv1.DeploymentFailed {
				return paasv1.Deployment{}, errors.New("PaaS Deployment failed")
			}
		}
		if !waitPoll(poll, 200*time.Millisecond) {
			break
		}
	}
	return paasv1.Deployment{}, errors.New("PaaS Deployment did not converge")
}

func waitPoll(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (client *edgeClient) queryAudit(
	ctx context.Context,
	bearer []byte,
	request auditv1.QueryRecordsRequest,
) (auditv1.RecordPage, error) {
	// Reading is itself audited. A busy chain may exhaust its bounded
	// SERIALIZABLE retries while dispatchers catch up after a restart. Retry
	// only that explicit unavailable response, never an invalid page or denial.
	poll, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for attempt := 0; attempt < 5; attempt++ {
		response, err := client.json(
			poll, http.MethodPost, "/api/audit/v1/records:query", bearer, request, nil, http.StatusOK, http.StatusServiceUnavailable,
		)
		if err != nil {
			return auditv1.RecordPage{}, err
		}
		if response.status == http.StatusServiceUnavailable {
			var problem auditv1.Problem
			valid := decodeOne(response.body, &problem) == nil && auditv1.ValidateProblem(problem) == nil &&
				problem.Status == http.StatusServiceUnavailable && problem.Code == "audit.unavailable" &&
				problem.Type == "https://matrix.xiak.com/problems/audit.unavailable"
			clear(response.body)
			if !valid {
				return auditv1.RecordPage{}, errors.New("Audit unavailable response failed")
			}
			if attempt == 4 || !waitPoll(poll, 250*time.Millisecond) {
				return auditv1.RecordPage{}, errors.New("Audit query remained unavailable")
			}
			continue
		}
		var page auditv1.RecordPage
		valid := decodeOne(response.body, &page) == nil && auditv1.ValidateRecordPage(page) == nil &&
			page.TenantID == "organization-default"
		clear(response.body)
		if !valid {
			return auditv1.RecordPage{}, errors.New("Audit query response failed")
		}
		return page, nil
	}
	return auditv1.RecordPage{}, errors.New("Audit query remained unavailable")
}

func (client *edgeClient) allAuditRecords(
	ctx context.Context,
	bearer []byte,
) ([]auditv1.AuditRecord, error) {
	request := auditv1.QueryRecordsRequest{PageSize: auditv1.MaxPageSize}
	var records []auditv1.AuditRecord
	for pageNumber := 0; pageNumber < 8; pageNumber++ {
		page, err := client.queryAudit(ctx, bearer, request)
		if err != nil {
			return nil, err
		}
		records = append(records, page.Records...)
		if page.NextCursor == "" {
			return records, nil
		}
		request.Cursor = page.NextCursor
	}
	return nil, errors.New("Audit query exceeded acceptance page bound")
}

func (client *edgeClient) waitAuditActions(
	ctx context.Context,
	bearer []byte,
	want map[auditv1.Action]string,
) ([]auditv1.AuditRecord, error) {
	poll, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for poll.Err() == nil {
		records, err := client.allAuditRecords(poll, bearer)
		if err == nil {
			remaining := make(map[auditv1.Action]string, len(want))
			for action, target := range want {
				remaining[action] = target
			}
			for _, record := range records {
				target, found := remaining[record.Event.Action]
				if found && (target == "" || record.Event.Target.ID == target) {
					delete(remaining, record.Event.Action)
				}
			}
			if len(remaining) == 0 {
				return records, nil
			}
		}
		if !waitPoll(poll, 250*time.Millisecond) {
			break
		}
	}
	return nil, errors.New("Audit actions did not arrive")
}

func (client *edgeClient) verifyAuditChain(
	ctx context.Context,
	bearer []byte,
) (auditv1.ChainVerification, error) {
	response, err := client.json(
		ctx, http.MethodPost, "/api/audit/v1/integrity:verify", bearer,
		auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: auditv1.MaxVerifyRecords},
		nil, http.StatusOK,
	)
	if err != nil {
		return auditv1.ChainVerification{}, err
	}
	defer clear(response.body)
	var result auditv1.ChainVerification
	if decodeOne(response.body, &result) != nil || auditv1.ValidateChainVerification(result) != nil ||
		result.TenantID != "organization-default" || result.State != auditv1.VerificationVerified ||
		!result.Complete || result.RecordCount == 0 {
		return auditv1.ChainVerification{}, errors.New("Audit chain verification failed")
	}
	return result, nil
}

func auditRecordHashes(records []auditv1.AuditRecord) map[string]struct{} {
	result := make(map[string]struct{}, len(records))
	for _, record := range records {
		result[record.RecordHash] = struct{}{}
	}
	return result
}

func containsAuditHistory(records []auditv1.AuditRecord, baseline map[string]struct{}) bool {
	observed := auditRecordHashes(records)
	for hash := range baseline {
		if _, found := observed[hash]; !found {
			return false
		}
	}
	return true
}

func fixedDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func randomPassword(entropy io.Reader) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := io.ReadFull(entropy, random); err != nil {
		clear(random)
		return nil, err
	}
	password := []byte("mxp1." + base64.RawURLEncoding.EncodeToString(random) + "-Aa1!")
	clear(random)
	return password, nil
}

func generationText(value uint64) string { return strconv.FormatUint(value, 10) }

func isQuotedResourceVersion(header http.Header, value uint64) bool {
	return header.Get("ETag") == "\""+strconv.FormatUint(value, 10)+"\""
}

func scanAuditForConfigurationValues(records []auditv1.AuditRecord, values ...string) bool {
	encoded, err := json.Marshal(records)
	if err != nil {
		return false
	}
	defer clear(encoded)
	for _, value := range values {
		if strings.Contains(string(encoded), value) {
			return false
		}
	}
	return true
}
