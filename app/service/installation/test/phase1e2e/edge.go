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
	wantMediaType := "application/json"
	if response.StatusCode >= http.StatusBadRequest {
		wantMediaType = "application/problem+json"
	}
	content, readErr := io.ReadAll(io.LimitReader(response.Body, maximumHTTPBody+1))
	if readErr != nil || len(content) > maximumHTTPBody || mediaErr != nil ||
		mediaType != wantMediaType || response.Header.Get("Content-Encoding") != "" ||
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
	result, err := client.loginNamed(ctx, "admin", password, "organization-default", "principal-admin", requestID)
	if err != nil {
		return nil, err
	}
	return result.Credential.CopyBytes(), nil
}

func (client *edgeClient) loginNamed(
	ctx context.Context, loginName string, password []byte,
	tenantID iamv1.OrganizationID, principalID iamv1.PrincipalID, requestID string,
) (iamv1.LoginResponse, error) {
	response, err := client.json(
		ctx, http.MethodPost, "/api/iam/v1/auth/login", nil,
		loginWire{LoginName: loginName, Password: string(password), RequestID: requestID},
		nil, http.StatusOK,
	)
	if err != nil {
		return iamv1.LoginResponse{}, err
	}
	defer clear(response.body)
	var result iamv1.LoginResponse
	if decodeOne(response.body, &result) != nil || iamv1.ValidateLoginResponse(result) != nil ||
		result.Session.PrincipalID != principalID || result.Session.OrganizationID != tenantID ||
		result.Session.Status != iamv1.SessionActive {
		return iamv1.LoginResponse{}, errors.New("IAM login response failed")
	}
	credential := result.Credential.CopyBytes()
	defer clear(credential)
	if len(credential) == 0 {
		return iamv1.LoginResponse{}, errors.New("IAM login credential failed")
	}
	return result, nil
}

func (client *edgeClient) changePassword(
	ctx context.Context,
	bearer, current, next []byte,
	retireBootstrap bool,
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
		iamv1.ValidateChangePasswordResponse(result) != nil || result.BootstrapFileRetirable != retireBootstrap {
		return errors.New("IAM password change response failed")
	}
	return nil
}

func (client *edgeClient) mutateIAM(ctx context.Context, path string, bearer []byte, body, destination any, status int) error {
	response, err := client.json(ctx, http.MethodPost, "/api/iam/v1"+path, bearer, body, nil, status)
	if err != nil {
		return err
	}
	defer clear(response.body)
	if destination != nil && decodeOne(response.body, destination) != nil {
		return errors.New("IAM mutation response failed")
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
	tenantID iamv1.OrganizationID,
	installationID string,
) (auditv1.RecordPage, error) {
	path := "/api/audit/v1/records:query"
	if installationID != "" {
		path = "/api/audit/v1/platform/records:query"
	}
	response, err := client.json(
		ctx, http.MethodPost, path, bearer, request, nil, http.StatusOK,
	)
	if err != nil {
		return auditv1.RecordPage{}, err
	}
	defer clear(response.body)
	var page auditv1.RecordPage
	if decodeOne(response.body, &page) != nil || auditv1.ValidateRecordPage(page) != nil ||
		string(page.TenantID) != string(tenantID) || page.InstallationID != installationID {
		return auditv1.RecordPage{}, errors.New("Audit query response failed")
	}
	return page, nil
}

func (client *edgeClient) allAuditRecords(
	ctx context.Context,
	bearer []byte,
	tenantID iamv1.OrganizationID,
	installationID string,
) ([]auditv1.AuditRecord, error) {
	request := auditv1.QueryRecordsRequest{PageSize: auditv1.MaxPageSize}
	var records []auditv1.AuditRecord
	for pageNumber := 0; pageNumber < 8; pageNumber++ {
		page, err := client.queryAudit(ctx, bearer, request, tenantID, installationID)
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
		records, err := client.allAuditRecords(poll, bearer, "organization-default", "")
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
	tenantID iamv1.OrganizationID,
	installationID string,
) (auditv1.ChainVerification, error) {
	path := "/api/audit/v1/integrity:verify"
	if installationID != "" {
		path = "/api/audit/v1/platform/integrity:verify"
	}
	response, err := client.json(
		ctx, http.MethodPost, path, bearer,
		auditv1.VerifyChainRequest{FromSequence: 1, MaximumRecords: auditv1.MaxVerifyRecords},
		nil, http.StatusOK,
	)
	if err != nil {
		return auditv1.ChainVerification{}, err
	}
	defer clear(response.body)
	var result auditv1.ChainVerification
	if decodeOne(response.body, &result) != nil || auditv1.ValidateChainVerification(result) != nil ||
		string(result.TenantID) != string(tenantID) || result.InstallationID != installationID || result.State != auditv1.VerificationVerified ||
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
