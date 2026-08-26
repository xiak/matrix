package localmachine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	auditv1 "github.com/xiak/matrix/api/audit/v1"
	"github.com/xiak/matrix/api/contractjson"
	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
)

const (
	maximumVerificationResponseBytes = int64(64 * 1024)
	verificationPollInterval         = time.Second
	maximumVerificationPolls         = 180
	verificationRequestTimeout       = 2 * time.Second
	paasVerificationPath             = "/api/paas/v1/installation:verify"
	auditVerificationPath            = "/api/audit/v1/installation:verify"
)

var (
	errVerificationEndpointUnavailable = errors.New("installation verification endpoint is unavailable")
	errInstallationVerificationFailed  = errors.New("installation verification did not establish readiness")
)

type installationVerifier interface {
	Verify(
		context.Context,
		platformcommand.InstallPlan,
	) (paasv1.InstallationVerification, error)
}

type verificationCallOutcome uint8

const (
	verificationCallOK verificationCallOutcome = iota + 1
	verificationCallUnavailable
	verificationCallRejected
	verificationCallInvalid
)

type httpInstallationVerifier struct {
	client       *http.Client
	wait         func(context.Context, time.Duration) error
	pollInterval time.Duration
	maximumPolls int
}

func newHTTPInstallationVerifier(client *http.Client) *httpInstallationVerifier {
	if client == nil {
		client = newVerificationHTTPClient()
	} else {
		clone := *client
		client = &clone
		if client.Timeout <= 0 || client.Timeout > verificationRequestTimeout {
			client.Timeout = verificationRequestTimeout
		}
		client.CheckRedirect = rejectVerificationRedirect
	}
	return &httpInstallationVerifier{
		client: client, wait: waitForVerificationPoll,
		pollInterval: verificationPollInterval, maximumPolls: maximumVerificationPolls,
	}
}

func (verifier *httpInstallationVerifier) Verify(
	ctx context.Context,
	plan platformcommand.InstallPlan,
) (paasv1.InstallationVerification, error) {
	if verifier == nil || verifier.client == nil || verifier.wait == nil ||
		verifier.pollInterval <= 0 || verifier.maximumPolls <= 0 || ctx == nil {
		return paasv1.InstallationVerification{}, errors.Join(
			platformcommand.ErrEffectUnavailable,
			errVerificationEndpointUnavailable,
		)
	}
	if paasv1.ValidateID("installationId", plan.InstallationID) != nil ||
		paasv1.ValidateID("releaseId", plan.Bundle.Manifest.Release.ID) != nil ||
		paasv1.ValidateID("correlationId", plan.CorrelationID) != nil ||
		plan.Port == 0 {
		return paasv1.InstallationVerification{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errInstallationVerificationFailed,
		)
	}
	credential, err := readManagedFile(
		plan.Root,
		filepath.FromSlash(layout.InstallationVerifierCredential),
		maximumCredentialFile,
	)
	if err != nil || !validGeneratedCredential(credential, "mx1.", false) {
		clear(credential)
		return paasv1.InstallationVerification{}, errors.Join(
			platformcommand.ErrEffectVerification,
			errInstallationVerificationFailed,
		)
	}
	defer clear(credential)
	endpoint := "http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(int(plan.Port)))
	idempotencyKey := "verify-" + plan.CorrelationID
	if paasv1.ValidateSafeExternalText(
		"Idempotency-Key", idempotencyKey, 128, true,
	) != nil {
		return paasv1.InstallationVerification{}, verificationFailure()
	}

	paasResult, err := verifier.pollPaaS(ctx, endpoint, credential, plan, idempotencyKey)
	if err != nil {
		return paasv1.InstallationVerification{}, err
	}
	expectedDeploymentID, err := paasv1.InstallationVerificationDeploymentID(plan.InstallationID)
	if err != nil || paasResult.DeploymentID != expectedDeploymentID {
		return paasv1.InstallationVerification{}, verificationFailure()
	}
	auditRequest := auditv1.VerifyInstallationRequest{
		InstallationID: plan.InstallationID,
		OperationID:    auditv1.OperationID(paasResult.OperationID),
		DeploymentID:   string(paasResult.DeploymentID),
	}
	if err := verifier.pollAudit(ctx, endpoint, credential, auditRequest); err != nil {
		return paasv1.InstallationVerification{}, err
	}
	return paasResult, nil
}

func (verifier *httpInstallationVerifier) pollPaaS(
	ctx context.Context,
	endpoint string,
	credential []byte,
	plan platformcommand.InstallPlan,
	idempotencyKey string,
) (paasv1.InstallationVerification, error) {
	request := paasv1.VerifyInstallationRequest{
		InstallationID: plan.InstallationID,
		ReleaseID:      plan.Bundle.Manifest.Release.ID,
	}
	observedPending := false
	for attempt := 0; attempt < verifier.maximumPolls; attempt++ {
		var result paasv1.InstallationVerification
		outcome, err := verifier.postJSON(
			ctx, endpoint+paasVerificationPath, credential, idempotencyKey, request, &result,
		)
		if err != nil {
			return paasv1.InstallationVerification{}, err
		}
		switch outcome {
		case verificationCallOK:
			if paasv1.ValidateInstallationVerification(result) != nil ||
				result.InstallationID != request.InstallationID ||
				result.ReleaseID != request.ReleaseID {
				return paasv1.InstallationVerification{}, verificationFailure()
			}
			switch result.State {
			case paasv1.InstallationVerificationReady:
				return result, nil
			case paasv1.InstallationVerificationFailed:
				return paasv1.InstallationVerification{}, verificationFailure()
			case paasv1.InstallationVerificationPending:
				observedPending = true
			}
		case verificationCallRejected, verificationCallInvalid:
			return paasv1.InstallationVerification{}, verificationFailure()
		case verificationCallUnavailable:
		}
		if attempt+1 < verifier.maximumPolls {
			if err := verifier.wait(ctx, verifier.pollInterval); err != nil {
				return paasv1.InstallationVerification{}, err
			}
		}
	}
	if observedPending {
		return paasv1.InstallationVerification{}, verificationFailure()
	}
	return paasv1.InstallationVerification{}, verificationUnavailable()
}

func (verifier *httpInstallationVerifier) pollAudit(
	ctx context.Context,
	endpoint string,
	credential []byte,
	request auditv1.VerifyInstallationRequest,
) error {
	if auditv1.ValidateVerifyInstallationRequest(request) != nil {
		return verificationFailure()
	}
	observedPending := false
	for attempt := 0; attempt < verifier.maximumPolls; attempt++ {
		var result auditv1.InstallationVerification
		outcome, err := verifier.postJSON(
			ctx, endpoint+auditVerificationPath, credential, "", request, &result,
		)
		if err != nil {
			return err
		}
		switch outcome {
		case verificationCallOK:
			if auditv1.ValidateInstallationVerification(result) != nil ||
				result.InstallationID != request.InstallationID ||
				result.OperationID != request.OperationID ||
				result.DeploymentID != request.DeploymentID {
				return verificationFailure()
			}
			switch result.State {
			case auditv1.InstallationVerificationVerified:
				return nil
			case auditv1.InstallationVerificationPending:
				observedPending = true
			}
		case verificationCallRejected, verificationCallInvalid:
			return verificationFailure()
		case verificationCallUnavailable:
		}
		if attempt+1 < verifier.maximumPolls {
			if err := verifier.wait(ctx, verifier.pollInterval); err != nil {
				return err
			}
		}
	}
	if observedPending {
		return verificationFailure()
	}
	return verificationUnavailable()
}

func (verifier *httpInstallationVerifier) postJSON(
	ctx context.Context,
	endpoint string,
	credential []byte,
	idempotencyKey string,
	requestBody any,
	responseBody any,
) (verificationCallOutcome, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		return verificationCallInvalid, nil
	}
	defer clear(encoded)
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, endpoint, bytes.NewReader(encoded),
	)
	if err != nil {
		return verificationCallInvalid, nil
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+string(credential))
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	defer request.Header.Del("Authorization")
	defer request.Header.Del("Idempotency-Key")
	response, err := verifier.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return verificationCallUnavailable, nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maximumVerificationResponseBytes))
		if response.StatusCode == http.StatusRequestTimeout ||
			response.StatusCode == http.StatusTooManyRequests ||
			response.StatusCode >= http.StatusInternalServerError {
			return verificationCallUnavailable, nil
		}
		return verificationCallRejected, nil
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" ||
		response.Header.Get("Content-Encoding") != "" ||
		contractjson.DecodeObject(
			response.Body, maximumVerificationResponseBytes, responseBody,
		) != nil {
		return verificationCallInvalid, nil
	}
	return verificationCallOK, nil
}

func newVerificationHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: verificationRequestTimeout, KeepAlive: 30 * time.Second}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil, DialContext: dialer.DialContext,
			ForceAttemptHTTP2: false, DisableCompression: true,
			MaxIdleConns: 2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 2,
			IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: verificationRequestTimeout,
		},
		Timeout: verificationRequestTimeout, CheckRedirect: rejectVerificationRedirect,
	}
}

func rejectVerificationRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func waitForVerificationPoll(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func verificationFailure() error {
	return errors.Join(
		platformcommand.ErrEffectVerification,
		errInstallationVerificationFailed,
	)
}

func verificationUnavailable() error {
	return errors.Join(
		platformcommand.ErrEffectUnavailable,
		errVerificationEndpointUnavailable,
	)
}
