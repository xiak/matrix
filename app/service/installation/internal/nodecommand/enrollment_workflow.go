package nodecommand

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	paasv1 "github.com/xiak/matrix/api/paas/v1"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
	"github.com/xiak/matrix/app/service/internal/processconfig"
)

type enrollmentCeremony struct {
	intent   EnrollmentIntent
	response paasv1.NodeEnrollmentExchangeResponse
}

func (value enrollmentCeremony) Clear() { value.intent.Clear() }

func absoluteInstallInput(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || len(value) > 4096 {
		return "", errors.New("node install input path is invalid")
	}
	if filepath.IsAbs(value) {
		return filepath.Clean(value), nil
	}
	absolute, err := filepath.Abs(value)
	if err != nil || absolute == "" || len(absolute) > 4096 {
		return "", errors.New("node install input path is invalid")
	}
	return filepath.Clean(absolute), nil
}

func readNodeEnrollmentJoin(path string) (nodeconfig.JoinFile, error) {
	source, err := processconfig.ReadFile(path, nodeconfig.MaximumBytes, true)
	if err != nil {
		return nodeconfig.JoinFile{}, err
	}
	defer clear(source)
	return nodeconfig.DecodeJoinFile(source)
}

func sameEnrollmentJoin(left, right paasv1.NodeEnrollmentJoin) bool {
	return left == right
}

func (backend *Backend) prepareEnrollment(
	ctx context.Context,
	root string,
	joinFile nodeconfig.JoinFile,
) (enrollmentCeremony, error) {
	credentialUnexpired := backend.now().UTC().Before(joinFile.Join.ExpiresAt)
	intent, exists, err := backend.store.ReadEnrollmentIntent(root)
	if err != nil {
		intent.Clear()
		return enrollmentCeremony{}, err
	}
	if exists {
		if !sameEnrollmentJoin(intent.Join, joinFile.Join) {
			intent.Clear()
			return enrollmentCeremony{}, ErrConflict
		}
	} else {
		if !credentialUnexpired {
			return enrollmentCeremony{}, ErrEnrollmentRejected
		}
		fingerprint, err := backend.host.MachineFingerprint(ctx, root)
		if err != nil {
			return enrollmentCeremony{}, err
		}
		intent, err = newEnrollmentIntent(joinFile.Join, fingerprint, backend.entropy)
		if err != nil {
			return enrollmentCeremony{}, ErrVerification
		}
		if err := backend.store.CreateEnrollmentIntent(root, intent); err != nil {
			intent.Clear()
			return enrollmentCeremony{}, err
		}
	}
	response, exists, err := backend.store.ReadEnrollmentResponse(root, intent)
	if err != nil {
		intent.Clear()
		return enrollmentCeremony{}, err
	}
	if exists {
		return enrollmentCeremony{intent: intent, response: response}, nil
	}
	attempted, err := backend.store.EnrollmentExchangeAttempted(root, intent)
	if err != nil {
		intent.Clear()
		return enrollmentCeremony{}, err
	}
	if attempted {
		response, err = backend.recoverEnrollment(ctx, intent, joinFile.Credential, credentialUnexpired)
	} else {
		if !credentialUnexpired {
			return enrollmentCeremony{}, backend.discardRejectedEnrollment(root, intent)
		}
		if err = backend.store.MarkEnrollmentExchangeAttempted(root, intent); err == nil {
			request := intent.exchangeRequest(joinFile.Credential)
			response, err = backend.enrollment.Exchange(ctx, intent.Join, request)
			request.Credential = ""
		}
	}
	if err != nil {
		if errors.Is(err, ErrEnrollmentRejected) {
			err = backend.discardRejectedEnrollment(root, intent)
		} else {
			intent.Clear()
		}
		return enrollmentCeremony{}, err
	}
	if ValidateEnrollmentResponse(intent, response) != nil {
		intent.Clear()
		return enrollmentCeremony{}, ErrEnrollmentRejected
	}
	if err := backend.store.CreateEnrollmentResponse(root, intent, response); err != nil {
		intent.Clear()
		return enrollmentCeremony{}, err
	}
	return enrollmentCeremony{intent: intent, response: response}, nil
}

func (backend *Backend) recoverEnrollment(
	ctx context.Context,
	intent EnrollmentIntent,
	credential string,
	credentialUnexpired bool,
) (paasv1.NodeEnrollmentExchangeResponse, error) {
	request, err := intent.recoveryChallengeRequest()
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrVerification
	}
	challenge, err := backend.enrollment.CreateRecoveryChallenge(ctx, intent.Join, request)
	if errors.Is(err, ErrEnrollmentNotExchanged) {
		if !credentialUnexpired {
			return paasv1.NodeEnrollmentExchangeResponse{}, ErrEnrollmentRejected
		}
		exchange := intent.exchangeRequest(credential)
		response, exchangeErr := backend.enrollment.Exchange(ctx, intent.Join, exchange)
		exchange.Credential = ""
		if errors.Is(exchangeErr, ErrEnrollmentRejected) {
			// The original request may have committed immediately after the
			// challenge observed WAITING_INSTALL. A rejection of this guarded
			// replay therefore cannot prove that no exchange exists. Ask once
			// more and recover only through both persisted role keys.
			return backend.recoverEnrollmentAfterReplayRejection(ctx, intent, request)
		}
		return response, exchangeErr
	}
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	proof, err := intent.recoveryProof(challenge)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrVerification
	}
	return backend.enrollment.RecoverExchange(ctx, intent.Join, proof)
}

func (backend *Backend) recoverEnrollmentAfterReplayRejection(
	ctx context.Context,
	intent EnrollmentIntent,
	request paasv1.CreateNodeEnrollmentRecoveryChallengeRequest,
) (paasv1.NodeEnrollmentExchangeResponse, error) {
	challenge, err := backend.enrollment.CreateRecoveryChallenge(ctx, intent.Join, request)
	if errors.Is(err, ErrEnrollmentNotExchanged) {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrEnrollmentRejected
	}
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, err
	}
	proof, err := intent.recoveryProof(challenge)
	if err != nil {
		return paasv1.NodeEnrollmentExchangeResponse{}, ErrVerification
	}
	return backend.enrollment.RecoverExchange(ctx, intent.Join, proof)
}

func (backend *Backend) discardRejectedEnrollment(root string, intent EnrollmentIntent) error {
	defer intent.Clear()
	if err := backend.store.DiscardEnrollmentIntent(root, intent); err != nil {
		return err
	}
	return ErrEnrollmentRejected
}

func (backend *Backend) readEnrollmentCeremony(root string) (enrollmentCeremony, error) {
	intent, exists, err := backend.store.ReadEnrollmentIntent(root)
	if err != nil || !exists {
		intent.Clear()
		if err == nil {
			err = ErrVerification
		}
		return enrollmentCeremony{}, err
	}
	response, exists, err := backend.store.ReadEnrollmentResponse(root, intent)
	if err != nil || !exists {
		intent.Clear()
		if err == nil {
			err = ErrVerification
		}
		return enrollmentCeremony{}, err
	}
	return enrollmentCeremony{intent: intent, response: response}, nil
}

func (backend *Backend) storedEnrollmentPlan(
	root string,
	state lifecycle.Journal,
) (Plan, enrollmentCeremony, error) {
	ceremony, err := backend.readEnrollmentCeremony(root)
	if err != nil {
		return Plan{}, enrollmentCeremony{}, err
	}
	releasePlan, err := backend.releasePlan(root, state)
	if err != nil {
		ceremony.Clear()
		return Plan{}, enrollmentCeremony{}, err
	}
	plan, err := planFromEnrollment(
		root, releasePlan.Bundle, releasePlan.Trust, releasePlan.TrustBytes,
		ceremony.intent, ceremony.response,
	)
	if err != nil || state.Node == nil || state.InstallationID != plan.Configuration.Identity.InstallationID ||
		*state.Node != plan.Binding || backend.effects.ValidateEnrollment(plan) != nil {
		ceremony.Clear()
		plan.Clear()
		return Plan{}, enrollmentCeremony{}, ErrVerification
	}
	installedConfiguration, installedCredentials, err := backend.effects.ReadInstallation(root)
	if err != nil {
		ceremony.Clear()
		plan.Clear()
		return Plan{}, enrollmentCeremony{}, ErrVerification
	}
	defer installedCredentials.Clear()
	installed := plan
	installed.Configuration, installed.Credentials = installedConfiguration, installedCredentials
	if installedConfiguration != plan.Configuration || ValidatePlan(installed) != nil ||
		backend.effects.ValidateEnrollment(installed) != nil {
		ceremony.Clear()
		plan.Clear()
		return Plan{}, enrollmentCeremony{}, ErrVerification
	}
	return plan, ceremony, nil
}

func (backend *Backend) finalizeCompletedEnrollment(root string, state lifecycle.Journal) error {
	intent, exists, err := backend.store.ReadEnrollmentIntent(root)
	if err != nil || !exists {
		return err
	}
	intent.Clear()
	plan, ceremony, err := backend.storedEnrollmentPlan(root, state)
	if err != nil {
		return err
	}
	defer plan.Clear()
	defer ceremony.Clear()
	return backend.store.FinalizeEnrollment(root, ceremony.intent, ceremony.response)
}

func rejectedEnrollmentCleanupPending(state lifecycle.Journal) bool {
	return state.Active == nil && state.CurrentReleaseID == "" && state.Last != nil &&
		state.Last.Command.Action == lifecycle.ActionInstall &&
		state.Last.Outcome == lifecycle.OutcomeRolledBack &&
		state.Last.FailureCode == lifecycle.NodeEnrollmentRejectedFailureCode
}

func (backend *Backend) rejectedEnrollmentPlan(
	root string,
	state lifecycle.Journal,
) (Plan, enrollmentCeremony, error) {
	if !rejectedEnrollmentCleanupPending(state) || state.Node == nil {
		return Plan{}, enrollmentCeremony{}, ErrVerification
	}
	ceremony, err := backend.readEnrollmentCeremony(root)
	if err != nil {
		return Plan{}, enrollmentCeremony{}, err
	}
	releasePlan, err := backend.releasePlanAt(
		root, state, state.Last.Command.TargetReleaseID, state.Last.Command.InputDigest,
	)
	if err != nil {
		ceremony.Clear()
		return Plan{}, enrollmentCeremony{}, err
	}
	plan, err := planFromEnrollment(
		root, releasePlan.Bundle, releasePlan.Trust, releasePlan.TrustBytes,
		ceremony.intent, ceremony.response,
	)
	if err != nil || state.InstallationID != plan.Configuration.Identity.InstallationID ||
		*state.Node != plan.Binding || backend.effects.ValidateEnrollment(plan) != nil {
		ceremony.Clear()
		plan.Clear()
		return Plan{}, enrollmentCeremony{}, ErrVerification
	}
	return plan, ceremony, nil
}

func (backend *Backend) cleanupRejectedEnrollment(
	ctx context.Context,
	root string,
	state lifecycle.Journal,
) error {
	intent, exists, err := backend.store.ReadEnrollmentIntent(root)
	intent.Clear()
	if err != nil || !exists {
		return err
	}
	plan, ceremony, err := backend.rejectedEnrollmentPlan(root, state)
	if err != nil {
		return err
	}
	defer plan.Clear()
	defer ceremony.Clear()
	return backend.store.CleanupRejectedEnrollment(ctx, plan, ceremony.intent, ceremony.response)
}

func (backend *Backend) completeEnrollment(
	ctx context.Context,
	ceremony enrollmentCeremony,
) error {
	request, err := ceremony.intent.completionRequest(ceremony.response)
	if err != nil {
		return ErrVerification
	}
	return backend.enrollment.Complete(ctx, ceremony.intent.Join, request)
}
