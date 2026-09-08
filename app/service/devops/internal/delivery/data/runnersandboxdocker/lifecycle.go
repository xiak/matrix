package runnersandboxdocker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	devopsv1 "github.com/xiak/matrix/api/devops/v1"
	"github.com/xiak/matrix/app/service/devops/internal/delivery/runnerlog"
)

const maximumLogTransportBytes = devopsv1.FixedMaxLogBytes * 9

var (
	ErrStepNotFound       = errors.New("runner sandbox step was not found")
	ErrStepConflict       = errors.New("runner sandbox step conflicts")
	ErrStepOutcomeUnknown = errors.New("runner sandbox step outcome is unknown")
)

type StepState string

const (
	StepCreated   StepState = "CREATED"
	StepRunning   StepState = "RUNNING"
	StepPassed    StepState = "PASSED"
	StepFailed    StepState = "FAILED"
	StepCancelled StepState = "CANCELLED"
)

type StepResult struct {
	State  StepState
	Chunks []runnerlog.Chunk
}

// CreateStep creates one deterministic fixed-profile container and proves its
// complete host-side configuration before untrusted code may start.
func (client *Client) CreateStep(ctx context.Context, plan ContainerPlan) error {
	content, err := plan.MarshalJSON()
	if err != nil || client == nil || ctx == nil {
		return ErrInvalid
	}
	response, err := client.engineRequest(
		ctx, http.MethodPost, createPath(plan.Name()), content, true,
	)
	if err != nil {
		return err
	}
	switch response.StatusCode {
	case http.StatusCreated:
		var created createResponse
		if err := decodeEngineJSON(response, maximumVersionBytes, &created); err != nil {
			return errors.Join(ErrStepOutcomeUnknown, err)
		}
		if !validContainerID(created.ID) || len(created.Warnings) != 0 {
			if validContainerID(created.ID) {
				cleanupContext, cancelCleanup := boundedCleanupContext(ctx)
				_ = client.deleteContainer(cleanupContext, created.ID)
				cancelCleanup()
			}
			return ErrStepOutcomeUnknown
		}
		inspection, state, inspectErr := client.inspectStepReference(ctx, plan, created.ID)
		if inspectErr != nil || state != StepCreated || inspection.ID != created.ID {
			cleanupContext, cancelCleanup := boundedCleanupContext(ctx)
			cleanupErr := client.deleteContainer(cleanupContext, created.ID)
			cancelCleanup()
			return errors.Join(ErrStepOutcomeUnknown, inspectErr, cleanupErr)
		}
		return nil
	case http.StatusConflict:
		return errors.Join(ErrStepConflict, closeEngineResponse(response))
	default:
		return errors.Join(ErrUnavailable, closeEngineResponse(response))
	}
}

// StartStep is idempotent for an already-running or terminal exact container.
// A same-name container with any changed host-side field fails closed.
func (client *Client) StartStep(ctx context.Context, plan ContainerPlan) error {
	if client == nil || ctx == nil || validateContainerPlan(plan) != nil || validProbeName(plan.Name()) {
		return ErrInvalid
	}
	inspection, state, err := client.inspectStepReference(ctx, plan, plan.Name())
	if err != nil {
		return err
	}
	if state == StepRunning || state == StepPassed || state == StepFailed {
		return nil
	}
	if state != StepCreated {
		return ErrStepConflict
	}
	containerID := inspection.ID
	response, err := client.engineRequest(
		ctx, http.MethodPost, startPath(containerID), nil, true,
	)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusNotModified {
		if response.StatusCode == http.StatusNotFound {
			return errors.Join(ErrStepNotFound, closeEngineResponse(response))
		}
		return errors.Join(ErrUnavailable, closeEngineResponse(response))
	}
	if err := closeEmptyEngineResponse(response); err != nil {
		return errors.Join(ErrStepOutcomeUnknown, err)
	}
	inspection, state, err = client.inspectStepReference(ctx, plan, plan.Name())
	if err != nil {
		return errors.Join(ErrStepOutcomeUnknown, err)
	}
	if inspection.ID != containerID ||
		(state != StepRunning && state != StepPassed && state != StepFailed) {
		return ErrStepOutcomeUnknown
	}
	return nil
}

// ObserveStep returns only a closed state after revalidating every immutable
// container field. It never starts, kills, or deletes a container.
func (client *Client) ObserveStep(
	ctx context.Context,
	plan ContainerPlan,
) (StepState, error) {
	if client == nil || ctx == nil || validateContainerPlan(plan) != nil || validProbeName(plan.Name()) {
		return "", ErrInvalid
	}
	_, state, err := client.inspectStepReference(ctx, plan, plan.Name())
	return state, err
}

// FollowStep reads the complete multiplexed stdout/stderr stream while a step
// runs, waits for terminal Engine evidence, and then re-inspects every fixed
// postcondition. The caller owns the fixed deadline through ctx.
func (client *Client) FollowStep(
	ctx context.Context,
	plan ContainerPlan,
	budget *LogBudget,
) (StepResult, error) {
	if client == nil || ctx == nil || budget == nil ||
		validateContainerPlan(plan) != nil || validProbeName(plan.Name()) {
		return StepResult{}, ErrInvalid
	}
	inspection, state, err := client.inspectStepReference(ctx, plan, plan.Name())
	if err != nil {
		return StepResult{}, err
	}
	if state == StepCreated {
		return StepResult{}, ErrStepConflict
	}
	containerID := inspection.ID
	follow := state == StepRunning
	chunks, err := client.readStepLogs(ctx, containerID, budget, follow)
	if err != nil {
		return StepResult{}, err
	}
	if follow {
		exitCode, waitErr := client.waitStep(ctx, containerID)
		if waitErr != nil {
			return StepResult{}, waitErr
		}
		inspection, state, err = client.inspectStepReference(ctx, plan, plan.Name())
		if err != nil {
			return StepResult{}, err
		}
		if inspection.ID != containerID || inspection.State.ExitCode != exitCode {
			return StepResult{}, ErrStepOutcomeUnknown
		}
	}
	if state != StepPassed && state != StepFailed {
		return StepResult{}, ErrStepOutcomeUnknown
	}
	return StepResult{State: state, Chunks: chunks}, nil
}

// CancelStep prevents a created step from starting or sends SIGKILL to one
// running exact container. Terminal work wins the race and keeps its result.
func (client *Client) CancelStep(
	ctx context.Context,
	plan ContainerPlan,
) (StepState, error) {
	if client == nil || ctx == nil || validateContainerPlan(plan) != nil || validProbeName(plan.Name()) {
		return "", ErrInvalid
	}
	inspection, state, err := client.inspectStepReference(ctx, plan, plan.Name())
	if err != nil {
		return "", err
	}
	if state == StepCreated {
		if err := client.removeStep(ctx, plan, inspection.ID, true); err != nil {
			return "", err
		}
		return StepCancelled, nil
	}
	if state == StepPassed || state == StepFailed {
		return state, nil
	}
	containerID := inspection.ID
	response, err := client.engineRequest(
		ctx, http.MethodPost, killPath(containerID), nil, true,
	)
	if err != nil {
		return "", err
	}
	switch response.StatusCode {
	case http.StatusNoContent:
		if err := closeEmptyEngineResponse(response); err != nil {
			return "", errors.Join(ErrStepOutcomeUnknown, err)
		}
		exitCode, waitErr := client.waitStep(ctx, containerID)
		if waitErr != nil {
			return "", waitErr
		}
		terminal, terminalState, inspectErr := client.inspectStepReference(
			ctx, plan, plan.Name(),
		)
		if inspectErr != nil || terminal.ID != containerID ||
			(terminalState != StepPassed && terminalState != StepFailed) ||
			terminal.State.ExitCode != exitCode {
			return "", errors.Join(ErrStepOutcomeUnknown, inspectErr)
		}
		return StepCancelled, nil
	case http.StatusConflict:
		if closeErr := closeEngineResponse(response); closeErr != nil {
			return "", errors.Join(ErrUnavailable, closeErr)
		}
		terminal, terminalState, inspectErr := client.inspectStepReference(ctx, plan, plan.Name())
		if inspectErr != nil {
			return "", inspectErr
		}
		if terminal.ID != containerID {
			return "", ErrStepOutcomeUnknown
		}
		if terminalState == StepPassed || terminalState == StepFailed {
			return terminalState, nil
		}
		return "", ErrStepOutcomeUnknown
	case http.StatusNotFound:
		return "", errors.Join(ErrStepNotFound, closeEngineResponse(response))
	default:
		return "", errors.Join(ErrUnavailable, closeEngineResponse(response))
	}
}

// DeleteStep removes only a revalidated, non-running deterministic container.
// Absence is equal replay; transport ambiguity remains observable by name.
func (client *Client) DeleteStep(ctx context.Context, plan ContainerPlan) error {
	if client == nil || ctx == nil || validateContainerPlan(plan) != nil || validProbeName(plan.Name()) {
		return ErrInvalid
	}
	inspection, state, err := client.inspectStepReference(ctx, plan, plan.Name())
	if errors.Is(err, ErrStepNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if state == StepRunning {
		return ErrStepConflict
	}
	return client.removeStep(ctx, plan, inspection.ID, false)
}

func (client *Client) removeStep(
	ctx context.Context,
	plan ContainerPlan,
	containerID string,
	force bool,
) error {
	target := deleteStoppedPath(containerID)
	if force {
		target = deletePath(containerID)
	}
	response, err := client.engineRequest(ctx, http.MethodDelete, target, nil, true)
	if err != nil {
		return err
	}
	switch response.StatusCode {
	case http.StatusNoContent:
		if err := closeEmptyEngineResponse(response); err != nil {
			return errors.Join(ErrStepOutcomeUnknown, err)
		}
	case http.StatusNotFound:
		if err := closeEngineResponse(response); err != nil {
			return errors.Join(ErrStepOutcomeUnknown, err)
		}
	case http.StatusConflict:
		if force {
			return errors.Join(ErrStepOutcomeUnknown, closeEngineResponse(response))
		}
		return errors.Join(ErrStepConflict, closeEngineResponse(response))
	default:
		return errors.Join(ErrUnavailable, closeEngineResponse(response))
	}
	_, _, observeErr := client.inspectStepReference(ctx, plan, plan.Name())
	if errors.Is(observeErr, ErrStepNotFound) {
		return nil
	}
	return errors.Join(ErrStepOutcomeUnknown, observeErr)
}

func (client *Client) inspectStepReference(
	ctx context.Context,
	plan ContainerPlan,
	reference string,
) (containerInspection, StepState, error) {
	if client == nil || ctx == nil || validateContainerPlan(plan) != nil ||
		validProbeName(plan.Name()) || (!validContainerID(reference) && reference != plan.Name()) {
		return containerInspection{}, "", ErrInvalid
	}
	response, err := client.engineRequest(
		ctx, http.MethodGet, containerInspectPath(reference), nil, false,
	)
	if err != nil {
		return containerInspection{}, "", err
	}
	if response.StatusCode == http.StatusNotFound {
		return containerInspection{}, "", errors.Join(ErrStepNotFound, closeEngineResponse(response))
	}
	if response.StatusCode != http.StatusOK {
		return containerInspection{}, "", errors.Join(ErrUnavailable, closeEngineResponse(response))
	}
	var inspection containerInspection
	if err := decodeEngineJSON(response, maximumInspectBytes, &inspection); err != nil {
		return containerInspection{}, "", err
	}
	state, valid := validatedStepState(inspection, plan)
	if !valid {
		return containerInspection{}, "", ErrStepConflict
	}
	return inspection, state, nil
}

func (client *Client) waitStep(ctx context.Context, containerID string) (int64, error) {
	if !validContainerID(containerID) {
		return 0, ErrInvalid
	}
	response, err := client.engineRequest(
		ctx, http.MethodPost, waitPath(containerID), nil, false,
	)
	if err != nil {
		return 0, err
	}
	if response.StatusCode == http.StatusNotFound {
		return 0, errors.Join(ErrStepNotFound, closeEngineResponse(response))
	}
	if response.StatusCode != http.StatusOK {
		return 0, errors.Join(ErrUnavailable, closeEngineResponse(response))
	}
	var waited waitResponse
	if err := decodeEngineJSON(response, maximumWaitBytes, &waited); err != nil {
		return 0, err
	}
	if waited.StatusCode < 0 || waited.StatusCode > 255 ||
		(waited.Error != nil && waited.Error.Message != "") {
		return 0, ErrUnavailable
	}
	return waited.StatusCode, nil
}

func (client *Client) readStepLogs(
	ctx context.Context,
	containerID string,
	budget *LogBudget,
	follow bool,
) ([]runnerlog.Chunk, error) {
	if client == nil || ctx == nil || budget == nil || !validContainerID(containerID) {
		return nil, ErrInvalid
	}
	request, err := newRequest(ctx, http.MethodGet, logsPath(containerID, follow), nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/vnd.docker.raw-stream")
	response, err := client.doEngineRequest(request, false)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusNotFound {
		return nil, errors.Join(ErrStepNotFound, closeEngineResponse(response))
	}
	if response.StatusCode != http.StatusOK {
		return nil, errors.Join(ErrUnavailable, closeEngineResponse(response))
	}
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) > 1 || response.Header.Get("Content-Encoding") != "" ||
		len(response.Header.Values("Content-Encoding")) > 1 ||
		response.ContentLength > maximumLogTransportBytes {
		_ = response.Body.Close()
		return nil, ErrUnavailable
	}
	if len(contentTypes) == 1 {
		mediaType, _, mediaErr := mime.ParseMediaType(contentTypes[0])
		if mediaErr != nil || mediaType != "application/vnd.docker.raw-stream" {
			_ = response.Body.Close()
			return nil, ErrUnavailable
		}
	}
	reader := &logCountingReader{source: response.Body}
	chunks, decodeErr := budget.DecodeDockerStream(reader)
	closeErr := response.Body.Close()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	lengthMismatch := response.ContentLength >= 0 && reader.read != response.ContentLength
	if decodeErr != nil || closeErr != nil || lengthMismatch {
		if decodeErr == nil {
			budget.invalidate()
		}
		return nil, errors.Join(ErrUnavailable, decodeErr, closeErr)
	}
	return chunks, nil
}

func (client *Client) engineRequest(
	ctx context.Context,
	method string,
	target string,
	content []byte,
	effect bool,
) (*http.Response, error) {
	if client == nil || client.httpClient == nil || ctx == nil ||
		(method != http.MethodGet && method != http.MethodPost && method != http.MethodDelete) ||
		len(content) > maximumRequestBytes || (len(content) > 0 && method != http.MethodPost) {
		return nil, ErrInvalid
	}
	request, err := newRequest(ctx, method, target, content)
	if err != nil {
		return nil, err
	}
	return client.doEngineRequest(request, effect)
}

func (client *Client) doEngineRequest(
	request *http.Request,
	effect bool,
) (*http.Response, error) {
	if client == nil || client.httpClient == nil || request == nil {
		return nil, ErrInvalid
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		if ctxErr := request.Context().Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if effect {
			return nil, ErrStepOutcomeUnknown
		}
		return nil, ErrUnavailable
	}
	if response == nil || response.Body == nil ||
		response.Header.Get("Content-Encoding") != "" ||
		len(response.Header.Values("Content-Encoding")) > 1 {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if effect {
			return nil, ErrStepOutcomeUnknown
		}
		return nil, ErrUnavailable
	}
	return response, nil
}

func decodeEngineJSON(response *http.Response, maximum int64, destination any) error {
	if response == nil || response.Body == nil || destination == nil || maximum <= 0 ||
		len(response.Header.Values("Content-Type")) != 1 ||
		response.ContentLength == 0 || response.ContentLength > maximum {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return ErrUnavailable
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		_ = response.Body.Close()
		return ErrUnavailable
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) == 0 || int64(len(body)) > maximum ||
		(response.ContentLength >= 0 && int64(len(body)) != response.ContentLength) {
		return errors.Join(ErrUnavailable, readErr, closeErr)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(destination); err != nil {
		return ErrUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrUnavailable
	}
	return nil
}

func closeEmptyEngineResponse(response *http.Response) error {
	if response == nil || response.Body == nil ||
		(response.ContentLength != 0 && response.ContentLength != -1) {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return ErrUnavailable
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) != 0 {
		return errors.Join(ErrUnavailable, readErr, closeErr)
	}
	return nil
}

func closeEngineResponse(response *http.Response) error {
	if response == nil || response.Body == nil {
		return ErrUnavailable
	}
	content, readErr := io.ReadAll(io.LimitReader(response.Body, maximumWaitBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(content) > maximumWaitBytes {
		return errors.Join(ErrUnavailable, readErr, closeErr)
	}
	return nil
}

type logCountingReader struct {
	source io.Reader
	read   int64
}

func (reader *logCountingReader) Read(destination []byte) (int, error) {
	read, err := reader.source.Read(destination)
	reader.read += int64(read)
	return read, err
}

func validatedStepState(value containerInspection, plan ContainerPlan) (StepState, bool) {
	config := value.Config
	if !validContainerID(value.ID) || value.Name != "/"+plan.Name() || value.RestartCount != 0 ||
		value.Image != devopsv1.Go126OfflineToolchainImageDigest ||
		config.Image != plan.request.Image || !equalStrings(config.Cmd, plan.request.Cmd) ||
		len(config.Entrypoint) != 0 || !equalEnvironment(config.Env, plan.request.Env) ||
		config.User != plan.request.User || config.WorkingDir != plan.request.WorkingDir ||
		!config.NetworkDisabled || config.AttachStdin || !config.AttachStdout ||
		!config.AttachStderr || config.OpenStdin || config.StdinOnce || config.Tty ||
		!equalStringMap(config.Labels, plan.request.Labels) ||
		!validInspectedHostConfig(value.HostConfig, plan.request.HostConfig) ||
		!validNoneNetworks(value.NetworkSettings.Networks) || value.State.Paused ||
		value.State.Restarting || value.State.Dead ||
		value.State.Error != "" {
		return "", false
	}
	switch {
	case value.State.Status == "created" && !value.State.Running &&
		!value.State.OOMKilled && value.State.PID == 0 && value.State.ExitCode == 0:
		return StepCreated, true
	case value.State.Status == "running" && value.State.Running &&
		!value.State.OOMKilled && value.State.PID > 0 && value.State.ExitCode == 0:
		return StepRunning, true
	case value.State.Status == "exited" && !value.State.Running &&
		value.State.PID == 0 && value.State.ExitCode >= 0 && value.State.ExitCode <= 255:
		if value.State.ExitCode == 0 && !value.State.OOMKilled {
			return StepPassed, true
		}
		if value.State.ExitCode == 0 {
			return "", false
		}
		return StepFailed, true
	default:
		return "", false
	}
}

func logsPath(containerID string, follow bool) string {
	return "/" + EngineAPIVersionPath() + "/containers/" + containerID +
		"/logs?follow=" + strconv.FormatBool(follow) +
		"&stderr=true&stdout=true&tail=all&timestamps=false"
}

func killPath(containerID string) string {
	return "/" + EngineAPIVersionPath() + "/containers/" + containerID + "/kill?signal=SIGKILL"
}

func deleteStoppedPath(containerID string) string {
	return "/" + EngineAPIVersionPath() + "/containers/" + containerID +
		"?force=false&v=true"
}
