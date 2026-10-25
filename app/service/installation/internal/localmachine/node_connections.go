package localmachine

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/xiak/matrix/api/contractjson"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/lifecycle"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/nodeconfig"
)

// The pending file is never mounted into a service. It binds both sides of
// this one replacement so interrupted publication cannot invent a predecessor.
type nodeControllerPending struct {
	CommandID string `json:"commandId"`
	Before    []byte `json:"before"`
	After     []byte `json:"after"`
}

func readNodeController(root, installationID string) (nodeconfig.ControllerConfiguration, []byte, error) {
	encoded, err := readManagedFile(root, filepath.FromSlash(layout.NodeControllerConfiguration), nodeconfig.MaximumControllerBytes)
	if err != nil {
		return nodeconfig.ControllerConfiguration{}, nil, platformcommand.ErrEffectVerification
	}
	configuration, err := nodeconfig.DecodeController(encoded)
	if err != nil || configuration.InstallationID != installationID {
		clear(encoded)
		configuration.Clear()
		return nodeconfig.ControllerConfiguration{}, nil, platformcommand.ErrEffectVerification
	}
	canonical, err := nodeconfig.EncodeController(configuration)
	defer clear(canonical)
	if err != nil || !bytes.Equal(encoded, canonical) {
		clear(encoded)
		configuration.Clear()
		return nodeconfig.ControllerConfiguration{}, nil, platformcommand.ErrEffectVerification
	}
	return configuration, encoded, nil
}

func (effects *Effects) NodeConnectionsDigest(ctx context.Context, installed platformcommand.InstalledPlan) (string, error) {
	if ctx == nil || ctx.Err() != nil {
		return "", platformcommand.ErrEffectUnavailable
	}
	plan, err := authenticateInstalledPlan(installed)
	if err != nil {
		return "", platformcommand.ErrEffectVerification
	}
	defer clear(plan.TrustBytes)
	configuration, encoded, err := readNodeController(installed.Root, installed.InstallationID)
	defer configuration.Clear()
	defer clear(encoded)
	if err != nil {
		return "", err
	}
	return nodeconfig.ControllerDigest(configuration)
}

func (effects *Effects) PrepareNodeConnections(ctx context.Context, installed platformcommand.InstalledPlan,
	inputFile, expected string, previous *lifecycle.Execution) (platformcommand.NodeConnectionsPlan, error) {
	invalid := platformcommand.ErrEffectVerification
	if effects == nil || effects.runtime == nil || ctx == nil || ctx.Err() != nil {
		return platformcommand.NodeConnectionsPlan{}, platformcommand.ErrEffectUnavailable
	}
	installation, err := authenticateInstalledPlan(installed)
	if err != nil {
		return platformcommand.NodeConnectionsPlan{}, invalid
	}
	defer clear(installation.TrustBytes)
	if _, err := verifiedInstallationConfiguration(installation); err != nil {
		return platformcommand.NodeConnectionsPlan{}, invalid
	}
	current, currentBytes, err := readNodeController(installed.Root, installed.InstallationID)
	if err != nil {
		return platformcommand.NodeConnectionsPlan{}, err
	}
	defer current.Clear()
	defer clear(currentBytes)
	currentDigest, _ := nodeconfig.ControllerDigest(current)
	active := previous != nil && previous.Outcome == ""
	if inputFile == "" || active {
		if previous == nil || previous.Command.Action != lifecycle.ActionConfigureNodes {
			return platformcommand.NodeConnectionsPlan{}, platformcommand.ErrEffectPrecondition
		}
		plan := platformcommand.NodeConnectionsPlan{InstalledPlan: installed, CommandID: previous.Command.ID,
			InputDigest: previous.Command.InputDigest, ExpectedDigest: previous.Command.ExpectedConfigurationDigest}
		if !active || previous.Phase == lifecycle.PhaseCommitting {
			if currentDigest != plan.InputDigest {
				return platformcommand.NodeConnectionsPlan{}, platformcommand.ErrEffectConflict
			}
			plan.After = append([]byte(nil), currentBytes...)
			if inputFile != "" {
				candidate, err := readControllerInput(inputFile, installed.InstallationID)
				defer candidate.Clear()
				digest, digestErr := nodeconfig.ControllerDigest(candidate)
				if err != nil || digestErr != nil || digest != plan.InputDigest || expected != plan.ExpectedDigest {
					plan.Clear()
					return platformcommand.NodeConnectionsPlan{}, platformcommand.ErrEffectConflict
				}
			}
			return plan, nil
		}
		pending, exists, err := readNodeControllerPending(installed.Root, plan)
		if err != nil {
			return platformcommand.NodeConnectionsPlan{}, err
		}
		if exists {
			plan.Before, plan.After = pending.Before, pending.After
			if currentDigest != plan.ExpectedDigest && currentDigest != plan.InputDigest {
				plan.Clear()
				return platformcommand.NodeConnectionsPlan{}, platformcommand.ErrEffectConflict
			}
			if inputFile != "" {
				candidate, err := readControllerInput(inputFile, installed.InstallationID)
				defer candidate.Clear()
				digest, digestErr := nodeconfig.ControllerDigest(candidate)
				if err != nil || digestErr != nil || digest != plan.InputDigest || expected != plan.ExpectedDigest {
					plan.Clear()
					return platformcommand.NodeConnectionsPlan{}, platformcommand.ErrEffectConflict
				}
			}
			return plan, nil
		}
		if previous.Phase != lifecycle.PhaseStaging || inputFile == "" || currentDigest != plan.ExpectedDigest {
			return platformcommand.NodeConnectionsPlan{}, platformcommand.ErrEffectPrecondition
		}
		// Only an interrupted STAGING before its private write may still need
		// the original file. Its bytes must match the already journaled digest.
	}
	candidate, err := readControllerInput(inputFile, installed.InstallationID)
	if err != nil {
		return platformcommand.NodeConnectionsPlan{}, err
	}
	defer candidate.Clear()
	digest, err := nodeconfig.ControllerDigest(candidate)
	if err != nil {
		return platformcommand.NodeConnectionsPlan{}, invalid
	}
	plan := platformcommand.NodeConnectionsPlan{InstalledPlan: installed, InputDigest: digest, ExpectedDigest: expected}
	if previous != nil && previous.Command.Action == lifecycle.ActionConfigureNodes &&
		previous.Command.InputDigest == digest && previous.Command.ExpectedConfigurationDigest == expected {
		if active {
			plan.CommandID = previous.Command.ID
		} else if previous.Outcome == lifecycle.OutcomeSucceeded && currentDigest == digest {
			plan.CommandID, plan.After = previous.Command.ID, append([]byte(nil), currentBytes...)
			return plan, nil
		}
	}
	if currentDigest != expected || nodeconfig.ValidateControllerUpdate(current, candidate) != nil ||
		(active && (previous.Command.InputDigest != digest || previous.Command.ExpectedConfigurationDigest != expected)) {
		return platformcommand.NodeConnectionsPlan{}, platformcommand.ErrEffectConflict
	}
	if err := effects.validateControllerCredentials(candidate); err != nil {
		return platformcommand.NodeConnectionsPlan{}, err
	}
	if _, _, _, err := inspectReadyInstalledPlatform(ctx, effects.runtime, installation); err != nil {
		return platformcommand.NodeConnectionsPlan{}, err
	}
	plan.Before = append([]byte(nil), currentBytes...)
	plan.After, err = nodeconfig.EncodeController(candidate)
	if err != nil {
		plan.Clear()
		return platformcommand.NodeConnectionsPlan{}, invalid
	}
	return plan, nil
}

func readControllerInput(path, installationID string) (nodeconfig.ControllerConfiguration, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4096 || strings.ContainsAny(path, "\x00\r\n") || validateManagedRoot(filepath.Dir(path)) != nil {
		return nodeconfig.ControllerConfiguration{}, platformcommand.ErrEffectVerification
	}
	encoded, err := readManagedFile(filepath.Dir(path), filepath.Base(path), nodeconfig.MaximumControllerBytes)
	defer clear(encoded)
	if err != nil {
		return nodeconfig.ControllerConfiguration{}, platformcommand.ErrEffectVerification
	}
	configuration, err := nodeconfig.DecodeController(encoded)
	if err != nil || configuration.InstallationID != installationID {
		configuration.Clear()
		return nodeconfig.ControllerConfiguration{}, platformcommand.ErrEffectVerification
	}
	return configuration, nil
}

func (effects *Effects) validateControllerCredentials(configuration nodeconfig.ControllerConfiguration) error {
	if len(configuration.Nodes) == 0 {
		return nil
	}
	if effects.validateController == nil || effects.validateController(configuration) != nil {
		return platformcommand.ErrEffectVerification
	}
	return nil
}

func readNodeControllerPending(root string, plan platformcommand.NodeConnectionsPlan) (nodeControllerPending, bool, error) {
	exists, err := managedFileExists(root, filepath.FromSlash(layout.NodeControllerPending))
	if err != nil {
		return nodeControllerPending{}, false, platformcommand.ErrEffectConflict
	}
	if !exists {
		return nodeControllerPending{}, false, nil
	}
	encoded, err := readManagedFile(root, filepath.FromSlash(layout.NodeControllerPending), maximumManagedFileBytes)
	defer clear(encoded)
	var pending nodeControllerPending
	if err != nil || contractjson.DecodeObjectBytes(encoded, maximumManagedFileBytes, &pending) != nil {
		clear(pending.Before)
		clear(pending.After)
		return nodeControllerPending{}, true, platformcommand.ErrEffectVerification
	}
	before, beforeErr := nodeconfig.DecodeController(pending.Before)
	after, afterErr := nodeconfig.DecodeController(pending.After)
	defer before.Clear()
	defer after.Clear()
	beforeDigest, _ := nodeconfig.ControllerDigest(before)
	afterDigest, _ := nodeconfig.ControllerDigest(after)
	if beforeErr != nil || afterErr != nil || pending.CommandID != plan.CommandID ||
		before.InstallationID != plan.InstallationID || beforeDigest != plan.ExpectedDigest || afterDigest != plan.InputDigest ||
		nodeconfig.ValidateControllerUpdate(before, after) != nil {
		clear(pending.Before)
		clear(pending.After)
		return nodeControllerPending{}, true, platformcommand.ErrEffectConflict
	}
	return pending, true, nil
}

func (effects *Effects) ApplyNodeConnectionsPhase(ctx context.Context, plan platformcommand.NodeConnectionsPlan, phase lifecycle.Phase) error {
	if effects == nil || effects.runtime == nil || ctx == nil || ctx.Err() != nil {
		return platformcommand.ErrEffectUnavailable
	}
	installation, err := authenticateInstalledPlan(plan.InstalledPlan)
	if err != nil {
		return platformcommand.ErrEffectVerification
	}
	defer clear(installation.TrustBytes)
	if lifecycle.ValidateCommandID(plan.CommandID) != nil {
		return platformcommand.ErrEffectVerification
	}
	if _, err := verifiedInstallationConfiguration(installation); err != nil {
		return platformcommand.ErrEffectVerification
	}
	candidate, err := nodeconfig.DecodeController(plan.After)
	defer candidate.Clear()
	digest, digestErr := nodeconfig.ControllerDigest(candidate)
	if err != nil || digestErr != nil || candidate.InstallationID != plan.InstallationID || digest != plan.InputDigest {
		return platformcommand.ErrEffectVerification
	}
	if phase == lifecycle.PhaseStaging {
		before, err := nodeconfig.DecodeController(plan.Before)
		defer before.Clear()
		beforeDigest, _ := nodeconfig.ControllerDigest(before)
		if err != nil || beforeDigest != plan.ExpectedDigest || nodeconfig.ValidateControllerUpdate(before, candidate) != nil {
			return platformcommand.ErrEffectConflict
		}
		encoded, err := json.Marshal(nodeControllerPending{plan.CommandID, plan.Before, plan.After})
		defer clear(encoded)
		if err != nil {
			return platformcommand.ErrEffectVerification
		}
		if err := writeManagedOnce(plan.Root, filepath.FromSlash(layout.NodeControllerPending), encoded); err != nil {
			return errors.Join(platformcommand.ErrEffectConflict, err)
		}
		return nil
	}
	pending, exists, err := readNodeControllerPending(plan.Root, plan)
	defer clear(pending.Before)
	defer clear(pending.After)
	if err != nil {
		return err
	}
	if !exists && phase != lifecycle.PhaseCommitting {
		return platformcommand.ErrEffectVerification
	}
	current, encoded, err := readNodeController(plan.Root, plan.InstallationID)
	defer current.Clear()
	defer clear(encoded)
	if err != nil {
		return err
	}
	if phase == lifecycle.PhaseConfiguring {
		if err := effects.validateControllerCredentials(candidate); err != nil {
			return err
		}
		if err := replaceManagedExpected(plan.Root, filepath.FromSlash(layout.NodeControllerConfiguration), pending.Before, pending.After); err != nil {
			if errors.Is(err, errManagedOutcomeUnknown) {
				return platformcommand.ErrEffectOutcomeUnknown
			}
			return platformcommand.ErrEffectConflict
		}
		return nil
	}
	currentDigest, _ := nodeconfig.ControllerDigest(current)
	if currentDigest != plan.InputDigest {
		return platformcommand.ErrEffectConflict
	}
	switch phase {
	case lifecycle.PhaseStarting:
		return restartNodeController(ctx, effects.runtime, installation)
	case lifecycle.PhaseVerifying:
		_, _, _, err := inspectReadyInstalledPlatform(ctx, effects.runtime, installation)
		return err
	case lifecycle.PhaseCommitting:
		if !exists {
			return nil
		}
		path, err := managedPath(plan.Root, filepath.FromSlash(layout.NodeControllerPending))
		if err != nil {
			return platformcommand.ErrEffectConflict
		}
		if os.Remove(path) != nil || syncManagedDirectory(filepath.Dir(path)) != nil {
			return platformcommand.ErrEffectOutcomeUnknown
		}
		return nil
	default:
		return platformcommand.ErrEffectVerification
	}
}

func restartNodeController(ctx context.Context, runtimeBoundary dockerRuntime, plan platformcommand.InstallPlan) error {
	installation, expectation, err := preparePlatformObservation(ctx, runtimeBoundary, plan)
	if err != nil {
		return err
	}
	// Validate every existing object and its fixed topology before selecting
	// the one API service. A foreign label/mount/socket/network is not repaired.
	observed, exists, err := inspectOwnedPlatformProject(ctx, runtimeBoundary, expectation)
	if err != nil {
		return err
	}
	if _, err := validatePlatformObservation(observed, exists, expectation); err != nil {
		return err
	}
	if !exists {
		return platformcommand.ErrEffectPrecondition
	}
	_, started, err := runtimeBoundary.Run(ctx, nil, "compose", "--file", installation.composePath,
		"--project-name", installation.topology.ProjectName, "up", "--detach", "--wait", "--wait-timeout", platformStartWaitSeconds,
		"--no-build", "--pull", "never", "--no-deps", "--force-recreate", "paas-api")
	if err != nil {
		if started {
			return platformcommand.ErrEffectOutcomeUnknown
		}
		return platformcommand.ErrEffectUnavailable
	}
	_, _, after, err := inspectReadyInstalledPlatform(ctx, runtimeBoundary, plan)
	if err != nil {
		return err
	}
	for name, before := range observed.Containers {
		current := after.Containers[name]
		if name != "paas-api" && (current.ID != before.ID || current.State.StartedAt != before.State.StartedAt || current.RestartCount != before.RestartCount) {
			return platformcommand.ErrEffectConflict
		}
	}
	return nil
}
