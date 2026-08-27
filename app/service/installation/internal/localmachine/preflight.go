package localmachine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/topology"
)

const maximumProviderObjects = 256

var (
	versionPattern   = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:[-+][0-9A-Za-z.~\-]+)?$`)
	providerIdentity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$`)
)

type dockerServerVersion struct {
	Version      string `json:"Version"`
	OS           string `json:"Os"`
	Architecture string `json:"Arch"`
}

func preflightInstall(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
) error {
	return preflightRelease(ctx, runtimeBoundary, plan, true)
}

func preflightUpgrade(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.UpgradePlan,
) error {
	source, err := authenticateInstalledPlan(plan.Source)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(source.TrustBytes)
	if err := validateUpgradeIdentity(source, plan.Target); err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	if _, _, _, err := inspectReadyInstalledPlatform(
		ctx, runtimeBoundary, source,
	); err != nil {
		return err
	}
	return preflightRelease(ctx, runtimeBoundary, plan.Target, false)
}

func preflightRelease(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
	requireFreeListener bool,
) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errors.Join(
			platformcommand.ErrEffectPrecondition,
			errors.New("host profile is unsupported"),
		)
	}
	if err := validateManagedRoot(plan.Root); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	available, err := availableFilesystemBytes(plan.Root)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	if available < plan.Bundle.Manifest.MinimumFreeBytes {
		return errors.Join(
			platformcommand.ErrEffectPrecondition,
			errors.New("installation filesystem has insufficient free space"),
		)
	}
	compiled, err := topology.Compile(plan.Bundle.Manifest, topology.Options{
		InstallationID: plan.InstallationID, Root: plan.Root,
		Listener: plan.Listener, Port: plan.Port,
	})
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}

	output, _, err := runtimeBoundary.Run(
		ctx, nil, "version", "--format", "{{json .Server}}",
	)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	var server dockerServerVersion
	if err := json.Unmarshal(output, &server); err != nil || server.OS != "linux" ||
		server.Architecture != "amd64" ||
		compareProviderVersion(server.Version, plan.Bundle.Manifest.Host.MinimumDocker) < 0 {
		return errors.Join(
			platformcommand.ErrEffectPrecondition,
			errors.New("Docker Engine profile is unsupported"),
		)
	}
	output, _, err = runtimeBoundary.Run(ctx, nil, "compose", "version", "--short")
	if err != nil {
		return errors.Join(platformcommand.ErrEffectUnavailable, err)
	}
	if compareProviderVersion(
		strings.TrimSpace(string(output)),
		plan.Bundle.Manifest.Host.MinimumCompose,
	) < 0 {
		return errors.Join(
			platformcommand.ErrEffectPrecondition,
			errors.New("Docker Compose profile is unsupported"),
		)
	}
	if err := rejectProjectCollision(ctx, runtimeBoundary, compiled.ProjectName, plan.InstallationID); err != nil {
		return err
	}
	for _, image := range plan.Bundle.Manifest.Images {
		present, err := inspectExactImage(ctx, runtimeBoundary, image.ImageID)
		if err != nil {
			return err
		}
		_ = present
	}

	if requireFreeListener {
		listener, err := net.Listen(
			"tcp4", net.JoinHostPort(plan.Listener, strconv.Itoa(int(plan.Port))),
		)
		if err != nil {
			return errors.Join(
				platformcommand.ErrEffectConflict,
				errors.New("northbound listener is unavailable"),
			)
		}
		if err := listener.Close(); err != nil {
			return errors.Join(platformcommand.ErrEffectUnavailable, err)
		}
	}
	return nil
}

func compareProviderVersion(actual, minimum string) int {
	left, leftOK := parseProviderVersion(actual)
	right, rightOK := parseProviderVersion(minimum)
	if !leftOK || !rightOK {
		return -1
	}
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

func parseProviderVersion(value string) ([3]uint64, bool) {
	if len(value) > 128 {
		return [3]uint64{}, false
	}
	match := versionPattern.FindStringSubmatch(strings.TrimSpace(value))
	if len(match) != 4 {
		return [3]uint64{}, false
	}
	var result [3]uint64
	for index := range result {
		parsed, err := strconv.ParseUint(match[index+1], 10, 32)
		if err != nil {
			return [3]uint64{}, false
		}
		result[index] = parsed
	}
	return result, true
}

func rejectProjectCollision(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	project string,
	installationID string,
) error {
	types := []struct {
		command string
		all     []string
		labels  string
	}{
		{command: "container", all: []string{"ls", "--all", "--quiet"}, labels: "{{json .Config.Labels}}"},
		{command: "network", all: []string{"ls", "--quiet"}, labels: "{{json .Labels}}"},
		{command: "volume", all: []string{"ls", "--quiet"}, labels: "{{json .Labels}}"},
	}
	for _, objectType := range types {
		arguments := append([]string{objectType.command}, objectType.all...)
		arguments = append(arguments, "--filter", "label=com.docker.compose.project="+project)
		output, _, err := runtimeBoundary.Run(ctx, nil, arguments...)
		if err != nil {
			return errors.Join(platformcommand.ErrEffectUnavailable, err)
		}
		identities := strings.Fields(string(output))
		if len(identities) > maximumProviderObjects {
			return errors.Join(
				platformcommand.ErrEffectConflict,
				errors.New("too many colliding provider objects"),
			)
		}
		for _, identity := range identities {
			if !providerIdentity.MatchString(identity) {
				return errors.Join(
					platformcommand.ErrEffectVerification,
					errors.New("provider object identity is invalid"),
				)
			}
			output, _, err := runtimeBoundary.Run(
				ctx, nil, objectType.command, "inspect", "--format", objectType.labels, identity,
			)
			if err != nil {
				return errors.Join(platformcommand.ErrEffectUnavailable, err)
			}
			var labels map[string]string
			if err := json.Unmarshal(output, &labels); err != nil ||
				labels["com.xiak.matrix.managed"] != "true" ||
				labels["com.xiak.matrix.installation"] != installationID {
				return errors.Join(
					platformcommand.ErrEffectConflict,
					fmt.Errorf("%s project object is not installation-owned", objectType.command),
				)
			}
		}
	}
	return nil
}

func inspectExactImage(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	imageID string,
) (bool, error) {
	output, started, err := runtimeBoundary.Run(
		ctx, nil, "image", "inspect", "--format", "{{.Id}}|{{.Os}}|{{.Architecture}}", imageID,
	)
	if err != nil {
		if !started {
			return false, errors.Join(platformcommand.ErrEffectUnavailable, err)
		}
		return false, nil
	}
	if strings.TrimSpace(string(output)) != imageID+"|linux|amd64" {
		return false, errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("local image identity or platform differs"),
		)
	}
	return true, nil
}
