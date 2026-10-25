package localmachine

import (
	"bytes"
	"errors"
	"path/filepath"

	installationv1 "github.com/xiak/matrix/api/adapter/installation/v1"
	iamv1 "github.com/xiak/matrix/api/iam/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

type releaseDirectoryVerifier func(string, []byte) (release.VerifiedBundle, error)

func authenticateInstalledPlan(
	installed platformcommand.InstalledPlan,
) (platformcommand.InstallPlan, error) {
	return authenticateInstalledPlanWithVerifier(installed, release.VerifyDirectory)
}

func authenticateInstalledPlanWithVerifier(
	installed platformcommand.InstalledPlan,
	verifyDirectory releaseDirectoryVerifier,
) (platformcommand.InstallPlan, error) {
	if verifyDirectory == nil {
		return platformcommand.InstallPlan{}, errors.New("release directory verifier is required")
	}
	if topology.ValidateNorthboundOrigin(installed.NorthboundOrigin, installed.Port) != nil {
		return platformcommand.InstallPlan{}, errors.New("installed northbound origin is invalid")
	}
	trustPath, err := managedPath(
		installed.Root, filepath.FromSlash(layout.ReleaseTrust),
	)
	if err != nil {
		return platformcommand.InstallPlan{}, err
	}
	trustBytes, trust, err := release.ReadTrustRootFile(trustPath)
	if err != nil || trust.KeyID != installed.TrustKeyID ||
		trust.PublicKeyFingerprint != installed.TrustFingerprint {
		clear(trustBytes)
		return platformcommand.InstallPlan{}, errors.New(
			"installed release trust differs from the sealed journal",
		)
	}
	releaseRoot, err := managedPath(
		installed.Root,
		filepath.FromSlash(layout.ReleaseDirectory(installed.ReleaseID)),
	)
	if err != nil {
		clear(trustBytes)
		return platformcommand.InstallPlan{}, err
	}
	bundle, err := verifyDirectory(releaseRoot, trustBytes)
	if err != nil || bundle.Manifest.Release.ID != installed.ReleaseID ||
		bundle.ManifestSHA256 != installed.ReleaseDigest ||
		topology.ValidateInstalledContract(bundle.Manifest) != nil {
		clear(trustBytes)
		return platformcommand.InstallPlan{}, errors.New(
			"installed release differs from the sealed current pointer",
		)
	}
	_, err = readEmailVerificationKeyring(installed.Root, installed.InstallationID)
	if err != nil {
		clear(trustBytes)
		return platformcommand.InstallPlan{}, errors.New(
			"installed email-verification custody is unavailable",
		)
	}
	channel, err := readSecurityMailSMTPChannel(installed.Root, installed.InstallationID)
	if err != nil {
		clear(trustBytes)
		return platformcommand.InstallPlan{}, errors.New(
			"installed security-mail custody is unavailable",
		)
	}
	configuration := installationv1.SecurityMailConfiguration{
		APIVersion:   installationv1.SecurityMailConfigurationAPIVersion,
		Kind:         installationv1.SecurityMailConfigurationKind,
		Host:         channel.Host,
		Port:         channel.Port,
		TLSMode:      channel.TLSMode,
		Username:     channel.Username,
		Password:     channel.Password,
		From:         channel.From,
		TrustedCAPEM: channel.TrustedCAPEM,
	}
	digest, digestErr := installationv1.SecurityMailConfigurationDigest(configuration)
	channel = iamv1.SecurityMailSMTPChannel{}
	configuration.Clear()
	if digestErr != nil || digest != installed.SecurityMailDigest {
		clear(trustBytes)
		return platformcommand.InstallPlan{}, errors.New(
			"installed security-mail custody differs from the sealed journal",
		)
	}
	return platformcommand.InstallPlan{
		Root: installed.Root, InstallationID: installed.InstallationID,
		CorrelationID: installed.CorrelationID,
		Listener:      installed.Listener, Port: installed.Port, NorthboundOrigin: installed.NorthboundOrigin,
		Bundle: bundle, Trust: trust, TrustBytes: trustBytes,
	}, nil
}

func verifiedStagedBundle(plan platformcommand.InstallPlan) (release.VerifiedBundle, error) {
	return verifiedStagedBundleWithVerifier(plan, release.VerifyDirectory)
}

func verifiedStagedBundleWithVerifier(
	plan platformcommand.InstallPlan,
	verifyDirectory releaseDirectoryVerifier,
) (release.VerifiedBundle, error) {
	if verifyDirectory == nil {
		return release.VerifiedBundle{}, errors.New("release directory verifier is required")
	}
	root, err := managedPath(
		plan.Root,
		filepath.FromSlash(layout.ReleaseDirectory(plan.Bundle.Manifest.Release.ID)),
	)
	if err != nil {
		return release.VerifiedBundle{}, err
	}
	staged, err := verifyDirectory(root, plan.TrustBytes)
	if err != nil || staged.ManifestSHA256 != plan.Bundle.ManifestSHA256 ||
		staged.Manifest.Release.ID != plan.Bundle.Manifest.Release.ID {
		return release.VerifiedBundle{}, errors.New("staged release differs from the installation plan")
	}
	return staged, nil
}

func verifiedLifecycleBundle(plan platformcommand.InstallPlan) (release.VerifiedBundle, error) {
	root, err := managedPath(
		plan.Root,
		filepath.FromSlash(layout.ReleaseDirectory(plan.Bundle.Manifest.Release.ID)),
	)
	if err != nil {
		return release.VerifiedBundle{}, err
	}
	staged, err := release.VerifyInstalledDirectory(root, plan.TrustBytes)
	if err != nil || staged.ManifestSHA256 != plan.Bundle.ManifestSHA256 ||
		staged.Manifest.Release.ID != plan.Bundle.Manifest.Release.ID ||
		topology.ValidateInstalledContract(staged.Manifest) != nil {
		return release.VerifiedBundle{}, errors.New("installed release differs from the lifecycle plan")
	}
	return staged, nil
}

type verifiedInstallation struct {
	bundle      release.VerifiedBundle
	topology    topology.Result
	composePath string
}

func verifiedInstallationConfiguration(
	plan platformcommand.InstallPlan,
) (verifiedInstallation, error) {
	staged, err := verifiedLifecycleBundle(plan)
	if err != nil {
		return verifiedInstallation{}, err
	}
	plan.Bundle = staged
	return authenticatedInstallationConfiguration(plan)
}

// authenticatedInstallationConfiguration consumes a plan whose exact bundle
// was authenticated earlier in the same command. Payloads opened by later
// effects retain their own same-file-descriptor verification boundary.
func authenticatedInstallationConfiguration(
	plan platformcommand.InstallPlan,
) (verifiedInstallation, error) {
	compiled, err := topology.Compile(plan.Bundle.Manifest, topology.Options{
		InstallationID:   plan.InstallationID,
		Root:             plan.Root,
		Listener:         plan.Listener,
		Port:             plan.Port,
		NorthboundOrigin: plan.NorthboundOrigin,
	})
	if err != nil {
		return verifiedInstallation{}, err
	}
	catalog, err := artifactCatalogConfig(plan.Bundle.Manifest)
	if err != nil {
		return verifiedInstallation{}, errors.New("generated artifact catalog is invalid")
	}
	expectedFiles := []struct {
		path    string
		content []byte
	}{
		{layout.Compose, compiled.ComposeJSON},
		{layout.ArtifactCatalog, catalog},
		{layout.APISIXRoutes, apisixStandaloneConfig(plan.NorthboundOrigin)},
		{layout.APISIXConfig, apisixMainConfig()},
		{layout.APISIXUID, []byte(compiled.ProjectName)},
	}
	for _, expected := range expectedFiles {
		content, readErr := readManagedFile(
			plan.Root, filepath.FromSlash(expected.path), maximumManagedFileBytes,
		)
		if readErr != nil || !bytes.Equal(content, expected.content) {
			return verifiedInstallation{}, errors.New(
				"generated installation configuration differs from authenticated input",
			)
		}
	}
	if _, err := readManagedFile(
		plan.Root, filepath.FromSlash(layout.APISIXNginx), maximumManagedFileBytes,
	); err != nil {
		return verifiedInstallation{}, errors.New("APISIX runtime configuration is unsafe")
	}
	composePath, err := managedPath(plan.Root, filepath.FromSlash(layout.Compose))
	if err != nil {
		return verifiedInstallation{}, err
	}
	return verifiedInstallation{
		bundle: plan.Bundle, topology: compiled, composePath: composePath,
	}, nil
}
