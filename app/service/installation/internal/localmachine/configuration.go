package localmachine

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"

	apphostingv1 "github.com/xiak/matrix/api/adapter/apphosting/v1"
	"github.com/xiak/matrix/app/service/installation/internal/layout"
	"github.com/xiak/matrix/app/service/installation/internal/platformcommand"
	"github.com/xiak/matrix/app/service/installation/release"
	"github.com/xiak/matrix/app/service/installation/topology"
)

func configureInstallation(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
) error {
	staged, err := verifiedStagedBundle(plan)
	if err != nil {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("staged release cannot supply configuration"),
		)
	}
	for _, image := range staged.Manifest.Images {
		present, err := inspectExactImage(ctx, runtimeBoundary, image.ImageID)
		if err != nil {
			return err
		}
		if !present {
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("configured image identity is absent"),
			)
		}
	}
	compiled, err := topology.Compile(staged.Manifest, topology.Options{
		InstallationID: plan.InstallationID, Root: plan.Root,
		Listener: plan.Listener, Port: plan.Port,
	})
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	return publishInstallationConfiguration(plan.Root, staged.Manifest, compiled)
}

func configureUpgrade(
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
	target, err := verifiedStagedBundle(plan.Target)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	for _, image := range target.Manifest.Images {
		present, err := inspectExactImage(ctx, runtimeBoundary, image.ImageID)
		if err != nil {
			return err
		}
		if !present {
			return errors.Join(
				platformcommand.ErrEffectVerification,
				errors.New("upgrade image identity is absent"),
			)
		}
	}
	return replaceReleaseConfiguration(
		plan.Target, source.Bundle.Manifest, target.Manifest,
	)
}

func restoreUpgradeConfiguration(plan platformcommand.UpgradePlan) error {
	source, err := authenticateInstalledPlan(plan.Source)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	defer clear(source.TrustBytes)
	if err := validateUpgradeIdentity(source, plan.Target); err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	return replaceReleaseConfiguration(
		plan.Target, plan.Target.Bundle.Manifest, source.Bundle.Manifest,
	)
}

func replaceReleaseConfiguration(
	plan platformcommand.InstallPlan,
	before release.Manifest,
	after release.Manifest,
) error {
	options := topology.Options{
		InstallationID: plan.InstallationID, Root: plan.Root,
		Listener: plan.Listener, Port: plan.Port,
	}
	beforeTopology, err := topology.Compile(before, options)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	afterTopology, err := topology.Compile(after, options)
	if err != nil || afterTopology.ProjectName != beforeTopology.ProjectName {
		return errors.Join(
			platformcommand.ErrEffectVerification,
			errors.New("release configuration project identity changed"),
		)
	}
	beforeCatalog, err := artifactCatalogConfig(before)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	afterCatalog, err := artifactCatalogConfig(after)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	for _, replacement := range []struct {
		path          string
		before, after []byte
	}{
		{layout.Compose, beforeTopology.ComposeJSON, afterTopology.ComposeJSON},
		{layout.ArtifactCatalog, beforeCatalog, afterCatalog},
	} {
		if err := replaceManagedExpected(
			plan.Root, filepath.FromSlash(replacement.path),
			replacement.before, replacement.after,
		); err != nil {
			if errors.Is(err, errManagedOutcomeUnknown) {
				return errors.Join(platformcommand.ErrEffectOutcomeUnknown, err)
			}
			return errors.Join(platformcommand.ErrEffectConflict, err)
		}
	}
	for _, fixed := range []struct {
		path    string
		content []byte
	}{
		{layout.APISIXRoutes, apisixStandaloneConfig()},
		{layout.APISIXConfig, apisixMainConfig()},
		{layout.APISIXUID, []byte(afterTopology.ProjectName)},
	} {
		if err := writeManagedOnce(
			plan.Root, filepath.FromSlash(fixed.path), fixed.content,
		); err != nil {
			return errors.Join(platformcommand.ErrEffectConflict, err)
		}
	}
	if err := ensureManagedMutableFile(
		plan.Root, filepath.FromSlash(layout.APISIXNginx), []byte("\n"),
	); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	return nil
}

func publishInstallationConfiguration(
	root string,
	manifest release.Manifest,
	compiled topology.Result,
) error {
	if err := writeManagedOnce(
		root, filepath.FromSlash(layout.Compose), compiled.ComposeJSON,
	); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}

	catalog, err := artifactCatalogConfig(manifest)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	if err := writeManagedOnce(
		root, filepath.FromSlash(layout.ArtifactCatalog), catalog,
	); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if err := writeManagedOnce(
		root, filepath.FromSlash(layout.APISIXRoutes), apisixStandaloneConfig(),
	); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if err := writeManagedOnce(
		root, filepath.FromSlash(layout.APISIXConfig), apisixMainConfig(),
	); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if err := writeManagedOnce(
		root, filepath.FromSlash(layout.APISIXUID), []byte(compiled.ProjectName),
	); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if err := ensureManagedMutableFile(
		root, filepath.FromSlash(layout.APISIXNginx), []byte("\n"),
	); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	return nil
}

func artifactCatalogConfig(manifest release.Manifest) ([]byte, error) {
	entries := make([]apphostingv1.ArtifactCatalogEntry, 0)
	for _, image := range manifest.Images {
		if image.Purpose == release.ImageWorkload {
			entries = append(entries, apphostingv1.ArtifactCatalogEntry{
				ArtifactDigest: image.SourceDigest, ImageID: image.ImageID,
			})
		}
	}
	slices.SortFunc(entries, func(left, right apphostingv1.ArtifactCatalogEntry) int {
		return strings.Compare(left.ArtifactDigest, right.ArtifactDigest)
	})
	catalog, err := apphostingv1.EncodeArtifactCatalog(apphostingv1.ArtifactCatalog{
		APIVersion: apphostingv1.ArtifactCatalogAPIVersion,
		Kind:       apphostingv1.ArtifactCatalogKind,
		Entries:    entries,
	})
	if err != nil {
		return nil, err
	}
	return catalog, nil
}

func apisixMainConfig() []byte {
	return []byte(`deployment:
  role: data_plane
  role_data_plane:
    config_provider: yaml
plugins:
  - proxy-rewrite
  - serverless-pre-function
stream_plugins: []
nginx_config:
  user: root
  error_log: /dev/stderr
  http:
    access_log: /dev/stdout
  http_configuration_snippet: |
    client_body_temp_path /tmp/client_body_temp;
    proxy_temp_path /tmp/proxy_temp;
    fastcgi_temp_path /tmp/fastcgi_temp;
    uwsgi_temp_path /tmp/uwsgi_temp;
    scgi_temp_path /tmp/scgi_temp;
`)
}

func apisixStandaloneConfig() []byte {
	return []byte(`routes:
  -
    id: matrix-ready
    uri: /ready
    priority: 1000
    plugins:
      serverless-pre-function:
        phase: rewrite
        functions:
          - |
            return function()
              ngx.header["Content-Type"] = "application/json"
              ngx.say('{"status":"ready"}')
              return ngx.exit(200)
            end
  -
    id: matrix-iam
    uri: /api/iam/*
    plugins:
      proxy-rewrite:
        regex_uri:
          - "^/api/iam/(.*)"
          - "/$1"
        headers:
          remove:
            - Matrix-Subject-Credential
    upstream:
      type: roundrobin
      nodes:
        "iam:8080": 1
  -
    id: matrix-audit-installation-verification
    uri: /api/audit/v1/installation:verify
    priority: 100
    plugins:
      proxy-rewrite:
        uri: /v1/installation:verify
        headers:
          remove:
            - Matrix-Subject-Credential
    upstream:
      type: roundrobin
      nodes:
        "audit:8080": 1
  -
    id: matrix-audit
    uri: /api/audit/*
    plugins:
      proxy-rewrite:
        regex_uri:
          - "^/api/audit/(.*)"
          - "/$1"
        headers:
          remove:
            - Matrix-Subject-Credential
    upstream:
      type: roundrobin
      nodes:
        "audit:8080": 1
  -
    id: matrix-paas-installation-verification
    uri: /api/paas/v1/installation:verify
    priority: 100
    plugins:
      proxy-rewrite:
        uri: /v1/installation:verify
        headers:
          remove:
            - Matrix-Subject-Credential
    upstream:
      type: roundrobin
      nodes:
        "paas-api:8080": 1
  -
    id: matrix-paas
    uri: /api/paas/*
    plugins:
      proxy-rewrite:
        regex_uri:
          - "^/api/paas/(.*)"
          - "/$1"
        headers:
          remove:
            - Matrix-Subject-Credential
    upstream:
      type: roundrobin
      nodes:
        "paas-api:8080": 1
  -
    id: matrix-ui
    uri: /*
    plugins:
      proxy-rewrite:
        headers:
          remove:
            - Authorization
            - Matrix-Subject-Credential
    upstream:
      type: roundrobin
      nodes:
        "paas-ui:8080": 1
#END
`)
}
