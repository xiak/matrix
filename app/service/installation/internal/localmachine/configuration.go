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
	"github.com/xiak/matrix/app/service/installation/internal/release"
	"github.com/xiak/matrix/app/service/installation/internal/topology"
)

func configureInstallation(
	ctx context.Context,
	runtimeBoundary dockerRuntime,
	plan platformcommand.InstallPlan,
) error {
	root, err := managedPath(
		plan.Root,
		filepath.FromSlash(layout.ReleaseDirectory(plan.Bundle.Manifest.Release.ID)),
	)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	staged, err := release.VerifyDirectory(root, plan.TrustBytes)
	if err != nil || staged.ManifestSHA256 != plan.Bundle.ManifestSHA256 {
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
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	if err := writeManagedOnce(
		root, filepath.FromSlash(layout.ArtifactCatalog), catalog,
	); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if err := writeManagedOnce(
		root, filepath.FromSlash(layout.APISIX), apisixStandaloneConfig(),
	); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	return nil
}

func apisixStandaloneConfig() []byte {
	return []byte(`routes:
  -
    id: matrix-ready
    uri: /ready
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
  -
    id: matrix-iam
    uri: /api/iam/*
    plugin_config_id: matrix-service-auth
    plugins:
      proxy-rewrite:
        regex_uri:
          - "^/api/iam/(.*)"
          - "/$1"
    upstream:
      type: roundrobin
      nodes:
        "iam:8080": 1
  -
    id: matrix-audit
    uri: /api/audit/*
    plugin_config_id: matrix-service-auth
    plugins:
      proxy-rewrite:
        regex_uri:
          - "^/api/audit/(.*)"
          - "/$1"
    upstream:
      type: roundrobin
      nodes:
        "audit:8080": 1
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
plugin_configs:
  -
    id: matrix-service-auth
    plugins:
      serverless-pre-function:
        phase: rewrite
        functions:
          - |
            local credential
            return function()
              local headers = ngx.req.get_headers()
              local authorization = headers["authorization"]
              ngx.req.clear_header("Matrix-Subject-Credential")
              if authorization then
                local subject = string.match(authorization, "^Bearer ([^%s]+)$")
                if subject then
                  ngx.req.set_header("Matrix-Subject-Credential", subject)
                end
              end
              if not credential then
                local file = io.open("/run/matrix/apisix-iam-credential", "r")
                if not file then return ngx.exit(503) end
                credential = file:read("*a")
                file:close()
                if not credential or #credential == 0 or #credential > 16384 or
                   string.find(credential, "[%z\r\n]") then
                  credential = nil
                  return ngx.exit(503)
                end
              end
              ngx.req.set_header("Authorization", "Bearer " .. credential)
            end
#END
`)
}
