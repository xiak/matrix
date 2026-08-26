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
