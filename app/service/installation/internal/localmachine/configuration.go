package localmachine

import (
	"context"
	"errors"
	"fmt"
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
		_, present, err := inspectInstalledReleaseImage(ctx, runtimeBoundary, image)
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
		Listener: plan.Listener, Port: plan.Port, NorthboundOrigin: plan.NorthboundOrigin,
	})
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	return publishInstallationConfiguration(plan, staged.Manifest, compiled)
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
		_, present, err := inspectInstalledReleaseImage(ctx, runtimeBoundary, image)
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
	return restoreAuthenticatedUpgradeConfiguration(source, plan.Target)
}

func restoreAuthenticatedUpgradeConfiguration(
	source platformcommand.InstallPlan,
	target platformcommand.InstallPlan,
) error {
	return replaceReleaseConfiguration(
		target, target.Bundle.Manifest, source.Bundle.Manifest,
	)
}

func replaceReleaseConfiguration(
	plan platformcommand.InstallPlan,
	before release.Manifest,
	after release.Manifest,
) error {
	options := topology.Options{
		InstallationID: plan.InstallationID, Root: plan.Root,
		Listener: plan.Listener, Port: plan.Port, NorthboundOrigin: plan.NorthboundOrigin,
	}
	beforeTopology, err := topology.CompileInstalled(before, options)
	if err != nil {
		return errors.Join(platformcommand.ErrEffectVerification, err)
	}
	afterTopology, err := topology.CompileInstalled(after, options)
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
	beforeRoutes := installedAPISIXStandaloneConfig(before, plan.NorthboundOrigin)
	afterRoutes := installedAPISIXStandaloneConfig(after, plan.NorthboundOrigin)
	beforeMainConfig := installedAPISIXMainConfig(before)
	afterMainConfig := installedAPISIXMainConfig(after)
	for _, replacement := range []struct {
		path          string
		before, after []byte
	}{
		{layout.Compose, beforeTopology.ComposeJSON, afterTopology.ComposeJSON},
		{layout.ArtifactCatalog, beforeCatalog, afterCatalog},
		{layout.APISIXRoutes, beforeRoutes, afterRoutes},
		{layout.APISIXConfig, beforeMainConfig, afterMainConfig},
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

func installedAPISIXStandaloneConfig(
	manifest release.Manifest,
	northboundOrigin string,
) []byte {
	if release.IsLegacyProductlessManifest(manifest) {
		return legacyProductlessAPISIXStandaloneConfig()
	}
	return apisixStandaloneConfig(northboundOrigin)
}

func installedAPISIXMainConfig(manifest release.Manifest) []byte {
	if release.IsLegacyProductlessManifest(manifest) {
		return legacyProductlessAPISIXMainConfig()
	}
	return apisixMainConfig()
}

func publishInstallationConfiguration(
	plan platformcommand.InstallPlan,
	manifest release.Manifest,
	compiled topology.Result,
) error {
	root := plan.Root
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
		root, filepath.FromSlash(layout.APISIXRoutes),
		installedAPISIXStandaloneConfig(manifest, plan.NorthboundOrigin),
	); err != nil {
		return errors.Join(platformcommand.ErrEffectConflict, err)
	}
	if err := writeManagedOnce(
		root, filepath.FromSlash(layout.APISIXConfig), installedAPISIXMainConfig(manifest),
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
			imageIDs := image.RuntimeImageIDs()
			slices.Sort(imageIDs)
			entries = append(entries, apphostingv1.ArtifactCatalogEntry{
				ArtifactDigest: image.SourceDigest,
				LocalReference: image.RuntimeReference(),
				ImageIDs:       imageIDs,
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
	return []byte(fmt.Sprintf(`apisix:
  node_listen:
    - ip: 0.0.0.0
      port: 9080
    - ip: 127.0.0.1
      port: %d
  ssl:
    enable: false
deployment:
  role: data_plane
  role_data_plane:
    config_provider: yaml
plugins:
  - proxy-rewrite
  - serverless-pre-function
  - serverless-post-function
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
    server {
      listen 0.0.0.0:%d ssl;
      server_name _;
      ssl_certificate %s;
      ssl_certificate_key %s;
      ssl_protocols TLSv1.3;
      ssl_session_cache off;
      ssl_session_tickets off;
      location ~ "^(?:/ready|/api/paas/v1/node-enrollments/node-enrollment-[0-9a-f]{32}/(?:exchange|recovery-challenge|recover|complete))$" {
        client_max_body_size 64k;
        client_body_timeout 10s;
        proxy_http_version 1.1;
        proxy_connect_timeout 3s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
        proxy_set_header Host $host;
        proxy_set_header Authorization "";
        proxy_set_header Cookie "";
        proxy_set_header Idempotency-Key "";
        proxy_set_header If-Match "";
        proxy_set_header Matrix-Subject-Credential "";
        proxy_set_header X-Matrix-Public-Origin "";
        proxy_set_header X-Matrix-Observed-Peer "";
        proxy_set_header X-Matrix-Transport-Scheme "";
        proxy_set_header X-Matrix-TLS-Peer $remote_addr;
        proxy_pass http://127.0.0.1:%d;
      }
      location / {
        return 404;
      }
    }
`, topology.NodeEnrollmentIngressLoopbackPort,
		topology.NodeEnrollmentIngressTargetPort,
		topology.NodeEnrollmentIngressCertificateTarget,
		topology.NodeEnrollmentIngressPrivateKeyTarget,
		topology.NodeEnrollmentIngressLoopbackPort,
	))
}

func apisixStandaloneConfig(northboundOrigin string) []byte {
	return []byte(fmt.Sprintf(`routes:
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
            - X-Matrix-Edge-Assertion
            - Forwarded
            - X-Forwarded-For
            - X-Real-IP
            - X-Matrix-External-Origin
            - X-Matrix-External-Request-Target
            - X-Matrix-External-Source-IP
            - X-Matrix-Observed-Peer
            - X-Matrix-Transport-Scheme
            - X-Matrix-TLS-Peer
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
            - X-Matrix-Edge-Assertion
            - Forwarded
            - X-Forwarded-For
            - X-Real-IP
            - X-Matrix-Observed-Peer
            - X-Matrix-Transport-Scheme
            - X-Matrix-TLS-Peer
            - X-Matrix-External-Origin
            - X-Matrix-External-Request-Target
            - X-Matrix-External-Source-IP
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
            - X-Matrix-Edge-Assertion
            - Forwarded
            - X-Forwarded-For
            - X-Real-IP
          # proxy-rewrite applies removals after mutations. Setting these
          # edge-owned facts already overwrites caller input; listing the
          # same names under remove would erase the trusted replacements.
          set:
            X-Matrix-External-Origin: %q
            X-Matrix-External-Request-Target: "$request_uri"
            X-Matrix-External-Source-IP: "$remote_addr"
      serverless-post-function:
        phase: rewrite
        functions:
          - |
            local assertion
            return function()
              if assertion == nil then
                local file = io.open("/run/matrix/audit-edge-assertion", "rb")
                if file == nil then
                  return 503
                end
                local value = file:read(65)
                file:close()
                if type(value) ~= "string" or #value ~= 64 or string.find(value, "[^0-9a-f]") ~= nil then
                  return 503
                end
                assertion = value
              end
              ngx.req.clear_header("X-Matrix-Edge-Assertion")
              ngx.req.set_header("X-Matrix-Edge-Assertion", assertion)
            end
    upstream:
      type: roundrobin
      nodes:
        "audit:8080": 1
  -
    id: matrix-platform
    uri: /api/platform/*
    plugins:
      proxy-rewrite:
        regex_uri:
          - "^/api/platform/(.*)"
          - "/$1"
        headers:
          remove:
            - Matrix-Subject-Credential
    upstream:
      type: roundrobin
      nodes:
        "platform-api:8080": 1
  -
    id: matrix-paas-node-enrollment-bootstrap
    uris:
      - /api/paas/v1/node-enrollments/*/exchange
      - /api/paas/v1/node-enrollments/*/recovery-challenge
      - /api/paas/v1/node-enrollments/*/recover
      - /api/paas/v1/node-enrollments/*/complete
    methods:
      - POST
    priority: 300
    timeout:
      connect: 3
      send: 10
      read: 10
    vars:
      -
        - uri
        - "~~"
        - "^/api/paas/v1/node-enrollments/node-enrollment-[0-9a-f]{32}/(?:exchange|recovery-challenge|recover|complete)$"
      -
        - server_port
        - "=="
        - "%d"
    plugins:
      proxy-rewrite:
        regex_uri:
          - "^/api/paas/(.*)"
          - "/$1"
        headers:
          set:
            X-Matrix-Observed-Peer: "$http_x_matrix_tls_peer"
            X-Matrix-Transport-Scheme: "https"
          remove:
            - Authorization
            - Cookie
            - Forwarded
            - Idempotency-Key
            - If-Match
            - Matrix-Subject-Credential
            - X-Matrix-Edge-Assertion
            - X-Matrix-External-Origin
            - X-Matrix-External-Request-Target
            - X-Matrix-External-Source-IP
            - X-Forwarded-For
            - X-Matrix-Public-Origin
            - X-Matrix-TLS-Peer
            - X-Real-IP
    upstream:
      type: roundrobin
      nodes:
        "paas-api:8080": 1
  -
    id: matrix-paas-terminal
    uri: /api/paas/v1/terminal-sessions/*
    methods:
      - GET
    priority: 200
    vars:
      -
        - uri
        - "~~"
        - "^/api/paas/v1/terminal-sessions/terminal-session-[0-9a-f]{32}/connect$"
    enable_websocket: true
    timeout:
      connect: 5
      send: 10
      read: 130
    plugins:
      proxy-rewrite:
        regex_uri:
          - "^/api/paas/(.*)"
          - "/$1"
        headers:
          remove:
            - X-Matrix-Observed-Peer
            - X-Matrix-Transport-Scheme
            - X-Matrix-TLS-Peer
    upstream:
      type: roundrobin
      nodes:
        "paas-api:8080": 1
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
            - X-Matrix-Edge-Assertion
            - Forwarded
            - X-Forwarded-For
            - X-Real-IP
            - X-Matrix-External-Origin
            - X-Matrix-External-Request-Target
            - X-Matrix-External-Source-IP
            - X-Matrix-Observed-Peer
            - X-Matrix-Transport-Scheme
            - X-Matrix-TLS-Peer
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
            - X-Matrix-Edge-Assertion
            - Forwarded
            - X-Forwarded-For
            - X-Real-IP
            - X-Matrix-Observed-Peer
            - X-Matrix-Transport-Scheme
            - X-Matrix-TLS-Peer
          # proxy-rewrite applies removals after mutations. Setting these
          # edge-owned facts already overwrites caller input; listing the
          # same names under remove would erase the trusted replacements.
          set:
            X-Matrix-External-Origin: %q
            X-Matrix-External-Request-Target: "$request_uri"
            X-Matrix-External-Source-IP: "$remote_addr"
      serverless-post-function:
        phase: rewrite
        functions:
          - |
            local assertion
            return function()
              if assertion == nil then
                local file = io.open("/run/matrix/paas-edge-assertion", "rb")
                if file == nil then
                  return 503
                end
                local value = file:read(65)
                file:close()
                if type(value) ~= "string" or #value ~= 64 or string.find(value, "[^0-9a-f]") ~= nil then
                  return 503
                end
                assertion = value
              end
              ngx.req.clear_header("X-Matrix-Edge-Assertion")
              ngx.req.set_header("X-Matrix-Edge-Assertion", assertion)
            end
    upstream:
      type: roundrobin
      nodes:
        "paas-api:8080": 1
  -
    id: matrix-managed-services
    uri: /api/managed-services/*
    plugins:
      proxy-rewrite:
        regex_uri:
          - "^/api/managed-services/(.*)"
          - "/managed-services/$1"
        headers:
          remove:
            - Matrix-Subject-Credential
            - X-Matrix-Edge-Assertion
            - Forwarded
            - X-Forwarded-For
            - X-Real-IP
            - X-Matrix-External-Origin
            - X-Matrix-External-Request-Target
            - X-Matrix-External-Source-IP
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
            - X-Matrix-Edge-Assertion
    upstream:
      type: roundrobin
      nodes:
        "matrix-ui:8080": 1
#END
`, northboundOrigin, topology.NodeEnrollmentIngressLoopbackPort, northboundOrigin))
}
