package localmachine

// legacyProductlessAPISIXStandaloneConfig is the byte-exact gateway contract
// owned by the accepted productless Phase 1 release. It exists only so an
// authenticated installed predecessor can be observed, restored, and started
// during upgrade, rollback, and recovery.
func legacyProductlessAPISIXStandaloneConfig() []byte {
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
