BEGIN;
SET LOCAL ROLE matrix_devops_owner;

REVOKE ALL ON SCHEMA delivery FROM PUBLIC;
GRANT USAGE ON SCHEMA delivery TO matrix_devops_api, matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.current_tenant_id()
RETURNS text
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT CASE
        WHEN current_setting('matrix.devops_tenant_id', true)
            COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        THEN current_setting('matrix.devops_tenant_id', true)
        ELSE NULL
    END
$function$;

CREATE TABLE IF NOT EXISTS delivery.projects (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT projects_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT projects_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT projects_document_identity CHECK (
        document->>'apiVersion' = 'devops.matrix.xiak.com/v1'
        AND document->>'kind' = 'DevOpsProject'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
    )
);

CREATE TABLE IF NOT EXISTS delivery.source_connections (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    adapter_id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT source_connections_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND adapter_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT source_connections_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT source_connections_document_identity CHECK (
        document->>'apiVersion' = 'devops.matrix.xiak.com/v1'
        AND document->>'kind' = 'SourceConnection'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND document#>>'{spec,adapterId}' = adapter_id
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
    )
);

CREATE TABLE IF NOT EXISTS delivery.repository_bindings (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    project_id text COLLATE "C" NOT NULL,
    source_connection_id text COLLATE "C" NOT NULL,
    content_digest text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT repository_bindings_project_identity_uq UNIQUE (tenant_id, id, project_id),
    CONSTRAINT repository_bindings_project_fk FOREIGN KEY (tenant_id, project_id)
        REFERENCES delivery.projects (tenant_id, id),
    CONSTRAINT repository_bindings_connection_fk FOREIGN KEY (tenant_id, source_connection_id)
        REFERENCES delivery.source_connections (tenant_id, id),
    CONSTRAINT repository_bindings_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND project_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND source_connection_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    CONSTRAINT repository_bindings_digest_valid CHECK (
        content_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT repository_bindings_version_valid CHECK (
        resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT repository_bindings_document_identity CHECK (
        document->>'apiVersion' = 'devops.matrix.xiak.com/v1'
        AND document->>'kind' = 'RepositoryBinding'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND document->>'projectId' = project_id
        AND document#>>'{spec,sourceConnectionId}' = source_connection_id
        AND document->>'contentDigest' = content_digest
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
    )
);

CREATE TABLE IF NOT EXISTS delivery.repository_binding_revisions (
    tenant_id text COLLATE "C" NOT NULL,
    binding_id text COLLATE "C" NOT NULL,
    project_id text COLLATE "C" NOT NULL,
    source_connection_id text COLLATE "C" NOT NULL,
    content_digest text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    created_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, binding_id, content_digest),
    CONSTRAINT repository_binding_revisions_version_uq UNIQUE (
        tenant_id, binding_id, resource_version
    ),
    CONSTRAINT repository_binding_revisions_project_identity_uq UNIQUE (
        tenant_id, binding_id, content_digest, project_id
    ),
    CONSTRAINT repository_binding_revisions_binding_fk FOREIGN KEY (tenant_id, binding_id)
        REFERENCES delivery.repository_bindings (tenant_id, id),
    CONSTRAINT repository_binding_revisions_project_fk FOREIGN KEY (tenant_id, project_id)
        REFERENCES delivery.projects (tenant_id, id),
    CONSTRAINT repository_binding_revisions_connection_fk FOREIGN KEY (tenant_id, source_connection_id)
        REFERENCES delivery.source_connections (tenant_id, id),
    CONSTRAINT repository_binding_revisions_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND binding_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND project_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND source_connection_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND content_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND resource_version BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT repository_binding_revisions_document_identity CHECK (
        document->>'apiVersion' = 'devops.matrix.xiak.com/v1'
        AND document->>'kind' = 'RepositoryBinding'
        AND document#>>'{metadata,id}' = binding_id
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND document->>'projectId' = project_id
        AND document#>>'{spec,sourceConnectionId}' = source_connection_id
        AND document->>'contentDigest' = content_digest
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
        AND (document#>>'{metadata,updatedAt}')::timestamptz = created_at
    )
);

CREATE TABLE IF NOT EXISTS delivery.pipelines (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    project_id text COLLATE "C" NOT NULL,
    repository_binding_id text COLLATE "C" NOT NULL,
    draft_digest text COLLATE "C" NOT NULL,
    active_revision_id text COLLATE "C",
    active_revision bigint,
    active_revision_digest text COLLATE "C",
    resource_version bigint NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT pipelines_project_identity_uq UNIQUE (tenant_id, id, project_id),
    CONSTRAINT pipelines_project_fk FOREIGN KEY (tenant_id, project_id)
        REFERENCES delivery.projects (tenant_id, id),
    CONSTRAINT pipelines_binding_fk FOREIGN KEY (tenant_id, repository_binding_id, project_id)
        REFERENCES delivery.repository_bindings (tenant_id, id, project_id),
    CONSTRAINT pipelines_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND project_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND repository_binding_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND draft_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND resource_version BETWEEN 1 AND 9007199254740991
        AND num_nonnulls(active_revision_id, active_revision, active_revision_digest) IN (0, 3)
        AND (active_revision IS NULL OR active_revision BETWEEN 1 AND 9007199254740991)
        AND (active_revision_digest IS NULL OR active_revision_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$')
    ),
    CONSTRAINT pipelines_document_identity CHECK (
        document->>'apiVersion' = 'devops.matrix.xiak.com/v1'
        AND document->>'kind' = 'Pipeline'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND document->>'projectId' = project_id
        AND document#>>'{draft,spec,repositoryBindingId}' = repository_binding_id
        AND document#>>'{draft,contentDigest}' = draft_digest
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
        AND (
            (active_revision_id IS NULL AND NOT (document ? 'activeRevision'))
            OR (
                document#>>'{activeRevision,id}' = active_revision_id
                AND (document#>>'{activeRevision,revision}')::numeric = active_revision
                AND document#>>'{activeRevision,contentDigest}' = active_revision_digest
            )
        )
    )
);

CREATE TABLE IF NOT EXISTS delivery.pipeline_revisions (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    pipeline_id text COLLATE "C" NOT NULL,
    project_id text COLLATE "C" NOT NULL,
    repository_binding_id text COLLATE "C" NOT NULL,
    repository_binding_digest text COLLATE "C" NOT NULL,
    revision bigint NOT NULL,
    content_digest text COLLATE "C" NOT NULL,
    activated_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT pipeline_revisions_number_uq UNIQUE (tenant_id, pipeline_id, revision),
    CONSTRAINT pipeline_revisions_active_identity_uq UNIQUE (
        tenant_id, id, pipeline_id, revision, content_digest
    ),
    CONSTRAINT pipeline_revisions_pipeline_fk FOREIGN KEY (tenant_id, pipeline_id, project_id)
        REFERENCES delivery.pipelines (tenant_id, id, project_id),
    CONSTRAINT pipeline_revisions_binding_snapshot_fk FOREIGN KEY (
        tenant_id, repository_binding_id, repository_binding_digest, project_id
    ) REFERENCES delivery.repository_binding_revisions (
        tenant_id, binding_id, content_digest, project_id
    ),
    CONSTRAINT pipeline_revisions_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND pipeline_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND project_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND repository_binding_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND repository_binding_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND revision BETWEEN 1 AND 9007199254740991
        AND content_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT pipeline_revisions_document_identity CHECK (
        document->>'apiVersion' = 'devops.matrix.xiak.com/v1'
        AND document->>'kind' = 'PipelineRevision'
        AND document->>'id' = id
        AND document#>>'{scope,tenantId}' = tenant_id
        AND document->>'pipelineId' = pipeline_id
        AND document->>'projectId' = project_id
        AND document#>>'{spec,repositoryBindingId}' = repository_binding_id
        AND document#>>'{spec,repositoryBindingDigest}' = repository_binding_digest
        AND (document->>'revision')::numeric = revision
        AND document->>'contentDigest' = content_digest
        AND (document->>'activatedAt')::timestamptz = activated_at
    )
);

DO $matrix_pipeline_active_fk$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace
           AND conname = 'pipelines_active_revision_fk'
    ) THEN
        ALTER TABLE delivery.pipelines
            ADD CONSTRAINT pipelines_active_revision_fk
            FOREIGN KEY (
                tenant_id, active_revision_id, id, active_revision, active_revision_digest
            ) REFERENCES delivery.pipeline_revisions (
                tenant_id, id, pipeline_id, revision, content_digest
            ) DEFERRABLE INITIALLY DEFERRED;
    END IF;
END
$matrix_pipeline_active_fk$;

CREATE TABLE IF NOT EXISTS delivery.mutations (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    mutation_kind text COLLATE "C" NOT NULL,
    command_target_id text COLLATE "C" NOT NULL,
    target_kind text COLLATE "C" NOT NULL,
    target_id text COLLATE "C" NOT NULL,
    idempotency_fingerprint text COLLATE "C" NOT NULL,
    request_digest text COLLATE "C" NOT NULL,
    result_kind text COLLATE "C" NOT NULL,
    created_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    result_document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT mutations_idempotency_uq UNIQUE (tenant_id, idempotency_fingerprint),
    CONSTRAINT mutations_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND command_target_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND target_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND mutation_kind IN (
            'CREATE_PROJECT', 'CREATE_SOURCE_CONNECTION', 'UPDATE_SOURCE_CONNECTION',
            'CREATE_REPOSITORY_BINDING', 'UPDATE_REPOSITORY_BINDING',
            'CREATE_PIPELINE', 'UPDATE_PIPELINE_DRAFT', 'ACTIVATE_PIPELINE'
        )
        AND target_kind IN (
            'DEVOPS_PROJECT', 'SOURCE_CONNECTION', 'REPOSITORY_BINDING',
            'PIPELINE', 'PIPELINE_REVISION'
        )
        AND idempotency_fingerprint COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND request_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND result_kind IN (
            'DevOpsProject', 'SourceConnection', 'RepositoryBinding',
            'Pipeline', 'PipelineActivation'
        )
    ),
    CONSTRAINT mutations_document_identity CHECK (
        document->>'schemaVersion' = 'v1'
        AND document->>'id' = id
        AND document->>'tenantId' = tenant_id
        AND document->>'kind' = mutation_kind
        AND document->>'commandTargetId' = command_target_id
        AND document#>>'{target,kind}' = target_kind
        AND document#>>'{target,id}' = target_id
        AND document->>'idempotencyFingerprint' = idempotency_fingerprint
        AND document->>'requestDigest' = request_digest
        AND document->>'resultKind' = result_kind
        AND (document->>'createdAt')::timestamptz = created_at
        AND result_document->>'kind' = result_kind
    )
);

CREATE TABLE IF NOT EXISTS delivery.audit_outbox (
    tenant_id text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    operation_id text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL,
    available_at timestamptz(6) NOT NULL,
    attempts integer NOT NULL,
    fencing_token bigint NOT NULL,
    lease_owner text COLLATE "C",
    lease_expires_at timestamptz(6),
    last_error_code text COLLATE "C",
    delivered_at timestamptz(6),
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, event_id),
    CONSTRAINT audit_outbox_operation_fk FOREIGN KEY (tenant_id, operation_id)
        REFERENCES delivery.mutations (tenant_id, id),
    CONSTRAINT audit_outbox_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND event_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND operation_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND status IN ('PENDING', 'LEASED', 'RETRY', 'DELIVERED', 'DEAD_LETTER')
        AND attempts BETWEEN 0 AND 100
        AND fencing_token BETWEEN 0 AND 9007199254740991
        AND ((lease_owner IS NULL) = (lease_expires_at IS NULL))
        AND updated_at >= created_at
    ),
    CONSTRAINT audit_outbox_document_identity CHECK (
        document->>'apiVersion' = 'audit.matrix.xiak.com/v1'
        AND document->>'kind' = 'AuditEvent'
        AND document->>'eventId' = event_id
        AND document->>'tenantId' = tenant_id
        AND document->>'operationId' = operation_id
    )
);

ALTER TABLE delivery.audit_outbox
    ADD COLUMN IF NOT EXISTS delivered_at timestamptz(6);

DO $matrix_audit_outbox_state_constraint$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace
           AND conname = 'audit_outbox_delivery_state_valid'
    ) THEN
        ALTER TABLE delivery.audit_outbox
            ADD CONSTRAINT audit_outbox_delivery_state_valid CHECK (
                ((status = 'LEASED') = (lease_owner IS NOT NULL))
                AND (
                    (status = 'DELIVERED'
                        AND delivered_at IS NOT NULL
                        AND delivered_at >= created_at
                        AND last_error_code IS NULL)
                    OR (status = 'DEAD_LETTER'
                        AND delivered_at IS NULL
                        AND last_error_code IS NOT NULL)
                    OR (status IN ('PENDING', 'LEASED', 'RETRY')
                        AND delivered_at IS NULL
                        AND last_error_code IS NULL)
                )
            );
    END IF;
END
$matrix_audit_outbox_state_constraint$;

ALTER TABLE delivery.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.projects FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.source_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.source_connections FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.repository_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.repository_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.repository_binding_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.repository_binding_revisions FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.pipelines ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.pipelines FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.pipeline_revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.pipeline_revisions FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.mutations ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.mutations FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.audit_outbox FORCE ROW LEVEL SECURITY;

DO $matrix_delivery_policy$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'projects', 'source_connections', 'repository_bindings',
        'repository_binding_revisions', 'pipelines', 'pipeline_revisions',
        'mutations', 'audit_outbox'
    ]
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_policies
             WHERE schemaname = 'delivery' AND tablename = table_name
               AND policyname = 'tenant_isolation'
        ) THEN
            EXECUTE format(
                'CREATE POLICY tenant_isolation ON delivery.%I '
                'USING (tenant_id = delivery.current_tenant_id()) '
                'WITH CHECK (tenant_id = delivery.current_tenant_id())',
                table_name
            );
        END IF;
    END LOOP;
END
$matrix_delivery_policy$;

DO $matrix_audit_outbox_owner_policy$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_policies
         WHERE schemaname = 'delivery' AND tablename = 'audit_outbox'
           AND policyname = 'owner_dispatch'
    ) THEN
        CREATE POLICY owner_dispatch ON delivery.audit_outbox
            TO matrix_devops_owner
            USING (true)
            WITH CHECK (true);
    END IF;
END
$matrix_audit_outbox_owner_policy$;

CREATE OR REPLACE FUNCTION delivery.commit_configuration_mutation(
    requested_kind text,
    expected_resource_version bigint,
    submitted_resource jsonb,
    submitted_secondary jsonb,
    submitted_mutation jsonb,
    submitted_result jsonb,
    submitted_audit_event jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    effective_now timestamptz(6);
    expected_iam_action text;
    expected_iam_resource text;
    expected_audit_action text;
    expected_audit_target text;
    expected_result_kind text;
    result_field text;
    resource_kind text;
    resource_id text;
    audit_target_id text;
    current_document jsonb;
    affected integer;
BEGIN
    effective_tenant_id := delivery.current_tenant_id();
    effective_now := transaction_timestamp();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'valid transaction-local delivery tenant is required';
    END IF;

    expected_iam_action := CASE requested_kind
        WHEN 'CREATE_PROJECT' THEN 'devops.project.create'
        WHEN 'CREATE_SOURCE_CONNECTION' THEN 'devops.source-connection.create'
        WHEN 'UPDATE_SOURCE_CONNECTION' THEN 'devops.source-connection.update'
        WHEN 'CREATE_REPOSITORY_BINDING' THEN 'devops.repository-binding.create'
        WHEN 'UPDATE_REPOSITORY_BINDING' THEN 'devops.repository-binding.update'
        WHEN 'CREATE_PIPELINE' THEN 'devops.pipeline.create'
        WHEN 'UPDATE_PIPELINE_DRAFT' THEN 'devops.pipeline.update'
        WHEN 'ACTIVATE_PIPELINE' THEN 'devops.pipeline.activate'
        ELSE NULL
    END;
    expected_iam_resource := CASE
        WHEN requested_kind = 'CREATE_PROJECT' THEN 'DEVOPS_PROJECT'
        WHEN requested_kind IN ('CREATE_SOURCE_CONNECTION', 'UPDATE_SOURCE_CONNECTION')
            THEN 'SOURCE_CONNECTION'
        WHEN requested_kind IN ('CREATE_REPOSITORY_BINDING', 'UPDATE_REPOSITORY_BINDING')
            THEN 'REPOSITORY_BINDING'
        ELSE 'PIPELINE'
    END;
    expected_audit_action := CASE requested_kind
        WHEN 'CREATE_PROJECT' THEN 'devops.project.created'
        WHEN 'CREATE_SOURCE_CONNECTION' THEN 'devops.source-connection.created'
        WHEN 'UPDATE_SOURCE_CONNECTION' THEN 'devops.source-connection.updated'
        WHEN 'CREATE_REPOSITORY_BINDING' THEN 'devops.repository-binding.created'
        WHEN 'UPDATE_REPOSITORY_BINDING' THEN 'devops.repository-binding.updated'
        WHEN 'CREATE_PIPELINE' THEN 'devops.pipeline.created'
        WHEN 'UPDATE_PIPELINE_DRAFT' THEN 'devops.pipeline.draft-updated'
        WHEN 'ACTIVATE_PIPELINE' THEN 'devops.pipeline-revision.activated'
        ELSE NULL
    END;
    expected_audit_target := CASE
        WHEN requested_kind = 'CREATE_PROJECT' THEN 'DEVOPS_PROJECT'
        WHEN requested_kind IN ('CREATE_SOURCE_CONNECTION', 'UPDATE_SOURCE_CONNECTION')
            THEN 'SOURCE_CONNECTION'
        WHEN requested_kind IN ('CREATE_REPOSITORY_BINDING', 'UPDATE_REPOSITORY_BINDING')
            THEN 'REPOSITORY_BINDING'
        WHEN requested_kind = 'ACTIVATE_PIPELINE' THEN 'PIPELINE_REVISION'
        ELSE 'PIPELINE'
    END;
    expected_result_kind := CASE
        WHEN requested_kind = 'CREATE_PROJECT' THEN 'DevOpsProject'
        WHEN requested_kind IN ('CREATE_SOURCE_CONNECTION', 'UPDATE_SOURCE_CONNECTION')
            THEN 'SourceConnection'
        WHEN requested_kind IN ('CREATE_REPOSITORY_BINDING', 'UPDATE_REPOSITORY_BINDING')
            THEN 'RepositoryBinding'
        WHEN requested_kind = 'ACTIVATE_PIPELINE' THEN 'PipelineActivation'
        ELSE 'Pipeline'
    END;
    result_field := CASE expected_result_kind
        WHEN 'DevOpsProject' THEN 'project'
        WHEN 'SourceConnection' THEN 'sourceConnection'
        WHEN 'RepositoryBinding' THEN 'repositoryBinding'
        WHEN 'Pipeline' THEN 'pipeline'
        WHEN 'PipelineActivation' THEN 'pipelineActivation'
        ELSE NULL
    END;
    resource_kind := CASE
        WHEN requested_kind = 'CREATE_PROJECT' THEN 'DevOpsProject'
        WHEN requested_kind IN ('CREATE_SOURCE_CONNECTION', 'UPDATE_SOURCE_CONNECTION')
            THEN 'SourceConnection'
        WHEN requested_kind IN ('CREATE_REPOSITORY_BINDING', 'UPDATE_REPOSITORY_BINDING')
            THEN 'RepositoryBinding'
        ELSE 'Pipeline'
    END;
    IF expected_iam_action IS NULL OR expected_resource_version IS NULL
       OR expected_resource_version NOT BETWEEN 0 AND 9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'delivery mutation kind or version is invalid';
    END IF;
    IF (requested_kind = 'ACTIVATE_PIPELINE' AND jsonb_typeof(submitted_secondary) IS DISTINCT FROM 'object')
       OR (requested_kind <> 'ACTIVATE_PIPELINE' AND submitted_secondary IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'delivery secondary resource is invalid';
    END IF;
    IF jsonb_typeof(submitted_resource) IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_mutation) IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_result) IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_audit_event) IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_resource->'metadata') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_mutation->'requestedBy') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_mutation->'iamResource') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_mutation->'target') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_audit_event->'actor') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_audit_event->'target') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'delivery mutation documents must be objects';
    END IF;

    resource_id := submitted_resource#>>'{metadata,id}';
    audit_target_id := CASE WHEN requested_kind = 'ACTIVATE_PIPELINE'
        THEN submitted_secondary->>'id' ELSE resource_id END;
    IF NOT (submitted_resource ?& ARRAY['apiVersion', 'kind', 'metadata'])
       OR NOT ((submitted_resource->'metadata') ?& ARRAY[
            'id', 'name', 'scope', 'resourceVersion', 'createdAt', 'updatedAt'
       ])
       OR submitted_resource->>'apiVersion' IS DISTINCT FROM 'devops.matrix.xiak.com/v1'
       OR submitted_resource->>'kind' IS DISTINCT FROM resource_kind
       OR submitted_resource#>>'{metadata,scope,tenantId}' IS DISTINCT FROM effective_tenant_id
       OR COALESCE(resource_id, '') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR (submitted_resource#>>'{metadata,updatedAt}')::timestamptz IS DISTINCT FROM effective_now
       OR (CASE WHEN requested_kind LIKE 'CREATE_%'
            THEN (expected_resource_version <> 0
                 OR submitted_resource#>>'{metadata,resourceVersion}' IS DISTINCT FROM '1'
                 OR (submitted_resource#>>'{metadata,createdAt}')::timestamptz IS DISTINCT FROM effective_now)
            ELSE (expected_resource_version < 1
                 OR (submitted_resource#>>'{metadata,resourceVersion}')::numeric
                    IS DISTINCT FROM expected_resource_version + 1)
          END) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'delivery resource identity is invalid';
    END IF;

    IF NOT (submitted_mutation ?& ARRAY[
            'schemaVersion', 'id', 'tenantId', 'kind', 'commandTargetId',
            'requestedBy', 'iamDecisionId', 'iamAction', 'iamResource',
            'idempotencyFingerprint', 'requestDigest', 'resultKind', 'target',
            'requestId', 'correlationId', 'createdAt'
       ])
       OR (submitted_mutation - ARRAY[
            'schemaVersion', 'id', 'tenantId', 'kind', 'commandTargetId',
            'requestedBy', 'iamDecisionId', 'iamAction', 'iamResource',
            'idempotencyFingerprint', 'requestDigest', 'resultKind', 'target',
            'requestId', 'correlationId', 'traceparent', 'createdAt'
       ]) <> '{}'::jsonb
       OR ((submitted_mutation->'requestedBy') - ARRAY['kind', 'id']) <> '{}'::jsonb
       OR ((submitted_mutation->'iamResource') - ARRAY['kind', 'id']) <> '{}'::jsonb
       OR ((submitted_mutation->'target') - ARRAY['kind', 'id']) <> '{}'::jsonb
       OR submitted_mutation->>'schemaVersion' IS DISTINCT FROM 'v1'
       OR submitted_mutation->>'tenantId' IS DISTINCT FROM effective_tenant_id
       OR submitted_mutation->>'kind' IS DISTINCT FROM requested_kind
       OR submitted_mutation->>'commandTargetId' IS DISTINCT FROM resource_id
       OR submitted_mutation->>'iamAction' IS DISTINCT FROM expected_iam_action
       OR submitted_mutation#>>'{iamResource,kind}' IS DISTINCT FROM expected_iam_resource
       OR submitted_mutation#>>'{iamResource,id}' IS DISTINCT FROM resource_id
       OR submitted_mutation->>'resultKind' IS DISTINCT FROM expected_result_kind
       OR submitted_mutation#>>'{target,kind}' IS DISTINCT FROM expected_audit_target
       OR submitted_mutation#>>'{target,id}' IS DISTINCT FROM audit_target_id
       OR COALESCE(submitted_mutation->>'id', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_mutation#>>'{requestedBy,id}', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_mutation#>>'{requestedBy,kind}' NOT IN ('USER', 'SERVICE_ACCOUNT')
       OR COALESCE(submitted_mutation->>'iamDecisionId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_mutation->>'idempotencyFingerprint', '') COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR COALESCE(submitted_mutation->>'requestDigest', '') COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR COALESCE(submitted_mutation->>'requestId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_mutation->>'correlationId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR (submitted_mutation->>'createdAt')::timestamptz IS DISTINCT FROM effective_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'delivery mutation record is invalid';
    END IF;

    IF submitted_result->>'kind' IS DISTINCT FROM expected_result_kind
       OR (submitted_result - ARRAY['kind', result_field]) <> '{}'::jsonb
       OR (CASE WHEN requested_kind = 'ACTIVATE_PIPELINE'
            THEN (submitted_result->result_field->'pipeline' IS DISTINCT FROM submitted_resource
                 OR submitted_result->result_field->'revision' IS DISTINCT FROM submitted_secondary)
            ELSE submitted_result->result_field IS DISTINCT FROM submitted_resource
          END) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'delivery mutation result is invalid';
    END IF;

    IF NOT (submitted_audit_event ?& ARRAY[
            'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
            'iamDecisionId', 'action', 'target', 'result', 'requestDigest',
            'requestId', 'correlationId', 'operationId', 'occurredAt'
       ])
       OR (submitted_audit_event - ARRAY[
            'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
            'iamDecisionId', 'action', 'target', 'result', 'requestDigest',
            'requestId', 'correlationId', 'operationId', 'traceparent', 'occurredAt'
       ]) <> '{}'::jsonb
       OR ((submitted_audit_event->'actor') - ARRAY['type', 'id']) <> '{}'::jsonb
       OR ((submitted_audit_event->'target') - ARRAY['kind', 'id']) <> '{}'::jsonb
       OR submitted_audit_event->>'apiVersion' IS DISTINCT FROM 'audit.matrix.xiak.com/v1'
       OR submitted_audit_event->>'kind' IS DISTINCT FROM 'AuditEvent'
       OR submitted_audit_event->>'tenantId' IS DISTINCT FROM effective_tenant_id
       OR submitted_audit_event#>>'{actor,type}' IS DISTINCT FROM submitted_mutation#>>'{requestedBy,kind}'
       OR submitted_audit_event#>>'{actor,id}' IS DISTINCT FROM submitted_mutation#>>'{requestedBy,id}'
       OR submitted_audit_event->>'iamDecisionId' IS DISTINCT FROM submitted_mutation->>'iamDecisionId'
       OR submitted_audit_event->>'action' IS DISTINCT FROM expected_audit_action
       OR submitted_audit_event->'target' IS DISTINCT FROM submitted_mutation->'target'
       OR submitted_audit_event->>'result' IS DISTINCT FROM 'SUCCEEDED'
       OR submitted_audit_event->>'requestDigest' IS DISTINCT FROM submitted_mutation->>'requestDigest'
       OR submitted_audit_event->>'requestId' IS DISTINCT FROM submitted_mutation->>'requestId'
       OR submitted_audit_event->>'correlationId' IS DISTINCT FROM submitted_mutation->>'correlationId'
       OR submitted_audit_event->>'operationId' IS DISTINCT FROM submitted_mutation->>'id'
       OR COALESCE(submitted_audit_event->>'traceparent', '')
            IS DISTINCT FROM COALESCE(submitted_mutation->>'traceparent', '')
       OR (submitted_audit_event->>'occurredAt')::timestamptz IS DISTINCT FROM effective_now
       OR COALESCE(submitted_audit_event->>'eventId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'delivery Audit event is invalid';
    END IF;

    CASE requested_kind
    WHEN 'CREATE_PROJECT' THEN
        INSERT INTO delivery.projects (tenant_id, id, resource_version, document)
        VALUES (effective_tenant_id, resource_id, 1, submitted_resource);
    WHEN 'CREATE_SOURCE_CONNECTION' THEN
        INSERT INTO delivery.source_connections (
            tenant_id, id, adapter_id, resource_version, document
        ) VALUES (
            effective_tenant_id, resource_id,
            submitted_resource#>>'{spec,adapterId}', 1, submitted_resource
        );
    WHEN 'UPDATE_SOURCE_CONNECTION' THEN
        SELECT document INTO current_document
          FROM delivery.source_connections
         WHERE tenant_id = effective_tenant_id AND id = resource_id
         FOR UPDATE;
        IF current_document IS NULL
           OR (current_document#>>'{metadata,resourceVersion}')::numeric <> expected_resource_version THEN
            RAISE EXCEPTION USING ERRCODE = 'MX409', MESSAGE = 'SourceConnection version conflict';
        END IF;
        IF current_document#>>'{spec,adapterId}' IS DISTINCT FROM submitted_resource#>>'{spec,adapterId}'
           OR current_document#>'{spec,allowedEndpointOrigins}'
                IS DISTINCT FROM submitted_resource#>'{spec,allowedEndpointOrigins}'
           OR current_document#>>'{metadata,name}' IS DISTINCT FROM submitted_resource#>>'{metadata,name}'
           OR current_document#>>'{metadata,createdAt}' IS DISTINCT FROM submitted_resource#>>'{metadata,createdAt}' THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'SourceConnection immutable identity changed';
        END IF;
        UPDATE delivery.source_connections
           SET resource_version = expected_resource_version + 1,
               document = submitted_resource
         WHERE tenant_id = effective_tenant_id AND id = resource_id
           AND resource_version = expected_resource_version;
    WHEN 'CREATE_REPOSITORY_BINDING' THEN
        INSERT INTO delivery.repository_bindings (
            tenant_id, id, project_id, source_connection_id,
            content_digest, resource_version, document
        ) VALUES (
            effective_tenant_id, resource_id, submitted_resource->>'projectId',
            submitted_resource#>>'{spec,sourceConnectionId}',
            submitted_resource->>'contentDigest', 1, submitted_resource
        );
        INSERT INTO delivery.repository_binding_revisions (
            tenant_id, binding_id, project_id, source_connection_id,
            content_digest, resource_version, created_at, document
        ) VALUES (
            effective_tenant_id, resource_id, submitted_resource->>'projectId',
            submitted_resource#>>'{spec,sourceConnectionId}',
            submitted_resource->>'contentDigest', 1, effective_now, submitted_resource
        );
    WHEN 'UPDATE_REPOSITORY_BINDING' THEN
        SELECT document INTO current_document
          FROM delivery.repository_bindings
         WHERE tenant_id = effective_tenant_id AND id = resource_id
         FOR UPDATE;
        IF current_document IS NULL
           OR (current_document#>>'{metadata,resourceVersion}')::numeric <> expected_resource_version THEN
            RAISE EXCEPTION USING ERRCODE = 'MX409', MESSAGE = 'RepositoryBinding version conflict';
        END IF;
        IF current_document->>'projectId' IS DISTINCT FROM submitted_resource->>'projectId'
           OR current_document#>>'{metadata,name}' IS DISTINCT FROM submitted_resource#>>'{metadata,name}'
           OR current_document#>>'{metadata,createdAt}' IS DISTINCT FROM submitted_resource#>>'{metadata,createdAt}' THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'RepositoryBinding immutable identity changed';
        END IF;
        UPDATE delivery.repository_bindings
           SET source_connection_id = submitted_resource#>>'{spec,sourceConnectionId}',
               content_digest = submitted_resource->>'contentDigest',
               resource_version = expected_resource_version + 1,
               document = submitted_resource
         WHERE tenant_id = effective_tenant_id AND id = resource_id
           AND resource_version = expected_resource_version;
        INSERT INTO delivery.repository_binding_revisions (
            tenant_id, binding_id, project_id, source_connection_id,
            content_digest, resource_version, created_at, document
        ) VALUES (
            effective_tenant_id, resource_id, submitted_resource->>'projectId',
            submitted_resource#>>'{spec,sourceConnectionId}',
            submitted_resource->>'contentDigest', expected_resource_version + 1,
            effective_now, submitted_resource
        );
    WHEN 'CREATE_PIPELINE' THEN
        INSERT INTO delivery.pipelines (
            tenant_id, id, project_id, repository_binding_id, draft_digest,
            active_revision_id, active_revision, active_revision_digest,
            resource_version, document
        ) VALUES (
            effective_tenant_id, resource_id, submitted_resource->>'projectId',
            submitted_resource#>>'{draft,spec,repositoryBindingId}',
            submitted_resource#>>'{draft,contentDigest}', NULL, NULL, NULL, 1,
            submitted_resource
        );
    WHEN 'UPDATE_PIPELINE_DRAFT' THEN
        SELECT document INTO current_document
          FROM delivery.pipelines
         WHERE tenant_id = effective_tenant_id AND id = resource_id
         FOR UPDATE;
        IF current_document IS NULL
           OR (current_document#>>'{metadata,resourceVersion}')::numeric <> expected_resource_version THEN
            RAISE EXCEPTION USING ERRCODE = 'MX409', MESSAGE = 'Pipeline version conflict';
        END IF;
        IF current_document->>'projectId' IS DISTINCT FROM submitted_resource->>'projectId'
           OR current_document#>>'{metadata,name}' IS DISTINCT FROM submitted_resource#>>'{metadata,name}'
           OR current_document#>>'{metadata,createdAt}' IS DISTINCT FROM submitted_resource#>>'{metadata,createdAt}'
           OR current_document->'activeRevision' IS DISTINCT FROM submitted_resource->'activeRevision' THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Pipeline immutable identity changed';
        END IF;
        UPDATE delivery.pipelines
           SET repository_binding_id = submitted_resource#>>'{draft,spec,repositoryBindingId}',
               draft_digest = submitted_resource#>>'{draft,contentDigest}',
               resource_version = expected_resource_version + 1,
               document = submitted_resource
         WHERE tenant_id = effective_tenant_id AND id = resource_id
           AND resource_version = expected_resource_version;
    WHEN 'ACTIVATE_PIPELINE' THEN
        IF jsonb_typeof(submitted_secondary) IS DISTINCT FROM 'object'
           OR submitted_secondary->>'apiVersion' IS DISTINCT FROM 'devops.matrix.xiak.com/v1'
           OR submitted_secondary->>'kind' IS DISTINCT FROM 'PipelineRevision'
           OR submitted_secondary#>>'{scope,tenantId}' IS DISTINCT FROM effective_tenant_id
           OR submitted_secondary->>'pipelineId' IS DISTINCT FROM resource_id
           OR submitted_secondary->>'projectId' IS DISTINCT FROM submitted_resource->>'projectId'
           OR submitted_secondary#>>'{spec,repositoryBindingId}'
                IS DISTINCT FROM submitted_resource#>>'{draft,spec,repositoryBindingId}'
           OR submitted_secondary->'activatedBy' IS DISTINCT FROM submitted_mutation->'requestedBy'
           OR (submitted_secondary->>'activatedAt')::timestamptz IS DISTINCT FROM effective_now THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'PipelineRevision identity is invalid';
        END IF;
        SELECT document INTO current_document
          FROM delivery.pipelines
         WHERE tenant_id = effective_tenant_id AND id = resource_id
         FOR UPDATE;
        IF current_document IS NULL
           OR (current_document#>>'{metadata,resourceVersion}')::numeric <> expected_resource_version THEN
            RAISE EXCEPTION USING ERRCODE = 'MX409', MESSAGE = 'Pipeline version conflict';
        END IF;
        IF current_document->>'projectId' IS DISTINCT FROM submitted_resource->>'projectId'
           OR current_document#>>'{metadata,name}' IS DISTINCT FROM submitted_resource#>>'{metadata,name}'
           OR current_document#>>'{metadata,createdAt}' IS DISTINCT FROM submitted_resource#>>'{metadata,createdAt}'
           OR current_document->'draft' IS DISTINCT FROM submitted_resource->'draft' THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Pipeline activation changed its draft identity';
        END IF;
        INSERT INTO delivery.pipeline_revisions (
            tenant_id, id, pipeline_id, project_id, repository_binding_id,
            repository_binding_digest, revision, content_digest, activated_at, document
        ) VALUES (
            effective_tenant_id, submitted_secondary->>'id', resource_id,
            submitted_secondary->>'projectId',
            submitted_secondary#>>'{spec,repositoryBindingId}',
            submitted_secondary#>>'{spec,repositoryBindingDigest}',
            (submitted_secondary->>'revision')::bigint,
            submitted_secondary->>'contentDigest', effective_now, submitted_secondary
        );
        UPDATE delivery.pipelines
           SET active_revision_id = submitted_secondary->>'id',
               active_revision = (submitted_secondary->>'revision')::bigint,
               active_revision_digest = submitted_secondary->>'contentDigest',
               resource_version = expected_resource_version + 1,
               document = submitted_resource
         WHERE tenant_id = effective_tenant_id AND id = resource_id
           AND resource_version = expected_resource_version;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'unsupported delivery mutation';
    END CASE;

    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'MX409', MESSAGE = 'delivery resource version conflict';
    END IF;

    INSERT INTO delivery.mutations (
        tenant_id, id, mutation_kind, command_target_id, target_kind, target_id,
        idempotency_fingerprint, request_digest, result_kind, created_at,
        document, result_document
    ) VALUES (
        effective_tenant_id, submitted_mutation->>'id', requested_kind, resource_id,
        expected_audit_target, audit_target_id,
        submitted_mutation->>'idempotencyFingerprint', submitted_mutation->>'requestDigest',
        expected_result_kind, effective_now, submitted_mutation, submitted_result
    );

    INSERT INTO delivery.audit_outbox (
        tenant_id, event_id, operation_id, status, available_at, attempts,
        fencing_token, created_at, updated_at, document
    ) VALUES (
        effective_tenant_id, submitted_audit_event->>'eventId',
        submitted_mutation->>'id', 'PENDING', effective_now, 0, 0,
        effective_now, effective_now, submitted_audit_event
    );
END
$function$;

CREATE OR REPLACE FUNCTION delivery.claim_audit_event(
    requested_worker_id text,
    requested_lease_seconds integer
)
RETURNS TABLE (
    tenant_id text,
    event_id text,
    attempts integer,
    fencing_token bigint,
    lease_expires_at timestamptz,
    document jsonb
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_lease_seconds IS NULL
       OR requested_lease_seconds NOT BETWEEN 1 AND 300 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Audit claim parameters are invalid';
    END IF;
    RETURN QUERY
    WITH candidate AS (
        SELECT pending.tenant_id, pending.event_id
          FROM delivery.audit_outbox AS pending
         WHERE pending.attempts < 100
           AND pending.fencing_token < 9007199254740991
           AND (
                (pending.status IN ('PENDING', 'RETRY')
                    AND pending.available_at <= transaction_timestamp())
                OR (pending.status = 'LEASED'
                    AND pending.lease_expires_at <= transaction_timestamp())
           )
         ORDER BY pending.available_at, pending.created_at,
                  pending.tenant_id COLLATE "C", pending.event_id COLLATE "C"
         LIMIT 1
         FOR UPDATE SKIP LOCKED
    )
    UPDATE delivery.audit_outbox AS claimed
       SET status = 'LEASED',
           attempts = claimed.attempts + 1,
           lease_owner = requested_worker_id,
           lease_expires_at = transaction_timestamp()
                + make_interval(secs => requested_lease_seconds),
           fencing_token = claimed.fencing_token + 1,
           last_error_code = NULL,
           delivered_at = NULL,
           updated_at = transaction_timestamp()
      FROM candidate
     WHERE claimed.tenant_id = candidate.tenant_id
       AND claimed.event_id = candidate.event_id
    RETURNING claimed.tenant_id, claimed.event_id, claimed.attempts,
              claimed.fencing_token, claimed.lease_expires_at, claimed.document;
END
$function$;

REVOKE ALL ON FUNCTION delivery.claim_audit_event(text, integer)
    FROM PUBLIC, matrix_devops_api;
GRANT EXECUTE ON FUNCTION delivery.claim_audit_event(text, integer)
    TO matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.complete_audit_event(
    requested_tenant_id text,
    requested_event_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_outcome text,
    requested_retry_at timestamptz,
    requested_error_code text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    affected_rows bigint;
BEGIN
    IF requested_tenant_id IS NULL
       OR requested_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_event_id IS NULL
       OR requested_event_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR expected_fencing_token IS NULL
       OR expected_fencing_token NOT BETWEEN 1 AND 9007199254740991
       OR requested_outcome NOT IN ('DELIVERED', 'RETRY', 'DEAD_LETTER')
       OR (requested_outcome = 'RETRY'
            AND (requested_retry_at IS NULL
                OR requested_retry_at <= transaction_timestamp()
                OR requested_retry_at > transaction_timestamp() + interval '24 hours'))
       OR (requested_outcome <> 'RETRY' AND requested_retry_at IS NOT NULL)
       OR (requested_outcome = 'DEAD_LETTER'
            AND (requested_error_code IS NULL
                OR requested_error_code COLLATE "C" !~ '^[A-Z][A-Z0-9_]{0,63}$'))
       OR (requested_outcome <> 'DEAD_LETTER' AND requested_error_code IS NOT NULL) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Audit completion parameters are invalid';
    END IF;

    UPDATE delivery.audit_outbox AS event
       SET status = requested_outcome,
           available_at = CASE
                WHEN requested_outcome = 'RETRY' THEN requested_retry_at
                ELSE event.available_at
           END,
           lease_owner = NULL,
           lease_expires_at = NULL,
           last_error_code = CASE
                WHEN requested_outcome = 'DEAD_LETTER' THEN requested_error_code
                ELSE NULL
           END,
           delivered_at = CASE
                WHEN requested_outcome = 'DELIVERED' THEN transaction_timestamp()
                ELSE NULL
           END,
           updated_at = transaction_timestamp()
     WHERE event.tenant_id = requested_tenant_id
       AND event.event_id = requested_event_id
       AND event.status = 'LEASED'
       AND event.lease_owner = requested_worker_id
       AND event.fencing_token = expected_fencing_token
       AND event.lease_expires_at > clock_timestamp();
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'Audit event lease or fencing token is stale';
    END IF;
END
$function$;

REVOKE ALL ON FUNCTION delivery.complete_audit_event(
    text, text, text, bigint, text, timestamptz, text
) FROM PUBLIC, matrix_devops_api;
GRANT EXECUTE ON FUNCTION delivery.complete_audit_event(
    text, text, text, bigint, text, timestamptz, text
) TO matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.audit_outbox_snapshot()
RETURNS TABLE (
    pending_count bigint,
    leased_count bigint,
    retry_count bigint,
    delivered_count bigint,
    dead_letter_count bigint,
    expired_lease_count bigint
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT
        count(*) FILTER (WHERE status = 'PENDING'),
        count(*) FILTER (WHERE status = 'LEASED'),
        count(*) FILTER (WHERE status = 'RETRY'),
        count(*) FILTER (WHERE status = 'DELIVERED'),
        count(*) FILTER (WHERE status = 'DEAD_LETTER'),
        count(*) FILTER (
            WHERE status = 'LEASED'
              AND lease_expires_at <= transaction_timestamp()
        )
    FROM delivery.audit_outbox
$function$;

REVOKE ALL ON FUNCTION delivery.audit_outbox_snapshot()
    FROM PUBLIC, matrix_devops_api;
GRANT EXECUTE ON FUNCTION delivery.audit_outbox_snapshot()
    TO matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.readiness()
RETURNS TABLE (ready boolean, schema_version bigint, checked_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT
        to_regclass('delivery.projects') IS NOT NULL
        AND to_regclass('delivery.source_connections') IS NOT NULL
        AND to_regclass('delivery.repository_bindings') IS NOT NULL
        AND to_regclass('delivery.pipelines') IS NOT NULL
        AND to_regclass('delivery.pipeline_revisions') IS NOT NULL
        AND to_regprocedure(
            'delivery.commit_configuration_mutation(text,bigint,jsonb,jsonb,jsonb,jsonb,jsonb)'
        ) IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM delivery.audit_outbox AS outbox
             WHERE outbox.status = 'DEAD_LETTER'
                OR outbox.attempts >= 100
                OR outbox.fencing_token >= 9007199254740991
        ),
        1::bigint,
        transaction_timestamp()
$function$;

REVOKE ALL ON FUNCTION delivery.readiness()
    FROM PUBLIC, matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.readiness() TO matrix_devops_api;

CREATE OR REPLACE FUNCTION delivery.worker_readiness()
RETURNS TABLE (ready boolean, schema_version bigint, checked_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT
        to_regclass('delivery.audit_outbox') IS NOT NULL
        AND to_regprocedure('delivery.claim_audit_event(text,integer)') IS NOT NULL
        AND to_regprocedure(
            'delivery.complete_audit_event(text,text,text,bigint,text,timestamptz,text)'
        ) IS NOT NULL
        AND to_regprocedure('delivery.audit_outbox_snapshot()') IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM delivery.audit_outbox AS outbox
             WHERE outbox.status = 'DEAD_LETTER'
                OR outbox.attempts >= 100
                OR outbox.fencing_token >= 9007199254740991
        ),
        1::bigint,
        transaction_timestamp()
$function$;

REVOKE ALL ON FUNCTION delivery.worker_readiness()
    FROM PUBLIC, matrix_devops_api;
GRANT EXECUTE ON FUNCTION delivery.worker_readiness() TO matrix_devops_worker;

REVOKE ALL ON FUNCTION delivery.current_tenant_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION delivery.current_tenant_id()
    TO matrix_devops_api, matrix_devops_worker;
REVOKE ALL ON FUNCTION delivery.commit_configuration_mutation(
    text, bigint, jsonb, jsonb, jsonb, jsonb, jsonb
) FROM PUBLIC, matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.commit_configuration_mutation(
    text, bigint, jsonb, jsonb, jsonb, jsonb, jsonb
) TO matrix_devops_api;

REVOKE ALL ON ALL TABLES IN SCHEMA delivery FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA delivery
    FROM matrix_devops_api, matrix_devops_worker;
GRANT SELECT ON delivery.projects TO matrix_devops_api;
GRANT SELECT ON delivery.source_connections TO matrix_devops_api;
GRANT SELECT ON delivery.repository_bindings TO matrix_devops_api;
GRANT SELECT ON delivery.repository_binding_revisions TO matrix_devops_api;
GRANT SELECT ON delivery.pipelines TO matrix_devops_api;
GRANT SELECT ON delivery.pipeline_revisions TO matrix_devops_api;
GRANT SELECT ON delivery.mutations TO matrix_devops_api;

COMMIT;
