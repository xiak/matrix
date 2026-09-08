BEGIN;
SET LOCAL ROLE matrix_devops_owner;

REVOKE ALL ON SCHEMA delivery FROM PUBLIC;
GRANT USAGE ON SCHEMA delivery
    TO matrix_devops_api, matrix_devops_source_fetcher,
       matrix_devops_worker, matrix_devops_source_observer;

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
    external_repository_id text COLLATE "C" NOT NULL,
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
        AND external_repository_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
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
        AND document#>>'{spec,externalRepositoryId}' = external_repository_id
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
    external_repository_id text COLLATE "C" NOT NULL,
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
        AND external_repository_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
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
        AND document#>>'{spec,externalRepositoryId}' = external_repository_id
        AND document->>'contentDigest' = content_digest
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
        AND (document#>>'{metadata,updatedAt}')::timestamptz = created_at
    )
);

DROP POLICY IF EXISTS owner_schema_upgrade ON delivery.repository_bindings;
CREATE POLICY owner_schema_upgrade ON delivery.repository_bindings
    TO matrix_devops_owner USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS owner_schema_upgrade ON delivery.repository_binding_revisions;
CREATE POLICY owner_schema_upgrade ON delivery.repository_binding_revisions
    TO matrix_devops_owner USING (true) WITH CHECK (true);

ALTER TABLE delivery.repository_bindings
    ADD COLUMN IF NOT EXISTS external_repository_id text COLLATE "C";
UPDATE delivery.repository_bindings
   SET external_repository_id = document#>>'{spec,externalRepositoryId}'
 WHERE external_repository_id IS NULL;
ALTER TABLE delivery.repository_bindings
    ALTER COLUMN external_repository_id SET NOT NULL,
    DROP CONSTRAINT IF EXISTS repository_bindings_ids_valid,
    DROP CONSTRAINT IF EXISTS repository_bindings_document_identity;
ALTER TABLE delivery.repository_bindings
    ADD CONSTRAINT repository_bindings_ids_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND project_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND source_connection_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND external_repository_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    ),
    ADD CONSTRAINT repository_bindings_document_identity CHECK (
        document->>'apiVersion' = 'devops.matrix.xiak.com/v1'
        AND document->>'kind' = 'RepositoryBinding'
        AND document#>>'{metadata,id}' = id
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND document->>'projectId' = project_id
        AND document#>>'{spec,sourceConnectionId}' = source_connection_id
        AND document#>>'{spec,externalRepositoryId}' = external_repository_id
        AND document->>'contentDigest' = content_digest
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
    );

ALTER TABLE delivery.repository_binding_revisions
    ADD COLUMN IF NOT EXISTS external_repository_id text COLLATE "C";
UPDATE delivery.repository_binding_revisions
   SET external_repository_id = document#>>'{spec,externalRepositoryId}'
 WHERE external_repository_id IS NULL;
ALTER TABLE delivery.repository_binding_revisions
    ALTER COLUMN external_repository_id SET NOT NULL,
    DROP CONSTRAINT IF EXISTS repository_binding_revisions_values_valid,
    DROP CONSTRAINT IF EXISTS repository_binding_revisions_document_identity;
ALTER TABLE delivery.repository_binding_revisions
    ADD CONSTRAINT repository_binding_revisions_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND binding_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND project_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND source_connection_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND external_repository_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND content_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND resource_version BETWEEN 1 AND 9007199254740991
    ),
    ADD CONSTRAINT repository_binding_revisions_document_identity CHECK (
        document->>'apiVersion' = 'devops.matrix.xiak.com/v1'
        AND document->>'kind' = 'RepositoryBinding'
        AND document#>>'{metadata,id}' = binding_id
        AND document#>>'{metadata,scope,tenantId}' = tenant_id
        AND document->>'projectId' = project_id
        AND document#>>'{spec,sourceConnectionId}' = source_connection_id
        AND document#>>'{spec,externalRepositoryId}' = external_repository_id
        AND document->>'contentDigest' = content_digest
        AND CASE
            WHEN document#>>'{metadata,resourceVersion}' ~ '^[1-9][0-9]*$'
            THEN (document#>>'{metadata,resourceVersion}')::numeric = resource_version
            ELSE false
        END
        AND (document#>>'{metadata,updatedAt}')::timestamptz = created_at
    );

DO $matrix_repository_source_identity_constraints$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace
           AND conname = 'repository_bindings_source_repository_uq'
    ) THEN
        ALTER TABLE delivery.repository_bindings
            ADD CONSTRAINT repository_bindings_source_repository_uq
            UNIQUE (tenant_id, source_connection_id, external_repository_id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace
           AND conname = 'repository_binding_revisions_source_identity_uq'
    ) THEN
        ALTER TABLE delivery.repository_binding_revisions
            ADD CONSTRAINT repository_binding_revisions_source_identity_uq
            UNIQUE (
                tenant_id, binding_id, content_digest, project_id,
                source_connection_id, external_repository_id
            );
    END IF;
END
$matrix_repository_source_identity_constraints$;

DROP POLICY owner_schema_upgrade ON delivery.repository_bindings;
DROP POLICY owner_schema_upgrade ON delivery.repository_binding_revisions;

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

DO $matrix_pipeline_run_revision_identity$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace
           AND conname = 'pipeline_revisions_run_identity_uq'
    ) THEN
        ALTER TABLE delivery.pipeline_revisions
            ADD CONSTRAINT pipeline_revisions_run_identity_uq UNIQUE (
                tenant_id, id, content_digest, pipeline_id, project_id,
                repository_binding_id, repository_binding_digest
            );
    END IF;
END
$matrix_pipeline_run_revision_identity$;

DO $matrix_pipeline_build_receipt_identity$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace
           AND conname = 'pipeline_revisions_build_receipt_uq'
    ) THEN
        ALTER TABLE delivery.pipeline_revisions
            ADD CONSTRAINT pipeline_revisions_build_receipt_uq UNIQUE (
                tenant_id, id, content_digest
            );
    END IF;
END
$matrix_pipeline_build_receipt_identity$;

CREATE TABLE IF NOT EXISTS delivery.source_events (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    project_id text COLLATE "C" NOT NULL,
    source_connection_id text COLLATE "C" NOT NULL,
    repository_binding_id text COLLATE "C" NOT NULL,
    repository_binding_digest text COLLATE "C" NOT NULL,
    external_repository_id text COLLATE "C" NOT NULL,
    delivery_id text COLLATE "C" NOT NULL,
    canonical_payload_digest text COLLATE "C" NOT NULL,
    content_digest text COLLATE "C" NOT NULL,
    received_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT source_events_delivery_uq UNIQUE (
        tenant_id, source_connection_id, delivery_id
    ),
    CONSTRAINT source_events_run_identity_uq UNIQUE (
        tenant_id, id, content_digest, project_id,
        repository_binding_id, repository_binding_digest
    ),
    CONSTRAINT source_events_binding_snapshot_fk FOREIGN KEY (
        tenant_id, repository_binding_id, repository_binding_digest,
        project_id, source_connection_id, external_repository_id
    ) REFERENCES delivery.repository_binding_revisions (
        tenant_id, binding_id, content_digest,
        project_id, source_connection_id, external_repository_id
    ),
    CONSTRAINT source_events_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^source-event-[0-9a-f]{48}$'
        AND project_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND source_connection_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND repository_binding_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND external_repository_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND delivery_id COLLATE "C" ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        AND repository_binding_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND canonical_payload_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND content_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT source_events_document_identity CHECK (
        document->>'apiVersion' = 'devops.matrix.xiak.com/v1'
        AND document->>'kind' = 'SourceEvent'
        AND document->>'id' = id
        AND document#>>'{scope,tenantId}' = tenant_id
        AND document#>>'{spec,projectId}' = project_id
        AND document#>>'{spec,sourceConnectionId}' = source_connection_id
        AND document#>>'{spec,repositoryBindingId}' = repository_binding_id
        AND document#>>'{spec,repositoryBindingDigest}' = repository_binding_digest
        AND document#>>'{spec,externalRepositoryId}' = external_repository_id
        AND document#>>'{spec,deliveryId}' = delivery_id
        AND document#>>'{spec,canonicalPayloadDigest}' = canonical_payload_digest
        AND document->>'contentDigest' = content_digest
        AND (document->>'receivedAt')::timestamptz = received_at
    )
);

CREATE TABLE IF NOT EXISTS delivery.pipeline_runs (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    input_digest text COLLATE "C" NOT NULL,
    source_event_id text COLLATE "C" NOT NULL,
    source_event_digest text COLLATE "C" NOT NULL,
    pipeline_id text COLLATE "C" NOT NULL,
    project_id text COLLATE "C" NOT NULL,
    pipeline_revision_id text COLLATE "C" NOT NULL,
    pipeline_revision_digest text COLLATE "C" NOT NULL,
    repository_binding_id text COLLATE "C" NOT NULL,
    repository_binding_digest text COLLATE "C" NOT NULL,
    replay_of_run_id text COLLATE "C",
    replay_command_id text COLLATE "C",
    creation_operation_id text COLLATE "C" NOT NULL,
    state text COLLATE "C" NOT NULL,
    stage text COLLATE "C" NOT NULL,
    reason text COLLATE "C",
    resource_version bigint NOT NULL,
    cancellation_requested_at timestamptz(6),
    completed_at timestamptz(6),
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT pipeline_runs_replay_command_uq UNIQUE (
        tenant_id, replay_command_id
    ),
    CONSTRAINT pipeline_runs_source_event_fk FOREIGN KEY (
        tenant_id, source_event_id, source_event_digest, project_id,
        repository_binding_id, repository_binding_digest
    ) REFERENCES delivery.source_events (
        tenant_id, id, content_digest, project_id,
        repository_binding_id, repository_binding_digest
    ),
    CONSTRAINT pipeline_runs_revision_fk FOREIGN KEY (
        tenant_id, pipeline_revision_id, pipeline_revision_digest,
        pipeline_id, project_id, repository_binding_id,
        repository_binding_digest
    ) REFERENCES delivery.pipeline_revisions (
        tenant_id, id, content_digest, pipeline_id, project_id,
        repository_binding_id, repository_binding_digest
    ),
    CONSTRAINT pipeline_runs_replay_source_fk FOREIGN KEY (
        tenant_id, replay_of_run_id
    ) REFERENCES delivery.pipeline_runs (tenant_id, id),
    CONSTRAINT pipeline_runs_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^pipeline-run-[0-9a-f]{48}$'
        AND source_event_id COLLATE "C" ~ '^source-event-[0-9a-f]{48}$'
        AND pipeline_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND project_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND pipeline_revision_id COLLATE "C" ~ '^pipeline-revision-[0-9a-f]{48}$'
        AND repository_binding_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND source_event_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND pipeline_revision_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND repository_binding_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND resource_version BETWEEN 1 AND 9007199254740991
        AND updated_at >= created_at
        AND state IN (
            'QUEUED', 'FETCHING', 'VERIFYING', 'REPORTING', 'SUCCEEDED',
            'FAILED', 'CANCELLED', 'RECONCILING', 'MANUAL_INTERVENTION'
        )
        AND stage IN ('RECEIVE', 'FETCH', 'VERIFY', 'REPORT')
        AND (reason IS NULL OR reason IN (
            'EVENT_ADMITTED', 'COMPLETED', 'SOURCE_UNAVAILABLE',
            'COMMIT_MISMATCH', 'EXECUTOR_UNAVAILABLE', 'VERIFICATION_FAILED',
            'DEADLINE_EXCEEDED', 'REPORT_UNAVAILABLE', 'REPORT_CONFLICT',
            'CANCELLED', 'EXTERNAL_EFFECT_UNCERTAIN',
            'RECONCILIATION_EXHAUSTED'
        ))
        AND (
            (state = 'QUEUED' AND stage = 'RECEIVE'
                AND reason = 'EVENT_ADMITTED' AND resource_version = 1
                AND completed_at IS NULL AND created_at = updated_at)
            OR (state = 'FETCHING' AND stage = 'FETCH'
                AND reason IS NULL AND completed_at IS NULL)
            OR (state = 'VERIFYING' AND stage = 'VERIFY'
                AND reason IS NULL AND completed_at IS NULL)
            OR (state = 'REPORTING' AND stage = 'REPORT'
                AND reason IS NULL AND completed_at IS NULL)
            OR (state = 'SUCCEEDED' AND stage = 'REPORT'
                AND reason = 'COMPLETED' AND completed_at = updated_at)
            OR (state = 'FAILED' AND reason IN (
                    'SOURCE_UNAVAILABLE', 'COMMIT_MISMATCH',
                    'EXECUTOR_UNAVAILABLE', 'VERIFICATION_FAILED',
                    'DEADLINE_EXCEEDED', 'REPORT_UNAVAILABLE', 'REPORT_CONFLICT'
                ) AND completed_at = updated_at)
            OR (state = 'CANCELLED' AND reason = 'CANCELLED'
                AND completed_at = updated_at)
            OR (state = 'RECONCILING' AND stage = 'REPORT'
                AND reason = 'EXTERNAL_EFFECT_UNCERTAIN' AND completed_at IS NULL)
            OR (state = 'MANUAL_INTERVENTION' AND stage = 'REPORT'
                AND reason = 'RECONCILIATION_EXHAUSTED'
                AND completed_at = updated_at)
        )
    ),
    CONSTRAINT pipeline_runs_document_identity CHECK (
        document->>'apiVersion' = 'devops.matrix.xiak.com/v1'
        AND document->>'kind' = 'PipelineRun'
        AND document->>'id' = id
        AND document#>>'{scope,tenantId}' = tenant_id
        AND document->>'projectId' = project_id
        AND document->>'pipelineId' = pipeline_id
        AND document#>>'{input,sourceEventId}' = source_event_id
        AND document#>>'{input,sourceEventDigest}' = source_event_digest
        AND document#>>'{input,pipelineRevisionId}' = pipeline_revision_id
        AND document#>>'{input,pipelineRevisionDigest}' = pipeline_revision_digest
        AND document#>>'{input,repositoryBindingId}' = repository_binding_id
        AND document#>>'{input,repositoryBindingDigest}' = repository_binding_digest
        AND document->>'inputDigest' = input_digest
        AND document#>>'{status,state}' = state
        AND document#>>'{status,stage}' = stage
        AND document#>>'{status,reason}' IS NOT DISTINCT FROM reason
        AND (document#>>'{status,resourceVersion}')::numeric = resource_version
        AND (document#>>'{status,observedAt}')::timestamptz = updated_at
        AND (
            (completed_at IS NULL AND NOT ((document#>'{status}') ? 'completedAt'))
            OR (document#>>'{status,completedAt}')::timestamptz = completed_at
        )
        AND (document->>'createdAt')::timestamptz = created_at
        AND (document->>'updatedAt')::timestamptz = updated_at
    )
);

CREATE INDEX IF NOT EXISTS pipeline_runs_tenant_queue_idx
    ON delivery.pipeline_runs (tenant_id, state, created_at, id);

DROP POLICY IF EXISTS owner_schema_upgrade ON delivery.pipeline_runs;
CREATE POLICY owner_schema_upgrade ON delivery.pipeline_runs
    TO matrix_devops_owner USING (true) WITH CHECK (true);

ALTER TABLE delivery.pipeline_runs
    ADD COLUMN IF NOT EXISTS input_digest text COLLATE "C";
ALTER TABLE delivery.pipeline_runs
    ADD COLUMN IF NOT EXISTS cancellation_requested_at timestamptz(6);
ALTER TABLE delivery.pipeline_runs
    ADD COLUMN IF NOT EXISTS replay_of_run_id text COLLATE "C";
ALTER TABLE delivery.pipeline_runs
    ADD COLUMN IF NOT EXISTS replay_command_id text COLLATE "C";
ALTER TABLE delivery.pipeline_runs
    ADD COLUMN IF NOT EXISTS creation_operation_id text COLLATE "C";
UPDATE delivery.pipeline_runs
   SET input_digest = document->>'inputDigest'
 WHERE input_digest IS NULL;
UPDATE delivery.pipeline_runs
   SET cancellation_requested_at =
       (document#>>'{status,cancellationRequestedAt}')::timestamptz
 WHERE cancellation_requested_at IS NULL
   AND document#>'{status}' ? 'cancellationRequestedAt';
UPDATE delivery.pipeline_runs
   SET cancellation_requested_at = completed_at,
       document = jsonb_set(
           document,
           '{status,cancellationRequestedAt}',
           to_jsonb(to_char(
               completed_at AT TIME ZONE 'UTC',
               'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
           )),
           true
       )
 WHERE state = 'CANCELLED'
   AND cancellation_requested_at IS NULL;
UPDATE delivery.pipeline_runs
   SET creation_operation_id = id
 WHERE creation_operation_id IS NULL;
ALTER TABLE delivery.pipeline_runs
    ALTER COLUMN input_digest SET NOT NULL;
ALTER TABLE delivery.pipeline_runs
    ALTER COLUMN creation_operation_id SET NOT NULL;

ALTER TABLE delivery.pipeline_runs
    DROP CONSTRAINT IF EXISTS pipeline_runs_event_revision_uq;
CREATE UNIQUE INDEX IF NOT EXISTS pipeline_runs_event_revision_original_uq
    ON delivery.pipeline_runs (
        tenant_id, source_event_id, pipeline_revision_id
    )
    WHERE replay_of_run_id IS NULL;

DO $matrix_pipeline_run_replay_identity$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace
           AND conname = 'pipeline_runs_replay_command_uq'
    ) THEN
        ALTER TABLE delivery.pipeline_runs
            ADD CONSTRAINT pipeline_runs_replay_command_uq
            UNIQUE (tenant_id, replay_command_id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace
           AND conname = 'pipeline_runs_replay_source_fk'
    ) THEN
        ALTER TABLE delivery.pipeline_runs
            ADD CONSTRAINT pipeline_runs_replay_source_fk FOREIGN KEY (
                tenant_id, replay_of_run_id
            ) REFERENCES delivery.pipeline_runs (tenant_id, id);
    END IF;
END
$matrix_pipeline_run_replay_identity$;

ALTER TABLE delivery.pipeline_runs
    DROP CONSTRAINT IF EXISTS pipeline_runs_replay_valid;
ALTER TABLE delivery.pipeline_runs
    ADD CONSTRAINT pipeline_runs_replay_valid CHECK (
        (
            replay_of_run_id IS NULL
            AND replay_command_id IS NULL
            AND creation_operation_id = id
            AND NOT (document ? 'replay')
        )
        OR (
            replay_of_run_id IS NOT NULL
            AND replay_command_id IS NOT NULL
            AND creation_operation_id = replay_command_id
            AND replay_of_run_id <> id
            AND replay_of_run_id COLLATE "C" ~ '^pipeline-run-[0-9a-f]{48}$'
            AND replay_command_id COLLATE "C" ~ '^operation-[0-9a-f]{64}$'
            AND document ? 'replay'
            AND jsonb_typeof(document->'replay') = 'object'
            AND (document->'replay') ?& ARRAY[
                'sourceRunId', 'commandId', 'requestedBy'
            ]
            AND ((document->'replay') - ARRAY[
                'sourceRunId', 'commandId', 'requestedBy'
            ]) = '{}'::jsonb
            AND document#>>'{replay,sourceRunId}' = replay_of_run_id
            AND document#>>'{replay,commandId}' = replay_command_id
            AND jsonb_typeof(document#>'{replay,requestedBy}') = 'object'
            AND (document#>'{replay,requestedBy}') ?& ARRAY['kind', 'id']
            AND ((document#>'{replay,requestedBy}') - ARRAY['kind', 'id']) = '{}'::jsonb
            AND document#>>'{replay,requestedBy,kind}' IN (
                'USER', 'SERVICE_ACCOUNT'
            )
            AND document#>>'{replay,requestedBy,id}' COLLATE "C"
                ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        )
    );

ALTER TABLE delivery.pipeline_runs
    DROP CONSTRAINT IF EXISTS pipeline_runs_cancellation_valid;
ALTER TABLE delivery.pipeline_runs
    ADD CONSTRAINT pipeline_runs_cancellation_valid CHECK (
        (
            cancellation_requested_at IS NULL
            AND NOT (document#>'{status}' ? 'cancellationRequestedAt')
            AND state <> 'CANCELLED'
        )
        OR (
            cancellation_requested_at IS NOT NULL
            AND state <> 'QUEUED'
            AND cancellation_requested_at >= created_at
            AND cancellation_requested_at <= updated_at
            AND document#>'{status}' ? 'cancellationRequestedAt'
            AND (document#>>'{status,cancellationRequestedAt}')::timestamptz
                = cancellation_requested_at
        )
    );

DO $matrix_pipeline_run_task_identity$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace
           AND conname = 'pipeline_runs_task_identity_uq'
    ) THEN
        ALTER TABLE delivery.pipeline_runs
            ADD CONSTRAINT pipeline_runs_task_identity_uq
            UNIQUE (tenant_id, id, input_digest);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace
           AND conname = 'pipeline_runs_input_digest_valid'
    ) THEN
        ALTER TABLE delivery.pipeline_runs
            ADD CONSTRAINT pipeline_runs_input_digest_valid CHECK (
                input_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
                AND document->>'inputDigest' = input_digest
            );
    END IF;
END
$matrix_pipeline_run_task_identity$;

DROP POLICY owner_schema_upgrade ON delivery.pipeline_runs;

CREATE TABLE IF NOT EXISTS delivery.pipeline_run_tasks (
    tenant_id text COLLATE "C" NOT NULL,
    run_id text COLLATE "C" NOT NULL,
    input_digest text COLLATE "C" NOT NULL,
    stage text COLLATE "C" NOT NULL,
    attempt bigint NOT NULL,
    command_id text COLLATE "C" NOT NULL,
    status text COLLATE "C" NOT NULL,
    available_at timestamptz(6) NOT NULL,
    lease_owner text COLLATE "C",
    lease_expires_at timestamptz(6),
    fencing_token bigint NOT NULL,
    reconciliation_attempts bigint NOT NULL,
    last_claimed_at timestamptz(6),
    completed_at timestamptz(6),
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    PRIMARY KEY (tenant_id, run_id, stage, attempt),
    CONSTRAINT pipeline_run_tasks_command_uq UNIQUE (tenant_id, command_id),
    CONSTRAINT pipeline_run_tasks_run_fk FOREIGN KEY (
        tenant_id, run_id, input_digest
    ) REFERENCES delivery.pipeline_runs (tenant_id, id, input_digest)
        ON DELETE CASCADE,
    CONSTRAINT pipeline_run_tasks_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND run_id COLLATE "C" ~ '^pipeline-run-[0-9a-f]{48}$'
        AND input_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND stage IN ('FETCH', 'VERIFY', 'REPORT')
        AND attempt BETWEEN 1 AND 100
        AND command_id = run_id || ':' || lower(stage) || ':' || attempt::text
        AND command_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND status IN ('INTENT', 'COMPLETED')
        AND fencing_token BETWEEN 0 AND 9007199254740991
        AND reconciliation_attempts BETWEEN 0 AND 10
        AND ((lease_owner IS NULL) = (lease_expires_at IS NULL))
        AND (lease_owner IS NULL OR lease_owner COLLATE "C"
            ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
        AND ((fencing_token = 0) = (last_claimed_at IS NULL))
        AND ((status = 'COMPLETED') = (completed_at IS NOT NULL))
        AND (status = 'INTENT' OR lease_owner IS NULL)
        AND available_at >= created_at
        AND updated_at >= created_at
        AND (last_claimed_at IS NULL OR last_claimed_at >= created_at)
        AND (last_claimed_at IS NULL OR updated_at >= last_claimed_at)
        AND (lease_expires_at IS NULL OR lease_expires_at > last_claimed_at)
        AND (completed_at IS NULL OR completed_at >= created_at)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS pipeline_run_tasks_open_uq
    ON delivery.pipeline_run_tasks (tenant_id, run_id)
    WHERE status = 'INTENT';
CREATE INDEX IF NOT EXISTS pipeline_run_tasks_due_idx
    ON delivery.pipeline_run_tasks (
        status, available_at, lease_expires_at, tenant_id, run_id
    );

CREATE TABLE IF NOT EXISTS delivery.source_archives (
    tenant_id text COLLATE "C" NOT NULL,
    run_id text COLLATE "C" NOT NULL,
    command_id text COLLATE "C" NOT NULL,
    input_digest text COLLATE "C" NOT NULL,
    archive_digest text COLLATE "C" NOT NULL,
    archive_bytes bigint NOT NULL,
    expanded_bytes bigint NOT NULL,
    path_count bigint NOT NULL,
    head_commit text COLLATE "C" NOT NULL,
    trusted_base_commit text COLLATE "C" NOT NULL,
    media_type text COLLATE "C" NOT NULL,
    created_at timestamptz(6) NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    CONSTRAINT source_archives_command_uq UNIQUE (tenant_id, command_id),
    CONSTRAINT source_archives_run_fk FOREIGN KEY (
        tenant_id, run_id, input_digest
    ) REFERENCES delivery.pipeline_runs (tenant_id, id, input_digest)
        ON DELETE CASCADE,
    CONSTRAINT source_archives_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND run_id COLLATE "C" ~ '^pipeline-run-[0-9a-f]{48}$'
        AND split_part(command_id, ':', 1) = run_id
        AND command_id COLLATE "C"
            ~ '^pipeline-run-[0-9a-f]{48}:fetch:([1-9]|[1-9][0-9]|100)$'
        AND input_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND archive_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND archive_bytes BETWEEN 1 AND 67108864
        AND expanded_bytes BETWEEN 0 AND 536870912
        AND path_count BETWEEN 0 AND 20000
        AND head_commit COLLATE "C" ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
        AND trusted_base_commit COLLATE "C" ~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
        AND media_type = 'application/vnd.matrix.devops.source.v1+tar+gzip'
    )
);

CREATE TABLE IF NOT EXISTS delivery.build_receipts (
    tenant_id text COLLATE "C" NOT NULL,
    run_id text COLLATE "C" NOT NULL,
    command_id text COLLATE "C" NOT NULL,
    input_digest text COLLATE "C" NOT NULL,
    source_archive_digest text COLLATE "C" NOT NULL,
    pipeline_revision_id text COLLATE "C" NOT NULL,
    pipeline_revision_digest text COLLATE "C" NOT NULL,
    executor_id text COLLATE "C" NOT NULL,
    executor_profile text COLLATE "C" NOT NULL,
    toolchain_image_digest text COLLATE "C" NOT NULL,
    conclusion text COLLATE "C" NOT NULL,
    content_digest text COLLATE "C" NOT NULL,
    created_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, run_id),
    CONSTRAINT build_receipts_command_uq UNIQUE (tenant_id, command_id),
    CONSTRAINT build_receipts_run_fk FOREIGN KEY (
        tenant_id, run_id, input_digest
    ) REFERENCES delivery.pipeline_runs (tenant_id, id, input_digest)
        ON DELETE CASCADE,
    CONSTRAINT build_receipts_revision_fk FOREIGN KEY (
        tenant_id, pipeline_revision_id, pipeline_revision_digest
    ) REFERENCES delivery.pipeline_revisions (tenant_id, id, content_digest),
    CONSTRAINT build_receipts_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND run_id COLLATE "C" ~ '^pipeline-run-[0-9a-f]{48}$'
        AND split_part(command_id, ':', 1) = run_id
        AND command_id COLLATE "C"
            ~ '^pipeline-run-[0-9a-f]{48}:verify:([1-9]|[1-9][0-9]|100)$'
        AND input_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND source_archive_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND pipeline_revision_id COLLATE "C"
            ~ '^pipeline-revision-[0-9a-f]{48}$'
        AND pipeline_revision_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND executor_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND executor_profile = 'MATRIX_NATIVE_ISOLATED_V1'
        AND toolchain_image_digest =
            'sha256:07558d5472e9acb5fc5656b485e963602e925e00111b8ad676a804306e711ba3'
        AND conclusion IN ('PASSED', 'FAILED', 'CANCELLED')
        AND content_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND document->>'tenantId' = tenant_id
        AND document->>'runId' = run_id
        AND document->>'commandId' = command_id
        AND document->>'inputDigest' = input_digest
        AND document->>'sourceArchiveDigest' = source_archive_digest
        AND document->>'pipelineRevisionId' = pipeline_revision_id
        AND document->>'pipelineRevisionDigest' = pipeline_revision_digest
        AND document->>'executorId' = executor_id
        AND document->>'executorProfile' = executor_profile
        AND document->>'toolchainImageDigest' = toolchain_image_digest
        AND document->>'conclusion' = conclusion
        AND document->>'contentDigest' = content_digest
    )
);

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
            'CREATE_PIPELINE', 'UPDATE_PIPELINE_DRAFT', 'ACTIVATE_PIPELINE',
            'CANCEL_PIPELINE_RUN', 'REPLAY_PIPELINE_RUN'
        )
        AND idempotency_fingerprint COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND request_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND (
            (mutation_kind = 'CANCEL_PIPELINE_RUN'
                AND command_target_id = target_id
                AND target_kind = 'PIPELINE_RUN'
                AND result_kind = 'PipelineRun')
            OR (mutation_kind = 'REPLAY_PIPELINE_RUN'
                AND command_target_id <> target_id
                AND target_kind = 'PIPELINE_RUN'
                AND result_kind = 'PipelineRun')
            OR (mutation_kind NOT IN (
                    'CANCEL_PIPELINE_RUN', 'REPLAY_PIPELINE_RUN'
                )
                AND target_kind IN (
                    'DEVOPS_PROJECT', 'SOURCE_CONNECTION',
                    'REPOSITORY_BINDING', 'PIPELINE', 'PIPELINE_REVISION'
                )
                AND result_kind IN (
                    'DevOpsProject', 'SourceConnection', 'RepositoryBinding',
                    'Pipeline', 'PipelineActivation'
                ))
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

ALTER TABLE delivery.mutations
    DROP CONSTRAINT IF EXISTS mutations_values_valid;
ALTER TABLE delivery.mutations
    ADD CONSTRAINT mutations_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND command_target_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND target_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND mutation_kind IN (
            'CREATE_PROJECT', 'CREATE_SOURCE_CONNECTION', 'UPDATE_SOURCE_CONNECTION',
            'CREATE_REPOSITORY_BINDING', 'UPDATE_REPOSITORY_BINDING',
            'CREATE_PIPELINE', 'UPDATE_PIPELINE_DRAFT', 'ACTIVATE_PIPELINE',
            'CANCEL_PIPELINE_RUN', 'REPLAY_PIPELINE_RUN'
        )
        AND idempotency_fingerprint COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND request_digest COLLATE "C" ~ '^sha256:[0-9a-f]{64}$'
        AND (
            (mutation_kind = 'CANCEL_PIPELINE_RUN'
                AND command_target_id = target_id
                AND target_kind = 'PIPELINE_RUN'
                AND result_kind = 'PipelineRun')
            OR (mutation_kind = 'REPLAY_PIPELINE_RUN'
                AND command_target_id <> target_id
                AND target_kind = 'PIPELINE_RUN'
                AND result_kind = 'PipelineRun')
            OR (mutation_kind NOT IN (
                    'CANCEL_PIPELINE_RUN', 'REPLAY_PIPELINE_RUN'
                )
                AND target_kind IN (
                    'DEVOPS_PROJECT', 'SOURCE_CONNECTION',
                    'REPOSITORY_BINDING', 'PIPELINE', 'PIPELINE_REVISION'
                )
                AND result_kind IN (
                    'DevOpsProject', 'SourceConnection', 'RepositoryBinding',
                    'Pipeline', 'PipelineActivation'
                ))
        )
    );

CREATE TABLE IF NOT EXISTS delivery.audit_operations (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL,
    operation_kind text COLLATE "C" NOT NULL,
    target_kind text COLLATE "C" NOT NULL,
    target_id text COLLATE "C" NOT NULL,
    created_at timestamptz(6) NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT audit_operations_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND target_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND (
            (operation_kind = 'CONFIGURATION_MUTATION'
                AND target_kind IN (
                    'DEVOPS_PROJECT', 'SOURCE_CONNECTION',
                    'REPOSITORY_BINDING', 'PIPELINE', 'PIPELINE_REVISION'
                ))
            OR (operation_kind = 'SOURCE_EVENT_ADMISSION'
                AND target_kind = 'SOURCE_EVENT' AND id = target_id)
            OR (operation_kind = 'PIPELINE_RUN_CREATION'
                AND target_kind = 'PIPELINE_RUN' AND id = target_id)
            OR (operation_kind = 'PIPELINE_RUN_CANCELLATION'
                AND target_kind = 'PIPELINE_RUN'
                AND target_id COLLATE "C" ~ '^pipeline-run-[0-9a-f]{48}$'
                AND id COLLATE "C" ~ '^operation-[0-9a-f]{64}$')
            OR (operation_kind = 'PIPELINE_RUN_REPLAY'
                AND target_kind = 'PIPELINE_RUN'
                AND target_id COLLATE "C" ~ '^pipeline-run-[0-9a-f]{48}$'
                AND id COLLATE "C" ~ '^operation-[0-9a-f]{64}$')
            OR (operation_kind = 'PIPELINE_RUN_TERMINAL'
                AND target_kind = 'PIPELINE_RUN'
                AND target_id COLLATE "C" ~ '^pipeline-run-[0-9a-f]{48}$'
                AND id COLLATE "C" ~ '^pipeline-run-[0-9a-f]{48}:terminal:[1-9][0-9]{0,15}$'
                AND split_part(id, ':', 1) = target_id)
            OR (operation_kind = 'SOURCE_HEALTH_OBSERVATION'
                AND target_kind IN ('SOURCE_CONNECTION', 'REPOSITORY_BINDING')
                AND id COLLATE "C" ~ '^source-observation-[0-9a-f]{64}$')
        )
    )
);

ALTER TABLE delivery.audit_operations
    DROP CONSTRAINT IF EXISTS audit_operations_values_valid;
ALTER TABLE delivery.audit_operations
    ADD CONSTRAINT audit_operations_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND target_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND (
            (operation_kind = 'CONFIGURATION_MUTATION'
                AND target_kind IN (
                    'DEVOPS_PROJECT', 'SOURCE_CONNECTION',
                    'REPOSITORY_BINDING', 'PIPELINE', 'PIPELINE_REVISION'
                ))
            OR (operation_kind = 'SOURCE_EVENT_ADMISSION'
                AND target_kind = 'SOURCE_EVENT' AND id = target_id)
            OR (operation_kind = 'PIPELINE_RUN_CREATION'
                AND target_kind = 'PIPELINE_RUN' AND id = target_id)
            OR (operation_kind = 'PIPELINE_RUN_CANCELLATION'
                AND target_kind = 'PIPELINE_RUN'
                AND target_id COLLATE "C" ~ '^pipeline-run-[0-9a-f]{48}$'
                AND id COLLATE "C" ~ '^operation-[0-9a-f]{64}$')
            OR (operation_kind = 'PIPELINE_RUN_REPLAY'
                AND target_kind = 'PIPELINE_RUN'
                AND target_id COLLATE "C" ~ '^pipeline-run-[0-9a-f]{48}$'
                AND id COLLATE "C" ~ '^operation-[0-9a-f]{64}$')
            OR (operation_kind = 'PIPELINE_RUN_TERMINAL'
                AND target_kind = 'PIPELINE_RUN'
                AND target_id COLLATE "C" ~ '^pipeline-run-[0-9a-f]{48}$'
                AND id COLLATE "C" ~ '^pipeline-run-[0-9a-f]{48}:terminal:[1-9][0-9]{0,15}$'
                AND split_part(id, ':', 1) = target_id)
            OR (operation_kind = 'SOURCE_HEALTH_OBSERVATION'
                AND target_kind IN ('SOURCE_CONNECTION', 'REPOSITORY_BINDING')
                AND id COLLATE "C" ~ '^source-observation-[0-9a-f]{64}$')
        )
    );

DROP POLICY IF EXISTS owner_schema_upgrade ON delivery.mutations;
CREATE POLICY owner_schema_upgrade ON delivery.mutations
    TO matrix_devops_owner USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS owner_schema_upgrade ON delivery.audit_operations;
CREATE POLICY owner_schema_upgrade ON delivery.audit_operations
    TO matrix_devops_owner USING (true) WITH CHECK (true);

INSERT INTO delivery.audit_operations (
    tenant_id, id, operation_kind, target_kind, target_id, created_at
)
SELECT tenant_id, id,
       CASE mutation_kind
           WHEN 'CANCEL_PIPELINE_RUN' THEN 'PIPELINE_RUN_CANCELLATION'
           WHEN 'REPLAY_PIPELINE_RUN' THEN 'PIPELINE_RUN_REPLAY'
           ELSE 'CONFIGURATION_MUTATION'
       END,
       target_kind, target_id, created_at
  FROM delivery.mutations
ON CONFLICT (tenant_id, id) DO NOTHING;

DROP POLICY owner_schema_upgrade ON delivery.mutations;

ALTER TABLE delivery.pipeline_runs
    DROP CONSTRAINT IF EXISTS pipeline_runs_audit_operation_fk;

DO $matrix_audit_operation_constraints$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace
           AND conname = 'mutations_audit_operation_fk'
    ) THEN
        ALTER TABLE delivery.mutations
            ADD CONSTRAINT mutations_audit_operation_fk
            FOREIGN KEY (tenant_id, id)
            REFERENCES delivery.audit_operations (tenant_id, id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace
           AND conname = 'source_events_audit_operation_fk'
    ) THEN
        ALTER TABLE delivery.source_events
            ADD CONSTRAINT source_events_audit_operation_fk
            FOREIGN KEY (tenant_id, id)
            REFERENCES delivery.audit_operations (tenant_id, id);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_constraint
         WHERE connamespace = 'delivery'::regnamespace
           AND conname = 'pipeline_runs_audit_operation_fk'
    ) THEN
        ALTER TABLE delivery.pipeline_runs
            ADD CONSTRAINT pipeline_runs_audit_operation_fk
            FOREIGN KEY (tenant_id, creation_operation_id)
            REFERENCES delivery.audit_operations (tenant_id, id);
    END IF;
END
$matrix_audit_operation_constraints$;

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
        REFERENCES delivery.audit_operations (tenant_id, id),
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

ALTER TABLE delivery.audit_outbox
    DROP CONSTRAINT IF EXISTS audit_outbox_operation_fk;
ALTER TABLE delivery.audit_outbox
    ADD CONSTRAINT audit_outbox_operation_fk
    FOREIGN KEY (tenant_id, operation_id)
    REFERENCES delivery.audit_operations (tenant_id, id);

DROP POLICY owner_schema_upgrade ON delivery.audit_operations;

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

CREATE TABLE IF NOT EXISTS delivery.source_observation_tasks (
    tenant_id text COLLATE "C" NOT NULL,
    resource_kind text COLLATE "C" NOT NULL,
    resource_id text COLLATE "C" NOT NULL,
    resource_version bigint NOT NULL,
    available_at timestamptz(6) NOT NULL,
    lease_owner text COLLATE "C",
    lease_expires_at timestamptz(6),
    fencing_token bigint NOT NULL,
    last_claimed_at timestamptz(6),
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    PRIMARY KEY (tenant_id, resource_kind, resource_id),
    CONSTRAINT source_observation_tasks_values_valid CHECK (
        tenant_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND resource_kind IN ('SOURCE_CONNECTION', 'REPOSITORY_BINDING')
        AND resource_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        AND resource_version BETWEEN 1 AND 9007199254740991
        AND fencing_token BETWEEN 0 AND 9007199254740991
        AND ((lease_owner IS NULL) = (lease_expires_at IS NULL))
        AND (lease_owner IS NULL OR lease_owner COLLATE "C"
            ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
        AND ((fencing_token = 0) = (last_claimed_at IS NULL))
        AND available_at >= created_at
        AND updated_at >= created_at
        AND (last_claimed_at IS NULL OR last_claimed_at >= created_at)
        AND (last_claimed_at IS NULL OR updated_at >= last_claimed_at)
        AND (lease_expires_at IS NULL OR lease_expires_at > last_claimed_at)
    )
);

CREATE INDEX IF NOT EXISTS source_observation_tasks_due_idx
    ON delivery.source_observation_tasks (
        available_at, lease_expires_at, tenant_id, resource_kind, resource_id
    );

CREATE TABLE IF NOT EXISTS delivery.source_observer_heartbeat (
    singleton boolean PRIMARY KEY DEFAULT true,
    worker_id text COLLATE "C" NOT NULL,
    observed_at timestamptz(6) NOT NULL,
    CONSTRAINT source_observer_heartbeat_singleton CHECK (singleton),
    CONSTRAINT source_observer_heartbeat_worker_valid CHECK (
        worker_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    )
);

CREATE TABLE IF NOT EXISTS delivery.source_fetcher_heartbeat (
    singleton boolean PRIMARY KEY DEFAULT true,
    worker_id text COLLATE "C" NOT NULL,
    observed_at timestamptz(6) NOT NULL,
    CONSTRAINT source_fetcher_heartbeat_singleton CHECK (singleton),
    CONSTRAINT source_fetcher_heartbeat_worker_valid CHECK (
        worker_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    )
);

CREATE TABLE IF NOT EXISTS delivery.build_worker_heartbeat (
    singleton boolean PRIMARY KEY DEFAULT true,
    worker_id text COLLATE "C" NOT NULL,
    observed_at timestamptz(6) NOT NULL,
    CONSTRAINT build_worker_heartbeat_singleton CHECK (singleton),
    CONSTRAINT build_worker_heartbeat_worker_valid CHECK (
        worker_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
    )
);

INSERT INTO delivery.source_observation_tasks (
    tenant_id, resource_kind, resource_id, resource_version, available_at,
    fencing_token, created_at, updated_at
)
SELECT source.tenant_id, 'SOURCE_CONNECTION', source.id,
       source.resource_version, transaction_timestamp(), 0,
       transaction_timestamp(), transaction_timestamp()
  FROM delivery.source_connections AS source
ON CONFLICT ON CONSTRAINT source_observation_tasks_pkey DO UPDATE
   SET resource_version = excluded.resource_version,
       available_at = excluded.available_at,
       lease_owner = NULL,
       lease_expires_at = NULL,
       updated_at = excluded.updated_at
 WHERE source_observation_tasks.resource_version <> excluded.resource_version;

INSERT INTO delivery.source_observation_tasks (
    tenant_id, resource_kind, resource_id, resource_version, available_at,
    fencing_token, created_at, updated_at
)
SELECT binding.tenant_id, 'REPOSITORY_BINDING', binding.id,
       binding.resource_version, transaction_timestamp(), 0,
       transaction_timestamp(), transaction_timestamp()
  FROM delivery.repository_bindings AS binding
ON CONFLICT ON CONSTRAINT source_observation_tasks_pkey DO UPDATE
   SET resource_version = excluded.resource_version,
       available_at = excluded.available_at,
       lease_owner = NULL,
       lease_expires_at = NULL,
       updated_at = excluded.updated_at
 WHERE source_observation_tasks.resource_version <> excluded.resource_version;

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
ALTER TABLE delivery.source_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.source_events FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.pipeline_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.pipeline_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.pipeline_run_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.pipeline_run_tasks FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.source_archives ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.source_archives FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.build_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.build_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.mutations ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.mutations FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.audit_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.audit_operations FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.audit_outbox FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.source_observation_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.source_observation_tasks FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.source_observer_heartbeat ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.source_observer_heartbeat FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.source_fetcher_heartbeat ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.source_fetcher_heartbeat FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.build_worker_heartbeat ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.build_worker_heartbeat FORCE ROW LEVEL SECURITY;

DO $matrix_delivery_policy$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'projects', 'source_connections', 'repository_bindings',
        'repository_binding_revisions', 'pipelines', 'pipeline_revisions',
        'source_events', 'pipeline_runs', 'pipeline_run_tasks',
        'source_archives', 'build_receipts',
        'mutations', 'audit_operations',
        'audit_outbox', 'source_observation_tasks'
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

DO $matrix_run_worker_owner_policy$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_policies
         WHERE schemaname = 'delivery' AND tablename = 'pipeline_runs'
           AND policyname = 'owner_run_worker'
    ) THEN
        CREATE POLICY owner_run_worker ON delivery.pipeline_runs
            TO matrix_devops_owner
            USING (true)
            WITH CHECK (true);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_policies
         WHERE schemaname = 'delivery' AND tablename = 'pipeline_run_tasks'
           AND policyname = 'owner_run_worker'
    ) THEN
        CREATE POLICY owner_run_worker ON delivery.pipeline_run_tasks
            TO matrix_devops_owner
            USING (true)
            WITH CHECK (true);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_policies
         WHERE schemaname = 'delivery' AND tablename = 'audit_operations'
           AND policyname = 'owner_run_worker'
    ) THEN
        CREATE POLICY owner_run_worker ON delivery.audit_operations
            TO matrix_devops_owner
            USING (true)
            WITH CHECK (true);
    END IF;
END
$matrix_run_worker_owner_policy$;

DO $matrix_source_fetcher_owner_policy$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'source_connections', 'repository_binding_revisions',
        'pipeline_revisions', 'source_events', 'pipeline_runs',
        'pipeline_run_tasks', 'source_archives', 'source_fetcher_heartbeat'
    ]
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_policies
             WHERE schemaname = 'delivery' AND tablename = table_name
               AND policyname = 'owner_source_fetcher'
        ) THEN
            EXECUTE format(
                'CREATE POLICY owner_source_fetcher ON delivery.%I '
                'TO matrix_devops_owner USING (true) WITH CHECK (true)',
                table_name
            );
        END IF;
    END LOOP;
END
$matrix_source_fetcher_owner_policy$;

DO $matrix_build_worker_owner_policy$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'pipeline_revisions', 'pipeline_runs', 'pipeline_run_tasks',
        'source_archives', 'build_receipts', 'build_worker_heartbeat',
        'audit_operations', 'audit_outbox'
    ]
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_policies
             WHERE schemaname = 'delivery' AND tablename = table_name
               AND policyname = 'owner_build_worker'
        ) THEN
            EXECUTE format(
                'CREATE POLICY owner_build_worker ON delivery.%I '
                'TO matrix_devops_owner USING (true) WITH CHECK (true)',
                table_name
            );
        END IF;
    END LOOP;
END
$matrix_build_worker_owner_policy$;

DO $matrix_source_observer_owner_policy$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'source_connections', 'repository_bindings',
        'source_observation_tasks', 'source_observer_heartbeat',
        'audit_operations', 'audit_outbox'
    ]
    LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_policies
             WHERE schemaname = 'delivery' AND tablename = table_name
               AND policyname = 'owner_source_observer'
        ) THEN
            EXECUTE format(
                'CREATE POLICY owner_source_observer ON delivery.%I '
                'TO matrix_devops_owner USING (true) WITH CHECK (true)',
                table_name
            );
        END IF;
    END LOOP;
END
$matrix_source_observer_owner_policy$;

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
           OR current_document#>>'{spec,endpointOrigin}'
                IS DISTINCT FROM submitted_resource#>>'{spec,endpointOrigin}'
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
            tenant_id, id, project_id, source_connection_id, external_repository_id,
            content_digest, resource_version, document
        ) VALUES (
            effective_tenant_id, resource_id, submitted_resource->>'projectId',
            submitted_resource#>>'{spec,sourceConnectionId}',
            submitted_resource#>>'{spec,externalRepositoryId}',
            submitted_resource->>'contentDigest', 1, submitted_resource
        );
        INSERT INTO delivery.repository_binding_revisions (
            tenant_id, binding_id, project_id, source_connection_id,
            external_repository_id,
            content_digest, resource_version, created_at, document
        ) VALUES (
            effective_tenant_id, resource_id, submitted_resource->>'projectId',
            submitted_resource#>>'{spec,sourceConnectionId}',
            submitted_resource#>>'{spec,externalRepositoryId}',
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
               external_repository_id = submitted_resource#>>'{spec,externalRepositoryId}',
               content_digest = submitted_resource->>'contentDigest',
               resource_version = expected_resource_version + 1,
               document = submitted_resource
         WHERE tenant_id = effective_tenant_id AND id = resource_id
           AND resource_version = expected_resource_version;
        INSERT INTO delivery.repository_binding_revisions (
            tenant_id, binding_id, project_id, source_connection_id,
            external_repository_id,
            content_digest, resource_version, created_at, document
        ) VALUES (
            effective_tenant_id, resource_id, submitted_resource->>'projectId',
            submitted_resource#>>'{spec,sourceConnectionId}',
            submitted_resource#>>'{spec,externalRepositoryId}',
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

    IF requested_kind IN (
        'CREATE_SOURCE_CONNECTION', 'UPDATE_SOURCE_CONNECTION',
        'CREATE_REPOSITORY_BINDING', 'UPDATE_REPOSITORY_BINDING'
    ) THEN
        INSERT INTO delivery.source_observation_tasks (
            tenant_id, resource_kind, resource_id, resource_version,
            available_at, fencing_token, created_at, updated_at
        ) VALUES (
            effective_tenant_id,
            CASE
                WHEN requested_kind IN (
                    'CREATE_SOURCE_CONNECTION', 'UPDATE_SOURCE_CONNECTION'
                ) THEN 'SOURCE_CONNECTION'
                ELSE 'REPOSITORY_BINDING'
            END,
            resource_id,
            (submitted_resource#>>'{metadata,resourceVersion}')::bigint,
            effective_now, 0, effective_now, effective_now
        )
        ON CONFLICT ON CONSTRAINT source_observation_tasks_pkey DO UPDATE
           SET resource_version = excluded.resource_version,
               available_at = excluded.available_at,
               lease_owner = NULL,
               lease_expires_at = NULL,
               updated_at = greatest(
                   excluded.updated_at,
                   source_observation_tasks.last_claimed_at
               );
    END IF;

    IF requested_kind = 'UPDATE_SOURCE_CONNECTION' THEN
        INSERT INTO delivery.source_observation_tasks (
            tenant_id, resource_kind, resource_id, resource_version,
            available_at, fencing_token, created_at, updated_at
        )
        SELECT binding.tenant_id, 'REPOSITORY_BINDING', binding.id,
               binding.resource_version, effective_now, 0,
               effective_now, effective_now
          FROM delivery.repository_bindings AS binding
         WHERE binding.tenant_id = effective_tenant_id
           AND binding.source_connection_id = resource_id
        ON CONFLICT ON CONSTRAINT source_observation_tasks_pkey DO UPDATE
           SET resource_version = excluded.resource_version,
               available_at = excluded.available_at,
               lease_owner = NULL,
               lease_expires_at = NULL,
               updated_at = greatest(
                   excluded.updated_at,
                   source_observation_tasks.last_claimed_at
               );
    END IF;

    INSERT INTO delivery.audit_operations (
        tenant_id, id, operation_kind, target_kind, target_id, created_at
    ) VALUES (
        effective_tenant_id, submitted_mutation->>'id',
        'CONFIGURATION_MUTATION', expected_audit_target, audit_target_id,
        effective_now
    );

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

CREATE OR REPLACE FUNCTION delivery.lock_pipeline_run_for_cancellation(
    requested_run_id text
)
RETURNS TABLE (run_document jsonb, effect_may_exist boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    locked_document jsonb;
    pending_command_id text;
BEGIN
    effective_tenant_id := delivery.current_tenant_id();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'valid transaction-local delivery tenant is required';
    END IF;
    IF requested_run_id IS NULL
       OR requested_run_id COLLATE "C" !~ '^pipeline-run-[0-9a-f]{48}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'PipelineRun cancellation identity is invalid';
    END IF;

    SELECT run.document
      INTO locked_document
      FROM delivery.pipeline_runs AS run
     WHERE run.tenant_id = effective_tenant_id
       AND run.id = requested_run_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT task.command_id
      INTO pending_command_id
      FROM delivery.pipeline_run_tasks AS task
     WHERE task.tenant_id = effective_tenant_id
       AND task.run_id = requested_run_id
       AND task.status = 'INTENT'
     LIMIT 1
     FOR UPDATE;

    run_document := locked_document;
    effect_may_exist := pending_command_id IS NOT NULL;
    RETURN NEXT;
END
$function$;

REVOKE ALL ON FUNCTION delivery.lock_pipeline_run_for_cancellation(text)
    FROM PUBLIC, matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.lock_pipeline_run_for_cancellation(text)
    TO matrix_devops_api;

CREATE OR REPLACE FUNCTION delivery.commit_pipeline_run_cancellation(
    expected_resource_version bigint,
    submitted_run_document jsonb,
    submitted_operation jsonb,
    submitted_cancellation_event jsonb,
    submitted_terminal_event jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    effective_now timestamptz(6);
    requested_run_id text;
    current_state text;
    current_stage text;
    current_reason text;
    current_resource_version bigint;
    current_cancellation_requested_at timestamptz(6);
    current_completed_at timestamptz(6);
    current_updated_at timestamptz(6);
    current_run_document jsonb;
    current_command_id text;
    effect_may_exist boolean;
    terminal boolean;
    operation_id text;
    expected_cancellation_event_id text;
    terminal_operation_id text;
    expected_terminal_event_id text;
    affected_rows bigint;
BEGIN
    effective_tenant_id := delivery.current_tenant_id();
    effective_now := transaction_timestamp();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'valid transaction-local delivery tenant is required';
    END IF;
    IF expected_resource_version IS NULL
       OR expected_resource_version NOT BETWEEN 1 AND 9007199254740991
       OR jsonb_typeof(submitted_run_document) IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_operation) IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_cancellation_event) IS DISTINCT FROM 'object'
       OR (submitted_terminal_event IS NOT NULL
           AND jsonb_typeof(submitted_terminal_event) IS DISTINCT FROM 'object') THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'PipelineRun cancellation documents are invalid';
    END IF;

    requested_run_id := submitted_operation->>'runId';
    IF COALESCE(requested_run_id, '') COLLATE "C"
            !~ '^pipeline-run-[0-9a-f]{48}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'PipelineRun cancellation target is invalid';
    END IF;

    SELECT run.state,
           run.stage,
           run.reason,
           run.resource_version,
           run.cancellation_requested_at,
           run.completed_at,
           run.updated_at,
           run.document
      INTO current_state,
           current_stage,
           current_reason,
           current_resource_version,
           current_cancellation_requested_at,
           current_completed_at,
           current_updated_at,
           current_run_document
      FROM delivery.pipeline_runs AS run
     WHERE run.tenant_id = effective_tenant_id
       AND run.id = requested_run_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MX404',
            MESSAGE = 'PipelineRun does not exist';
    END IF;
    IF current_resource_version <> expected_resource_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MX409',
            MESSAGE = 'PipelineRun version conflict';
    END IF;
    IF current_state IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION')
       OR current_completed_at IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MX410',
            MESSAGE = 'terminal PipelineRun cannot be cancelled';
    END IF;
    IF current_cancellation_requested_at IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MX411',
            MESSAGE = 'PipelineRun cancellation is already requested';
    END IF;
    IF current_resource_version >= 9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE = 'MX409',
            MESSAGE = 'PipelineRun resource version is exhausted';
    END IF;
    IF effective_now <= current_updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '40001',
            MESSAGE = 'PipelineRun cancellation observation time did not advance';
    END IF;

    SELECT task.command_id
      INTO current_command_id
      FROM delivery.pipeline_run_tasks AS task
     WHERE task.tenant_id = effective_tenant_id
       AND task.run_id = requested_run_id
       AND task.status = 'INTENT'
     LIMIT 1
     FOR UPDATE;
    effect_may_exist := current_command_id IS NOT NULL;
    IF current_state = 'QUEUED' AND effect_may_exist THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'queued PipelineRun cannot have an external effect';
    END IF;
    IF current_state = 'RECONCILING' AND NOT effect_may_exist THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'reconciling PipelineRun lost its uncertain intent';
    END IF;
    terminal := NOT effect_may_exist;

    IF jsonb_typeof(submitted_run_document->'status') IS DISTINCT FROM 'object'
       OR NOT ((submitted_run_document->'status') ?& ARRAY[
            'state', 'stage', 'resourceVersion', 'observedAt',
            'cancellationRequestedAt'
       ])
       OR ((submitted_run_document->'status') - ARRAY[
            'state', 'stage', 'reason', 'resourceVersion', 'observedAt',
            'cancellationRequestedAt', 'completedAt'
       ]) <> '{}'::jsonb
       OR (submitted_run_document - ARRAY['status', 'updatedAt']) IS DISTINCT FROM
            (current_run_document - ARRAY['status', 'updatedAt'])
       OR submitted_run_document#>>'{status,state}' IS DISTINCT FROM
            (CASE WHEN terminal THEN 'CANCELLED' ELSE current_state END)
       OR submitted_run_document#>>'{status,stage}' IS DISTINCT FROM current_stage
       OR submitted_run_document#>>'{status,reason}' IS DISTINCT FROM
            (CASE WHEN terminal THEN 'CANCELLED' ELSE current_reason END)
       OR submitted_run_document#>>'{status,resourceVersion}' IS DISTINCT FROM
            (current_resource_version + 1)::text
       OR COALESCE(submitted_run_document#>>'{status,observedAt}', '') COLLATE "C"
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
       OR NOT pg_input_is_valid(
            COALESCE(submitted_run_document#>>'{status,observedAt}', ''),
            'timestamptz'
       )
       OR (submitted_run_document#>>'{status,observedAt}')::timestamptz
            IS DISTINCT FROM effective_now
       OR COALESCE(
            submitted_run_document#>>'{status,cancellationRequestedAt}', ''
          ) COLLATE "C"
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
       OR NOT pg_input_is_valid(
            COALESCE(
                submitted_run_document#>>'{status,cancellationRequestedAt}', ''
            ),
            'timestamptz'
       )
       OR (submitted_run_document#>>'{status,cancellationRequestedAt}')::timestamptz
            IS DISTINCT FROM effective_now
       OR COALESCE(submitted_run_document->>'updatedAt', '') COLLATE "C"
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
       OR NOT pg_input_is_valid(
            COALESCE(submitted_run_document->>'updatedAt', ''), 'timestamptz'
       )
       OR (submitted_run_document->>'updatedAt')::timestamptz
            IS DISTINCT FROM effective_now
       OR (terminal AND (
            NOT (submitted_run_document->'status' ? 'completedAt')
            OR COALESCE(
                submitted_run_document#>>'{status,completedAt}', ''
            ) COLLATE "C"
                !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
            OR NOT pg_input_is_valid(
                COALESCE(submitted_run_document#>>'{status,completedAt}', ''),
                'timestamptz'
            )
            OR (submitted_run_document#>>'{status,completedAt}')::timestamptz
                IS DISTINCT FROM effective_now
       ))
       OR (NOT terminal AND submitted_run_document->'status' ? 'completedAt') THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'submitted PipelineRun cancellation differs from database state';
    END IF;

    operation_id := submitted_operation->>'id';
    IF jsonb_typeof(submitted_operation->'requestedBy') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_operation->'iamResource') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_operation->'target') IS DISTINCT FROM 'object'
       OR NOT (submitted_operation ?& ARRAY[
            'schemaVersion', 'id', 'tenantId', 'kind', 'commandTargetId',
            'runId', 'requestedBy', 'iamDecisionId', 'iamAction', 'iamResource',
            'expectedResourceVersion', 'idempotencyFingerprint', 'requestDigest',
            'resultKind', 'target', 'requestId', 'correlationId', 'createdAt'
       ])
       OR (submitted_operation - ARRAY[
            'schemaVersion', 'id', 'tenantId', 'kind', 'commandTargetId',
            'runId', 'requestedBy', 'iamDecisionId', 'iamAction', 'iamResource',
            'expectedResourceVersion', 'idempotencyFingerprint', 'requestDigest',
            'resultKind', 'target', 'requestId', 'correlationId', 'traceparent',
            'createdAt'
       ]) <> '{}'::jsonb
       OR ((submitted_operation->'requestedBy') - ARRAY['kind', 'id']) <> '{}'::jsonb
       OR ((submitted_operation->'iamResource') - ARRAY['kind', 'id']) <> '{}'::jsonb
       OR ((submitted_operation->'target') - ARRAY['kind', 'id']) <> '{}'::jsonb
       OR submitted_operation->>'schemaVersion' IS DISTINCT FROM 'v1'
       OR submitted_operation->>'tenantId' IS DISTINCT FROM effective_tenant_id
       OR submitted_operation->>'kind' IS DISTINCT FROM 'CANCEL_PIPELINE_RUN'
       OR submitted_operation->>'commandTargetId' IS DISTINCT FROM requested_run_id
       OR submitted_operation->>'iamAction' IS DISTINCT FROM 'devops.run.cancel'
       OR submitted_operation#>>'{iamResource,kind}' IS DISTINCT FROM 'PIPELINE_RUN'
       OR submitted_operation#>>'{iamResource,id}' IS DISTINCT FROM requested_run_id
       OR submitted_operation#>>'{target,kind}' IS DISTINCT FROM 'PIPELINE_RUN'
       OR submitted_operation#>>'{target,id}' IS DISTINCT FROM requested_run_id
       OR submitted_operation->>'resultKind' IS DISTINCT FROM 'PipelineRun'
       OR COALESCE(operation_id, '') COLLATE "C" !~ '^operation-[0-9a-f]{64}$'
       OR operation_id IS DISTINCT FROM 'operation-' || encode(
            sha256(
                convert_to('matrix-devops-operation-v1', 'UTF8')
                || decode('00', 'hex')
                || convert_to(
                    submitted_operation->>'idempotencyFingerprint', 'UTF8'
                )
            ),
            'hex'
       )
       OR COALESCE(submitted_operation#>>'{requestedBy,id}', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_operation#>>'{requestedBy,kind}' NOT IN ('USER', 'SERVICE_ACCOUNT')
       OR COALESCE(submitted_operation->>'iamDecisionId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_operation->>'idempotencyFingerprint', '') COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR COALESCE(submitted_operation->>'requestDigest', '') COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR COALESCE(submitted_operation->>'requestId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_operation->>'correlationId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR NOT pg_input_is_valid(
            COALESCE(submitted_operation->>'expectedResourceVersion', ''),
            'bigint'
       )
       OR (submitted_operation->>'expectedResourceVersion')::bigint
            IS DISTINCT FROM expected_resource_version
       OR NOT pg_input_is_valid(
            COALESCE(submitted_operation->>'createdAt', ''), 'timestamptz'
       )
       OR (submitted_operation->>'createdAt')::timestamptz
            IS DISTINCT FROM effective_now
       OR (
            submitted_operation ? 'traceparent'
            AND COALESCE(submitted_operation->>'traceparent', '') COLLATE "C"
                !~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'PipelineRun cancellation Operation is invalid';
    END IF;

    expected_cancellation_event_id := 'audit-' || encode(
        sha256(
            convert_to('matrix-devops-audit-event-v1', 'UTF8')
            || decode('00', 'hex')
            || convert_to(operation_id, 'UTF8')
        ),
        'hex'
    );
    IF jsonb_typeof(submitted_cancellation_event->'actor') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_cancellation_event->'target') IS DISTINCT FROM 'object'
       OR NOT (submitted_cancellation_event ?& ARRAY[
            'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
            'iamDecisionId', 'action', 'target', 'result', 'requestDigest',
            'requestId', 'correlationId', 'operationId', 'occurredAt'
       ])
       OR (submitted_cancellation_event - ARRAY[
            'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
            'iamDecisionId', 'action', 'target', 'result', 'requestDigest',
            'requestId', 'correlationId', 'operationId', 'traceparent',
            'occurredAt'
       ]) <> '{}'::jsonb
       OR ((submitted_cancellation_event->'actor') - ARRAY['type', 'id']) <> '{}'::jsonb
       OR ((submitted_cancellation_event->'target') - ARRAY['kind', 'id']) <> '{}'::jsonb
       OR submitted_cancellation_event->>'apiVersion'
            IS DISTINCT FROM 'audit.matrix.xiak.com/v1'
       OR submitted_cancellation_event->>'kind' IS DISTINCT FROM 'AuditEvent'
       OR submitted_cancellation_event->>'eventId'
            IS DISTINCT FROM expected_cancellation_event_id
       OR submitted_cancellation_event->>'tenantId' IS DISTINCT FROM effective_tenant_id
       OR submitted_cancellation_event->'actor'
            IS DISTINCT FROM jsonb_build_object(
                'type', submitted_operation#>>'{requestedBy,kind}',
                'id', submitted_operation#>>'{requestedBy,id}'
            )
       OR submitted_cancellation_event->>'iamDecisionId'
            IS DISTINCT FROM submitted_operation->>'iamDecisionId'
       OR submitted_cancellation_event->>'action'
            IS DISTINCT FROM 'devops.pipeline-run.cancellation-requested'
       OR submitted_cancellation_event->'target'
            IS DISTINCT FROM jsonb_build_object('kind', 'PIPELINE_RUN', 'id', requested_run_id)
       OR submitted_cancellation_event->>'result' IS DISTINCT FROM 'ACCEPTED'
       OR submitted_cancellation_event->>'requestDigest'
            IS DISTINCT FROM submitted_operation->>'requestDigest'
       OR submitted_cancellation_event->>'requestId'
            IS DISTINCT FROM submitted_operation->>'requestId'
       OR submitted_cancellation_event->>'correlationId'
            IS DISTINCT FROM submitted_operation->>'correlationId'
       OR submitted_cancellation_event->>'operationId' IS DISTINCT FROM operation_id
       OR (submitted_cancellation_event ? 'traceparent')
            IS DISTINCT FROM (submitted_operation ? 'traceparent')
       OR submitted_cancellation_event->>'traceparent'
            IS DISTINCT FROM submitted_operation->>'traceparent'
       OR NOT pg_input_is_valid(
            COALESCE(submitted_cancellation_event->>'occurredAt', ''),
            'timestamptz'
       )
       OR (submitted_cancellation_event->>'occurredAt')::timestamptz
            IS DISTINCT FROM effective_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'PipelineRun cancellation Audit fact is invalid';
    END IF;

    IF terminal THEN
        terminal_operation_id := requested_run_id || ':terminal:' ||
            (current_resource_version + 1)::text;
        expected_terminal_event_id := 'audit-' || encode(
            sha256(
                convert_to('matrix-devops-audit-event-v1', 'UTF8')
                || decode('00', 'hex')
                || convert_to(terminal_operation_id, 'UTF8')
            ),
            'hex'
        );
        IF jsonb_typeof(submitted_terminal_event) IS DISTINCT FROM 'object'
           OR jsonb_typeof(submitted_terminal_event->'actor') IS DISTINCT FROM 'object'
           OR jsonb_typeof(submitted_terminal_event->'target') IS DISTINCT FROM 'object'
           OR NOT (submitted_terminal_event ?& ARRAY[
                'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
                'action', 'target', 'result', 'outcome', 'reason',
                'requestDigest', 'requestId', 'correlationId',
                'operationId', 'occurredAt'
           ])
           OR (submitted_terminal_event - ARRAY[
                'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
                'action', 'target', 'result', 'outcome', 'reason',
                'requestDigest', 'requestId', 'correlationId',
                'operationId', 'occurredAt'
           ]) <> '{}'::jsonb
           OR ((submitted_terminal_event->'actor') - ARRAY['type', 'id']) <> '{}'::jsonb
           OR ((submitted_terminal_event->'target') - ARRAY['kind', 'id']) <> '{}'::jsonb
           OR submitted_terminal_event->>'apiVersion'
                IS DISTINCT FROM 'audit.matrix.xiak.com/v1'
           OR submitted_terminal_event->>'kind' IS DISTINCT FROM 'AuditEvent'
           OR submitted_terminal_event->>'eventId'
                IS DISTINCT FROM expected_terminal_event_id
           OR submitted_terminal_event->>'tenantId' IS DISTINCT FROM effective_tenant_id
           OR submitted_terminal_event->'actor' IS DISTINCT FROM
                jsonb_build_object('type', 'SYSTEM', 'id', 'system-devops-run-control')
           OR submitted_terminal_event ? 'iamDecisionId'
           OR submitted_terminal_event ? 'traceparent'
           OR submitted_terminal_event->>'action'
                IS DISTINCT FROM 'devops.pipeline-run.completed'
           OR submitted_terminal_event->'target' IS DISTINCT FROM
                jsonb_build_object('kind', 'PIPELINE_RUN', 'id', requested_run_id)
           OR submitted_terminal_event->>'result' IS DISTINCT FROM 'SUCCEEDED'
           OR submitted_terminal_event->>'outcome' IS DISTINCT FROM 'CANCELLED'
           OR submitted_terminal_event->>'reason' IS DISTINCT FROM 'CANCELLED'
           OR submitted_terminal_event->>'requestDigest'
                IS DISTINCT FROM current_run_document->>'inputDigest'
           OR submitted_terminal_event->>'requestId'
                IS DISTINCT FROM submitted_operation->>'requestId'
           OR submitted_terminal_event->>'correlationId' IS DISTINCT FROM requested_run_id
           OR submitted_terminal_event->>'operationId'
                IS DISTINCT FROM terminal_operation_id
           OR NOT pg_input_is_valid(
                COALESCE(submitted_terminal_event->>'occurredAt', ''),
                'timestamptz'
           )
           OR (submitted_terminal_event->>'occurredAt')::timestamptz
                IS DISTINCT FROM effective_now THEN
            RAISE EXCEPTION USING ERRCODE = '22023',
                MESSAGE = 'PipelineRun cancellation terminal Audit fact is invalid';
        END IF;
    ELSIF submitted_terminal_event IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'pending PipelineRun cancellation cannot emit a terminal Audit fact';
    END IF;

    INSERT INTO delivery.audit_operations (
        tenant_id, id, operation_kind, target_kind, target_id, created_at
    ) VALUES (
        effective_tenant_id, operation_id, 'PIPELINE_RUN_CANCELLATION',
        'PIPELINE_RUN', requested_run_id, effective_now
    );
    INSERT INTO delivery.mutations (
        tenant_id, id, mutation_kind, command_target_id, target_kind, target_id,
        idempotency_fingerprint, request_digest, result_kind, created_at,
        document, result_document
    ) VALUES (
        effective_tenant_id, operation_id, 'CANCEL_PIPELINE_RUN',
        requested_run_id, 'PIPELINE_RUN', requested_run_id,
        submitted_operation->>'idempotencyFingerprint',
        submitted_operation->>'requestDigest', 'PipelineRun', effective_now,
        submitted_operation, submitted_run_document
    );
    UPDATE delivery.pipeline_runs AS cancelled
       SET state = CASE WHEN terminal THEN 'CANCELLED' ELSE current_state END,
           reason = CASE WHEN terminal THEN 'CANCELLED' ELSE current_reason END,
           resource_version = current_resource_version + 1,
           cancellation_requested_at = effective_now,
           completed_at = CASE WHEN terminal THEN effective_now ELSE NULL END,
           updated_at = effective_now,
           document = submitted_run_document
     WHERE cancelled.tenant_id = effective_tenant_id
       AND cancelled.id = requested_run_id
       AND cancelled.resource_version = expected_resource_version;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'MX409',
            MESSAGE = 'PipelineRun cancellation version conflict';
    END IF;
    IF effect_may_exist THEN
        UPDATE delivery.pipeline_run_tasks AS task
           SET available_at = effective_now,
               lease_expires_at = CASE
                   WHEN task.lease_owner IS NULL THEN NULL
                   ELSE effective_now
               END,
               updated_at = effective_now
         WHERE task.tenant_id = effective_tenant_id
           AND task.run_id = requested_run_id
           AND task.command_id = current_command_id
           AND task.status = 'INTENT';
        GET DIAGNOSTICS affected_rows = ROW_COUNT;
        IF affected_rows <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '40001',
                MESSAGE = 'PipelineRun cancellation intent changed concurrently';
        END IF;
    END IF;
    INSERT INTO delivery.audit_outbox (
        tenant_id, event_id, operation_id, status, available_at, attempts,
        fencing_token, created_at, updated_at, document
    ) VALUES (
        effective_tenant_id, expected_cancellation_event_id, operation_id,
        'PENDING', effective_now, 0, 0, effective_now, effective_now,
        submitted_cancellation_event
    );

    IF terminal THEN
        INSERT INTO delivery.audit_operations (
            tenant_id, id, operation_kind, target_kind, target_id, created_at
        ) VALUES (
            effective_tenant_id, terminal_operation_id, 'PIPELINE_RUN_TERMINAL',
            'PIPELINE_RUN', requested_run_id, effective_now
        );
        INSERT INTO delivery.audit_outbox (
            tenant_id, event_id, operation_id, status, available_at, attempts,
            fencing_token, created_at, updated_at, document
        ) VALUES (
            effective_tenant_id, expected_terminal_event_id,
            terminal_operation_id, 'PENDING', effective_now, 0, 0,
            effective_now, effective_now, submitted_terminal_event
        );
    END IF;
END
$function$;

REVOKE ALL ON FUNCTION delivery.commit_pipeline_run_cancellation(
    bigint, jsonb, jsonb, jsonb, jsonb
) FROM PUBLIC, matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.commit_pipeline_run_cancellation(
    bigint, jsonb, jsonb, jsonb, jsonb
) TO matrix_devops_api;

CREATE OR REPLACE FUNCTION delivery.lock_pipeline_run_for_replay(
    requested_source_run_id text,
    expected_resource_version bigint
)
RETURNS TABLE (run_document jsonb, replayed_at timestamptz(6))
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    locked_state text;
    locked_resource_version bigint;
    locked_completed_at timestamptz(6);
    locked_updated_at timestamptz(6);
    locked_document jsonb;
BEGIN
    effective_tenant_id := delivery.current_tenant_id();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'valid transaction-local delivery tenant is required';
    END IF;
    IF COALESCE(requested_source_run_id, '') COLLATE "C"
            !~ '^pipeline-run-[0-9a-f]{48}$'
       OR expected_resource_version IS NULL
       OR expected_resource_version NOT BETWEEN 1 AND 9007199254740991 THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'PipelineRun replay selector is invalid';
    END IF;

    SELECT run.state, run.resource_version, run.completed_at,
           run.updated_at, run.document
      INTO locked_state, locked_resource_version, locked_completed_at,
           locked_updated_at, locked_document
      FROM delivery.pipeline_runs AS run
     WHERE run.tenant_id = effective_tenant_id
       AND run.id = requested_source_run_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MX404',
            MESSAGE = 'PipelineRun does not exist';
    END IF;
    IF locked_resource_version <> expected_resource_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MX409',
            MESSAGE = 'PipelineRun version conflict';
    END IF;
    IF locked_state NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION')
       OR locked_completed_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MX412',
            MESSAGE = 'nonterminal PipelineRun cannot be replayed';
    END IF;

    run_document := locked_document;
    replayed_at := greatest(
        transaction_timestamp()::timestamptz(6),
        locked_updated_at + interval '1 microsecond'
    );
    RETURN NEXT;
END
$function$;

REVOKE ALL ON FUNCTION delivery.lock_pipeline_run_for_replay(text, bigint)
    FROM PUBLIC, matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.lock_pipeline_run_for_replay(text, bigint)
    TO matrix_devops_api;

CREATE OR REPLACE FUNCTION delivery.commit_pipeline_run_replay(
    expected_resource_version bigint,
    submitted_run_document jsonb,
    submitted_operation jsonb,
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
    source_run_id text;
    source_input_digest text;
    source_event_id text;
    source_event_digest text;
    source_pipeline_id text;
    source_project_id text;
    source_pipeline_revision_id text;
    source_pipeline_revision_digest text;
    source_repository_binding_id text;
    source_repository_binding_digest text;
    source_state text;
    source_resource_version bigint;
    source_completed_at timestamptz(6);
    source_updated_at timestamptz(6);
    source_run_document jsonb;
    replayed_run_id text;
    operation_id text;
    expected_audit_event_id text;
    queued_run_count bigint;
BEGIN
    effective_tenant_id := delivery.current_tenant_id();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'valid transaction-local delivery tenant is required';
    END IF;
    IF expected_resource_version IS NULL
       OR expected_resource_version NOT BETWEEN 1 AND 9007199254740991
       OR jsonb_typeof(submitted_run_document) IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_operation) IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_audit_event) IS DISTINCT FROM 'object'
       OR octet_length(submitted_run_document::text) > 131072
       OR octet_length(submitted_operation::text) > 131072
       OR octet_length(submitted_audit_event::text) > 131072 THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'PipelineRun replay documents are invalid';
    END IF;

    source_run_id := submitted_operation->>'sourceRunId';
    IF COALESCE(source_run_id, '') COLLATE "C"
            !~ '^pipeline-run-[0-9a-f]{48}$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'PipelineRun replay source is invalid';
    END IF;

    SELECT run.input_digest, run.source_event_id, run.source_event_digest,
           run.pipeline_id, run.project_id, run.pipeline_revision_id,
           run.pipeline_revision_digest, run.repository_binding_id,
           run.repository_binding_digest, run.state, run.resource_version,
           run.completed_at, run.updated_at, run.document
      INTO source_input_digest, source_event_id, source_event_digest,
           source_pipeline_id, source_project_id, source_pipeline_revision_id,
           source_pipeline_revision_digest, source_repository_binding_id,
           source_repository_binding_digest, source_state,
           source_resource_version, source_completed_at, source_updated_at,
           source_run_document
      FROM delivery.pipeline_runs AS run
     WHERE run.tenant_id = effective_tenant_id
       AND run.id = source_run_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MX404',
            MESSAGE = 'PipelineRun does not exist';
    END IF;
    IF source_resource_version <> expected_resource_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MX409',
            MESSAGE = 'PipelineRun version conflict';
    END IF;
    IF source_state NOT IN ('SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION')
       OR source_completed_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MX412',
            MESSAGE = 'nonterminal PipelineRun cannot be replayed';
    END IF;
    effective_now := greatest(
        transaction_timestamp()::timestamptz(6),
        source_updated_at + interval '1 microsecond'
    );

    replayed_run_id := submitted_run_document->>'id';
    operation_id := submitted_operation->>'id';
    IF jsonb_typeof(submitted_run_document->'scope') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_run_document->'input') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_run_document->'replay') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_run_document#>'{replay,requestedBy}') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_run_document->'status') IS DISTINCT FROM 'object'
       OR NOT (submitted_run_document ?& ARRAY[
            'apiVersion', 'kind', 'id', 'scope', 'projectId', 'pipelineId',
            'input', 'inputDigest', 'replay', 'status', 'createdAt', 'updatedAt'
       ])
       OR (submitted_run_document - ARRAY[
            'apiVersion', 'kind', 'id', 'scope', 'projectId', 'pipelineId',
            'input', 'inputDigest', 'replay', 'status', 'createdAt', 'updatedAt'
       ]) <> '{}'::jsonb
       OR ((submitted_run_document->'scope') - ARRAY['tenantId']) <> '{}'::jsonb
       OR NOT ((submitted_run_document->'scope') ?& ARRAY['tenantId'])
       OR ((submitted_run_document->'replay') - ARRAY[
            'sourceRunId', 'commandId', 'requestedBy'
       ]) <> '{}'::jsonb
       OR NOT ((submitted_run_document->'replay') ?& ARRAY[
            'sourceRunId', 'commandId', 'requestedBy'
       ])
       OR ((submitted_run_document#>'{replay,requestedBy}') - ARRAY['kind', 'id'])
            <> '{}'::jsonb
       OR NOT ((submitted_run_document#>'{replay,requestedBy}') ?& ARRAY['kind', 'id'])
       OR ((submitted_run_document->'status') - ARRAY[
            'state', 'stage', 'reason', 'resourceVersion', 'observedAt'
       ]) <> '{}'::jsonb
       OR NOT ((submitted_run_document->'status') ?& ARRAY[
            'state', 'stage', 'reason', 'resourceVersion', 'observedAt'
       ])
       OR submitted_run_document->>'apiVersion'
            IS DISTINCT FROM 'devops.matrix.xiak.com/v1'
       OR submitted_run_document->>'kind' IS DISTINCT FROM 'PipelineRun'
       OR submitted_run_document#>>'{scope,tenantId}' IS DISTINCT FROM effective_tenant_id
       OR COALESCE(replayed_run_id, '') COLLATE "C"
            !~ '^pipeline-run-[0-9a-f]{48}$'
       OR replayed_run_id IS NOT DISTINCT FROM source_run_id
       OR submitted_run_document->>'projectId' IS DISTINCT FROM source_project_id
       OR submitted_run_document->>'pipelineId' IS DISTINCT FROM source_pipeline_id
       OR submitted_run_document->'input' IS DISTINCT FROM source_run_document->'input'
       OR submitted_run_document->>'inputDigest' IS DISTINCT FROM source_input_digest
       OR submitted_run_document#>>'{replay,sourceRunId}' IS DISTINCT FROM source_run_id
       OR submitted_run_document#>>'{replay,commandId}' IS DISTINCT FROM operation_id
       OR submitted_run_document#>'{replay,requestedBy}'
            IS DISTINCT FROM submitted_operation->'requestedBy'
       OR submitted_run_document#>>'{status,state}' IS DISTINCT FROM 'QUEUED'
       OR submitted_run_document#>>'{status,stage}' IS DISTINCT FROM 'RECEIVE'
       OR submitted_run_document#>>'{status,reason}' IS DISTINCT FROM 'EVENT_ADMITTED'
       OR submitted_run_document#>>'{status,resourceVersion}' IS DISTINCT FROM '1'
       OR COALESCE(submitted_run_document#>>'{status,observedAt}', '') COLLATE "C"
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
       OR NOT pg_input_is_valid(
            COALESCE(submitted_run_document#>>'{status,observedAt}', ''),
            'timestamptz'
       )
       OR (submitted_run_document#>>'{status,observedAt}')::timestamptz
            IS DISTINCT FROM effective_now
       OR COALESCE(submitted_run_document->>'createdAt', '') COLLATE "C"
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
       OR NOT pg_input_is_valid(
            COALESCE(submitted_run_document->>'createdAt', ''), 'timestamptz'
       )
       OR (submitted_run_document->>'createdAt')::timestamptz
            IS DISTINCT FROM effective_now
       OR submitted_run_document->>'updatedAt'
            IS DISTINCT FROM submitted_run_document->>'createdAt' THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'queued PipelineRun replay document is invalid';
    END IF;

    IF jsonb_typeof(submitted_operation->'requestedBy') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_operation->'iamResource') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_operation->'target') IS DISTINCT FROM 'object'
       OR NOT (submitted_operation ?& ARRAY[
            'schemaVersion', 'id', 'tenantId', 'kind', 'commandTargetId',
            'sourceRunId', 'requestedBy', 'iamDecisionId', 'iamAction',
            'iamResource', 'expectedResourceVersion', 'idempotencyFingerprint',
            'requestDigest', 'resultKind', 'target', 'requestId',
            'correlationId', 'createdAt'
       ])
       OR (submitted_operation - ARRAY[
            'schemaVersion', 'id', 'tenantId', 'kind', 'commandTargetId',
            'sourceRunId', 'requestedBy', 'iamDecisionId', 'iamAction',
            'iamResource', 'expectedResourceVersion', 'idempotencyFingerprint',
            'requestDigest', 'resultKind', 'target', 'requestId',
            'correlationId', 'traceparent', 'createdAt'
       ]) <> '{}'::jsonb
       OR ((submitted_operation->'requestedBy') - ARRAY['kind', 'id']) <> '{}'::jsonb
       OR NOT ((submitted_operation->'requestedBy') ?& ARRAY['kind', 'id'])
       OR ((submitted_operation->'iamResource') - ARRAY['kind', 'id']) <> '{}'::jsonb
       OR NOT ((submitted_operation->'iamResource') ?& ARRAY['kind', 'id'])
       OR ((submitted_operation->'target') - ARRAY['kind', 'id']) <> '{}'::jsonb
       OR NOT ((submitted_operation->'target') ?& ARRAY['kind', 'id'])
       OR submitted_operation->>'schemaVersion' IS DISTINCT FROM 'v1'
       OR submitted_operation->>'tenantId' IS DISTINCT FROM effective_tenant_id
       OR submitted_operation->>'kind' IS DISTINCT FROM 'REPLAY_PIPELINE_RUN'
       OR submitted_operation->>'commandTargetId' IS DISTINCT FROM source_run_id
       OR submitted_operation->>'iamAction' IS DISTINCT FROM 'devops.run.replay'
       OR submitted_operation#>>'{iamResource,kind}' IS DISTINCT FROM 'PIPELINE_RUN'
       OR submitted_operation#>>'{iamResource,id}' IS DISTINCT FROM source_run_id
       OR submitted_operation#>>'{target,kind}' IS DISTINCT FROM 'PIPELINE_RUN'
       OR submitted_operation#>>'{target,id}' IS DISTINCT FROM replayed_run_id
       OR submitted_operation->>'resultKind' IS DISTINCT FROM 'PipelineRun'
       OR COALESCE(operation_id, '') COLLATE "C" !~ '^operation-[0-9a-f]{64}$'
       OR operation_id IS DISTINCT FROM 'operation-' || encode(
            sha256(
                convert_to('matrix-devops-operation-v1', 'UTF8')
                || decode('00', 'hex')
                || convert_to(
                    submitted_operation->>'idempotencyFingerprint', 'UTF8'
                )
            ),
            'hex'
       )
       OR COALESCE(submitted_operation#>>'{requestedBy,id}', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR submitted_operation#>>'{requestedBy,kind}' NOT IN ('USER', 'SERVICE_ACCOUNT')
       OR COALESCE(submitted_operation->>'iamDecisionId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_operation->>'idempotencyFingerprint', '') COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR COALESCE(submitted_operation->>'requestDigest', '') COLLATE "C"
            !~ '^sha256:[0-9a-f]{64}$'
       OR COALESCE(submitted_operation->>'requestId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(submitted_operation->>'correlationId', '') COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR NOT pg_input_is_valid(
            COALESCE(submitted_operation->>'expectedResourceVersion', ''), 'bigint'
       )
       OR (submitted_operation->>'expectedResourceVersion')::bigint
            IS DISTINCT FROM expected_resource_version
       OR NOT pg_input_is_valid(
            COALESCE(submitted_operation->>'createdAt', ''), 'timestamptz'
       )
       OR (submitted_operation->>'createdAt')::timestamptz
            IS DISTINCT FROM effective_now
       OR (
            submitted_operation ? 'traceparent'
            AND COALESCE(submitted_operation->>'traceparent', '') COLLATE "C"
                !~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'
       ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'PipelineRun replay Operation is invalid';
    END IF;

    expected_audit_event_id := 'audit-' || encode(
        sha256(
            convert_to('matrix-devops-audit-event-v1', 'UTF8')
            || decode('00', 'hex')
            || convert_to(operation_id, 'UTF8')
        ),
        'hex'
    );
    IF jsonb_typeof(submitted_audit_event->'actor') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_audit_event->'target') IS DISTINCT FROM 'object'
       OR NOT (submitted_audit_event ?& ARRAY[
            'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
            'iamDecisionId', 'action', 'target', 'result', 'requestDigest',
            'requestId', 'correlationId', 'operationId', 'occurredAt'
       ])
       OR (submitted_audit_event - ARRAY[
            'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
            'iamDecisionId', 'action', 'target', 'result', 'requestDigest',
            'requestId', 'correlationId', 'operationId', 'traceparent',
            'occurredAt'
       ]) <> '{}'::jsonb
       OR ((submitted_audit_event->'actor') - ARRAY['type', 'id']) <> '{}'::jsonb
       OR ((submitted_audit_event->'target') - ARRAY['kind', 'id']) <> '{}'::jsonb
       OR submitted_audit_event->>'apiVersion'
            IS DISTINCT FROM 'audit.matrix.xiak.com/v1'
       OR submitted_audit_event->>'kind' IS DISTINCT FROM 'AuditEvent'
       OR submitted_audit_event->>'eventId' IS DISTINCT FROM expected_audit_event_id
       OR submitted_audit_event->>'tenantId' IS DISTINCT FROM effective_tenant_id
       OR submitted_audit_event->'actor' IS DISTINCT FROM
            jsonb_build_object(
                'type', submitted_operation#>>'{requestedBy,kind}',
                'id', submitted_operation#>>'{requestedBy,id}'
            )
       OR submitted_audit_event->>'iamDecisionId'
            IS DISTINCT FROM submitted_operation->>'iamDecisionId'
       OR submitted_audit_event->>'action'
            IS DISTINCT FROM 'devops.pipeline-run.replayed'
       OR submitted_audit_event->'target' IS DISTINCT FROM
            jsonb_build_object('kind', 'PIPELINE_RUN', 'id', replayed_run_id)
       OR submitted_audit_event->>'result' IS DISTINCT FROM 'ACCEPTED'
       OR submitted_audit_event->>'requestDigest'
            IS DISTINCT FROM submitted_operation->>'requestDigest'
       OR submitted_audit_event->>'requestId'
            IS DISTINCT FROM submitted_operation->>'requestId'
       OR submitted_audit_event->>'correlationId'
            IS DISTINCT FROM submitted_operation->>'correlationId'
       OR submitted_audit_event->>'operationId' IS DISTINCT FROM operation_id
       OR (submitted_audit_event ? 'traceparent')
            IS DISTINCT FROM (submitted_operation ? 'traceparent')
       OR submitted_audit_event->>'traceparent'
            IS DISTINCT FROM submitted_operation->>'traceparent'
       OR NOT pg_input_is_valid(
            COALESCE(submitted_audit_event->>'occurredAt', ''), 'timestamptz'
       )
       OR (submitted_audit_event->>'occurredAt')::timestamptz
            IS DISTINCT FROM effective_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'PipelineRun replay Audit fact is invalid';
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended('matrix-devops-queued-runs-v1:' || effective_tenant_id, 0)
    );
    SELECT count(*) INTO queued_run_count
      FROM delivery.pipeline_runs
     WHERE tenant_id = effective_tenant_id AND state = 'QUEUED';
    IF queued_run_count >= 32 THEN
        RAISE EXCEPTION USING ERRCODE = 'MX429',
            MESSAGE = 'tenant queued-run capacity is exhausted';
    END IF;

    INSERT INTO delivery.audit_operations (
        tenant_id, id, operation_kind, target_kind, target_id, created_at
    ) VALUES (
        effective_tenant_id, operation_id, 'PIPELINE_RUN_REPLAY',
        'PIPELINE_RUN', replayed_run_id, effective_now
    );
    INSERT INTO delivery.mutations (
        tenant_id, id, mutation_kind, command_target_id, target_kind, target_id,
        idempotency_fingerprint, request_digest, result_kind, created_at,
        document, result_document
    ) VALUES (
        effective_tenant_id, operation_id, 'REPLAY_PIPELINE_RUN', source_run_id,
        'PIPELINE_RUN', replayed_run_id,
        submitted_operation->>'idempotencyFingerprint',
        submitted_operation->>'requestDigest', 'PipelineRun', effective_now,
        submitted_operation, submitted_run_document
    );
    INSERT INTO delivery.pipeline_runs (
        tenant_id, id, input_digest, source_event_id, source_event_digest,
        pipeline_id, project_id, pipeline_revision_id,
        pipeline_revision_digest, repository_binding_id,
        repository_binding_digest, replay_of_run_id, replay_command_id,
        creation_operation_id, state, stage, reason, resource_version,
        cancellation_requested_at, completed_at, created_at, updated_at,
        document
    ) VALUES (
        effective_tenant_id, replayed_run_id, source_input_digest,
        source_event_id, source_event_digest, source_pipeline_id,
        source_project_id, source_pipeline_revision_id,
        source_pipeline_revision_digest, source_repository_binding_id,
        source_repository_binding_digest, source_run_id, operation_id,
        operation_id, 'QUEUED', 'RECEIVE', 'EVENT_ADMITTED', 1,
        NULL, NULL, effective_now, effective_now, submitted_run_document
    );
    INSERT INTO delivery.audit_outbox (
        tenant_id, event_id, operation_id, status, available_at, attempts,
        fencing_token, created_at, updated_at, document
    ) VALUES (
        effective_tenant_id, expected_audit_event_id, operation_id,
        'PENDING', effective_now, 0, 0, effective_now, effective_now,
        submitted_audit_event
    );
END
$function$;

REVOKE ALL ON FUNCTION delivery.commit_pipeline_run_replay(
    bigint, jsonb, jsonb, jsonb
) FROM PUBLIC, matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.commit_pipeline_run_replay(
    bigint, jsonb, jsonb, jsonb
) TO matrix_devops_api;

CREATE OR REPLACE FUNCTION delivery.commit_run_admission(
    submitted_event jsonb,
    submitted_runs jsonb,
    submitted_audit_events jsonb
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_tenant_id text;
    effective_now timestamptz(6);
    admitted_event_id text;
    admitted_project_id text;
    admitted_source_connection_id text;
    admitted_repository_binding_id text;
    admitted_repository_binding_digest text;
    admitted_external_repository_id text;
    admitted_delivery_id text;
    admitted_canonical_payload_digest text;
    admitted_content_digest text;
    submitted_run_count integer;
    expected_run_count bigint;
    queued_run_count bigint;
    run_index integer;
    audit_index integer;
    run_document jsonb;
    audit_document jsonb;
    expected_action text;
    expected_target_kind text;
    expected_target_id text;
    expected_request_digest text;
    first_request_id text;
    first_correlation_id text;
    first_traceparent text;
BEGIN
    effective_tenant_id := delivery.current_tenant_id();
    effective_now := transaction_timestamp();
    IF effective_tenant_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501',
            MESSAGE = 'valid transaction-local delivery tenant is required';
    END IF;
    IF jsonb_typeof(submitted_event) IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_runs) IS DISTINCT FROM 'array'
       OR jsonb_typeof(submitted_audit_events) IS DISTINCT FROM 'array'
       OR octet_length(submitted_event::text) > 131072
       OR octet_length(submitted_runs::text) > 8388608
       OR octet_length(submitted_audit_events::text) > 8388608 THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'run admission documents are invalid';
    END IF;

    submitted_run_count := jsonb_array_length(submitted_runs);
    IF submitted_run_count NOT BETWEEN 0 AND 32
       OR jsonb_array_length(submitted_audit_events) <> submitted_run_count + 1 THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'run admission fan-out is invalid';
    END IF;

    admitted_event_id := submitted_event->>'id';
    admitted_project_id := submitted_event#>>'{spec,projectId}';
    admitted_source_connection_id := submitted_event#>>'{spec,sourceConnectionId}';
    admitted_repository_binding_id := submitted_event#>>'{spec,repositoryBindingId}';
    admitted_repository_binding_digest := submitted_event#>>'{spec,repositoryBindingDigest}';
    admitted_external_repository_id := submitted_event#>>'{spec,externalRepositoryId}';
    admitted_delivery_id := submitted_event#>>'{spec,deliveryId}';
    admitted_canonical_payload_digest := submitted_event#>>'{spec,canonicalPayloadDigest}';
    admitted_content_digest := submitted_event->>'contentDigest';

    IF NOT (submitted_event ?& ARRAY[
            'apiVersion', 'kind', 'id', 'scope', 'spec',
            'contentDigest', 'receivedAt'
       ])
       OR (submitted_event - ARRAY[
            'apiVersion', 'kind', 'id', 'scope', 'spec',
            'contentDigest', 'receivedAt'
       ]) <> '{}'::jsonb
       OR jsonb_typeof(submitted_event->'scope') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_event->'spec') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_event#>'{spec,change}') IS DISTINCT FROM 'object'
       OR ((submitted_event->'scope') - ARRAY['tenantId']) <> '{}'::jsonb
       OR NOT ((submitted_event->'scope') ?& ARRAY['tenantId'])
       OR ((submitted_event->'spec') - ARRAY[
            'projectId', 'sourceConnectionId', 'repositoryBindingId',
            'repositoryBindingDigest', 'externalRepositoryId', 'deliveryId',
            'canonicalPayloadDigest', 'change'
       ]) <> '{}'::jsonb
       OR NOT ((submitted_event->'spec') ?& ARRAY[
            'projectId', 'sourceConnectionId', 'repositoryBindingId',
            'repositoryBindingDigest', 'externalRepositoryId', 'deliveryId',
            'canonicalPayloadDigest', 'change'
       ])
       OR ((submitted_event#>'{spec,change}') - ARRAY[
            'number', 'action', 'headCommit', 'trustedBaseCommit'
       ]) <> '{}'::jsonb
       OR NOT ((submitted_event#>'{spec,change}') ?& ARRAY[
            'number', 'action', 'headCommit', 'trustedBaseCommit'
       ])
       OR submitted_event->>'apiVersion' IS DISTINCT FROM 'devops.matrix.xiak.com/v1'
       OR submitted_event->>'kind' IS DISTINCT FROM 'SourceEvent'
       OR submitted_event#>>'{scope,tenantId}' IS DISTINCT FROM effective_tenant_id
       OR COALESCE(admitted_event_id, '') COLLATE "C" !~ '^source-event-[0-9a-f]{48}$'
       OR COALESCE(admitted_project_id, '') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(admitted_source_connection_id, '') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(admitted_repository_binding_id, '') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(admitted_external_repository_id, '') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR COALESCE(admitted_delivery_id, '') COLLATE "C" !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
       OR COALESCE(admitted_repository_binding_digest, '') COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
       OR COALESCE(admitted_canonical_payload_digest, '') COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
       OR COALESCE(admitted_content_digest, '') COLLATE "C" !~ '^sha256:[0-9a-f]{64}$'
       OR submitted_event#>>'{spec,change,action}' NOT IN ('OPENED', 'REOPENED', 'UPDATED')
       OR COALESCE(submitted_event#>>'{spec,change,number}', '') COLLATE "C" !~ '^[1-9][0-9]*$'
       OR (submitted_event#>>'{spec,change,number}')::numeric > 9007199254740991
       OR COALESCE(submitted_event#>>'{spec,change,headCommit}', '') COLLATE "C"
            !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
       OR COALESCE(submitted_event#>>'{spec,change,trustedBaseCommit}', '') COLLATE "C"
            !~ '^([0-9a-f]{40}|[0-9a-f]{64})$'
       OR COALESCE(submitted_event->>'receivedAt', '') COLLATE "C"
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
       OR NOT pg_input_is_valid(COALESCE(submitted_event->>'receivedAt', ''), 'timestamptz')
       OR (submitted_event->>'receivedAt')::timestamptz IS DISTINCT FROM effective_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'SourceEvent admission document is invalid';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM delivery.source_connections AS connection
          JOIN delivery.repository_bindings AS binding
            ON binding.tenant_id = connection.tenant_id
           AND binding.source_connection_id = connection.id
         WHERE connection.tenant_id = effective_tenant_id
           AND connection.id = admitted_source_connection_id
           AND connection.document#>>'{status,health}' = 'READY'
           AND binding.id = admitted_repository_binding_id
           AND binding.project_id = admitted_project_id
           AND binding.external_repository_id = admitted_external_repository_id
           AND binding.content_digest = admitted_repository_binding_digest
           AND binding.document#>>'{status,health}' = 'READY'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23503',
            MESSAGE = 'SourceEvent has no ready repository binding';
    END IF;

    PERFORM pg_advisory_xact_lock(
        hashtextextended('matrix-devops-queued-runs-v1:' || effective_tenant_id, 0)
    );
    SELECT count(*) INTO expected_run_count
      FROM delivery.pipelines AS pipeline
      JOIN delivery.pipeline_revisions AS revision
        ON revision.tenant_id = pipeline.tenant_id
       AND revision.id = pipeline.active_revision_id
       AND revision.pipeline_id = pipeline.id
       AND revision.revision = pipeline.active_revision
       AND revision.content_digest = pipeline.active_revision_digest
     WHERE pipeline.tenant_id = effective_tenant_id
       AND revision.project_id = admitted_project_id
       AND revision.repository_binding_id = admitted_repository_binding_id
       AND revision.repository_binding_digest = admitted_repository_binding_digest
       AND revision.document#>>'{spec,triggerPolicy}' = 'CHANGE';
    IF expected_run_count <> submitted_run_count THEN
        RAISE EXCEPTION USING ERRCODE = '23503',
            MESSAGE = 'PipelineRun fan-out does not match active revisions';
    END IF;
    SELECT count(*) INTO queued_run_count
      FROM delivery.pipeline_runs
     WHERE tenant_id = effective_tenant_id AND state = 'QUEUED';
    IF queued_run_count + submitted_run_count > 32 THEN
        RAISE EXCEPTION USING ERRCODE = 'MX429',
            MESSAGE = 'tenant queued-run capacity is exhausted';
    END IF;

    INSERT INTO delivery.audit_operations (
        tenant_id, id, operation_kind, target_kind, target_id, created_at
    ) VALUES (
        effective_tenant_id, admitted_event_id, 'SOURCE_EVENT_ADMISSION',
        'SOURCE_EVENT', admitted_event_id, effective_now
    );
    INSERT INTO delivery.source_events (
        tenant_id, id, project_id, source_connection_id,
        repository_binding_id, repository_binding_digest,
        external_repository_id, delivery_id, canonical_payload_digest,
        content_digest, received_at, document
    ) VALUES (
        effective_tenant_id, admitted_event_id, admitted_project_id,
        admitted_source_connection_id, admitted_repository_binding_id,
        admitted_repository_binding_digest, admitted_external_repository_id,
        admitted_delivery_id, admitted_canonical_payload_digest,
        admitted_content_digest, effective_now, submitted_event
    );

    IF submitted_run_count > 0 THEN
        FOR run_index IN 0..submitted_run_count - 1 LOOP
            run_document := submitted_runs->run_index;
            IF jsonb_typeof(run_document) IS DISTINCT FROM 'object'
               OR NOT (run_document ?& ARRAY[
                    'apiVersion', 'kind', 'id', 'scope', 'projectId',
                    'pipelineId', 'input', 'inputDigest', 'status',
                    'createdAt', 'updatedAt'
               ])
               OR (run_document - ARRAY[
                    'apiVersion', 'kind', 'id', 'scope', 'projectId',
                    'pipelineId', 'input', 'inputDigest', 'status',
                    'createdAt', 'updatedAt'
               ]) <> '{}'::jsonb
               OR jsonb_typeof(run_document->'scope') IS DISTINCT FROM 'object'
               OR jsonb_typeof(run_document->'input') IS DISTINCT FROM 'object'
               OR jsonb_typeof(run_document#>'{input,change}') IS DISTINCT FROM 'object'
               OR jsonb_typeof(run_document->'status') IS DISTINCT FROM 'object'
               OR ((run_document->'scope') - ARRAY['tenantId']) <> '{}'::jsonb
               OR ((run_document->'input') - ARRAY[
                    'sourceEventId', 'sourceEventDigest', 'pipelineRevisionId',
                    'pipelineRevisionDigest', 'repositoryBindingId',
                    'repositoryBindingDigest', 'change'
               ]) <> '{}'::jsonb
               OR ((run_document->'status') - ARRAY[
                    'state', 'stage', 'reason', 'resourceVersion', 'observedAt'
               ]) <> '{}'::jsonb
               OR run_document->>'apiVersion' IS DISTINCT FROM 'devops.matrix.xiak.com/v1'
               OR run_document->>'kind' IS DISTINCT FROM 'PipelineRun'
               OR run_document#>>'{scope,tenantId}' IS DISTINCT FROM effective_tenant_id
               OR run_document->>'projectId' IS DISTINCT FROM admitted_project_id
               OR COALESCE(run_document->>'id', '') COLLATE "C" !~ '^pipeline-run-[0-9a-f]{48}$'
               OR COALESCE(run_document->>'pipelineId', '') COLLATE "C"
                    !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
               OR run_document#>>'{input,sourceEventId}' IS DISTINCT FROM admitted_event_id
               OR run_document#>>'{input,sourceEventDigest}' IS DISTINCT FROM admitted_content_digest
               OR run_document#>>'{input,repositoryBindingId}' IS DISTINCT FROM admitted_repository_binding_id
               OR run_document#>>'{input,repositoryBindingDigest}' IS DISTINCT FROM admitted_repository_binding_digest
               OR run_document#>'{input,change}' IS DISTINCT FROM submitted_event#>'{spec,change}'
               OR COALESCE(run_document#>>'{input,pipelineRevisionId}', '') COLLATE "C"
                    !~ '^pipeline-revision-[0-9a-f]{48}$'
               OR COALESCE(run_document#>>'{input,pipelineRevisionDigest}', '') COLLATE "C"
                    !~ '^sha256:[0-9a-f]{64}$'
               OR COALESCE(run_document->>'inputDigest', '') COLLATE "C"
                    !~ '^sha256:[0-9a-f]{64}$'
               OR run_document#>>'{status,state}' IS DISTINCT FROM 'QUEUED'
               OR run_document#>>'{status,stage}' IS DISTINCT FROM 'RECEIVE'
               OR run_document#>>'{status,reason}' IS DISTINCT FROM 'EVENT_ADMITTED'
               OR run_document#>>'{status,resourceVersion}' IS DISTINCT FROM '1'
               OR (run_document#>>'{status,observedAt}')::timestamptz IS DISTINCT FROM effective_now
               OR (run_document->>'createdAt')::timestamptz IS DISTINCT FROM effective_now
               OR (run_document->>'updatedAt')::timestamptz IS DISTINCT FROM effective_now
               OR NOT EXISTS (
                    SELECT 1
                      FROM delivery.pipelines AS pipeline
                      JOIN delivery.pipeline_revisions AS revision
                        ON revision.tenant_id = pipeline.tenant_id
                       AND revision.id = pipeline.active_revision_id
                       AND revision.pipeline_id = pipeline.id
                       AND revision.revision = pipeline.active_revision
                       AND revision.content_digest = pipeline.active_revision_digest
                     WHERE pipeline.tenant_id = effective_tenant_id
                       AND pipeline.id = run_document->>'pipelineId'
                       AND pipeline.project_id = admitted_project_id
                       AND revision.id = run_document#>>'{input,pipelineRevisionId}'
                       AND revision.content_digest = run_document#>>'{input,pipelineRevisionDigest}'
                       AND revision.repository_binding_id = admitted_repository_binding_id
                       AND revision.repository_binding_digest = admitted_repository_binding_digest
                       AND revision.document#>>'{spec,triggerPolicy}' = 'CHANGE'
               ) THEN
                RAISE EXCEPTION USING ERRCODE = '22023',
                    MESSAGE = 'queued PipelineRun admission document is invalid';
            END IF;

            INSERT INTO delivery.audit_operations (
                tenant_id, id, operation_kind, target_kind, target_id, created_at
            ) VALUES (
                effective_tenant_id, run_document->>'id',
                'PIPELINE_RUN_CREATION', 'PIPELINE_RUN',
                run_document->>'id', effective_now
            );
            INSERT INTO delivery.pipeline_runs (
                tenant_id, id, input_digest, source_event_id, source_event_digest,
                pipeline_id, project_id, pipeline_revision_id,
                pipeline_revision_digest, repository_binding_id,
                repository_binding_digest, creation_operation_id,
                state, stage, reason,
                resource_version, completed_at, created_at, updated_at, document
            ) VALUES (
                effective_tenant_id, run_document->>'id', run_document->>'inputDigest', admitted_event_id,
                admitted_content_digest, run_document->>'pipelineId',
                admitted_project_id,
                run_document#>>'{input,pipelineRevisionId}',
                run_document#>>'{input,pipelineRevisionDigest}',
                admitted_repository_binding_id, admitted_repository_binding_digest,
                run_document->>'id', 'QUEUED', 'RECEIVE', 'EVENT_ADMITTED', 1, NULL,
                effective_now, effective_now, run_document
            );
        END LOOP;
    END IF;

    first_request_id := submitted_audit_events#>>'{0,requestId}';
    first_correlation_id := submitted_audit_events#>>'{0,correlationId}';
    first_traceparent := submitted_audit_events#>>'{0,traceparent}';
    FOR audit_index IN 0..submitted_run_count LOOP
        audit_document := submitted_audit_events->audit_index;
        IF audit_index = 0 THEN
            expected_action := 'devops.source-event.admitted';
            expected_target_kind := 'SOURCE_EVENT';
            expected_target_id := admitted_event_id;
            expected_request_digest := admitted_content_digest;
        ELSE
            run_document := submitted_runs->(audit_index - 1);
            expected_action := 'devops.pipeline-run.created';
            expected_target_kind := 'PIPELINE_RUN';
            expected_target_id := run_document->>'id';
            expected_request_digest := run_document->>'inputDigest';
        END IF;
        IF jsonb_typeof(audit_document) IS DISTINCT FROM 'object'
           OR NOT (audit_document ?& ARRAY[
                'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
                'action', 'target', 'result', 'requestDigest', 'requestId',
                'correlationId', 'operationId', 'occurredAt'
           ])
           OR (audit_document - ARRAY[
                'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
                'action', 'target', 'result', 'requestDigest', 'requestId',
                'correlationId', 'operationId', 'traceparent', 'occurredAt'
           ]) <> '{}'::jsonb
           OR jsonb_typeof(audit_document->'actor') IS DISTINCT FROM 'object'
           OR jsonb_typeof(audit_document->'target') IS DISTINCT FROM 'object'
           OR ((audit_document->'actor') - ARRAY['type', 'id']) <> '{}'::jsonb
           OR ((audit_document->'target') - ARRAY['kind', 'id']) <> '{}'::jsonb
           OR audit_document->>'apiVersion' IS DISTINCT FROM 'audit.matrix.xiak.com/v1'
           OR audit_document->>'kind' IS DISTINCT FROM 'AuditEvent'
           OR audit_document->>'tenantId' IS DISTINCT FROM effective_tenant_id
           OR audit_document#>>'{actor,type}' IS DISTINCT FROM 'SYSTEM'
           OR audit_document#>>'{actor,id}' IS DISTINCT FROM 'system-devops-source-ingress'
           OR audit_document ? 'iamDecisionId'
           OR audit_document->>'action' IS DISTINCT FROM expected_action
           OR audit_document#>>'{target,kind}' IS DISTINCT FROM expected_target_kind
           OR audit_document#>>'{target,id}' IS DISTINCT FROM expected_target_id
           OR audit_document->>'result' IS DISTINCT FROM 'ACCEPTED'
           OR audit_document->>'requestDigest' IS DISTINCT FROM expected_request_digest
           OR audit_document->>'operationId' IS DISTINCT FROM expected_target_id
           OR audit_document->>'requestId' IS DISTINCT FROM first_request_id
           OR audit_document->>'correlationId' IS DISTINCT FROM first_correlation_id
           OR COALESCE(audit_document->>'traceparent', '')
                IS DISTINCT FROM COALESCE(first_traceparent, '')
           OR COALESCE(audit_document->>'eventId', '') COLLATE "C"
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
           OR COALESCE(audit_document->>'requestId', '') COLLATE "C"
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
           OR COALESCE(audit_document->>'correlationId', '') COLLATE "C"
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
           OR (audit_document ? 'traceparent' AND (
                COALESCE(audit_document->>'traceparent', '') COLLATE "C"
                    !~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$'
                OR split_part(audit_document->>'traceparent', '-', 2) = repeat('0', 32)
                OR split_part(audit_document->>'traceparent', '-', 3) = repeat('0', 16)
           ))
           OR (audit_document->>'occurredAt')::timestamptz IS DISTINCT FROM effective_now THEN
            RAISE EXCEPTION USING ERRCODE = '22023',
                MESSAGE = 'run admission Audit fact is invalid';
        END IF;

        INSERT INTO delivery.audit_outbox (
            tenant_id, event_id, operation_id, status, available_at, attempts,
            fencing_token, created_at, updated_at, document
        ) VALUES (
            effective_tenant_id, audit_document->>'eventId', expected_target_id,
            'PENDING', effective_now, 0, 0, effective_now, effective_now,
            audit_document
        );
    END LOOP;
END
$function$;

REVOKE ALL ON FUNCTION delivery.commit_run_admission(jsonb, jsonb, jsonb)
    FROM PUBLIC, matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.commit_run_admission(jsonb, jsonb, jsonb)
    TO matrix_devops_api;

CREATE OR REPLACE FUNCTION delivery.claim_pipeline_run_task_internal(
    requested_worker_id text,
    requested_lease_seconds integer,
    requested_stages text[]
)
RETURNS TABLE (
    tenant_id text,
    run_id text,
    command_id text,
    input_digest text,
    stage text,
    attempt bigint,
    claim_mode text,
    fencing_token bigint,
    lease_expires_at timestamptz,
    reconciliation_attempts bigint,
    run_document jsonb
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    selected_tenant_id text;
    selected_run_id text;
    selected_input_digest text;
    selected_state text;
    selected_stage text;
    selected_resource_version bigint;
    selected_updated_at timestamptz(6);
    selected_run_document jsonb;
    selected_task_stage text;
    selected_task_attempt bigint;
    selected_command_id text;
    selected_fencing_token bigint;
    selected_reconciliation_attempts bigint;
    effective_stage text;
    effective_attempt bigint;
    effective_command_id text;
    effective_fencing_token bigint;
    effective_lease_expires_at timestamptz(6);
    effective_now timestamptz(6);
    effective_time_text text;
    effective_run_document jsonb;
    effective_claim_mode text;
BEGIN
    IF requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_lease_seconds IS NULL
       OR requested_lease_seconds NOT BETWEEN 1 AND 300
       OR requested_stages IS NULL
       OR requested_stages NOT IN (
            ARRAY['FETCH']::text[], ARRAY['VERIFY']::text[],
            ARRAY['REPORT']::text[]
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'PipelineRun task claim parameters are invalid';
    END IF;

    SELECT run.tenant_id,
           run.id,
           run.input_digest,
           run.state,
           run.stage,
           run.resource_version,
           run.updated_at,
           run.document,
           task.stage,
           task.attempt,
           task.command_id,
           task.fencing_token,
           task.reconciliation_attempts
      INTO selected_tenant_id,
           selected_run_id,
           selected_input_digest,
           selected_state,
           selected_stage,
           selected_resource_version,
           selected_updated_at,
           selected_run_document,
           selected_task_stage,
           selected_task_attempt,
           selected_command_id,
           selected_fencing_token,
           selected_reconciliation_attempts
      FROM delivery.pipeline_runs AS run
      LEFT JOIN LATERAL (
            SELECT pending.stage,
                   pending.attempt,
                   pending.command_id,
                   pending.available_at,
                   pending.lease_owner,
                   pending.lease_expires_at,
                   pending.fencing_token,
                   pending.reconciliation_attempts
              FROM delivery.pipeline_run_tasks AS pending
             WHERE pending.tenant_id = run.tenant_id
               AND pending.run_id = run.id
               AND pending.status = 'INTENT'
             LIMIT 1
      ) AS task ON true
     WHERE run.state NOT IN (
            'SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION'
       )
       AND run.resource_version < 9007199254740991
       AND (
            (task.command_id IS NOT NULL
                AND task.stage = ANY(requested_stages)
                AND task.available_at <= transaction_timestamp()
                AND task.fencing_token < 9007199254740991
                AND (task.lease_owner IS NULL
                    OR task.lease_expires_at <= transaction_timestamp()))
            OR (task.command_id IS NULL
                AND CASE run.state
                    WHEN 'QUEUED' THEN 'FETCH'
                    WHEN 'FETCHING' THEN 'FETCH'
                    WHEN 'VERIFYING' THEN 'VERIFY'
                    WHEN 'REPORTING' THEN 'REPORT'
                    ELSE NULL
                END = ANY(requested_stages))
       )
       AND (
            run.state <> 'QUEUED'
            OR (
                SELECT count(*)
                  FROM delivery.pipeline_runs AS active
                 WHERE active.tenant_id = run.tenant_id
                   AND active.state IN (
                        'FETCHING', 'VERIFYING', 'REPORTING', 'RECONCILING'
                   )
            ) < 2
       )
     ORDER BY (
            SELECT max(history.last_claimed_at)
              FROM delivery.pipeline_run_tasks AS history
             WHERE history.tenant_id = run.tenant_id
       ) ASC NULLS FIRST,
       CASE
            WHEN task.command_id IS NOT NULL THEN 0
            WHEN run.state <> 'QUEUED' THEN 1
            ELSE 2
       END,
       COALESCE(task.available_at, run.updated_at),
       run.created_at,
       run.tenant_id COLLATE "C",
       run.id COLLATE "C"
     LIMIT 1
     FOR UPDATE OF run SKIP LOCKED;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    IF selected_state = 'QUEUED' THEN
        PERFORM pg_advisory_xact_lock(
            hashtextextended(
                'matrix-devops-queued-runs-v1:' || selected_tenant_id,
                0
            )
        );
        IF (
            SELECT count(*)
              FROM delivery.pipeline_runs AS active
             WHERE active.tenant_id = selected_tenant_id
               AND active.state IN (
                    'FETCHING', 'VERIFYING', 'REPORTING', 'RECONCILING'
               )
        ) >= 2 THEN
            RETURN;
        END IF;
    END IF;

    effective_now := greatest(
        transaction_timestamp(),
        selected_updated_at + interval '1 microsecond'
    );
    effective_time_text := to_char(
        effective_now AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    );
    effective_lease_expires_at := effective_now
        + make_interval(secs => requested_lease_seconds);
    effective_run_document := selected_run_document;

    IF selected_command_id IS NULL THEN
        effective_stage := CASE selected_state
            WHEN 'QUEUED' THEN 'FETCH'
            WHEN 'FETCHING' THEN 'FETCH'
            WHEN 'VERIFYING' THEN 'VERIFY'
            WHEN 'REPORTING' THEN 'REPORT'
            ELSE NULL
        END;
        IF effective_stage IS NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'PipelineRun has no claimable task stage';
        END IF;

        SELECT COALESCE(max(history.attempt), 0) + 1
          INTO effective_attempt
          FROM delivery.pipeline_run_tasks AS history
         WHERE history.tenant_id = selected_tenant_id
           AND history.run_id = selected_run_id
           AND history.stage = effective_stage;
        IF effective_attempt NOT BETWEEN 1 AND 100 THEN
            RAISE EXCEPTION USING
                ERRCODE = '55000',
                MESSAGE = 'PipelineRun task attempts are exhausted';
        END IF;
        effective_command_id := selected_run_id || ':' || lower(effective_stage)
            || ':' || effective_attempt::text;
        effective_fencing_token := 1;
        selected_reconciliation_attempts := 0;
        effective_claim_mode := 'EXECUTE';

        IF selected_state = 'QUEUED' THEN
            effective_run_document := jsonb_set(
                jsonb_set(
                    selected_run_document,
                    '{status}',
                    jsonb_build_object(
                        'state', 'FETCHING',
                        'stage', 'FETCH',
                        'resourceVersion', selected_resource_version + 1,
                        'observedAt', effective_time_text
                    ),
                    false
                ),
                '{updatedAt}',
                to_jsonb(effective_time_text),
                false
            );
            UPDATE delivery.pipeline_runs AS claimed_run
               SET state = 'FETCHING',
                   stage = 'FETCH',
                   reason = NULL,
                   resource_version = selected_resource_version + 1,
                   updated_at = effective_now,
                   document = effective_run_document
             WHERE claimed_run.tenant_id = selected_tenant_id
               AND claimed_run.id = selected_run_id;
        END IF;

        INSERT INTO delivery.pipeline_run_tasks (
            tenant_id, run_id, input_digest, stage, attempt, command_id,
            status, available_at, lease_owner, lease_expires_at,
            fencing_token, reconciliation_attempts, last_claimed_at,
            created_at, updated_at
        ) VALUES (
            selected_tenant_id, selected_run_id, selected_input_digest,
            effective_stage, effective_attempt, effective_command_id,
            'INTENT', effective_now, requested_worker_id,
            effective_lease_expires_at, effective_fencing_token,
            selected_reconciliation_attempts, effective_now,
            effective_now, effective_now
        );
    ELSE
        effective_stage := selected_task_stage;
        effective_attempt := selected_task_attempt;
        effective_command_id := selected_command_id;
        effective_fencing_token := selected_fencing_token + 1;
        effective_claim_mode := 'OBSERVE';
        UPDATE delivery.pipeline_run_tasks AS claimed_task
           SET lease_owner = requested_worker_id,
               lease_expires_at = effective_lease_expires_at,
               fencing_token = effective_fencing_token,
               last_claimed_at = effective_now,
               updated_at = effective_now
         WHERE claimed_task.tenant_id = selected_tenant_id
           AND claimed_task.run_id = selected_run_id
           AND claimed_task.stage = selected_task_stage
           AND claimed_task.attempt = selected_task_attempt
           AND claimed_task.status = 'INTENT';
    END IF;

    RETURN QUERY SELECT
        selected_tenant_id,
        selected_run_id,
        effective_command_id,
        selected_input_digest,
        effective_stage,
        effective_attempt,
        effective_claim_mode,
        effective_fencing_token,
        effective_lease_expires_at,
        selected_reconciliation_attempts,
        effective_run_document;
END
$function$;

REVOKE ALL ON FUNCTION delivery.claim_pipeline_run_task_internal(
    text, integer, text[]
) FROM PUBLIC, matrix_devops_api, matrix_devops_source_fetcher,
       matrix_devops_source_observer, matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.claim_pipeline_run_task(
    requested_worker_id text,
    requested_lease_seconds integer
)
RETURNS TABLE (
    tenant_id text,
    run_id text,
    command_id text,
    input_digest text,
    stage text,
    attempt bigint,
    claim_mode text,
    fencing_token bigint,
    lease_expires_at timestamptz,
    reconciliation_attempts bigint,
    run_document jsonb
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT claimed.tenant_id,
           claimed.run_id,
           claimed.command_id,
           claimed.input_digest,
           claimed.stage,
           claimed.attempt,
           claimed.claim_mode,
           claimed.fencing_token,
           claimed.lease_expires_at,
           claimed.reconciliation_attempts,
           claimed.run_document
      FROM delivery.claim_pipeline_run_task_internal(
        requested_worker_id,
        requested_lease_seconds,
        ARRAY['REPORT']::text[]
      ) AS claimed
$function$;

REVOKE ALL ON FUNCTION delivery.claim_pipeline_run_task(text, integer)
    FROM PUBLIC, matrix_devops_api, matrix_devops_source_fetcher,
         matrix_devops_source_observer;
GRANT EXECUTE ON FUNCTION delivery.claim_pipeline_run_task(text, integer)
    TO matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.claim_source_fetch_task(
    requested_worker_id text,
    requested_lease_seconds integer
)
RETURNS TABLE (
    tenant_id text,
    run_id text,
    command_id text,
    input_digest text,
    stage text,
    attempt bigint,
    claim_mode text,
    fencing_token bigint,
    lease_expires_at timestamptz,
    reconciliation_attempts bigint,
    run_document jsonb,
    connection_document jsonb,
    binding_revision_document jsonb,
    pipeline_revision_document jsonb,
    source_event_document jsonb
)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    WITH claimed AS MATERIALIZED (
        SELECT *
          FROM delivery.claim_pipeline_run_task_internal(
            requested_worker_id,
            requested_lease_seconds,
            ARRAY['FETCH']::text[]
          )
    )
    SELECT claimed.tenant_id,
           claimed.run_id,
           claimed.command_id,
           claimed.input_digest,
           claimed.stage,
           claimed.attempt,
           claimed.claim_mode,
           claimed.fencing_token,
           claimed.lease_expires_at,
           claimed.reconciliation_attempts,
           claimed.run_document,
           source.document,
           binding_revision.document,
           pipeline_revision.document,
           source_event.document
      FROM claimed
      JOIN delivery.pipeline_runs AS run
        ON run.tenant_id = claimed.tenant_id
       AND run.id = claimed.run_id
       AND run.input_digest = claimed.input_digest
      JOIN delivery.repository_binding_revisions AS binding_revision
        ON binding_revision.tenant_id = run.tenant_id
       AND binding_revision.binding_id = run.repository_binding_id
       AND binding_revision.content_digest = run.repository_binding_digest
      JOIN delivery.source_connections AS source
        ON source.tenant_id = binding_revision.tenant_id
       AND source.id = binding_revision.source_connection_id
      JOIN delivery.pipeline_revisions AS pipeline_revision
        ON pipeline_revision.tenant_id = run.tenant_id
       AND pipeline_revision.id = run.pipeline_revision_id
       AND pipeline_revision.content_digest = run.pipeline_revision_digest
      JOIN delivery.source_events AS source_event
        ON source_event.tenant_id = run.tenant_id
       AND source_event.id = run.source_event_id
       AND source_event.content_digest = run.source_event_digest
$function$;

REVOKE ALL ON FUNCTION delivery.claim_source_fetch_task(text, integer)
    FROM PUBLIC, matrix_devops_api, matrix_devops_source_observer,
         matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.claim_source_fetch_task(text, integer)
    TO matrix_devops_source_fetcher;

CREATE OR REPLACE FUNCTION delivery.claim_build_task(
    requested_worker_id text,
    requested_lease_seconds integer
)
RETURNS TABLE (
    tenant_id text,
    run_id text,
    command_id text,
    input_digest text,
    stage text,
    attempt bigint,
    claim_mode text,
    fencing_token bigint,
    lease_expires_at timestamptz,
    reconciliation_attempts bigint,
    run_document jsonb,
    pipeline_revision_document jsonb,
    source_archive_document jsonb,
    started_at timestamptz,
    deadline_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    claimed record;
    claimed_task_started_at timestamptz(6);
    claimed_revision_document jsonb;
    claimed_archive_document jsonb;
BEGIN
    SELECT internal_claim.*
      INTO claimed
      FROM delivery.claim_pipeline_run_task_internal(
            requested_worker_id,
            requested_lease_seconds,
            ARRAY['VERIFY']::text[]
      ) AS internal_claim;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT task.created_at,
           revision.document,
           jsonb_build_object(
                'tenantId', archive.tenant_id,
                'runId', archive.run_id,
                'commandId', archive.command_id,
                'inputDigest', archive.input_digest,
                'headCommit', archive.head_commit,
                'trustedBaseCommit', archive.trusted_base_commit,
                'mediaType', archive.media_type,
                'archiveDigest', archive.archive_digest,
                'archiveBytes', archive.archive_bytes,
                'expandedBytes', archive.expanded_bytes,
                'pathCount', archive.path_count
           )
      INTO claimed_task_started_at,
           claimed_revision_document,
           claimed_archive_document
      FROM delivery.pipeline_run_tasks AS task
      JOIN delivery.pipeline_runs AS run
        ON run.tenant_id = task.tenant_id
       AND run.id = task.run_id
       AND run.input_digest = task.input_digest
      JOIN delivery.pipeline_revisions AS revision
        ON revision.tenant_id = run.tenant_id
       AND revision.id = run.pipeline_revision_id
       AND revision.content_digest = run.pipeline_revision_digest
      JOIN delivery.source_archives AS archive
        ON archive.tenant_id = run.tenant_id
       AND archive.run_id = run.id
       AND archive.input_digest = run.input_digest
     WHERE task.tenant_id = claimed.tenant_id
       AND task.run_id = claimed.run_id
       AND task.command_id = claimed.command_id
       AND task.stage = 'VERIFY'
       AND task.attempt = claimed.attempt
       AND task.status = 'INTENT'
       AND task.lease_owner = requested_worker_id
       AND task.fencing_token = claimed.fencing_token;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'Claimed build task inputs are unavailable';
    END IF;

    RETURN QUERY SELECT
        claimed.tenant_id::text,
        claimed.run_id::text,
        claimed.command_id::text,
        claimed.input_digest::text,
        claimed.stage::text,
        claimed.attempt::bigint,
        claimed.claim_mode::text,
        claimed.fencing_token::bigint,
        claimed.lease_expires_at::timestamptz,
        claimed.reconciliation_attempts::bigint,
        claimed.run_document::jsonb,
        claimed_revision_document,
        claimed_archive_document,
        claimed_task_started_at,
        claimed_task_started_at + interval '20 minutes';
END
$function$;

REVOKE ALL ON FUNCTION delivery.claim_build_task(text, integer)
    FROM PUBLIC, matrix_devops_api, matrix_devops_source_fetcher,
         matrix_devops_source_observer;
GRANT EXECUTE ON FUNCTION delivery.claim_build_task(text, integer)
    TO matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.renew_pipeline_run_task_internal(
    requested_tenant_id text,
    requested_run_id text,
    requested_command_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_lease_seconds integer,
    requested_stage text
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    renewed_expires_at timestamptz(6);
BEGIN
    IF requested_tenant_id IS NULL
       OR requested_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_run_id IS NULL
       OR requested_run_id COLLATE "C" !~ '^pipeline-run-[0-9a-f]{48}$'
       OR requested_command_id IS NULL
       OR requested_command_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR expected_fencing_token IS NULL
       OR expected_fencing_token NOT BETWEEN 1 AND 9007199254740991
       OR requested_lease_seconds IS NULL
       OR requested_lease_seconds NOT BETWEEN 1 AND 300
       OR requested_stage NOT IN ('FETCH', 'VERIFY', 'REPORT') THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'PipelineRun task renewal parameters are invalid';
    END IF;

    UPDATE delivery.pipeline_run_tasks AS task
       SET lease_expires_at = greatest(
                task.lease_expires_at,
                transaction_timestamp()
                    + make_interval(secs => requested_lease_seconds)
           ),
           updated_at = transaction_timestamp()
     WHERE task.tenant_id = requested_tenant_id
       AND task.run_id = requested_run_id
       AND task.command_id = requested_command_id
       AND task.status = 'INTENT'
       AND task.lease_owner = requested_worker_id
       AND task.fencing_token = expected_fencing_token
       AND task.lease_expires_at > clock_timestamp()
       AND task.stage = requested_stage
    RETURNING task.lease_expires_at INTO renewed_expires_at;
    IF renewed_expires_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'PipelineRun task lease or fencing token is stale';
    END IF;
    RETURN renewed_expires_at;
END
$function$;

REVOKE ALL ON FUNCTION delivery.renew_pipeline_run_task_internal(
    text, text, text, text, bigint, integer, text
) FROM PUBLIC, matrix_devops_api, matrix_devops_source_fetcher,
       matrix_devops_source_observer, matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.renew_pipeline_run_task(
    requested_tenant_id text,
    requested_run_id text,
    requested_command_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_lease_seconds integer
)
RETURNS timestamptz
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT delivery.renew_pipeline_run_task_internal(
        requested_tenant_id,
        requested_run_id,
        requested_command_id,
        requested_worker_id,
        expected_fencing_token,
        requested_lease_seconds,
        'REPORT'
    )
$function$;

REVOKE ALL ON FUNCTION delivery.renew_pipeline_run_task(
    text, text, text, text, bigint, integer
) FROM PUBLIC, matrix_devops_api, matrix_devops_source_fetcher,
       matrix_devops_source_observer;
GRANT EXECUTE ON FUNCTION delivery.renew_pipeline_run_task(
    text, text, text, text, bigint, integer
) TO matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.renew_source_fetch_task(
    requested_tenant_id text,
    requested_run_id text,
    requested_command_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_lease_seconds integer
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM delivery.pipeline_run_tasks AS task
         WHERE task.tenant_id = requested_tenant_id
           AND task.run_id = requested_run_id
           AND task.command_id = requested_command_id
           AND task.stage = 'FETCH'
           AND task.status = 'INTENT'
           AND task.lease_owner = requested_worker_id
           AND task.fencing_token = expected_fencing_token
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'source fetch task lease or fencing token is stale';
    END IF;
    RETURN delivery.renew_pipeline_run_task_internal(
        requested_tenant_id,
        requested_run_id,
        requested_command_id,
        requested_worker_id,
        expected_fencing_token,
        requested_lease_seconds,
        'FETCH'
    );
END
$function$;

REVOKE ALL ON FUNCTION delivery.renew_source_fetch_task(
    text, text, text, text, bigint, integer
) FROM PUBLIC, matrix_devops_api, matrix_devops_source_observer,
       matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.renew_source_fetch_task(
    text, text, text, text, bigint, integer
) TO matrix_devops_source_fetcher;

CREATE OR REPLACE FUNCTION delivery.renew_build_task(
    requested_tenant_id text,
    requested_run_id text,
    requested_command_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_lease_seconds integer
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
BEGIN
    IF NOT EXISTS (
        SELECT 1
          FROM delivery.pipeline_run_tasks AS task
         WHERE task.tenant_id = requested_tenant_id
           AND task.run_id = requested_run_id
           AND task.command_id = requested_command_id
           AND task.stage = 'VERIFY'
           AND task.status = 'INTENT'
           AND task.lease_owner = requested_worker_id
           AND task.fencing_token = expected_fencing_token
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'build task lease or fencing token is stale';
    END IF;
    RETURN delivery.renew_pipeline_run_task_internal(
        requested_tenant_id,
        requested_run_id,
        requested_command_id,
        requested_worker_id,
        expected_fencing_token,
        requested_lease_seconds,
        'VERIFY'
    );
END
$function$;

REVOKE ALL ON FUNCTION delivery.renew_build_task(
    text, text, text, text, bigint, integer
) FROM PUBLIC, matrix_devops_api, matrix_devops_source_fetcher,
       matrix_devops_source_observer;
GRANT EXECUTE ON FUNCTION delivery.renew_build_task(
    text, text, text, text, bigint, integer
) TO matrix_devops_worker;

DROP FUNCTION IF EXISTS delivery.advance_pipeline_run_task(
    text, text, text, text, bigint, text, text
);
CREATE OR REPLACE FUNCTION delivery.advance_pipeline_run_task(
    requested_tenant_id text,
    requested_run_id text,
    requested_command_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_state text,
    requested_reason text,
    submitted_run_document jsonb,
    submitted_audit_event jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    current_state text;
    current_stage text;
    current_resource_version bigint;
    current_cancellation_requested_at timestamptz(6);
    current_updated_at timestamptz(6);
    current_run_document jsonb;
    current_task_stage text;
    current_task_status text;
    current_lease_owner text;
    current_lease_expires_at timestamptz(6);
    current_fencing_token bigint;
    current_reconciliation_attempts bigint;
    transition_allowed boolean;
    reason_allowed boolean;
    terminal boolean;
    next_stage text;
    effective_now timestamptz(6);
    next_document jsonb;
    terminal_operation_id text;
    expected_audit_event_id text;
BEGIN
    IF requested_tenant_id IS NULL
       OR requested_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_run_id IS NULL
       OR requested_run_id COLLATE "C" !~ '^pipeline-run-[0-9a-f]{48}$'
       OR requested_command_id IS NULL
       OR requested_command_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR expected_fencing_token IS NULL
       OR expected_fencing_token NOT BETWEEN 1 AND 9007199254740991
       OR jsonb_typeof(submitted_run_document) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'PipelineRun task transition identity is invalid';
    END IF;

    SELECT run.state,
           run.stage,
           run.resource_version,
           run.cancellation_requested_at,
           run.updated_at,
           run.document,
           task.stage,
           task.status,
           task.lease_owner,
           task.lease_expires_at,
           task.fencing_token,
           task.reconciliation_attempts
      INTO current_state,
           current_stage,
           current_resource_version,
           current_cancellation_requested_at,
           current_updated_at,
           current_run_document,
           current_task_stage,
           current_task_status,
           current_lease_owner,
           current_lease_expires_at,
           current_fencing_token,
           current_reconciliation_attempts
      FROM delivery.pipeline_runs AS run
      JOIN delivery.pipeline_run_tasks AS task
        ON task.tenant_id = run.tenant_id
       AND task.run_id = run.id
       AND task.command_id = requested_command_id
     WHERE run.tenant_id = requested_tenant_id
       AND run.id = requested_run_id
     FOR UPDATE OF run, task;
    IF NOT FOUND
       OR current_task_status <> 'INTENT'
       OR current_lease_owner IS DISTINCT FROM requested_worker_id
       OR current_fencing_token <> expected_fencing_token
       OR current_lease_expires_at IS NULL
       OR current_lease_expires_at <= clock_timestamp()
       OR current_task_stage <> current_stage THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'PipelineRun task lease or fencing token is stale';
    END IF;

    IF current_task_stage = 'FETCH'
       AND NOT pg_has_role(
            session_user,
            'matrix_devops_source_fetcher',
            'MEMBER'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'FETCH completion requires the source fetcher boundary';
    END IF;

    transition_allowed :=
        (current_state = 'FETCHING'
            AND requested_state IN ('VERIFYING', 'FAILED', 'CANCELLED'))
        OR (current_state = 'VERIFYING'
            AND requested_state IN ('REPORTING', 'FAILED', 'CANCELLED'))
        OR (current_state = 'REPORTING'
            AND requested_state IN ('SUCCEEDED', 'FAILED', 'CANCELLED'))
        OR (current_state = 'RECONCILING'
            AND requested_state IN (
                'SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION'
            ));
    reason_allowed :=
        (requested_state IN ('VERIFYING', 'REPORTING') AND requested_reason IS NULL)
        OR (requested_state = 'SUCCEEDED' AND requested_reason = 'COMPLETED')
        OR (requested_state = 'CANCELLED' AND requested_reason = 'CANCELLED')
        OR (requested_state = 'MANUAL_INTERVENTION'
            AND requested_reason = 'RECONCILIATION_EXHAUSTED')
        OR (requested_state = 'FAILED' AND (
            (current_state = 'FETCHING' AND requested_reason IN (
                'SOURCE_UNAVAILABLE', 'COMMIT_MISMATCH', 'DEADLINE_EXCEEDED'
            ))
            OR (current_state = 'VERIFYING' AND requested_reason IN (
                'EXECUTOR_UNAVAILABLE', 'VERIFICATION_FAILED', 'DEADLINE_EXCEEDED'
            ))
            OR (current_state IN ('REPORTING', 'RECONCILING')
                AND requested_reason IN (
                    'VERIFICATION_FAILED', 'REPORT_UNAVAILABLE',
                    'REPORT_CONFLICT', 'DEADLINE_EXCEEDED'
                ))
        ));
    IF NOT transition_allowed OR NOT reason_allowed
       OR (current_cancellation_requested_at IS NOT NULL
            AND requested_state NOT IN (
                'SUCCEEDED', 'FAILED', 'CANCELLED',
                'RECONCILING', 'MANUAL_INTERVENTION'
            ))
       OR (requested_state = 'CANCELLED'
            AND current_cancellation_requested_at IS NULL)
       OR (requested_state = 'MANUAL_INTERVENTION'
            AND current_reconciliation_attempts < 10)
       OR (current_state = 'FETCHING' AND requested_state = 'VERIFYING'
            AND NOT EXISTS (
                SELECT 1
                  FROM delivery.source_archives AS archive
                 WHERE archive.tenant_id = requested_tenant_id
                   AND archive.run_id = requested_run_id
                   AND archive.command_id = requested_command_id
                   AND archive.input_digest = current_run_document->>'inputDigest'
                   AND archive.head_commit =
                        current_run_document#>>'{input,change,headCommit}'
                   AND archive.trusted_base_commit =
                        current_run_document#>>'{input,change,trustedBaseCommit}'
            ))
       OR (current_state = 'VERIFYING' AND requested_state = 'REPORTING'
            AND NOT EXISTS (
                SELECT 1
                  FROM delivery.build_receipts AS receipt
                 WHERE receipt.tenant_id = requested_tenant_id
                   AND receipt.run_id = requested_run_id
                   AND receipt.command_id = requested_command_id
                   AND receipt.input_digest = current_run_document->>'inputDigest'
                   AND receipt.source_archive_digest = (
                        SELECT archive.archive_digest
                          FROM delivery.source_archives AS archive
                         WHERE archive.tenant_id = requested_tenant_id
                           AND archive.run_id = requested_run_id
                   )
                   AND receipt.pipeline_revision_id =
                        current_run_document#>>'{input,pipelineRevisionId}'
                   AND receipt.pipeline_revision_digest =
                        current_run_document#>>'{input,pipelineRevisionDigest}'
                   AND receipt.conclusion IN ('PASSED', 'FAILED')
            ))
       OR current_resource_version >= 9007199254740991 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'PipelineRun task transition is invalid';
    END IF;

    terminal := requested_state IN (
        'SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION'
    );
    next_stage := CASE requested_state
        WHEN 'VERIFYING' THEN 'VERIFY'
        WHEN 'REPORTING' THEN 'REPORT'
        WHEN 'SUCCEEDED' THEN 'REPORT'
        WHEN 'MANUAL_INTERVENTION' THEN 'REPORT'
        ELSE current_stage
    END;
    effective_now := greatest(
        transaction_timestamp(),
        current_updated_at + interval '1 microsecond'
    );
    IF jsonb_typeof(submitted_run_document->'status') IS DISTINCT FROM 'object'
       OR NOT ((submitted_run_document->'status') ?& ARRAY[
            'state', 'stage', 'resourceVersion', 'observedAt'
       ])
        OR ((submitted_run_document->'status') - ARRAY[
            'state', 'stage', 'reason', 'resourceVersion',
            'observedAt', 'cancellationRequestedAt', 'completedAt'
        ]) <> '{}'::jsonb
       OR (submitted_run_document - ARRAY['status', 'updatedAt']) IS DISTINCT FROM
            (current_run_document - ARRAY['status', 'updatedAt'])
       OR submitted_run_document#>>'{status,state}' IS DISTINCT FROM requested_state
       OR submitted_run_document#>>'{status,stage}' IS DISTINCT FROM next_stage
        OR submitted_run_document#>>'{status,reason}' IS DISTINCT FROM requested_reason
        OR submitted_run_document#>'{status,cancellationRequestedAt}'
            IS DISTINCT FROM current_run_document#>'{status,cancellationRequestedAt}'
       OR submitted_run_document#>>'{status,resourceVersion}' IS DISTINCT FROM
            (current_resource_version + 1)::text
       OR COALESCE(submitted_run_document#>>'{status,observedAt}', '') COLLATE "C"
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
       OR NOT pg_input_is_valid(
            COALESCE(submitted_run_document#>>'{status,observedAt}', ''),
            'timestamptz'
       )
       OR (submitted_run_document#>>'{status,observedAt}')::timestamptz IS DISTINCT FROM effective_now
       OR COALESCE(submitted_run_document->>'updatedAt', '') COLLATE "C"
            !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
       OR NOT pg_input_is_valid(
            COALESCE(submitted_run_document->>'updatedAt', ''), 'timestamptz'
       )
       OR (submitted_run_document->>'updatedAt')::timestamptz IS DISTINCT FROM effective_now
       OR (terminal AND (
            NOT (submitted_run_document->'status' ? 'completedAt')
            OR COALESCE(submitted_run_document#>>'{status,completedAt}', '') COLLATE "C"
                !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]{1,6})?Z$'
            OR NOT pg_input_is_valid(
                COALESCE(submitted_run_document#>>'{status,completedAt}', ''),
                'timestamptz'
            )
            OR (submitted_run_document#>>'{status,completedAt}')::timestamptz IS DISTINCT FROM effective_now
       ))
       OR (NOT terminal AND submitted_run_document->'status' ? 'completedAt') THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'submitted PipelineRun transition document differs from database state';
    END IF;
    next_document := submitted_run_document;

    IF terminal THEN
        terminal_operation_id := requested_run_id || ':terminal:' ||
            (current_resource_version + 1)::text;
        expected_audit_event_id := 'audit-' || encode(
            sha256(
                convert_to('matrix-devops-audit-event-v1', 'UTF8')
                || decode('00', 'hex')
                || convert_to(terminal_operation_id, 'UTF8')
            ),
            'hex'
        );
        IF jsonb_typeof(submitted_audit_event) IS DISTINCT FROM 'object'
           OR NOT (submitted_audit_event ?& ARRAY[
                'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
                'action', 'target', 'result', 'outcome', 'reason',
                'requestDigest', 'requestId', 'correlationId',
                'operationId', 'occurredAt'
           ])
           OR (submitted_audit_event - ARRAY[
                'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
                'action', 'target', 'result', 'outcome', 'reason',
                'requestDigest', 'requestId', 'correlationId',
                'operationId', 'occurredAt'
           ]) <> '{}'::jsonb
           OR jsonb_typeof(submitted_audit_event->'actor') IS DISTINCT FROM 'object'
           OR jsonb_typeof(submitted_audit_event->'target') IS DISTINCT FROM 'object'
           OR ((submitted_audit_event->'actor') - ARRAY['type', 'id']) <> '{}'::jsonb
           OR ((submitted_audit_event->'target') - ARRAY['kind', 'id']) <> '{}'::jsonb
           OR submitted_audit_event->>'apiVersion' IS DISTINCT FROM 'audit.matrix.xiak.com/v1'
           OR submitted_audit_event->>'kind' IS DISTINCT FROM 'AuditEvent'
           OR submitted_audit_event->>'eventId' IS DISTINCT FROM expected_audit_event_id
           OR submitted_audit_event->>'tenantId' IS DISTINCT FROM requested_tenant_id
           OR submitted_audit_event#>>'{actor,type}' IS DISTINCT FROM 'SYSTEM'
           OR submitted_audit_event#>>'{actor,id}' IS DISTINCT FROM 'system-devops-run-worker'
           OR submitted_audit_event ? 'iamDecisionId'
           OR submitted_audit_event ? 'traceparent'
           OR submitted_audit_event->>'action' IS DISTINCT FROM 'devops.pipeline-run.completed'
           OR submitted_audit_event#>>'{target,kind}' IS DISTINCT FROM 'PIPELINE_RUN'
           OR submitted_audit_event#>>'{target,id}' IS DISTINCT FROM requested_run_id
           OR submitted_audit_event->>'result' IS DISTINCT FROM 'SUCCEEDED'
           OR submitted_audit_event->>'outcome' IS DISTINCT FROM requested_state
           OR submitted_audit_event->>'reason' IS DISTINCT FROM requested_reason
           OR submitted_audit_event->>'requestDigest' IS DISTINCT FROM
                current_run_document->>'inputDigest'
           OR submitted_audit_event->>'requestId' IS DISTINCT FROM requested_command_id
           OR submitted_audit_event->>'correlationId' IS DISTINCT FROM requested_run_id
           OR submitted_audit_event->>'operationId' IS DISTINCT FROM terminal_operation_id
           OR (submitted_audit_event->>'occurredAt')::timestamptz IS DISTINCT FROM effective_now THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'PipelineRun terminal Audit fact is invalid';
        END IF;
    ELSIF submitted_audit_event IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'nonterminal PipelineRun transition cannot emit a terminal Audit fact';
    END IF;

    UPDATE delivery.pipeline_runs AS transitioned
       SET state = requested_state,
           stage = next_stage,
           reason = requested_reason,
           resource_version = current_resource_version + 1,
           completed_at = CASE WHEN terminal THEN effective_now ELSE NULL END,
           updated_at = effective_now,
           document = next_document
     WHERE transitioned.tenant_id = requested_tenant_id
       AND transitioned.id = requested_run_id;
    UPDATE delivery.pipeline_run_tasks AS completed
       SET status = 'COMPLETED',
           lease_owner = NULL,
           lease_expires_at = NULL,
           completed_at = effective_now,
           updated_at = effective_now
     WHERE completed.tenant_id = requested_tenant_id
       AND completed.run_id = requested_run_id
       AND completed.command_id = requested_command_id;
    IF terminal THEN
        INSERT INTO delivery.audit_operations (
            tenant_id, id, operation_kind, target_kind, target_id, created_at
        ) VALUES (
            requested_tenant_id, terminal_operation_id,
            'PIPELINE_RUN_TERMINAL', 'PIPELINE_RUN', requested_run_id,
            effective_now
        );
        INSERT INTO delivery.audit_outbox (
            tenant_id, event_id, operation_id, status, available_at, attempts,
            fencing_token, created_at, updated_at, document
        ) VALUES (
            requested_tenant_id, submitted_audit_event->>'eventId',
            terminal_operation_id, 'PENDING', effective_now, 0, 0,
            effective_now, effective_now, submitted_audit_event
        );
    END IF;
    RETURN next_document;
END
$function$;

REVOKE ALL ON FUNCTION delivery.advance_pipeline_run_task(
    text, text, text, text, bigint, text, text, jsonb, jsonb
) FROM PUBLIC, matrix_devops_api;
GRANT EXECUTE ON FUNCTION delivery.advance_pipeline_run_task(
    text, text, text, text, bigint, text, text, jsonb, jsonb
) TO matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.complete_build_task(
    requested_tenant_id text,
    requested_run_id text,
    requested_command_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_state text,
    requested_reason text,
    submitted_receipt jsonb,
    submitted_run_document jsonb,
    submitted_audit_event jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    current_input_digest text;
    current_pipeline_revision_id text;
    current_pipeline_revision_digest text;
    current_source_archive_digest text;
    current_executor_profile text;
    current_toolchain_image_digest text;
    current_task_stage text;
    current_task_status text;
    current_lease_owner text;
    current_lease_expires_at timestamptz(6);
    current_fencing_token bigint;
    expected_receipt_digest text;
BEGIN
    SELECT run.input_digest,
           run.pipeline_revision_id,
           run.pipeline_revision_digest,
           archive.archive_digest,
           revision.document#>>'{spec,executorProfile}',
           revision.document#>>'{spec,toolchainImageDigest}',
           task.stage,
           task.status,
           task.lease_owner,
           task.lease_expires_at,
           task.fencing_token
      INTO current_input_digest,
           current_pipeline_revision_id,
           current_pipeline_revision_digest,
           current_source_archive_digest,
           current_executor_profile,
           current_toolchain_image_digest,
           current_task_stage,
           current_task_status,
           current_lease_owner,
           current_lease_expires_at,
           current_fencing_token
      FROM delivery.pipeline_runs AS run
      JOIN delivery.pipeline_run_tasks AS task
        ON task.tenant_id = run.tenant_id
       AND task.run_id = run.id
       AND task.command_id = requested_command_id
      JOIN delivery.source_archives AS archive
        ON archive.tenant_id = run.tenant_id
       AND archive.run_id = run.id
       AND archive.input_digest = run.input_digest
      JOIN delivery.pipeline_revisions AS revision
        ON revision.tenant_id = run.tenant_id
       AND revision.id = run.pipeline_revision_id
       AND revision.content_digest = run.pipeline_revision_digest
     WHERE run.tenant_id = requested_tenant_id
       AND run.id = requested_run_id
     FOR UPDATE OF run, task;
    IF NOT FOUND
       OR current_task_stage <> 'VERIFY'
       OR current_task_status <> 'INTENT'
       OR current_lease_owner IS DISTINCT FROM requested_worker_id
       OR current_fencing_token <> expected_fencing_token
       OR current_lease_expires_at IS NULL
       OR current_lease_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'build task lease or fencing token is stale';
    END IF;

    IF requested_state = 'REPORTING' AND submitted_receipt IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'reporting requires a build receipt';
    END IF;
    IF submitted_receipt IS NOT NULL THEN
        IF jsonb_typeof(submitted_receipt) IS DISTINCT FROM 'object'
           OR NOT (submitted_receipt ?& ARRAY[
                'tenantId', 'runId', 'commandId', 'inputDigest',
                'sourceArchiveDigest', 'pipelineRevisionId',
                'pipelineRevisionDigest', 'executorId', 'executorProfile',
                'toolchainImageDigest', 'conclusion', 'steps', 'contentDigest'
           ])
           OR (submitted_receipt - ARRAY[
                'tenantId', 'runId', 'commandId', 'inputDigest',
                'sourceArchiveDigest', 'pipelineRevisionId',
                'pipelineRevisionDigest', 'executorId', 'executorProfile',
                'toolchainImageDigest', 'conclusion', 'steps', 'contentDigest'
           ]) <> '{}'::jsonb
           OR EXISTS (
                SELECT 1
                  FROM unnest(ARRAY[
                    'tenantId', 'runId', 'commandId', 'inputDigest',
                    'sourceArchiveDigest', 'pipelineRevisionId',
                    'pipelineRevisionDigest', 'executorId', 'executorProfile',
                    'toolchainImageDigest', 'conclusion', 'contentDigest'
                  ]) AS string_field(name)
                 WHERE jsonb_typeof(submitted_receipt->string_field.name)
                    IS DISTINCT FROM 'string'
           )
           OR jsonb_typeof(submitted_receipt->'steps') IS DISTINCT FROM 'array'
           OR jsonb_array_length(submitted_receipt->'steps') <> 2 THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'build receipt shape is invalid';
        END IF;
        IF EXISTS (
            SELECT 1
              FROM jsonb_array_elements(submitted_receipt->'steps')
                    WITH ORDINALITY AS step(document, ordinal)
             WHERE jsonb_typeof(step.document) IS DISTINCT FROM 'object'
                OR NOT (step.document ?& ARRAY['ordinal', 'kind', 'conclusion'])
                OR (step.document - ARRAY['ordinal', 'kind', 'conclusion'])
                    <> '{}'::jsonb
                OR jsonb_typeof(step.document->'ordinal') IS DISTINCT FROM 'number'
                OR jsonb_typeof(step.document->'kind') IS DISTINCT FROM 'string'
                OR jsonb_typeof(step.document->'conclusion') IS DISTINCT FROM 'string'
                OR step.document->>'ordinal' IS DISTINCT FROM step.ordinal::text
                OR step.document->>'kind' IS DISTINCT FROM CASE step.ordinal
                    WHEN 1 THEN 'GO_TEST'
                    WHEN 2 THEN 'GO_VET'
                    ELSE NULL
                END
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'build receipt steps are invalid';
        END IF;
        IF submitted_receipt->>'tenantId' IS DISTINCT FROM requested_tenant_id
           OR submitted_receipt->>'runId' IS DISTINCT FROM requested_run_id
           OR submitted_receipt->>'commandId' IS DISTINCT FROM requested_command_id
           OR submitted_receipt->>'inputDigest' IS DISTINCT FROM current_input_digest
           OR submitted_receipt->>'sourceArchiveDigest'
                IS DISTINCT FROM current_source_archive_digest
           OR submitted_receipt->>'pipelineRevisionId'
                IS DISTINCT FROM current_pipeline_revision_id
           OR submitted_receipt->>'pipelineRevisionDigest'
                IS DISTINCT FROM current_pipeline_revision_digest
           OR COALESCE(submitted_receipt->>'executorId', '') COLLATE "C"
                !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
           OR submitted_receipt->>'executorProfile'
                IS DISTINCT FROM current_executor_profile
           OR submitted_receipt->>'executorProfile'
                IS DISTINCT FROM 'MATRIX_NATIVE_ISOLATED_V1'
           OR submitted_receipt->>'toolchainImageDigest'
                IS DISTINCT FROM current_toolchain_image_digest
           OR submitted_receipt->>'toolchainImageDigest' IS DISTINCT FROM
                'sha256:07558d5472e9acb5fc5656b485e963602e925e00111b8ad676a804306e711ba3'
           OR COALESCE(submitted_receipt->>'contentDigest', '') COLLATE "C"
                !~ '^sha256:[0-9a-f]{64}$'
           OR NOT (
                (submitted_receipt->>'conclusion' = 'PASSED'
                    AND submitted_receipt#>>'{steps,0,conclusion}' = 'PASSED'
                    AND submitted_receipt#>>'{steps,1,conclusion}' = 'PASSED')
                OR (submitted_receipt->>'conclusion' = 'FAILED' AND (
                    (submitted_receipt#>>'{steps,0,conclusion}' = 'FAILED'
                        AND submitted_receipt#>>'{steps,1,conclusion}' = 'NOT_RUN')
                    OR (submitted_receipt#>>'{steps,0,conclusion}' = 'PASSED'
                        AND submitted_receipt#>>'{steps,1,conclusion}' = 'FAILED')
                ))
                OR (submitted_receipt->>'conclusion' = 'CANCELLED' AND (
                    (submitted_receipt#>>'{steps,0,conclusion}' = 'CANCELLED'
                        AND submitted_receipt#>>'{steps,1,conclusion}' = 'NOT_RUN')
                    OR (submitted_receipt#>>'{steps,0,conclusion}' = 'PASSED'
                        AND submitted_receipt#>>'{steps,1,conclusion}' = 'CANCELLED')
                ))
           )
           OR (requested_state = 'REPORTING'
                AND submitted_receipt->>'conclusion' NOT IN ('PASSED', 'FAILED'))
           OR (requested_state = 'FAILED'
                AND submitted_receipt->>'conclusion' <> 'CANCELLED') THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'build receipt authority is invalid';
        END IF;

        expected_receipt_digest := 'sha256:' || encode(sha256(
            int8send(octet_length(convert_to(
                'matrix-devops-build-receipt-v1', 'UTF8'
            ))::bigint)
            || convert_to('matrix-devops-build-receipt-v1', 'UTF8')
            || int8send(octet_length(convert_to(
                submitted_receipt->>'tenantId', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt->>'tenantId', 'UTF8')
            || int8send(octet_length(convert_to(
                submitted_receipt->>'runId', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt->>'runId', 'UTF8')
            || int8send(octet_length(convert_to(
                submitted_receipt->>'commandId', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt->>'commandId', 'UTF8')
            || int8send(octet_length(convert_to(
                submitted_receipt->>'inputDigest', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt->>'inputDigest', 'UTF8')
            || int8send(octet_length(convert_to(
                submitted_receipt->>'sourceArchiveDigest', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt->>'sourceArchiveDigest', 'UTF8')
            || int8send(octet_length(convert_to(
                submitted_receipt->>'pipelineRevisionId', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt->>'pipelineRevisionId', 'UTF8')
            || int8send(octet_length(convert_to(
                submitted_receipt->>'pipelineRevisionDigest', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt->>'pipelineRevisionDigest', 'UTF8')
            || int8send(octet_length(convert_to(
                submitted_receipt->>'executorId', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt->>'executorId', 'UTF8')
            || int8send(octet_length(convert_to(
                submitted_receipt->>'executorProfile', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt->>'executorProfile', 'UTF8')
            || int8send(octet_length(convert_to(
                submitted_receipt->>'toolchainImageDigest', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt->>'toolchainImageDigest', 'UTF8')
            || int8send(octet_length(convert_to(
                submitted_receipt->>'conclusion', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt->>'conclusion', 'UTF8')
            || int8send(1::bigint)
            || int8send(octet_length(convert_to(
                submitted_receipt#>>'{steps,0,kind}', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt#>>'{steps,0,kind}', 'UTF8')
            || int8send(octet_length(convert_to(
                submitted_receipt#>>'{steps,0,conclusion}', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt#>>'{steps,0,conclusion}', 'UTF8')
            || int8send(2::bigint)
            || int8send(octet_length(convert_to(
                submitted_receipt#>>'{steps,1,kind}', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt#>>'{steps,1,kind}', 'UTF8')
            || int8send(octet_length(convert_to(
                submitted_receipt#>>'{steps,1,conclusion}', 'UTF8'
            ))::bigint) || convert_to(submitted_receipt#>>'{steps,1,conclusion}', 'UTF8')
        ), 'hex');
        IF submitted_receipt->>'contentDigest' IS DISTINCT FROM
            expected_receipt_digest THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'build receipt digest is invalid';
        END IF;

        INSERT INTO delivery.build_receipts (
            tenant_id, run_id, command_id, input_digest,
            source_archive_digest, pipeline_revision_id,
            pipeline_revision_digest, executor_id, executor_profile,
            toolchain_image_digest, conclusion, content_digest,
            created_at, document
        ) VALUES (
            requested_tenant_id,
            requested_run_id,
            requested_command_id,
            current_input_digest,
            current_source_archive_digest,
            current_pipeline_revision_id,
            current_pipeline_revision_digest,
            submitted_receipt->>'executorId',
            submitted_receipt->>'executorProfile',
            submitted_receipt->>'toolchainImageDigest',
            submitted_receipt->>'conclusion',
            submitted_receipt->>'contentDigest',
            transaction_timestamp(),
            submitted_receipt
        );
    END IF;

    RETURN delivery.advance_pipeline_run_task(
        requested_tenant_id,
        requested_run_id,
        requested_command_id,
        requested_worker_id,
        expected_fencing_token,
        requested_state,
        requested_reason,
        submitted_run_document,
        submitted_audit_event
    );
END
$function$;

REVOKE ALL ON FUNCTION delivery.complete_build_task(
    text, text, text, text, bigint, text, text, jsonb, jsonb, jsonb
) FROM PUBLIC, matrix_devops_api, matrix_devops_source_fetcher,
       matrix_devops_source_observer;
GRANT EXECUTE ON FUNCTION delivery.complete_build_task(
    text, text, text, text, bigint, text, text, jsonb, jsonb, jsonb
) TO matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.complete_source_fetch_task(
    requested_tenant_id text,
    requested_run_id text,
    requested_command_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_state text,
    requested_reason text,
    submitted_receipt jsonb,
    submitted_run_document jsonb,
    submitted_audit_event jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    current_input_digest text;
    current_run_document jsonb;
    current_task_stage text;
    current_task_status text;
    current_lease_owner text;
    current_lease_expires_at timestamptz(6);
    current_fencing_token bigint;
BEGIN
    SELECT run.input_digest,
           run.document,
           task.stage,
           task.status,
           task.lease_owner,
           task.lease_expires_at,
           task.fencing_token
      INTO current_input_digest,
           current_run_document,
           current_task_stage,
           current_task_status,
           current_lease_owner,
           current_lease_expires_at,
           current_fencing_token
      FROM delivery.pipeline_runs AS run
      JOIN delivery.pipeline_run_tasks AS task
        ON task.tenant_id = run.tenant_id
       AND task.run_id = run.id
       AND task.command_id = requested_command_id
     WHERE run.tenant_id = requested_tenant_id
       AND run.id = requested_run_id
     FOR UPDATE OF run, task;
    IF NOT FOUND
       OR current_task_stage <> 'FETCH'
       OR current_task_status <> 'INTENT'
       OR current_lease_owner IS DISTINCT FROM requested_worker_id
       OR current_fencing_token <> expected_fencing_token
       OR current_lease_expires_at IS NULL
       OR current_lease_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'source fetch task lease or fencing token is stale';
    END IF;

    IF requested_state = 'VERIFYING' THEN
        IF requested_reason IS NOT NULL
           OR jsonb_typeof(submitted_receipt) IS DISTINCT FROM 'object'
           OR NOT (submitted_receipt ?& ARRAY[
                'tenantId', 'runId', 'commandId', 'inputDigest',
                'headCommit', 'trustedBaseCommit', 'mediaType',
                'archiveDigest', 'archiveBytes', 'expandedBytes', 'pathCount'
           ])
           OR (submitted_receipt - ARRAY[
                'tenantId', 'runId', 'commandId', 'inputDigest',
                'headCommit', 'trustedBaseCommit', 'mediaType',
                'archiveDigest', 'archiveBytes', 'expandedBytes', 'pathCount'
           ]) <> '{}'::jsonb
           OR EXISTS (
                SELECT 1
                  FROM unnest(ARRAY[
                    'tenantId', 'runId', 'commandId', 'inputDigest',
                    'headCommit', 'trustedBaseCommit', 'mediaType',
                    'archiveDigest'
                  ]) AS string_field(name)
                 WHERE jsonb_typeof(submitted_receipt->string_field.name)
                    IS DISTINCT FROM 'string'
           )
           OR EXISTS (
                SELECT 1
                  FROM unnest(ARRAY[
                    'archiveBytes', 'expandedBytes', 'pathCount'
                  ]) AS number_field(name)
                 WHERE jsonb_typeof(submitted_receipt->number_field.name)
                    IS DISTINCT FROM 'number'
           )
           OR submitted_receipt->>'tenantId' IS DISTINCT FROM requested_tenant_id
           OR submitted_receipt->>'runId' IS DISTINCT FROM requested_run_id
           OR submitted_receipt->>'commandId' IS DISTINCT FROM requested_command_id
           OR submitted_receipt->>'inputDigest' IS DISTINCT FROM current_input_digest
           OR submitted_receipt->>'headCommit' IS DISTINCT FROM
                current_run_document#>>'{input,change,headCommit}'
           OR submitted_receipt->>'trustedBaseCommit' IS DISTINCT FROM
                current_run_document#>>'{input,change,trustedBaseCommit}'
           OR submitted_receipt->>'mediaType' IS DISTINCT FROM
                'application/vnd.matrix.devops.source.v1+tar+gzip'
           OR COALESCE(submitted_receipt->>'archiveDigest', '') COLLATE "C"
                !~ '^sha256:[0-9a-f]{64}$'
           OR NOT (CASE
                WHEN COALESCE(submitted_receipt->>'archiveBytes', '') COLLATE "C"
                    ~ '^[1-9][0-9]*$'
                THEN (submitted_receipt->>'archiveBytes')::numeric
                    BETWEEN 1 AND 67108864
                ELSE false
           END)
           OR NOT (CASE
                WHEN COALESCE(submitted_receipt->>'expandedBytes', '') COLLATE "C"
                    ~ '^[0-9]+$'
                THEN (submitted_receipt->>'expandedBytes')::numeric
                    BETWEEN 0 AND 536870912
                ELSE false
           END)
           OR NOT (CASE
                WHEN COALESCE(submitted_receipt->>'pathCount', '') COLLATE "C"
                    ~ '^[0-9]+$'
                THEN (submitted_receipt->>'pathCount')::numeric
                    BETWEEN 0 AND 20000
                ELSE false
           END) THEN
            RAISE EXCEPTION USING
                ERRCODE = '22023',
                MESSAGE = 'source archive receipt is invalid';
        END IF;

        INSERT INTO delivery.source_archives (
            tenant_id, run_id, command_id, input_digest,
            archive_digest, archive_bytes, expanded_bytes, path_count,
            head_commit, trusted_base_commit, media_type, created_at
        ) VALUES (
            requested_tenant_id,
            requested_run_id,
            requested_command_id,
            current_input_digest,
            submitted_receipt->>'archiveDigest',
            (submitted_receipt->>'archiveBytes')::bigint,
            (submitted_receipt->>'expandedBytes')::bigint,
            (submitted_receipt->>'pathCount')::bigint,
            submitted_receipt->>'headCommit',
            submitted_receipt->>'trustedBaseCommit',
            submitted_receipt->>'mediaType',
            transaction_timestamp()
        );
    ELSIF submitted_receipt IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'terminal source fetch completion cannot store a receipt';
    END IF;

    RETURN delivery.advance_pipeline_run_task(
        requested_tenant_id,
        requested_run_id,
        requested_command_id,
        requested_worker_id,
        expected_fencing_token,
        requested_state,
        requested_reason,
        submitted_run_document,
        submitted_audit_event
    );
END
$function$;

REVOKE ALL ON FUNCTION delivery.complete_source_fetch_task(
    text, text, text, text, bigint, text, text, jsonb, jsonb, jsonb
) FROM PUBLIC, matrix_devops_api, matrix_devops_source_observer,
       matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.complete_source_fetch_task(
    text, text, text, text, bigint, text, text, jsonb, jsonb, jsonb
) TO matrix_devops_source_fetcher;

CREATE OR REPLACE FUNCTION delivery.mark_pipeline_run_report_uncertain(
    requested_tenant_id text,
    requested_run_id text,
    requested_command_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_next_attempt_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    current_state text;
    current_stage text;
    current_resource_version bigint;
    current_updated_at timestamptz(6);
    current_run_document jsonb;
    current_task_status text;
    current_lease_owner text;
    current_lease_expires_at timestamptz(6);
    current_fencing_token bigint;
    effective_now timestamptz(6);
    effective_time_text text;
    next_document jsonb;
BEGIN
    IF requested_tenant_id IS NULL
       OR requested_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_run_id IS NULL
       OR requested_run_id COLLATE "C" !~ '^pipeline-run-[0-9a-f]{48}$'
       OR requested_command_id IS NULL
       OR requested_command_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR expected_fencing_token IS NULL
       OR expected_fencing_token NOT BETWEEN 1 AND 9007199254740991
       OR requested_next_attempt_at IS NULL
       OR date_trunc('microseconds', requested_next_attempt_at)
            <> requested_next_attempt_at
       OR requested_next_attempt_at <= transaction_timestamp()
       OR requested_next_attempt_at > transaction_timestamp() + interval '24 hours' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'PipelineRun report uncertainty parameters are invalid';
    END IF;

    SELECT run.state,
           run.stage,
           run.resource_version,
           run.updated_at,
           run.document,
           task.status,
           task.lease_owner,
           task.lease_expires_at,
           task.fencing_token
      INTO current_state,
           current_stage,
           current_resource_version,
           current_updated_at,
           current_run_document,
           current_task_status,
           current_lease_owner,
           current_lease_expires_at,
           current_fencing_token
      FROM delivery.pipeline_runs AS run
      JOIN delivery.pipeline_run_tasks AS task
        ON task.tenant_id = run.tenant_id
       AND task.run_id = run.id
       AND task.command_id = requested_command_id
       AND task.stage = 'REPORT'
     WHERE run.tenant_id = requested_tenant_id
       AND run.id = requested_run_id
     FOR UPDATE OF run, task;
    IF NOT FOUND
       OR current_state <> 'REPORTING'
       OR current_stage <> 'REPORT'
       OR current_task_status <> 'INTENT'
       OR current_lease_owner IS DISTINCT FROM requested_worker_id
       OR current_fencing_token <> expected_fencing_token
       OR current_lease_expires_at IS NULL
       OR current_lease_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'PipelineRun task lease or fencing token is stale';
    END IF;
    IF current_resource_version >= 9007199254740991 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'PipelineRun resource version is exhausted';
    END IF;

    effective_now := greatest(
        transaction_timestamp(),
        current_updated_at + interval '1 microsecond'
    );
    effective_time_text := to_char(
        effective_now AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    );
    next_document := jsonb_set(
        jsonb_set(
            current_run_document,
            '{status}',
            jsonb_build_object(
                'state', 'RECONCILING',
                'stage', 'REPORT',
                'reason', 'EXTERNAL_EFFECT_UNCERTAIN',
                'resourceVersion', current_resource_version + 1,
                'observedAt', effective_time_text
            ),
            false
        ),
        '{updatedAt}', to_jsonb(effective_time_text), false
    );
    IF current_run_document#>'{status,cancellationRequestedAt}' IS NOT NULL THEN
        next_document := jsonb_set(
            next_document,
            '{status,cancellationRequestedAt}',
            current_run_document#>'{status,cancellationRequestedAt}',
            true
        );
    END IF;
    UPDATE delivery.pipeline_runs AS transitioned
       SET state = 'RECONCILING',
           stage = 'REPORT',
           reason = 'EXTERNAL_EFFECT_UNCERTAIN',
           resource_version = current_resource_version + 1,
           updated_at = effective_now,
           document = next_document
     WHERE transitioned.tenant_id = requested_tenant_id
       AND transitioned.id = requested_run_id;
    UPDATE delivery.pipeline_run_tasks AS uncertain
       SET available_at = requested_next_attempt_at,
           lease_owner = NULL,
           lease_expires_at = NULL,
           updated_at = effective_now
     WHERE uncertain.tenant_id = requested_tenant_id
       AND uncertain.run_id = requested_run_id
       AND uncertain.command_id = requested_command_id;
    RETURN next_document;
END
$function$;

REVOKE ALL ON FUNCTION delivery.mark_pipeline_run_report_uncertain(
    text, text, text, text, bigint, timestamptz
) FROM PUBLIC, matrix_devops_api;
GRANT EXECUTE ON FUNCTION delivery.mark_pipeline_run_report_uncertain(
    text, text, text, text, bigint, timestamptz
) TO matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.defer_pipeline_run_reconciliation(
    requested_tenant_id text,
    requested_run_id text,
    requested_command_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_next_attempt_at timestamptz
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    current_attempts bigint;
    affected_rows bigint;
BEGIN
    IF requested_tenant_id IS NULL
       OR requested_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_run_id IS NULL
       OR requested_run_id COLLATE "C" !~ '^pipeline-run-[0-9a-f]{48}$'
       OR requested_command_id IS NULL
       OR requested_command_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR expected_fencing_token IS NULL
       OR expected_fencing_token NOT BETWEEN 1 AND 9007199254740991
       OR requested_next_attempt_at IS NULL
       OR date_trunc('microseconds', requested_next_attempt_at)
            <> requested_next_attempt_at
       OR requested_next_attempt_at <= transaction_timestamp()
       OR requested_next_attempt_at > transaction_timestamp() + interval '24 hours' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'PipelineRun reconciliation deferral parameters are invalid';
    END IF;

    SELECT task.reconciliation_attempts
      INTO current_attempts
      FROM delivery.pipeline_runs AS run
      JOIN delivery.pipeline_run_tasks AS task
        ON task.tenant_id = run.tenant_id
       AND task.run_id = run.id
       AND task.command_id = requested_command_id
       AND task.stage = 'REPORT'
     WHERE run.tenant_id = requested_tenant_id
       AND run.id = requested_run_id
       AND run.state = 'RECONCILING'
       AND task.status = 'INTENT'
       AND task.lease_owner = requested_worker_id
       AND task.fencing_token = expected_fencing_token
       AND task.lease_expires_at > clock_timestamp()
     FOR UPDATE OF run, task;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'PipelineRun task lease or fencing token is stale';
    END IF;
    IF current_attempts >= 10 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX410',
            MESSAGE = 'PipelineRun reconciliation attempts are exhausted';
    END IF;

    UPDATE delivery.pipeline_run_tasks AS deferred
       SET reconciliation_attempts = current_attempts + 1,
           available_at = requested_next_attempt_at,
           lease_owner = NULL,
           lease_expires_at = NULL,
           updated_at = transaction_timestamp()
     WHERE deferred.tenant_id = requested_tenant_id
       AND deferred.run_id = requested_run_id
       AND deferred.command_id = requested_command_id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'PipelineRun task lease or fencing token is stale';
    END IF;
    RETURN current_attempts + 1;
END
$function$;

REVOKE ALL ON FUNCTION delivery.defer_pipeline_run_reconciliation(
    text, text, text, text, bigint, timestamptz
) FROM PUBLIC, matrix_devops_api;
GRANT EXECUTE ON FUNCTION delivery.defer_pipeline_run_reconciliation(
    text, text, text, text, bigint, timestamptz
) TO matrix_devops_worker;

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

DROP POLICY IF EXISTS owner_source_contract_upgrade
    ON delivery.source_connections;
CREATE POLICY owner_source_contract_upgrade
    ON delivery.source_connections
    TO matrix_devops_owner USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS owner_source_contract_upgrade
    ON delivery.repository_bindings;
CREATE POLICY owner_source_contract_upgrade
    ON delivery.repository_bindings
    TO matrix_devops_owner USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS owner_source_contract_upgrade
    ON delivery.repository_binding_revisions;
CREATE POLICY owner_source_contract_upgrade
    ON delivery.repository_binding_revisions
    TO matrix_devops_owner USING (true) WITH CHECK (true);
DROP POLICY IF EXISTS owner_source_contract_upgrade
    ON delivery.mutations;
CREATE POLICY owner_source_contract_upgrade
    ON delivery.mutations
    TO matrix_devops_owner USING (true) WITH CHECK (true);

DO $matrix_devops_exact_source_origin$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM delivery.source_connections
         WHERE document#>'{spec,allowedEndpointOrigins}' IS NOT NULL
           AND CASE
                WHEN jsonb_typeof(document#>'{spec,allowedEndpointOrigins}') = 'array'
                THEN jsonb_array_length(document#>'{spec,allowedEndpointOrigins}') <> 1
                  OR (
                    document#>'{spec,endpointOrigin}' IS NOT NULL
                    AND document#>>'{spec,endpointOrigin}'
                        IS DISTINCT FROM document#>>'{spec,allowedEndpointOrigins,0}'
                  )
                ELSE true
               END
    ) OR EXISTS (
        SELECT 1
          FROM delivery.mutations
         WHERE result_document#>'{sourceConnection,spec,allowedEndpointOrigins}' IS NOT NULL
           AND CASE
                WHEN jsonb_typeof(result_document#>'{sourceConnection,spec,allowedEndpointOrigins}') = 'array'
                THEN jsonb_array_length(result_document#>'{sourceConnection,spec,allowedEndpointOrigins}') <> 1
                  OR (
                    result_document#>'{sourceConnection,spec,endpointOrigin}' IS NOT NULL
                    AND result_document#>>'{sourceConnection,spec,endpointOrigin}'
                        IS DISTINCT FROM result_document#>>'{sourceConnection,spec,allowedEndpointOrigins,0}'
                  )
                ELSE true
               END
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'legacy SourceConnection must contain exactly one endpoint origin';
    END IF;
END
$matrix_devops_exact_source_origin$;

UPDATE delivery.source_connections
   SET document = jsonb_set(
        document #- '{spec,allowedEndpointOrigins}',
        '{spec,endpointOrigin}',
        document#>'{spec,allowedEndpointOrigins,0}',
        true
   )
 WHERE document#>'{spec,allowedEndpointOrigins}' IS NOT NULL;

UPDATE delivery.mutations
   SET result_document = jsonb_set(
        result_document #- '{sourceConnection,spec,allowedEndpointOrigins}',
        '{sourceConnection,spec,endpointOrigin}',
        result_document#>'{sourceConnection,spec,allowedEndpointOrigins,0}',
        true
   )
 WHERE result_document#>'{sourceConnection,spec,allowedEndpointOrigins}' IS NOT NULL;

UPDATE delivery.source_connections
   SET document = jsonb_set(
        document,
        '{status,reason}',
        to_jsonb(CASE document#>>'{status,health}'
            WHEN 'PENDING' THEN 'CONFIGURATION_CHANGED'
            WHEN 'READY' THEN 'OBSERVED'
            ELSE 'PROVIDER_UNAVAILABLE'
        END),
        true
   )
 WHERE document#>'{status,reason}' IS NULL;

UPDATE delivery.repository_bindings
   SET document = jsonb_set(
        document,
        '{status,reason}',
        to_jsonb(CASE document#>>'{status,health}'
            WHEN 'PENDING' THEN 'CONFIGURATION_CHANGED'
            WHEN 'READY' THEN 'OBSERVED'
            ELSE 'REPOSITORY_UNAVAILABLE'
        END),
        true
   )
 WHERE document#>'{status,reason}' IS NULL;

UPDATE delivery.repository_binding_revisions
   SET document = jsonb_set(
        document,
        '{status,reason}',
        to_jsonb(CASE document#>>'{status,health}'
            WHEN 'PENDING' THEN 'CONFIGURATION_CHANGED'
            WHEN 'READY' THEN 'OBSERVED'
            ELSE 'REPOSITORY_UNAVAILABLE'
        END),
        true
   )
 WHERE document#>'{status,reason}' IS NULL;

UPDATE delivery.mutations
   SET result_document = jsonb_set(
        result_document,
        '{sourceConnection,status,reason}',
        to_jsonb(CASE result_document#>>'{sourceConnection,status,health}'
            WHEN 'PENDING' THEN 'CONFIGURATION_CHANGED'
            WHEN 'READY' THEN 'OBSERVED'
            ELSE 'PROVIDER_UNAVAILABLE'
        END),
        true
   )
 WHERE result_document#>'{sourceConnection,status}' IS NOT NULL
   AND result_document#>'{sourceConnection,status,reason}' IS NULL;

UPDATE delivery.mutations
   SET result_document = jsonb_set(
        result_document,
        '{repositoryBinding,status,reason}',
        to_jsonb(CASE result_document#>>'{repositoryBinding,status,health}'
            WHEN 'PENDING' THEN 'CONFIGURATION_CHANGED'
            WHEN 'READY' THEN 'OBSERVED'
            ELSE 'REPOSITORY_UNAVAILABLE'
        END),
        true
   )
 WHERE result_document#>'{repositoryBinding,status}' IS NOT NULL
   AND result_document#>'{repositoryBinding,status,reason}' IS NULL;

DO $matrix_devops_source_contract_valid$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM delivery.source_connections
         WHERE document#>'{spec,allowedEndpointOrigins}' IS NOT NULL
            OR jsonb_typeof(document#>'{spec,endpointOrigin}') IS DISTINCT FROM 'string'
            OR (
                document#>>'{status,health}' = 'PENDING'
                AND document#>>'{status,reason}' = 'CONFIGURATION_CHANGED'
                OR document#>>'{status,health}' = 'READY'
                AND document#>>'{status,reason}' = 'OBSERVED'
                OR document#>>'{status,health}' = 'UNAVAILABLE'
                AND document#>>'{status,reason}' IN (
                    'SECRET_UNAVAILABLE', 'PROVIDER_UNAVAILABLE',
                    'PROVIDER_UNSUPPORTED', 'CREDENTIAL_REJECTED'
                )
            ) IS NOT TRUE
    ) OR EXISTS (
        SELECT 1
          FROM delivery.repository_bindings
         WHERE (
                document#>>'{status,health}' = 'PENDING'
                AND document#>>'{status,reason}' IN (
                    'CONFIGURATION_CHANGED', 'CONNECTION_NOT_READY'
                )
                OR document#>>'{status,health}' = 'READY'
                AND document#>>'{status,reason}' = 'OBSERVED'
                OR document#>>'{status,health}' = 'UNAVAILABLE'
                AND document#>>'{status,reason}' IN (
                    'REPOSITORY_UNAVAILABLE', 'IDENTITY_MISMATCH',
                    'FETCH_PERMISSION_DENIED', 'REPORT_PERMISSION_DENIED'
                )
            ) IS NOT TRUE
    ) OR EXISTS (
        SELECT 1
          FROM delivery.repository_binding_revisions
         WHERE (
                document#>>'{status,health}' = 'PENDING'
                AND document#>>'{status,reason}' IN (
                    'CONFIGURATION_CHANGED', 'CONNECTION_NOT_READY'
                )
                OR document#>>'{status,health}' = 'READY'
                AND document#>>'{status,reason}' = 'OBSERVED'
                OR document#>>'{status,health}' = 'UNAVAILABLE'
                AND document#>>'{status,reason}' IN (
                    'REPOSITORY_UNAVAILABLE', 'IDENTITY_MISMATCH',
                    'FETCH_PERMISSION_DENIED', 'REPORT_PERMISSION_DENIED'
                )
            ) IS NOT TRUE
    ) OR EXISTS (
        SELECT 1
          FROM delivery.mutations
         WHERE result_document#>'{sourceConnection}' IS NOT NULL
           AND (
                result_document#>'{sourceConnection,spec,allowedEndpointOrigins}' IS NOT NULL
                OR jsonb_typeof(result_document#>'{sourceConnection,spec,endpointOrigin}')
                    IS DISTINCT FROM 'string'
                OR result_document#>'{sourceConnection,status,reason}' IS NULL
           )
    ) OR EXISTS (
        SELECT 1
          FROM delivery.mutations
         WHERE result_document#>'{repositoryBinding}' IS NOT NULL
           AND result_document#>'{repositoryBinding,status,reason}' IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023',
            MESSAGE = 'source readiness contract migration is incomplete';
    END IF;
END
$matrix_devops_source_contract_valid$;

DROP POLICY owner_source_contract_upgrade ON delivery.source_connections;
DROP POLICY owner_source_contract_upgrade ON delivery.repository_bindings;
DROP POLICY owner_source_contract_upgrade ON delivery.repository_binding_revisions;
DROP POLICY owner_source_contract_upgrade ON delivery.mutations;

CREATE OR REPLACE FUNCTION delivery.record_source_fetcher_heartbeat(
    requested_worker_id text
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_observed_at timestamptz(6);
BEGIN
    IF requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'source fetcher heartbeat identity is invalid';
    END IF;

    INSERT INTO delivery.source_fetcher_heartbeat (
        singleton, worker_id, observed_at
    ) VALUES (
        true, requested_worker_id, transaction_timestamp()
    )
    ON CONFLICT (singleton) DO UPDATE
       SET worker_id = CASE
               WHEN excluded.observed_at >= source_fetcher_heartbeat.observed_at
               THEN excluded.worker_id
               ELSE source_fetcher_heartbeat.worker_id
           END,
           observed_at = greatest(
               excluded.observed_at,
               source_fetcher_heartbeat.observed_at
           )
    RETURNING observed_at INTO effective_observed_at;

    RETURN effective_observed_at;
END
$function$;

REVOKE ALL ON FUNCTION delivery.record_source_fetcher_heartbeat(text)
    FROM PUBLIC, matrix_devops_api, matrix_devops_source_observer,
         matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.record_source_fetcher_heartbeat(text)
    TO matrix_devops_source_fetcher;

CREATE OR REPLACE FUNCTION delivery.record_build_worker_heartbeat(
    requested_worker_id text
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_observed_at timestamptz(6);
BEGIN
    IF requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'build worker heartbeat identity is invalid';
    END IF;

    INSERT INTO delivery.build_worker_heartbeat (
        singleton, worker_id, observed_at
    ) VALUES (
        true, requested_worker_id, transaction_timestamp()
    )
    ON CONFLICT (singleton) DO UPDATE
       SET worker_id = CASE
               WHEN excluded.observed_at >= build_worker_heartbeat.observed_at
               THEN excluded.worker_id
               ELSE build_worker_heartbeat.worker_id
           END,
           observed_at = greatest(
               excluded.observed_at,
               build_worker_heartbeat.observed_at
           )
    RETURNING observed_at INTO effective_observed_at;

    RETURN effective_observed_at;
END
$function$;

REVOKE ALL ON FUNCTION delivery.record_build_worker_heartbeat(text)
    FROM PUBLIC, matrix_devops_api, matrix_devops_source_fetcher,
         matrix_devops_source_observer;
GRANT EXECUTE ON FUNCTION delivery.record_build_worker_heartbeat(text)
    TO matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.record_source_observer_heartbeat(
    requested_worker_id text
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    effective_observed_at timestamptz(6);
BEGIN
    IF requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'source observer heartbeat identity is invalid';
    END IF;

    INSERT INTO delivery.source_observer_heartbeat (
        singleton, worker_id, observed_at
    ) VALUES (
        true, requested_worker_id, transaction_timestamp()
    )
    ON CONFLICT (singleton) DO UPDATE
       SET worker_id = CASE
               WHEN excluded.observed_at >= source_observer_heartbeat.observed_at
               THEN excluded.worker_id
               ELSE source_observer_heartbeat.worker_id
           END,
           observed_at = greatest(
               excluded.observed_at,
               source_observer_heartbeat.observed_at
           )
    RETURNING observed_at INTO effective_observed_at;

    RETURN effective_observed_at;
END
$function$;

REVOKE ALL ON FUNCTION delivery.record_source_observer_heartbeat(text)
    FROM PUBLIC, matrix_devops_api, matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.record_source_observer_heartbeat(text)
    TO matrix_devops_source_observer;

CREATE OR REPLACE FUNCTION delivery.claim_source_observation(
    requested_worker_id text,
    requested_lease_seconds integer
)
RETURNS TABLE (
    tenant_id text,
    resource_kind text,
    resource_id text,
    resource_version bigint,
    fencing_token bigint,
    claimed_at timestamptz,
    lease_expires_at timestamptz,
    connection_document jsonb,
    binding_document jsonb
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    selected_tenant_id text;
    selected_resource_kind text;
    selected_resource_id text;
    selected_resource_version bigint;
    selected_fencing_token bigint;
    selected_last_claimed_at timestamptz(6);
    effective_fencing_token bigint;
    effective_claimed_at timestamptz(6);
    effective_lease_expires_at timestamptz(6);
    selected_connection_document jsonb;
    selected_binding_document jsonb;
BEGIN
    IF requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_lease_seconds IS DISTINCT FROM 30 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'source observation claim parameters are invalid';
    END IF;

    SELECT task.tenant_id,
           task.resource_kind,
           task.resource_id,
           task.resource_version,
           task.fencing_token,
           task.last_claimed_at
      INTO selected_tenant_id,
           selected_resource_kind,
           selected_resource_id,
           selected_resource_version,
           selected_fencing_token,
           selected_last_claimed_at
      FROM delivery.source_observation_tasks AS task
     WHERE task.available_at <= transaction_timestamp()
       AND task.resource_version < 9007199254740991
       AND task.fencing_token < 9007199254740991
       AND (
            task.lease_owner IS NULL
            OR task.lease_expires_at <= transaction_timestamp()
       )
       AND (
            (task.resource_kind = 'SOURCE_CONNECTION' AND EXISTS (
                SELECT 1
                  FROM delivery.source_connections AS source
                 WHERE source.tenant_id = task.tenant_id
                   AND source.id = task.resource_id
                   AND source.resource_version = task.resource_version
            ))
            OR (task.resource_kind = 'REPOSITORY_BINDING' AND EXISTS (
                SELECT 1
                  FROM delivery.repository_bindings AS binding
                  JOIN delivery.source_connections AS source
                    ON source.tenant_id = binding.tenant_id
                   AND source.id = binding.source_connection_id
                 WHERE binding.tenant_id = task.tenant_id
                   AND binding.id = task.resource_id
                   AND binding.resource_version = task.resource_version
            ))
       )
     ORDER BY (
            SELECT max(fairness.last_claimed_at)
              FROM delivery.source_observation_tasks AS fairness
             WHERE fairness.tenant_id = task.tenant_id
       ) ASC NULLS FIRST,
       task.available_at,
       task.tenant_id COLLATE "C",
       task.resource_kind COLLATE "C",
       task.resource_id COLLATE "C"
     LIMIT 1
     FOR UPDATE OF task SKIP LOCKED;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    effective_claimed_at := greatest(
        transaction_timestamp(),
        selected_last_claimed_at + interval '1 microsecond'
    );
    effective_fencing_token := selected_fencing_token + 1;
    effective_lease_expires_at := effective_claimed_at
        + make_interval(secs => requested_lease_seconds);

    UPDATE delivery.source_observation_tasks AS claimed
       SET lease_owner = requested_worker_id,
           lease_expires_at = effective_lease_expires_at,
           fencing_token = effective_fencing_token,
           last_claimed_at = effective_claimed_at,
           updated_at = effective_claimed_at
     WHERE claimed.tenant_id = selected_tenant_id
       AND claimed.resource_kind = selected_resource_kind
       AND claimed.resource_id = selected_resource_id;

    IF selected_resource_kind = 'SOURCE_CONNECTION' THEN
        SELECT source.document
          INTO selected_connection_document
          FROM delivery.source_connections AS source
         WHERE source.tenant_id = selected_tenant_id
           AND source.id = selected_resource_id
           AND source.resource_version = selected_resource_version;
        selected_binding_document := NULL;
    ELSE
        SELECT source.document, binding.document
          INTO selected_connection_document, selected_binding_document
          FROM delivery.repository_bindings AS binding
          JOIN delivery.source_connections AS source
            ON source.tenant_id = binding.tenant_id
           AND source.id = binding.source_connection_id
         WHERE binding.tenant_id = selected_tenant_id
           AND binding.id = selected_resource_id
           AND binding.resource_version = selected_resource_version;
    END IF;

    IF selected_connection_document IS NULL
       OR (selected_resource_kind = 'REPOSITORY_BINDING'
            AND selected_binding_document IS NULL) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'source observation resource disappeared during claim';
    END IF;

    RETURN QUERY SELECT
        selected_tenant_id,
        selected_resource_kind,
        selected_resource_id,
        selected_resource_version,
        effective_fencing_token,
        effective_claimed_at,
        effective_lease_expires_at,
        selected_connection_document,
        selected_binding_document;
END
$function$;

REVOKE ALL ON FUNCTION delivery.claim_source_observation(text, integer)
    FROM PUBLIC, matrix_devops_api, matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.claim_source_observation(text, integer)
    TO matrix_devops_source_observer;

CREATE OR REPLACE FUNCTION delivery.complete_source_observation(
    requested_tenant_id text,
    requested_resource_kind text,
    requested_resource_id text,
    expected_resource_version bigint,
    requested_worker_id text,
    expected_fencing_token bigint,
    submitted_resource jsonb,
    submitted_audit_event jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
DECLARE
    current_document jsonb;
    current_queue_version bigint;
    current_lease_owner text;
    current_lease_expires_at timestamptz(6);
    current_fencing_token bigint;
    expected_document_kind text;
    expected_target_kind text;
    expected_audit_action text;
    effective_now timestamptz(6);
    effective_time_text text;
    observation_payload text;
    expected_request_digest text;
    expected_operation_id text;
    expected_event_id text;
    transitioned boolean;
    health_pair_valid boolean;
    affected integer;
BEGIN
    IF requested_tenant_id IS NULL
       OR requested_tenant_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR requested_resource_kind NOT IN (
            'SOURCE_CONNECTION', 'REPOSITORY_BINDING'
       )
       OR requested_resource_id IS NULL
       OR requested_resource_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR expected_resource_version IS NULL
       OR expected_resource_version NOT BETWEEN 1 AND 9007199254740990
       OR requested_worker_id IS NULL
       OR requested_worker_id COLLATE "C"
            !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
       OR expected_fencing_token IS NULL
       OR expected_fencing_token NOT BETWEEN 1 AND 9007199254740991
       OR jsonb_typeof(submitted_resource) IS DISTINCT FROM 'object'
       OR (
            submitted_audit_event IS NOT NULL
            AND jsonb_typeof(submitted_audit_event) IS DISTINCT FROM 'object'
       ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'source observation completion parameters are invalid';
    END IF;

    expected_document_kind := CASE requested_resource_kind
        WHEN 'SOURCE_CONNECTION' THEN 'SourceConnection'
        ELSE 'RepositoryBinding'
    END;
    expected_target_kind := requested_resource_kind;
    expected_audit_action := CASE requested_resource_kind
        WHEN 'SOURCE_CONNECTION'
            THEN 'devops.source-connection.health-transitioned'
        ELSE 'devops.repository-binding.health-transitioned'
    END;

    IF requested_resource_kind = 'SOURCE_CONNECTION' THEN
        SELECT source.document
          INTO current_document
          FROM delivery.source_connections AS source
         WHERE source.tenant_id = requested_tenant_id
           AND source.id = requested_resource_id
         FOR UPDATE;
    ELSE
        SELECT binding.document
          INTO current_document
          FROM delivery.repository_bindings AS binding
         WHERE binding.tenant_id = requested_tenant_id
           AND binding.id = requested_resource_id
         FOR UPDATE;
    END IF;

    IF current_document IS NULL
       OR (current_document#>>'{metadata,resourceVersion}')::numeric
            IS DISTINCT FROM expected_resource_version THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'source observation resource version is stale';
    END IF;

    SELECT task.resource_version,
           task.lease_owner,
           task.lease_expires_at,
           task.fencing_token
      INTO current_queue_version,
           current_lease_owner,
           current_lease_expires_at,
           current_fencing_token
      FROM delivery.source_observation_tasks AS task
     WHERE task.tenant_id = requested_tenant_id
       AND task.resource_kind = requested_resource_kind
       AND task.resource_id = requested_resource_id
     FOR UPDATE;

    IF NOT FOUND
       OR current_queue_version IS DISTINCT FROM expected_resource_version
       OR current_lease_owner IS DISTINCT FROM requested_worker_id
       OR current_fencing_token IS DISTINCT FROM expected_fencing_token
       OR current_lease_expires_at <= transaction_timestamp() THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'source observation lease or fencing token is stale';
    END IF;

    effective_now := greatest(
        transaction_timestamp(),
        (current_document#>>'{metadata,updatedAt}')::timestamptz
            + interval '1 microsecond'
    );
    effective_time_text := to_char(
        effective_now AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    );

    IF jsonb_typeof(submitted_resource->'metadata') IS DISTINCT FROM 'object'
       OR jsonb_typeof(submitted_resource->'status') IS DISTINCT FROM 'object'
       OR submitted_resource->>'apiVersion'
            IS DISTINCT FROM 'devops.matrix.xiak.com/v1'
       OR submitted_resource->>'kind' IS DISTINCT FROM expected_document_kind
       OR submitted_resource#>>'{metadata,scope,tenantId}'
            IS DISTINCT FROM requested_tenant_id
       OR submitted_resource#>>'{metadata,id}'
            IS DISTINCT FROM requested_resource_id
       OR (submitted_resource#>>'{metadata,resourceVersion}')::numeric
            IS DISTINCT FROM expected_resource_version + 1
       OR (submitted_resource#>>'{metadata,updatedAt}')::timestamptz
            IS DISTINCT FROM effective_now
       OR (submitted_resource#>>'{status,observedAt}')::timestamptz
            IS DISTINCT FROM effective_now
       OR (submitted_resource - ARRAY['metadata', 'status'])
            IS DISTINCT FROM (current_document - ARRAY['metadata', 'status'])
       OR ((submitted_resource->'metadata')
            - ARRAY['resourceVersion', 'updatedAt'])
            IS DISTINCT FROM ((current_document->'metadata')
                - ARRAY['resourceVersion', 'updatedAt'])
       OR ((submitted_resource->'status')
            - ARRAY['health', 'reason', 'observedAt']) <> '{}'::jsonb THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'source observation resource document is invalid';
    END IF;

    health_pair_valid := CASE requested_resource_kind
        WHEN 'SOURCE_CONNECTION' THEN
            (submitted_resource#>>'{status,health}' = 'READY'
                AND submitted_resource#>>'{status,reason}' = 'OBSERVED')
            OR (submitted_resource#>>'{status,health}' = 'UNAVAILABLE'
                AND submitted_resource#>>'{status,reason}' IN (
                    'SECRET_UNAVAILABLE', 'PROVIDER_UNAVAILABLE',
                    'PROVIDER_UNSUPPORTED', 'CREDENTIAL_REJECTED'
                ))
        ELSE
            (submitted_resource#>>'{status,health}' = 'PENDING'
                AND submitted_resource#>>'{status,reason}'
                    = 'CONNECTION_NOT_READY')
            OR (submitted_resource#>>'{status,health}' = 'READY'
                AND submitted_resource#>>'{status,reason}' = 'OBSERVED')
            OR (submitted_resource#>>'{status,health}' = 'UNAVAILABLE'
                AND submitted_resource#>>'{status,reason}' IN (
                    'REPOSITORY_UNAVAILABLE', 'IDENTITY_MISMATCH',
                    'FETCH_PERMISSION_DENIED', 'REPORT_PERMISSION_DENIED'
                ))
    END;
    IF NOT health_pair_valid THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'source observation health pair is invalid';
    END IF;

    transitioned := current_document#>>'{status,health}'
            IS DISTINCT FROM submitted_resource#>>'{status,health}'
        OR current_document#>>'{status,reason}'
            IS DISTINCT FROM submitted_resource#>>'{status,reason}';
    observation_payload := array_to_string(ARRAY[
        'matrix-devops-source-health-observation-v1',
        expected_target_kind,
        requested_tenant_id,
        requested_resource_id,
        submitted_resource#>>'{status,health}',
        submitted_resource#>>'{status,reason}',
        (expected_resource_version + 1)::text,
        effective_time_text
    ], E'\n');
    expected_request_digest := 'sha256:' || encode(
        sha256(convert_to(observation_payload, 'UTF8')), 'hex'
    );
    expected_operation_id := 'source-observation-'
        || substring(expected_request_digest FROM 8);
    expected_event_id := 'audit-' || encode(
        sha256(
            convert_to('matrix-devops-audit-event-v1', 'UTF8')
            || decode('00', 'hex')
            || convert_to(expected_operation_id, 'UTF8')
        ),
        'hex'
    );

    IF transitioned AND (
        submitted_audit_event IS NULL
        OR NOT (submitted_audit_event ?& ARRAY[
            'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
            'action', 'target', 'result', 'requestDigest', 'requestId',
            'correlationId', 'operationId', 'occurredAt'
        ])
        OR (submitted_audit_event - ARRAY[
            'apiVersion', 'kind', 'eventId', 'tenantId', 'actor',
            'action', 'target', 'result', 'requestDigest', 'requestId',
            'correlationId', 'operationId', 'occurredAt'
        ]) <> '{}'::jsonb
        OR jsonb_typeof(submitted_audit_event->'actor') IS DISTINCT FROM 'object'
        OR jsonb_typeof(submitted_audit_event->'target') IS DISTINCT FROM 'object'
        OR ((submitted_audit_event->'actor') - ARRAY['type', 'id']) <> '{}'::jsonb
        OR ((submitted_audit_event->'target') - ARRAY['kind', 'id']) <> '{}'::jsonb
        OR submitted_audit_event->>'apiVersion'
            IS DISTINCT FROM 'audit.matrix.xiak.com/v1'
        OR submitted_audit_event->>'kind' IS DISTINCT FROM 'AuditEvent'
        OR submitted_audit_event->>'eventId' IS DISTINCT FROM expected_event_id
        OR submitted_audit_event->>'tenantId' IS DISTINCT FROM requested_tenant_id
        OR submitted_audit_event#>>'{actor,type}' IS DISTINCT FROM 'SYSTEM'
        OR submitted_audit_event#>>'{actor,id}'
            IS DISTINCT FROM 'system-devops-source-observer'
        OR submitted_audit_event->>'action' IS DISTINCT FROM expected_audit_action
        OR submitted_audit_event#>>'{target,kind}'
            IS DISTINCT FROM expected_target_kind
        OR submitted_audit_event#>>'{target,id}'
            IS DISTINCT FROM requested_resource_id
        OR submitted_audit_event->>'result' IS DISTINCT FROM 'SUCCEEDED'
        OR submitted_audit_event->>'requestDigest'
            IS DISTINCT FROM expected_request_digest
        OR submitted_audit_event->>'requestId'
            IS DISTINCT FROM expected_operation_id
        OR submitted_audit_event->>'correlationId'
            IS DISTINCT FROM requested_resource_id
        OR submitted_audit_event->>'operationId'
            IS DISTINCT FROM expected_operation_id
        OR (submitted_audit_event->>'occurredAt')::timestamptz
            IS DISTINCT FROM effective_now
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'source health transition Audit fact is invalid';
    ELSIF NOT transitioned AND submitted_audit_event IS NOT NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'equal source health observation cannot emit Audit';
    END IF;

    IF requested_resource_kind = 'SOURCE_CONNECTION' THEN
        UPDATE delivery.source_connections AS source
           SET resource_version = expected_resource_version + 1,
               document = submitted_resource
         WHERE source.tenant_id = requested_tenant_id
           AND source.id = requested_resource_id
           AND source.resource_version = expected_resource_version;
    ELSE
        UPDATE delivery.repository_bindings AS binding
           SET resource_version = expected_resource_version + 1,
               document = submitted_resource
         WHERE binding.tenant_id = requested_tenant_id
           AND binding.id = requested_resource_id
           AND binding.resource_version = expected_resource_version;
    END IF;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'source observation resource version is stale';
    END IF;

    UPDATE delivery.source_observation_tasks AS task
       SET resource_version = expected_resource_version + 1,
           available_at = effective_now + interval '60 seconds',
           lease_owner = NULL,
           lease_expires_at = NULL,
           updated_at = effective_now
     WHERE task.tenant_id = requested_tenant_id
       AND task.resource_kind = requested_resource_kind
       AND task.resource_id = requested_resource_id
       AND task.resource_version = expected_resource_version
       AND task.lease_owner = requested_worker_id
       AND task.fencing_token = expected_fencing_token;
    GET DIAGNOSTICS affected = ROW_COUNT;
    IF affected <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'source observation lease or fencing token is stale';
    END IF;

    IF transitioned AND requested_resource_kind = 'SOURCE_CONNECTION' THEN
        INSERT INTO delivery.source_observation_tasks (
            tenant_id, resource_kind, resource_id, resource_version,
            available_at, fencing_token, created_at, updated_at
        )
        SELECT binding.tenant_id, 'REPOSITORY_BINDING', binding.id,
               binding.resource_version, effective_now, 0,
               effective_now, effective_now
          FROM delivery.repository_bindings AS binding
         WHERE binding.tenant_id = requested_tenant_id
           AND binding.source_connection_id = requested_resource_id
        ON CONFLICT ON CONSTRAINT source_observation_tasks_pkey DO UPDATE
           SET resource_version = excluded.resource_version,
               available_at = least(
                   source_observation_tasks.available_at,
                   excluded.available_at
               ),
               lease_owner = NULL,
               lease_expires_at = NULL,
               updated_at = greatest(
                   excluded.updated_at,
                   source_observation_tasks.last_claimed_at
               );
    END IF;

    IF transitioned THEN
        INSERT INTO delivery.audit_operations (
            tenant_id, id, operation_kind, target_kind, target_id, created_at
        ) VALUES (
            requested_tenant_id, expected_operation_id,
            'SOURCE_HEALTH_OBSERVATION', expected_target_kind,
            requested_resource_id, effective_now
        );
        INSERT INTO delivery.audit_outbox (
            tenant_id, event_id, operation_id, status, available_at,
            attempts, fencing_token, created_at, updated_at, document
        ) VALUES (
            requested_tenant_id, expected_event_id, expected_operation_id,
            'PENDING', effective_now, 0, 0, effective_now, effective_now,
            submitted_audit_event
        );
    END IF;

    RETURN submitted_resource;
END
$function$;

REVOKE ALL ON FUNCTION delivery.complete_source_observation(
    text, text, text, bigint, text, bigint, jsonb, jsonb
) FROM PUBLIC, matrix_devops_api, matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.complete_source_observation(
    text, text, text, bigint, text, bigint, jsonb, jsonb
) TO matrix_devops_source_observer;

CREATE OR REPLACE FUNCTION delivery.build_worker_readiness()
RETURNS TABLE (ready boolean, schema_version bigint, checked_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT
        to_regclass('delivery.pipeline_runs') IS NOT NULL
        AND to_regclass('delivery.pipeline_run_tasks') IS NOT NULL
        AND to_regclass('delivery.source_archives') IS NOT NULL
        AND to_regclass('delivery.build_receipts') IS NOT NULL
        AND to_regclass('delivery.build_worker_heartbeat') IS NOT NULL
        AND to_regprocedure(
            'delivery.record_build_worker_heartbeat(text)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.claim_build_task(text,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.renew_build_task(text,text,text,text,bigint,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.complete_build_task(text,text,text,text,bigint,text,text,jsonb,jsonb,jsonb)'
        ) IS NOT NULL
        AND EXISTS (
            SELECT 1
              FROM delivery.build_worker_heartbeat AS heartbeat
             WHERE heartbeat.singleton
               AND heartbeat.observed_at <= transaction_timestamp()
               AND heartbeat.observed_at
                    >= transaction_timestamp() - interval '30 seconds'
        )
        AND NOT EXISTS (
            SELECT 1
              FROM delivery.pipeline_run_tasks AS task
             WHERE task.stage = 'VERIFY'
               AND task.fencing_token >= 9007199254740991
        )
        AND NOT EXISTS (
            SELECT 1
              FROM delivery.build_receipts AS receipt
              JOIN delivery.pipeline_runs AS run
                ON run.tenant_id = receipt.tenant_id
               AND run.id = receipt.run_id
               AND run.input_digest = receipt.input_digest
              JOIN delivery.pipeline_run_tasks AS task
                ON task.tenant_id = receipt.tenant_id
               AND task.run_id = receipt.run_id
               AND task.command_id = receipt.command_id
              JOIN delivery.source_archives AS archive
                ON archive.tenant_id = receipt.tenant_id
               AND archive.run_id = receipt.run_id
             WHERE task.stage <> 'VERIFY'
                OR task.status <> 'COMPLETED'
                OR run.stage = 'VERIFY'
                OR receipt.source_archive_digest <> archive.archive_digest
                OR receipt.pipeline_revision_id <> run.pipeline_revision_id
                OR receipt.pipeline_revision_digest <> run.pipeline_revision_digest
        ),
        1::bigint,
        transaction_timestamp()
$function$;

REVOKE ALL ON FUNCTION delivery.build_worker_readiness()
    FROM PUBLIC, matrix_devops_api, matrix_devops_source_fetcher,
         matrix_devops_source_observer;
GRANT EXECUTE ON FUNCTION delivery.build_worker_readiness()
    TO matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.source_fetcher_readiness()
RETURNS TABLE (ready boolean, schema_version bigint, checked_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT
        to_regclass('delivery.pipeline_runs') IS NOT NULL
        AND to_regclass('delivery.pipeline_run_tasks') IS NOT NULL
        AND to_regclass('delivery.source_archives') IS NOT NULL
        AND to_regclass('delivery.source_fetcher_heartbeat') IS NOT NULL
        AND to_regprocedure(
            'delivery.record_source_fetcher_heartbeat(text)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.claim_source_fetch_task(text,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.renew_source_fetch_task(text,text,text,text,bigint,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.complete_source_fetch_task(text,text,text,text,bigint,text,text,jsonb,jsonb,jsonb)'
        ) IS NOT NULL
        AND EXISTS (
            SELECT 1
              FROM delivery.source_fetcher_heartbeat AS heartbeat
             WHERE heartbeat.singleton
               AND heartbeat.observed_at <= transaction_timestamp()
               AND heartbeat.observed_at
                    >= transaction_timestamp() - interval '30 seconds'
        )
        AND NOT EXISTS (
            SELECT 1
              FROM delivery.pipeline_run_tasks AS task
             WHERE task.stage = 'FETCH'
               AND task.fencing_token >= 9007199254740991
        )
        AND NOT EXISTS (
            SELECT 1
              FROM delivery.source_archives AS archive
              JOIN delivery.pipeline_runs AS run
                ON run.tenant_id = archive.tenant_id
               AND run.id = archive.run_id
               AND run.input_digest = archive.input_digest
              JOIN delivery.pipeline_run_tasks AS task
                ON task.tenant_id = archive.tenant_id
               AND task.run_id = archive.run_id
               AND task.command_id = archive.command_id
             WHERE task.stage <> 'FETCH'
                OR task.status <> 'COMPLETED'
                OR run.stage = 'FETCH'
                OR archive.head_commit <>
                    run.document#>>'{input,change,headCommit}'
                OR archive.trusted_base_commit <>
                    run.document#>>'{input,change,trustedBaseCommit}'
        ),
        1::bigint,
        transaction_timestamp()
$function$;

REVOKE ALL ON FUNCTION delivery.source_fetcher_readiness()
    FROM PUBLIC, matrix_devops_api, matrix_devops_source_observer,
         matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.source_fetcher_readiness()
    TO matrix_devops_source_fetcher;

CREATE OR REPLACE FUNCTION delivery.source_observer_readiness()
RETURNS TABLE (ready boolean, schema_version bigint, checked_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $function$
    SELECT
        to_regclass('delivery.source_observation_tasks') IS NOT NULL
        AND to_regclass('delivery.source_observer_heartbeat') IS NOT NULL
        AND to_regprocedure(
            'delivery.record_source_observer_heartbeat(text)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.claim_source_observation(text,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.complete_source_observation(text,text,text,bigint,text,bigint,jsonb,jsonb)'
        ) IS NOT NULL
        AND EXISTS (
            SELECT 1
              FROM delivery.source_observer_heartbeat AS heartbeat
             WHERE heartbeat.singleton
               AND heartbeat.observed_at <= transaction_timestamp()
               AND heartbeat.observed_at
                    >= transaction_timestamp() - interval '30 seconds'
        )
        AND NOT EXISTS (
            SELECT 1
              FROM delivery.source_observation_tasks AS task
             WHERE task.fencing_token >= 9007199254740991
                OR (task.resource_kind = 'SOURCE_CONNECTION' AND NOT EXISTS (
                    SELECT 1
                      FROM delivery.source_connections AS source
                     WHERE source.tenant_id = task.tenant_id
                       AND source.id = task.resource_id
                       AND source.resource_version = task.resource_version
                ))
                OR (task.resource_kind = 'REPOSITORY_BINDING' AND NOT EXISTS (
                    SELECT 1
                      FROM delivery.repository_bindings AS binding
                     WHERE binding.tenant_id = task.tenant_id
                       AND binding.id = task.resource_id
                       AND binding.resource_version = task.resource_version
                ))
        ),
        1::bigint,
        transaction_timestamp()
$function$;

REVOKE ALL ON FUNCTION delivery.source_observer_readiness()
    FROM PUBLIC, matrix_devops_api, matrix_devops_worker;
GRANT EXECUTE ON FUNCTION delivery.source_observer_readiness()
    TO matrix_devops_source_observer;

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
        AND to_regclass('delivery.source_events') IS NOT NULL
        AND to_regclass('delivery.pipeline_runs') IS NOT NULL
        AND to_regclass('delivery.pipeline_run_tasks') IS NOT NULL
        AND to_regclass('delivery.source_archives') IS NOT NULL
        AND to_regclass('delivery.build_receipts') IS NOT NULL
        AND to_regclass('delivery.source_fetcher_heartbeat') IS NOT NULL
        AND to_regclass('delivery.build_worker_heartbeat') IS NOT NULL
        AND to_regclass('delivery.audit_operations') IS NOT NULL
        AND to_regclass('delivery.source_observation_tasks') IS NOT NULL
        AND to_regclass('delivery.source_observer_heartbeat') IS NOT NULL
        AND to_regprocedure(
            'delivery.commit_configuration_mutation(text,bigint,jsonb,jsonb,jsonb,jsonb,jsonb)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.lock_pipeline_run_for_cancellation(text)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.commit_pipeline_run_cancellation(bigint,jsonb,jsonb,jsonb,jsonb)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.lock_pipeline_run_for_replay(text,bigint)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.commit_pipeline_run_replay(bigint,jsonb,jsonb,jsonb)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.commit_run_admission(jsonb,jsonb,jsonb)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.claim_pipeline_run_task(text,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.record_source_fetcher_heartbeat(text)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.claim_source_fetch_task(text,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.record_build_worker_heartbeat(text)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.claim_build_task(text,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.renew_build_task(text,text,text,text,bigint,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.complete_build_task(text,text,text,text,bigint,text,text,jsonb,jsonb,jsonb)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.renew_source_fetch_task(text,text,text,text,bigint,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.complete_source_fetch_task(text,text,text,text,bigint,text,text,jsonb,jsonb,jsonb)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.record_source_observer_heartbeat(text)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.claim_source_observation(text,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.complete_source_observation(text,text,text,bigint,text,bigint,jsonb,jsonb)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.renew_pipeline_run_task(text,text,text,text,bigint,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.advance_pipeline_run_task(text,text,text,text,bigint,text,text,jsonb,jsonb)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.advance_pipeline_run_task(text,text,text,text,bigint,text,text)'
        ) IS NULL
        AND to_regprocedure(
            'delivery.mark_pipeline_run_report_uncertain(text,text,text,text,bigint,timestamp with time zone)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.defer_pipeline_run_reconciliation(text,text,text,text,bigint,timestamp with time zone)'
        ) IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
              FROM delivery.pipeline_run_tasks AS task
              JOIN delivery.pipeline_runs AS run
                ON run.tenant_id = task.tenant_id AND run.id = task.run_id
             WHERE task.fencing_token >= 9007199254740991
                OR (task.status = 'INTENT' AND (
                    run.state IN (
                        'SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION'
                    )
                    OR task.stage <> run.stage
                ))
        )
        AND NOT EXISTS (
            SELECT 1 FROM delivery.pipeline_runs AS run
             WHERE run.state = 'RECONCILING'
               AND NOT EXISTS (
                    SELECT 1 FROM delivery.pipeline_run_tasks AS task
                     WHERE task.tenant_id = run.tenant_id
                       AND task.run_id = run.id
                       AND task.stage = 'REPORT'
                       AND task.status = 'INTENT'
                )
        )
        AND NOT EXISTS (
            SELECT 1 FROM delivery.pipeline_runs AS run
             WHERE run.state IN ('REPORTING', 'RECONCILING', 'SUCCEEDED')
               AND NOT EXISTS (
                    SELECT 1 FROM delivery.build_receipts AS receipt
                     WHERE receipt.tenant_id = run.tenant_id
                       AND receipt.run_id = run.id
                       AND receipt.input_digest = run.input_digest
                       AND receipt.pipeline_revision_id = run.pipeline_revision_id
                       AND receipt.pipeline_revision_digest = run.pipeline_revision_digest
                       AND receipt.conclusion IN ('PASSED', 'FAILED')
               )
        )
        AND NOT EXISTS (
            SELECT 1 FROM delivery.pipeline_runs AS run
             WHERE run.cancellation_requested_at IS NOT NULL
               AND run.state NOT IN (
                    'SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION'
               )
               AND NOT EXISTS (
                    SELECT 1 FROM delivery.pipeline_run_tasks AS task
                     WHERE task.tenant_id = run.tenant_id
                       AND task.run_id = run.id
                       AND task.status = 'INTENT'
               )
        )
        AND NOT EXISTS (
            SELECT active.tenant_id
              FROM delivery.pipeline_runs AS active
             WHERE active.state IN (
                'FETCHING', 'VERIFYING', 'REPORTING', 'RECONCILING'
             )
             GROUP BY active.tenant_id
            HAVING count(*) > 2
        )
        AND NOT EXISTS (
            SELECT 1 FROM delivery.audit_outbox AS outbox
             WHERE outbox.status = 'DEAD_LETTER'
                OR outbox.attempts >= 100
                OR outbox.fencing_token >= 9007199254740991
        )
        AND (SELECT fetcher.ready FROM delivery.source_fetcher_readiness() AS fetcher)
        AND (
            NOT EXISTS (SELECT 1 FROM delivery.source_connections)
            OR EXISTS (
                SELECT 1
                  FROM delivery.source_observer_heartbeat AS heartbeat
                 WHERE heartbeat.singleton
                   AND heartbeat.observed_at <= transaction_timestamp()
                   AND heartbeat.observed_at
                        >= transaction_timestamp() - interval '30 seconds'
            )
        ),
        1::bigint,
        transaction_timestamp()
$function$;

REVOKE ALL ON FUNCTION delivery.readiness()
    FROM PUBLIC, matrix_devops_source_fetcher,
         matrix_devops_worker, matrix_devops_source_observer;
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
        AND to_regclass('delivery.pipeline_run_tasks') IS NOT NULL
        AND to_regprocedure('delivery.claim_pipeline_run_task(text,integer)') IS NOT NULL
        AND to_regprocedure(
            'delivery.renew_pipeline_run_task(text,text,text,text,bigint,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.advance_pipeline_run_task(text,text,text,text,bigint,text,text,jsonb,jsonb)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.advance_pipeline_run_task(text,text,text,text,bigint,text,text)'
        ) IS NULL
        AND to_regprocedure(
            'delivery.mark_pipeline_run_report_uncertain(text,text,text,text,bigint,timestamp with time zone)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.defer_pipeline_run_reconciliation(text,text,text,text,bigint,timestamp with time zone)'
        ) IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
              FROM delivery.pipeline_run_tasks AS task
              JOIN delivery.pipeline_runs AS run
                ON run.tenant_id = task.tenant_id AND run.id = task.run_id
             WHERE task.fencing_token >= 9007199254740991
                OR (task.status = 'INTENT' AND (
                    run.state IN (
                        'SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION'
                    )
                    OR task.stage <> run.stage
                ))
        )
        AND NOT EXISTS (
            SELECT 1 FROM delivery.pipeline_runs AS run
             WHERE run.state = 'RECONCILING'
               AND NOT EXISTS (
                    SELECT 1 FROM delivery.pipeline_run_tasks AS task
                     WHERE task.tenant_id = run.tenant_id
                       AND task.run_id = run.id
                       AND task.stage = 'REPORT'
                       AND task.status = 'INTENT'
                )
        )
        AND NOT EXISTS (
            SELECT 1 FROM delivery.pipeline_runs AS run
             WHERE run.cancellation_requested_at IS NOT NULL
               AND run.state NOT IN (
                    'SUCCEEDED', 'FAILED', 'CANCELLED', 'MANUAL_INTERVENTION'
               )
               AND NOT EXISTS (
                    SELECT 1 FROM delivery.pipeline_run_tasks AS task
                     WHERE task.tenant_id = run.tenant_id
                       AND task.run_id = run.id
                       AND task.status = 'INTENT'
               )
        )
        AND NOT EXISTS (
            SELECT active.tenant_id
              FROM delivery.pipeline_runs AS active
             WHERE active.state IN (
                'FETCHING', 'VERIFYING', 'REPORTING', 'RECONCILING'
             )
             GROUP BY active.tenant_id
            HAVING count(*) > 2
        )
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
    FROM PUBLIC, matrix_devops_api, matrix_devops_source_fetcher,
         matrix_devops_source_observer;
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
    FROM matrix_devops_api, matrix_devops_source_fetcher,
         matrix_devops_worker, matrix_devops_source_observer;
GRANT SELECT ON delivery.projects TO matrix_devops_api;
GRANT SELECT ON delivery.source_connections TO matrix_devops_api;
GRANT SELECT ON delivery.repository_bindings TO matrix_devops_api;
GRANT SELECT ON delivery.repository_binding_revisions TO matrix_devops_api;
GRANT SELECT ON delivery.pipelines TO matrix_devops_api;
GRANT SELECT ON delivery.pipeline_revisions TO matrix_devops_api;
GRANT SELECT ON delivery.source_events TO matrix_devops_api;
GRANT SELECT ON delivery.pipeline_runs TO matrix_devops_api;
GRANT SELECT ON delivery.mutations TO matrix_devops_api;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA delivery
    FROM matrix_devops_source_fetcher;
GRANT EXECUTE ON FUNCTION delivery.record_source_fetcher_heartbeat(text)
    TO matrix_devops_source_fetcher;
GRANT EXECUTE ON FUNCTION delivery.claim_source_fetch_task(text, integer)
    TO matrix_devops_source_fetcher;
GRANT EXECUTE ON FUNCTION delivery.renew_source_fetch_task(
    text, text, text, text, bigint, integer
) TO matrix_devops_source_fetcher;
GRANT EXECUTE ON FUNCTION delivery.complete_source_fetch_task(
    text, text, text, text, bigint, text, text, jsonb, jsonb, jsonb
) TO matrix_devops_source_fetcher;
GRANT EXECUTE ON FUNCTION delivery.source_fetcher_readiness()
    TO matrix_devops_source_fetcher;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA delivery
    FROM matrix_devops_source_observer;
GRANT EXECUTE ON FUNCTION delivery.record_source_observer_heartbeat(text)
    TO matrix_devops_source_observer;
GRANT EXECUTE ON FUNCTION delivery.claim_source_observation(text, integer)
    TO matrix_devops_source_observer;
GRANT EXECUTE ON FUNCTION delivery.complete_source_observation(
    text, text, text, bigint, text, bigint, jsonb, jsonb
) TO matrix_devops_source_observer;
GRANT EXECUTE ON FUNCTION delivery.source_observer_readiness()
    TO matrix_devops_source_observer;

COMMIT;
