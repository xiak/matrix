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
    state text COLLATE "C" NOT NULL,
    stage text COLLATE "C" NOT NULL,
    reason text COLLATE "C",
    resource_version bigint NOT NULL,
    completed_at timestamptz(6),
    created_at timestamptz(6) NOT NULL,
    updated_at timestamptz(6) NOT NULL,
    document jsonb NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT pipeline_runs_event_revision_uq UNIQUE (
        tenant_id, source_event_id, pipeline_revision_id
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
UPDATE delivery.pipeline_runs
   SET input_digest = document->>'inputDigest'
 WHERE input_digest IS NULL;
ALTER TABLE delivery.pipeline_runs
    ALTER COLUMN input_digest SET NOT NULL;

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
        )
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
SELECT tenant_id, id, 'CONFIGURATION_MUTATION', target_kind, target_id, created_at
  FROM delivery.mutations
ON CONFLICT (tenant_id, id) DO NOTHING;

DROP POLICY owner_schema_upgrade ON delivery.mutations;

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
            FOREIGN KEY (tenant_id, id)
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
ALTER TABLE delivery.mutations ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.mutations FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.audit_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.audit_operations FORCE ROW LEVEL SECURITY;
ALTER TABLE delivery.audit_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE delivery.audit_outbox FORCE ROW LEVEL SECURITY;

DO $matrix_delivery_policy$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'projects', 'source_connections', 'repository_bindings',
        'repository_binding_revisions', 'pipelines', 'pipeline_revisions',
        'source_events', 'pipeline_runs', 'pipeline_run_tasks',
        'mutations', 'audit_operations',
        'audit_outbox'
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
END
$matrix_run_worker_owner_policy$;

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
                repository_binding_digest, state, stage, reason,
                resource_version, completed_at, created_at, updated_at, document
            ) VALUES (
                effective_tenant_id, run_document->>'id', run_document->>'inputDigest', admitted_event_id,
                admitted_content_digest, run_document->>'pipelineId',
                admitted_project_id,
                run_document#>>'{input,pipelineRevisionId}',
                run_document#>>'{input,pipelineRevisionDigest}',
                admitted_repository_binding_id, admitted_repository_binding_digest,
                'QUEUED', 'RECEIVE', 'EVENT_ADMITTED', 1, NULL,
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
       OR requested_lease_seconds NOT BETWEEN 1 AND 300 THEN
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
                AND task.available_at <= transaction_timestamp()
                AND task.fencing_token < 9007199254740991
                AND (task.lease_owner IS NULL
                    OR task.lease_expires_at <= transaction_timestamp()))
            OR (task.command_id IS NULL
                AND run.state IN ('QUEUED', 'FETCHING', 'VERIFYING', 'REPORTING'))
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

REVOKE ALL ON FUNCTION delivery.claim_pipeline_run_task(text, integer)
    FROM PUBLIC, matrix_devops_api;
GRANT EXECUTE ON FUNCTION delivery.claim_pipeline_run_task(text, integer)
    TO matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.renew_pipeline_run_task(
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
       OR requested_lease_seconds NOT BETWEEN 1 AND 300 THEN
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
    RETURNING task.lease_expires_at INTO renewed_expires_at;
    IF renewed_expires_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MX412',
            MESSAGE = 'PipelineRun task lease or fencing token is stale';
    END IF;
    RETURN renewed_expires_at;
END
$function$;

REVOKE ALL ON FUNCTION delivery.renew_pipeline_run_task(
    text, text, text, text, bigint, integer
) FROM PUBLIC, matrix_devops_api;
GRANT EXECUTE ON FUNCTION delivery.renew_pipeline_run_task(
    text, text, text, text, bigint, integer
) TO matrix_devops_worker;

CREATE OR REPLACE FUNCTION delivery.advance_pipeline_run_task(
    requested_tenant_id text,
    requested_run_id text,
    requested_command_id text,
    requested_worker_id text,
    expected_fencing_token bigint,
    requested_state text,
    requested_reason text
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
    effective_time_text text;
    next_status jsonb;
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
       OR expected_fencing_token NOT BETWEEN 1 AND 9007199254740991 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'PipelineRun task transition identity is invalid';
    END IF;

    SELECT run.state,
           run.stage,
           run.resource_version,
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
       OR (requested_state = 'MANUAL_INTERVENTION'
            AND current_reconciliation_attempts < 10)
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
    effective_time_text := to_char(
        effective_now AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    );
    next_status := jsonb_build_object(
        'state', requested_state,
        'stage', next_stage,
        'resourceVersion', current_resource_version + 1,
        'observedAt', effective_time_text
    );
    IF requested_reason IS NOT NULL THEN
        next_status := next_status || jsonb_build_object('reason', requested_reason);
    END IF;
    IF terminal THEN
        next_status := next_status || jsonb_build_object('completedAt', effective_time_text);
    END IF;
    next_document := jsonb_set(
        jsonb_set(current_run_document, '{status}', next_status, false),
        '{updatedAt}', to_jsonb(effective_time_text), false
    );

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
    RETURN next_document;
END
$function$;

REVOKE ALL ON FUNCTION delivery.advance_pipeline_run_task(
    text, text, text, text, bigint, text, text
) FROM PUBLIC, matrix_devops_api;
GRANT EXECUTE ON FUNCTION delivery.advance_pipeline_run_task(
    text, text, text, text, bigint, text, text
) TO matrix_devops_worker;

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
        AND to_regclass('delivery.audit_operations') IS NOT NULL
        AND to_regprocedure(
            'delivery.commit_configuration_mutation(text,bigint,jsonb,jsonb,jsonb,jsonb,jsonb)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.commit_run_admission(jsonb,jsonb,jsonb)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.claim_pipeline_run_task(text,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.renew_pipeline_run_task(text,text,text,text,bigint,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.advance_pipeline_run_task(text,text,text,text,bigint,text,text)'
        ) IS NOT NULL
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
        AND to_regclass('delivery.pipeline_run_tasks') IS NOT NULL
        AND to_regprocedure('delivery.claim_pipeline_run_task(text,integer)') IS NOT NULL
        AND to_regprocedure(
            'delivery.renew_pipeline_run_task(text,text,text,text,bigint,integer)'
        ) IS NOT NULL
        AND to_regprocedure(
            'delivery.advance_pipeline_run_task(text,text,text,text,bigint,text,text)'
        ) IS NOT NULL
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
GRANT SELECT ON delivery.source_events TO matrix_devops_api;
GRANT SELECT ON delivery.pipeline_runs TO matrix_devops_api;
GRANT SELECT ON delivery.mutations TO matrix_devops_api;

COMMIT;
