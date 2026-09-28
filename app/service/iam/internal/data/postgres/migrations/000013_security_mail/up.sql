SET LOCAL ROLE matrix_iam_owner;

-- Contact possession, private delivery and its short-lived secret are not
-- authentication authority. This owner never mutates a password or MFA factor.
CREATE TABLE IF NOT EXISTS iam.email_verification_keys (
    installation_id text COLLATE "C" NOT NULL REFERENCES iam.bootstrap_receipts(installation_id),
    key_id text COLLATE "C" NOT NULL CHECK(key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    format_version integer NOT NULL CHECK(format_version=1),
    material_commitment text NOT NULL CHECK(material_commitment ~ '^sha256:[0-9a-f]{64}$'),
    PRIMARY KEY(installation_id,key_id)
);
CREATE TABLE IF NOT EXISTS iam.email_verification_keysets (
    installation_id text COLLATE "C" NOT NULL REFERENCES iam.bootstrap_receipts(installation_id),
    revision bigint NOT NULL CHECK(revision>0),
    registration jsonb NOT NULL CHECK(jsonb_typeof(registration)='object' AND octet_length(registration::text)<=8192),
    PRIMARY KEY(installation_id,revision)
);

CREATE OR REPLACE FUNCTION iam.valid_security_mail_address(address text)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE parts text[]; label text;
BEGIN
    IF address IS NULL OR octet_length(address)>254 THEN RETURN false; END IF;
    parts:=string_to_array(address,'@');
    IF cardinality(parts)<>2 OR octet_length(parts[1]) NOT BETWEEN 1 AND 64
        OR parts[1] COLLATE "C" !~ '^[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+$'
        OR left(parts[1],1)='.' OR right(parts[1],1)='.' OR position('..' IN parts[1])>0
        OR octet_length(parts[2]) NOT BETWEEN 3 AND 253 OR position('.' IN parts[2])=0 THEN RETURN false; END IF;
    FOREACH label IN ARRAY string_to_array(parts[2],'.') LOOP
        IF label COLLATE "C" !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
END $function$;

CREATE TABLE IF NOT EXISTS iam.notification_contact_verifications (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL CHECK(id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    user_id text COLLATE "C" NOT NULL,
    session_id text COLLATE "C",
    request_id text COLLATE "C" NOT NULL CHECK(request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    intent_digest text NOT NULL CHECK(intent_digest ~ '^sha256:[0-9a-f]{64}$'),
    installation_id text COLLATE "C" NOT NULL,
    bootstrap_digest text NOT NULL CHECK(bootstrap_digest ~ '^sha256:[0-9a-f]{64}$'),
    credential_generation bigint NOT NULL CHECK(credential_generation BETWEEN 1 AND 9007199254740991),
    contact_revision bigint NOT NULL CHECK(contact_revision=0),
    email text COLLATE "C" NOT NULL CHECK(iam.valid_security_mail_address(email)),
    key_id text COLLATE "C" NOT NULL,
    nonce bytea NOT NULL CHECK(octet_length(nonce)=12),
    ciphertext bytea NOT NULL CHECK(octet_length(ciphertext)=24),
    issued_at timestamptz(6) NOT NULL,
    expires_at timestamptz(6) NOT NULL,
    state text NOT NULL CHECK(state IN ('PENDING','VERIFIED','CANCELLED','EXPIRED')),
    completed_at timestamptz(6),
    confirmation_request_id text COLLATE "C",
    completion_event_id text COLLATE "C",
    started_event_id text COLLATE "C" NOT NULL,
    notification_id text COLLATE "C" NOT NULL,
    PRIMARY KEY(tenant_id,id),
    UNIQUE(tenant_id,id,user_id),
    UNIQUE(tenant_id,user_id,request_id),
    FOREIGN KEY(tenant_id,user_id) REFERENCES iam.principals(tenant_id,id),
    FOREIGN KEY(tenant_id,session_id) REFERENCES iam.sessions(tenant_id,id),
    FOREIGN KEY(installation_id,key_id) REFERENCES iam.email_verification_keys(installation_id,key_id),
    FOREIGN KEY(tenant_id,started_event_id) REFERENCES iam.audit_outbox(tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY(tenant_id,completion_event_id) REFERENCES iam.audit_outbox(tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT notification_verification_completion CHECK((state='PENDING' AND completed_at IS NULL AND confirmation_request_id IS NULL AND completion_event_id IS NULL)
        OR (state='VERIFIED' AND completed_at IS NOT NULL AND completed_at>=issued_at AND completed_at<expires_at
            AND confirmation_request_id IS NOT NULL AND confirmation_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' AND completion_event_id IS NOT NULL)
        OR (state='CANCELLED' AND completed_at IS NOT NULL AND completed_at>=issued_at AND confirmation_request_id IS NULL AND completion_event_id IS NULL)
        OR (state='EXPIRED' AND completed_at IS NOT NULL AND completed_at=expires_at AND confirmation_request_id IS NULL AND completion_event_id IS NULL))
);
ALTER TABLE iam.notification_contact_verifications ADD COLUMN IF NOT EXISTS enrollment_challenge_id text COLLATE "C";
ALTER TABLE iam.notification_contact_verifications ALTER COLUMN session_id DROP NOT NULL;
-- The original ten-minute Session ceremony is unchanged. Initial setup can
-- only use the remaining lifetime of its original five-minute challenge.
ALTER TABLE iam.notification_contact_verifications DROP CONSTRAINT IF EXISTS notification_contact_verifications_check;
ALTER TABLE iam.notification_contact_verifications DROP CONSTRAINT IF EXISTS notification_contact_verifications_check1;
ALTER TABLE iam.notification_contact_verifications DROP CONSTRAINT IF EXISTS notification_verification_completion;
ALTER TABLE iam.notification_contact_verifications ADD CONSTRAINT notification_verification_completion CHECK(
    (state='PENDING' AND completed_at IS NULL AND confirmation_request_id IS NULL AND completion_event_id IS NULL)
    OR (state='VERIFIED' AND completed_at IS NOT NULL AND completed_at>=issued_at AND completed_at<expires_at
        AND confirmation_request_id IS NOT NULL AND confirmation_request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' AND completion_event_id IS NOT NULL)
    OR (state='CANCELLED' AND completed_at IS NOT NULL AND completed_at>=issued_at AND confirmation_request_id IS NULL AND completion_event_id IS NULL)
    OR (state='EXPIRED' AND completed_at IS NOT NULL AND completed_at=expires_at AND confirmation_request_id IS NULL AND completion_event_id IS NULL));
ALTER TABLE iam.notification_contact_verifications DROP CONSTRAINT IF EXISTS notification_verification_origin;
ALTER TABLE iam.notification_contact_verifications ADD CONSTRAINT notification_verification_origin CHECK(
    num_nonnulls(session_id,enrollment_challenge_id)=1 AND expires_at>issued_at
    AND expires_at<=issued_at+interval '10 minutes'
    AND (session_id IS NULL OR expires_at=issued_at+interval '10 minutes'));
DO $contact_challenge$
BEGIN
    IF NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint WHERE conrelid='iam.notification_contact_verifications'::regclass AND conname='contact_initial_enrollment') THEN
        ALTER TABLE iam.notification_contact_verifications ADD CONSTRAINT contact_initial_enrollment
            FOREIGN KEY(tenant_id,enrollment_challenge_id) REFERENCES iam.authentication_challenges(tenant_id,id);
    END IF;
END $contact_challenge$;
CREATE UNIQUE INDEX IF NOT EXISTS notification_contact_one_pending ON iam.notification_contact_verifications(tenant_id,user_id) WHERE state='PENDING';

CREATE TABLE IF NOT EXISTS iam.notification_contacts (
    tenant_id text COLLATE "C" NOT NULL,
    user_id text COLLATE "C" NOT NULL,
    email text COLLATE "C" NOT NULL CHECK(iam.valid_security_mail_address(email)),
    resource_version bigint NOT NULL CHECK(resource_version=1),
    verified_at timestamptz(6) NOT NULL,
    verification_id text COLLATE "C" NOT NULL,
    PRIMARY KEY(tenant_id,user_id),
    FOREIGN KEY(tenant_id,verification_id,user_id) REFERENCES iam.notification_contact_verifications(tenant_id,id,user_id)
);

-- One current window per key, not one unbounded row per attempt. Recipient
-- keys are private purpose digests, never a public address-existence index.
CREATE TABLE IF NOT EXISTS iam.notification_send_budgets (
    scope text COLLATE "C" NOT NULL CHECK(scope IN ('INSTALLATION','ACCOUNT','USER','RECIPIENT')),
    subject text COLLATE "C" NOT NULL,
    window_started_at timestamptz(6) NOT NULL,
    used integer NOT NULL CHECK(used BETWEEN 1 AND 1000),
    PRIMARY KEY(scope,subject)
);
CREATE TABLE IF NOT EXISTS iam.notification_confirmation_attempts (
    tenant_id text COLLATE "C" NOT NULL,
    user_id text COLLATE "C" NOT NULL,
    window_started_at timestamptz(6) NOT NULL,
    used integer NOT NULL CHECK(used BETWEEN 1 AND 5),
    sequence bigint NOT NULL CHECK(sequence>0),
    attempt_id text COLLATE "C" NOT NULL CHECK(attempt_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    verification_id text COLLATE "C" NOT NULL,
    state text NOT NULL CHECK(state IN ('RESERVED','REJECTED','ABANDONED','SUCCEEDED')),
    expires_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,user_id),
    FOREIGN KEY(tenant_id,verification_id,user_id) REFERENCES iam.notification_contact_verifications(tenant_id,id,user_id)
);

CREATE TABLE IF NOT EXISTS iam.security_notifications (
    tenant_id text COLLATE "C" NOT NULL,
    id text COLLATE "C" NOT NULL CHECK(id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    user_id text COLLATE "C" NOT NULL,
    installation_id text COLLATE "C" NOT NULL REFERENCES iam.bootstrap_receipts(installation_id),
    verification_id text COLLATE "C" NOT NULL,
    event_id text COLLATE "C" NOT NULL,
    kind text NOT NULL CHECK(kind IN ('ADDRESS_VERIFICATION','CONTACT_VERIFIED')),
    email text COLLATE "C" NOT NULL CHECK(iam.valid_security_mail_address(email)),
    contact_revision bigint NOT NULL CHECK(contact_revision IN (0,1)),
    created_at timestamptz(6) NOT NULL,
    state text NOT NULL CHECK(state IN ('PENDING','IN_FLIGHT','RETRY_WAIT','ACCEPTED','FAILED','EXPIRED')),
    attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
    fence bigint NOT NULL DEFAULT 0 CHECK(fence>=0),
    worker_id text COLLATE "C",
    lease_expires_at timestamptz(6),
    next_attempt_at timestamptz(6) NOT NULL,
    last_outcome text CHECK(last_outcome IN ('ACCEPTED','REJECTED','UNKNOWN','UNAVAILABLE')),
    last_smtp_code integer,
    updated_at timestamptz(6) NOT NULL,
    PRIMARY KEY(tenant_id,id),
    UNIQUE(tenant_id,event_id,kind),
    FOREIGN KEY(tenant_id,verification_id,user_id) REFERENCES iam.notification_contact_verifications(tenant_id,id,user_id),
    FOREIGN KEY(tenant_id,event_id) REFERENCES iam.audit_outbox(tenant_id,event_id) DEFERRABLE INITIALLY DEFERRED,
    CHECK((state='IN_FLIGHT' AND worker_id IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR (state<>'IN_FLIGHT' AND worker_id IS NULL AND lease_expires_at IS NULL)),
    CHECK(((last_outcome IS NULL AND last_smtp_code IS NULL) OR (last_outcome='ACCEPTED' AND last_smtp_code IS NOT NULL AND last_smtp_code=250 AND state='ACCEPTED')
        OR (last_outcome='REJECTED' AND last_smtp_code IS NOT NULL AND last_smtp_code BETWEEN 400 AND 599)
        OR (last_outcome IN ('UNKNOWN','UNAVAILABLE') AND last_smtp_code IS NULL)) IS TRUE),
    CHECK((kind='ADDRESS_VERIFICATION' AND contact_revision=0) OR (kind='CONTACT_VERIFIED' AND contact_revision=1))
);
CREATE INDEX IF NOT EXISTS security_notifications_due ON iam.security_notifications(next_attempt_at,tenant_id,id)
    WHERE state IN ('PENDING','RETRY_WAIT','IN_FLIGHT');
-- Extend only the closed security-notice kind. The original address/lease
-- constraints remain; an MFA notice carries no verification code envelope.
ALTER TABLE iam.security_notifications DROP CONSTRAINT IF EXISTS security_notifications_kind_check;
ALTER TABLE iam.security_notifications ADD CONSTRAINT security_notifications_kind_check
    CHECK(kind IN ('ADDRESS_VERIFICATION','CONTACT_VERIFIED','AUTHENTICATOR_BOUND','AUTHENTICATOR_REPLACED','RECOVERY_STARTED','AUTHENTICATOR_RECOVERED','RECOVERY_CODES_REGENERATED','SECURITY_SETTINGS_CHANGED'));
ALTER TABLE iam.security_notifications DROP CONSTRAINT IF EXISTS security_notifications_check2;
ALTER TABLE iam.security_notifications ADD CONSTRAINT security_notifications_check2
    CHECK((kind='ADDRESS_VERIFICATION' AND contact_revision=0)
        OR (kind IN ('CONTACT_VERIFIED','AUTHENTICATOR_BOUND','AUTHENTICATOR_REPLACED','RECOVERY_STARTED','AUTHENTICATOR_RECOVERED','RECOVERY_CODES_REGENERATED','SECURITY_SETTINGS_CHANGED') AND contact_revision=1));
DROP TRIGGER IF EXISTS verify_security_settings_change ON iam.security_notifications;
CREATE CONSTRAINT TRIGGER verify_security_settings_change AFTER INSERT OR UPDATE ON iam.security_notifications
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.verify_security_settings_change();
ALTER TABLE iam.security_notifications ENABLE ALWAYS TRIGGER verify_security_settings_change;
DROP TRIGGER IF EXISTS verify_totp_binding ON iam.security_notifications;
CREATE CONSTRAINT TRIGGER verify_totp_binding AFTER INSERT OR UPDATE ON iam.security_notifications
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.verify_totp_binding();
ALTER TABLE iam.security_notifications ENABLE ALWAYS TRIGGER verify_totp_binding;
DROP TRIGGER IF EXISTS verify_authenticator_recovery ON iam.security_notifications;
CREATE CONSTRAINT TRIGGER verify_authenticator_recovery AFTER INSERT OR UPDATE ON iam.security_notifications
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.verify_authenticator_recovery();
ALTER TABLE iam.security_notifications ENABLE ALWAYS TRIGGER verify_authenticator_recovery;
DROP TRIGGER IF EXISTS verify_recovery_regeneration ON iam.security_notifications;
CREATE CONSTRAINT TRIGGER verify_recovery_regeneration AFTER INSERT OR UPDATE ON iam.security_notifications
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.verify_recovery_regeneration();
ALTER TABLE iam.security_notifications ENABLE ALWAYS TRIGGER verify_recovery_regeneration;
CREATE TABLE IF NOT EXISTS iam.security_notification_attempts (
    tenant_id text COLLATE "C" NOT NULL,
    notification_id text COLLATE "C" NOT NULL,
    fence bigint NOT NULL CHECK(fence>0),
    worker_id text COLLATE "C" NOT NULL,
    claimed_at timestamptz(6) NOT NULL,
    lease_expires_at timestamptz(6) NOT NULL CHECK(lease_expires_at=claimed_at+interval '45 seconds'),
    completed_at timestamptz(6),
    outcome text CHECK(outcome IN ('ACCEPTED','REJECTED','UNKNOWN','UNAVAILABLE')),
    smtp_code integer,
    PRIMARY KEY(tenant_id,notification_id,fence),
    FOREIGN KEY(tenant_id,notification_id) REFERENCES iam.security_notifications(tenant_id,id),
    CHECK((outcome IS NULL AND completed_at IS NULL AND smtp_code IS NULL)
        OR (outcome IS NOT NULL AND completed_at IS NOT NULL AND completed_at>=claimed_at AND ((outcome='ACCEPTED' AND smtp_code IS NOT NULL AND smtp_code=250)
            OR (outcome='REJECTED' AND smtp_code IS NOT NULL AND smtp_code BETWEEN 400 AND 599)
            OR (outcome IN ('UNKNOWN','UNAVAILABLE') AND smtp_code IS NULL))))
);

DO $mail_rls$
DECLARE relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['notification_contact_verifications','notification_contacts','notification_confirmation_attempts',
        'security_notifications','security_notification_attempts'] LOOP
        EXECUTE format('ALTER TABLE iam.%I ENABLE ROW LEVEL SECURITY',relation_name);
        EXECUTE format('ALTER TABLE iam.%I FORCE ROW LEVEL SECURITY',relation_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON iam.%I',relation_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON iam.%I USING(tenant_id=iam.current_tenant_id() OR current_setting(''matrix.iam_notification_delivery'',true)=''trusted'') WITH CHECK(tenant_id=iam.current_tenant_id() OR current_setting(''matrix.iam_notification_delivery'',true)=''trusted'')',relation_name);
    END LOOP;
END $mail_rls$;

CREATE OR REPLACE FUNCTION iam.register_email_verification_keyset(document jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; latest iam.email_verification_keysets%ROWTYPE;
    item jsonb; previous_id text:=''; active_found boolean:=false; revision bigint;
BEGIN
    IF document IS NULL OR jsonb_typeof(document) IS DISTINCT FROM 'object' OR octet_length(document::text)>8192
        OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(document) k) IS DISTINCT FROM ARRAY['activeKeyId','contentDigest','keys','keysetRevision','scope']
        OR jsonb_typeof(document->'keys') IS DISTINCT FROM 'array' OR jsonb_array_length(document->'keys') NOT BETWEEN 1 AND 8
        OR jsonb_typeof(document->'keysetRevision') IS DISTINCT FROM 'number'
        OR COALESCE(document->>'keysetRevision','') !~ '^[1-9][0-9]{0,18}$'
        OR jsonb_typeof(document->'contentDigest') IS DISTINCT FROM 'string' OR COALESCE(document->>'contentDigest','') !~ '^sha256:[0-9a-f]{64}$'
        OR jsonb_typeof(document->'activeKeyId') IS DISTINCT FROM 'string' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='email verification registration is invalid';
    END IF;
    revision:=(document->>'keysetRevision')::bigint;
    SELECT * INTO receipt FROM iam.bootstrap_receipts WHERE singleton FOR SHARE;
    IF NOT FOUND OR document->'scope' IS DISTINCT FROM jsonb_build_object('installationId',receipt.installation_id,'bootstrapDigest',receipt.content_digest) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='email verification installation differs';
    END IF;
    LOCK TABLE iam.email_verification_keysets IN SHARE ROW EXCLUSIVE MODE;
    SELECT * INTO latest FROM iam.email_verification_keysets s WHERE s.installation_id=receipt.installation_id ORDER BY s.revision DESC LIMIT 1;
    IF FOUND AND (revision<latest.revision OR (revision=latest.revision AND document<>latest.registration)) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='email verification keyset conflicts';
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(document->'keys') LOOP
        IF jsonb_typeof(item) IS DISTINCT FROM 'object'
            OR (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(item) k) IS DISTINCT FROM ARRAY['formatVersion','keyId','materialCommitment']
            OR jsonb_typeof(item->'keyId') IS DISTINCT FROM 'string'
            OR COALESCE(item->>'keyId','') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
            OR (item->>'keyId') COLLATE "C"<=previous_id COLLATE "C" OR item->'formatVersion' IS DISTINCT FROM '1'::jsonb
            OR jsonb_typeof(item->'materialCommitment') IS DISTINCT FROM 'string' OR COALESCE(item->>'materialCommitment','') !~ '^sha256:[0-9a-f]{64}$' THEN
            RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='email verification key is invalid';
        END IF;
        previous_id:=item->>'keyId'; active_found:=active_found OR previous_id=document->>'activeKeyId';
        IF EXISTS(SELECT 1 FROM iam.email_verification_keys k WHERE k.installation_id=receipt.installation_id AND k.key_id=previous_id
            AND k.material_commitment<>item->>'materialCommitment') THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='email verification material conflicts';
        END IF;
    END LOOP;
    IF NOT active_found OR EXISTS(SELECT 1 FROM iam.email_verification_keys k WHERE k.installation_id<>receipt.installation_id
        OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(document->'keys') v WHERE v->>'keyId'=k.key_id)) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='email verification key retirement is unsupported';
    END IF;
    IF revision=latest.revision THEN RETURN; END IF;
    INSERT INTO iam.email_verification_keys SELECT receipt.installation_id,k->>'keyId',1,k->>'materialCommitment'
        FROM jsonb_array_elements(document->'keys') k ON CONFLICT DO NOTHING;
    INSERT INTO iam.email_verification_keysets VALUES(receipt.installation_id,revision,document);
END $function$;

-- Not granted to any runtime role. The caller retains identity locks before
-- taking budgets in this fixed order; no budget function takes a USER lock.
CREATE OR REPLACE FUNCTION iam.debit_notification_send_budget(budget_scope text,budget_subject text,window_seconds integer,maximum integer)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE current_budget iam.notification_send_budgets%ROWTYPE; effective_now timestamptz(6):=clock_timestamp();
BEGIN
    INSERT INTO iam.notification_send_budgets(scope,subject,window_started_at,used)
        VALUES(budget_scope,budget_subject,effective_now,1) ON CONFLICT DO NOTHING;
    IF FOUND THEN RETURN; END IF;
    SELECT * INTO current_budget FROM iam.notification_send_budgets b WHERE b.scope=budget_scope AND b.subject=budget_subject FOR UPDATE;
    IF current_budget.window_started_at+make_interval(secs=>window_seconds)>effective_now AND current_budget.used>=maximum THEN
        RAISE EXCEPTION USING ERRCODE='P0003',MESSAGE='notification work is at capacity';
    END IF;
    UPDATE iam.notification_send_budgets b SET
        used=CASE WHEN current_budget.window_started_at+make_interval(secs=>window_seconds)>effective_now THEN current_budget.used+1 ELSE 1 END,
        window_started_at=CASE WHEN current_budget.window_started_at+make_interval(secs=>window_seconds)>effective_now THEN current_budget.window_started_at ELSE effective_now END
        WHERE b.scope=budget_scope AND b.subject=budget_subject;
END $function$;

DROP FUNCTION IF EXISTS iam.start_notification_verification(text,text,text,text,bigint,text,text,text,text,text,text,bigint,text,text,bytea,bytea,timestamptz,timestamptz,jsonb);
CREATE OR REPLACE FUNCTION iam.start_notification_verification(
    tenant text,subject_id text,caller_id text,enrollment_challenge text,password_attempt text,password_sequence bigint,
    request_id text,intent_digest text,verification_id text,notification_id text,
    installation text,bootstrap_digest text,credential_generation bigint,recipient text,key_id text,
    nonce bytea,ciphertext bytea,issued_at timestamptz,expires_at timestamptz,audit_event jsonb
)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE generation bigint; registration jsonb; existing iam.notification_contact_verifications%ROWTYPE;
BEGIN
    registration:=iam.read_email_verification_keyset();
    IF registration IS NULL OR registration->'scope' IS DISTINCT FROM jsonb_build_object('installationId',installation,'bootstrapDigest',bootstrap_digest)
        OR registration->>'activeKeyId' IS DISTINCT FROM key_id THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='notification material unavailable';
    END IF;
    generation:=iam.lock_notification_subject(tenant,subject_id,caller_id,enrollment_challenge);
    IF generation IS DISTINCT FROM credential_generation OR NOT iam.valid_security_mail_address(recipient)
        OR COALESCE(request_id,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'
        OR COALESCE(intent_digest,'') !~ '^sha256:[0-9a-f]{64}$'
        OR issued_at IS DISTINCT FROM transaction_timestamp()
        OR expires_at IS DISTINCT FROM (CASE WHEN enrollment_challenge IS NULL THEN issued_at+interval '10 minutes'
            ELSE (SELECT c.expires_at FROM iam.authentication_challenges c WHERE c.tenant_id=tenant AND c.id=enrollment_challenge) END)
        OR expires_at<=clock_timestamp() OR octet_length(nonce) IS DISTINCT FROM 12 OR octet_length(ciphertext) IS DISTINCT FROM 24 THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='notification verification input is invalid';
    END IF;
    IF enrollment_challenge IS NULL THEN
        PERFORM iam.consume_password_attempt(tenant,subject_id,caller_id,password_attempt,password_sequence,'NOTIFICATION_CONTACT_VERIFY',intent_digest);
    ELSIF password_attempt IS NOT NULL OR password_sequence IS NOT NULL THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='notification authentication origins are mutually exclusive';
    END IF;
    SELECT * INTO existing FROM iam.notification_contact_verifications v WHERE v.tenant_id=tenant AND v.user_id=subject_id AND v.request_id=start_notification_verification.request_id;
    IF FOUND THEN
        IF (existing.session_id,existing.enrollment_challenge_id) IS DISTINCT FROM (caller_id,enrollment_challenge)
            OR existing.credential_generation<>generation OR existing.email<>recipient OR existing.intent_digest<>intent_digest THEN
            RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='notification request conflicts';
        END IF;
        RETURN iam.notification_verification_snapshot(tenant,existing.id);
    END IF;
    IF EXISTS(SELECT 1 FROM iam.notification_contacts c WHERE c.tenant_id=tenant AND c.user_id=subject_id) THEN
        RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='notification contact already exists';
    END IF;
    -- Sender budgets are committed with the one immutable intent, never with
    -- SMTP I/O. A failed transaction cannot leave a message to send.
    PERFORM iam.debit_notification_send_budget('INSTALLATION',installation,3600,1000);
    PERFORM iam.debit_notification_send_budget('ACCOUNT',tenant,3600,100);
    PERFORM iam.debit_notification_send_budget('USER',tenant||'/'||subject_id,600,3);
    PERFORM iam.debit_notification_send_budget('RECIPIENT',encode(sha256(convert_to(jsonb_build_array(installation,recipient)::text,'UTF8')),'hex'),3600,5);
    -- Prune only expired private recipient windows, not live attempts or facts.
    DELETE FROM iam.notification_send_budgets WHERE (scope,subject) IN (
        SELECT b.scope,b.subject FROM iam.notification_send_budgets b WHERE b.scope='RECIPIENT'
            AND b.window_started_at+interval '1 hour'<=clock_timestamp() ORDER BY b.window_started_at LIMIT 32 FOR UPDATE SKIP LOCKED);
    UPDATE iam.notification_contact_verifications v SET state=CASE WHEN v.expires_at<=clock_timestamp() THEN 'EXPIRED' ELSE 'CANCELLED' END,
        completed_at=CASE WHEN v.expires_at<=clock_timestamp() THEN v.expires_at ELSE transaction_timestamp() END
        WHERE v.tenant_id=tenant AND v.user_id=subject_id AND v.state='PENDING';
    PERFORM iam.assert_audit_event(audit_event,tenant,'iam.notification-contact.verification-started','USER',subject_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,subject_id,audit_event);
    IF audit_event->>'requestId' IS DISTINCT FROM request_id THEN RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='notification request fact differs'; END IF;
    INSERT INTO iam.notification_contact_verifications(tenant_id,id,user_id,session_id,enrollment_challenge_id,request_id,intent_digest,installation_id,bootstrap_digest,
        credential_generation,contact_revision,email,key_id,nonce,ciphertext,issued_at,expires_at,state,started_event_id,notification_id)
    VALUES(tenant,verification_id,subject_id,caller_id,enrollment_challenge,request_id,intent_digest,installation,bootstrap_digest,generation,0,recipient,key_id,
        nonce,ciphertext,issued_at,expires_at,'PENDING',audit_event->>'eventId',notification_id);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
        VALUES(tenant,audit_event->>'eventId',audit_event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
    INSERT INTO iam.security_notifications(tenant_id,id,user_id,installation_id,verification_id,event_id,kind,email,contact_revision,created_at,state,next_attempt_at,updated_at)
        VALUES(tenant,notification_id,subject_id,installation,verification_id,audit_event->>'eventId','ADDRESS_VERIFICATION',recipient,0,issued_at,'PENDING',issued_at,issued_at);
    RETURN iam.notification_verification_snapshot(tenant,verification_id);
END $function$;

DROP FUNCTION IF EXISTS iam.reserve_notification_confirmation(text,text,text,text,text);
CREATE OR REPLACE FUNCTION iam.reserve_notification_confirmation(tenant text,subject_id text,caller_id text,enrollment_challenge text,verification text,attempt text)
RETURNS TABLE(installation_id text,bootstrap_digest text,credential_generation bigint,contact_revision bigint,email text,
    issued_at timestamptz,expires_at timestamptz,key_id text,nonce bytea,ciphertext bytea,attempt_sequence bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE generation bigint; original iam.notification_contact_verifications%ROWTYPE;
    budget iam.notification_confirmation_attempts%ROWTYPE; effective_now timestamptz(6); used_count integer; started timestamptz; next_sequence bigint;
BEGIN
    generation:=iam.lock_notification_subject(tenant,subject_id,caller_id,enrollment_challenge);
    SELECT * INTO original FROM iam.notification_contact_verifications v WHERE v.tenant_id=tenant AND v.id=verification AND v.user_id=subject_id FOR UPDATE;
    IF NOT FOUND OR (original.session_id,original.enrollment_challenge_id) IS DISTINCT FROM (caller_id,enrollment_challenge)
        OR original.credential_generation<>generation THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='notification verification unavailable';
    END IF;
    effective_now:=clock_timestamp();
    IF original.state<>'PENDING' OR original.expires_at<=effective_now THEN
        RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='notification verification ended';
    END IF;
    SELECT * INTO budget FROM iam.notification_confirmation_attempts b WHERE b.tenant_id=tenant AND b.user_id=subject_id FOR UPDATE;
    IF (budget.state='RESERVED' AND budget.expires_at>effective_now)
        OR (budget.window_started_at+interval '10 minutes'>effective_now AND budget.used>=5) THEN RETURN; END IF;
    IF budget.attempt_id=attempt THEN RETURN; END IF;
    started:=CASE WHEN budget.window_started_at+interval '10 minutes'>effective_now THEN budget.window_started_at ELSE effective_now END;
    used_count:=CASE WHEN budget.window_started_at+interval '10 minutes'>effective_now THEN budget.used+1 ELSE 1 END;
    next_sequence:=COALESCE(budget.sequence,0)+1;
    INSERT INTO iam.notification_confirmation_attempts AS b(tenant_id,user_id,window_started_at,used,sequence,attempt_id,verification_id,state,expires_at)
        VALUES(tenant,subject_id,started,used_count,next_sequence,attempt,verification,'RESERVED',least(original.expires_at,effective_now+interval '30 seconds'))
        ON CONFLICT ON CONSTRAINT notification_confirmation_attempts_pkey DO UPDATE SET window_started_at=EXCLUDED.window_started_at,
            used=EXCLUDED.used,sequence=EXCLUDED.sequence,attempt_id=EXCLUDED.attempt_id,verification_id=EXCLUDED.verification_id,state='RESERVED',expires_at=EXCLUDED.expires_at;
    RETURN QUERY SELECT original.installation_id,original.bootstrap_digest,original.credential_generation,original.contact_revision,original.email,
        original.issued_at,original.expires_at,original.key_id,original.nonce,original.ciphertext,next_sequence;
END $function$;

CREATE OR REPLACE FUNCTION iam.reject_notification_confirmation(tenant text,subject_id text,attempt text,attempt_sequence bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts a WHERE a.id=tenant FOR SHARE;
    PERFORM 1 FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=subject_id FOR UPDATE;
    UPDATE iam.notification_confirmation_attempts b SET state=CASE WHEN b.expires_at>clock_timestamp() THEN 'REJECTED' ELSE 'ABANDONED' END
        WHERE b.tenant_id=tenant AND b.user_id=subject_id AND b.attempt_id=attempt AND b.sequence=attempt_sequence AND b.state='RESERVED';
END $function$;

DROP FUNCTION IF EXISTS iam.confirm_notification_contact(text,text,text,text,text,bigint,text,jsonb);
CREATE OR REPLACE FUNCTION iam.confirm_notification_contact(tenant text,subject_id text,caller_id text,enrollment_challenge text,verification text,
    attempt text,attempt_sequence bigint,notification_id text,audit_event jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE generation bigint; original iam.notification_contact_verifications%ROWTYPE; budget iam.notification_confirmation_attempts%ROWTYPE; effective_now timestamptz;
BEGIN
    generation:=iam.lock_notification_subject(tenant,subject_id,caller_id,enrollment_challenge);
    SELECT * INTO original FROM iam.notification_contact_verifications v WHERE v.tenant_id=tenant AND v.id=verification AND v.user_id=subject_id FOR UPDATE;
    IF NOT FOUND OR (original.session_id,original.enrollment_challenge_id) IS DISTINCT FROM (caller_id,enrollment_challenge)
        OR original.credential_generation<>generation THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='notification verification unavailable';
    END IF;
    SELECT * INTO budget FROM iam.notification_confirmation_attempts b WHERE b.tenant_id=tenant AND b.user_id=subject_id FOR UPDATE;
    effective_now:=clock_timestamp();
    IF NOT FOUND OR budget.state<>'RESERVED' OR budget.attempt_id IS DISTINCT FROM attempt OR budget.sequence IS DISTINCT FROM attempt_sequence
        OR budget.verification_id<>verification OR budget.expires_at<=effective_now OR original.expires_at<=effective_now OR original.state<>'PENDING'
        OR EXISTS(SELECT 1 FROM iam.notification_contacts c WHERE c.tenant_id=tenant AND c.user_id=subject_id) THEN
        RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='notification confirmation conflicts';
    END IF;
    PERFORM iam.assert_audit_event(audit_event,tenant,'iam.notification-contact.verified','USER',subject_id,'SUCCEEDED');
    PERFORM iam.assert_user_audit_actor(tenant,subject_id,audit_event);
    UPDATE iam.notification_confirmation_attempts b SET state='SUCCEEDED' WHERE b.tenant_id=tenant AND b.user_id=subject_id;
    UPDATE iam.notification_contact_verifications v SET state='VERIFIED',completed_at=transaction_timestamp(),
        confirmation_request_id=audit_event->>'requestId',completion_event_id=audit_event->>'eventId' WHERE v.tenant_id=tenant AND v.id=verification;
    INSERT INTO iam.notification_contacts VALUES(tenant,subject_id,original.email,1,transaction_timestamp(),verification);
    INSERT INTO iam.audit_outbox(tenant_id,event_id,event_document,next_attempt_at,created_at,updated_at)
        VALUES(tenant,audit_event->>'eventId',audit_event,transaction_timestamp(),transaction_timestamp(),transaction_timestamp());
    INSERT INTO iam.security_notifications(tenant_id,id,user_id,installation_id,verification_id,event_id,kind,email,contact_revision,created_at,state,next_attempt_at,updated_at)
        VALUES(tenant,notification_id,subject_id,original.installation_id,verification,audit_event->>'eventId','CONTACT_VERIFIED',original.email,1,
            transaction_timestamp(),'PENDING',transaction_timestamp(),transaction_timestamp());
    RETURN iam.notification_verification_snapshot(tenant,verification);
END $function$;

CREATE OR REPLACE FUNCTION iam.read_email_verification_keyset()
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE receipt iam.bootstrap_receipts%ROWTYPE; latest iam.email_verification_keysets%ROWTYPE;
BEGIN
    IF session_user='matrix_iam_notification_worker_login' THEN PERFORM iam.assert_notification_worker(); END IF;
    IF NOT iam.notification_contract_ready() THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='notification schema unavailable'; END IF;
    LOCK TABLE iam.email_verification_keysets IN SHARE MODE;
    SELECT * INTO receipt FROM iam.bootstrap_receipts WHERE singleton;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='email verification installation unavailable'; END IF;
    SELECT * INTO latest FROM iam.email_verification_keysets s WHERE s.installation_id=receipt.installation_id ORDER BY revision DESC LIMIT 1;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF latest.registration->'scope' IS DISTINCT FROM jsonb_build_object('installationId',receipt.installation_id,'bootstrapDigest',receipt.content_digest)
        OR (SELECT count(*) FROM iam.email_verification_keys)<>jsonb_array_length(latest.registration->'keys')
        OR EXISTS(SELECT 1 FROM iam.email_verification_keys k WHERE k.installation_id<>receipt.installation_id
            OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(latest.registration->'keys') v
                WHERE v=jsonb_build_object('keyId',k.key_id,'formatVersion',k.format_version,'materialCommitment',k.material_commitment))) THEN
        RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='email verification custody differs';
    END IF;
    RETURN latest.registration;
END $function$;

-- Internal lock order: Account -> USER -> credential -> actual caller Session.
-- A claim can deliver already queued bytes but never obtains this capability.
DROP FUNCTION IF EXISTS iam.lock_notification_subject(text,text,text);
CREATE OR REPLACE FUNCTION iam.lock_notification_subject(tenant text,subject_id text,caller_id text,enrollment_challenge text)
RETURNS bigint LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE credential iam.user_credentials%ROWTYPE; caller iam.sessions%ROWTYPE; challenge iam.authentication_challenges%ROWTYPE;
BEGIN
    IF num_nonnulls(caller_id,enrollment_challenge)<>1 THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='notification authentication origin is unavailable';
    END IF;
    IF enrollment_challenge IS NOT NULL THEN
        challenge:=iam.lock_initial_enrollment_challenge(tenant,subject_id,enrollment_challenge,'ENROLLMENT');
        RETURN challenge.credential_generation;
    END IF;
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    PERFORM 1 FROM iam.accounts a WHERE a.id=tenant AND a.status='ACTIVE' FOR SHARE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='notification subject unavailable'; END IF;
    PERFORM 1 FROM iam.principals p WHERE p.tenant_id=tenant AND p.id=subject_id AND p.principal_type='USER'
        AND p.status='ACTIVE' AND p.deleted_at IS NULL AND NOT p.must_change_password FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='notification subject unavailable'; END IF;
    SELECT * INTO credential FROM iam.user_credentials c WHERE c.tenant_id=tenant AND c.principal_id=subject_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='notification subject unavailable'; END IF;
    SELECT * INTO caller FROM iam.sessions s WHERE s.tenant_id=tenant AND s.principal_id=subject_id AND s.id=caller_id FOR UPDATE;
    IF NOT FOUND OR caller.status<>'ACTIVE' OR caller.revoked_at IS NOT NULL OR caller.expires_at<=clock_timestamp()
        OR caller.credential_version IS DISTINCT FROM credential.credential_version THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='notification subject unavailable';
    END IF;
    -- Evaluate this Session's actual authentication facts against the
    -- current factor state; a bound User is neither automatically allowed
    -- nor categorically denied access to their own contact information.
    IF NOT iam.session_mfa_eligible(tenant,subject_id,caller_id) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='notification subject unavailable';
    END IF;
    RETURN credential.credential_version;
END $function$;

CREATE OR REPLACE FUNCTION iam.notification_verification_snapshot(tenant text,verification text)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','NotificationContactVerification',
        'id',v.id,'accountId',v.tenant_id,'userId',v.user_id,'requestId',v.request_id,'email',v.email,
        'state',CASE WHEN v.state='PENDING' AND v.expires_at<=clock_timestamp() THEN 'EXPIRED' ELSE v.state END,
        'issuedAt',v.issued_at,'expiresAt',v.expires_at,
        'completedAt',CASE WHEN v.state='PENDING' AND v.expires_at<=clock_timestamp() THEN v.expires_at ELSE v.completed_at END,
        'delivery',jsonb_build_object('state',n.state,'attempts',n.attempts,'lastOutcome',n.last_outcome,'lastSmtpCode',n.last_smtp_code,'updatedAt',n.updated_at)))
    FROM iam.notification_contact_verifications v JOIN iam.security_notifications n ON n.tenant_id=v.tenant_id AND n.id=v.notification_id
    WHERE v.tenant_id=tenant AND v.id=verification
$function$;

CREATE OR REPLACE FUNCTION iam.notification_contact_snapshot(tenant text,subject_id text,caller_id text,enrollment_challenge text,generation bigint)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $function$
DECLARE contact iam.notification_contacts%ROWTYPE; pending text;
BEGIN
    SELECT * INTO contact FROM iam.notification_contacts c WHERE c.tenant_id=tenant AND c.user_id=subject_id;
    IF FOUND THEN RETURN jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','NotificationContact','accountId',tenant,
        'userId',subject_id,'state','VERIFIED','resourceVersion',contact.resource_version,'email',contact.email,'verifiedAt',contact.verified_at); END IF;
    SELECT id INTO pending FROM iam.notification_contact_verifications v WHERE v.tenant_id=tenant AND v.user_id=subject_id
        AND (v.session_id,v.enrollment_challenge_id) IS NOT DISTINCT FROM (caller_id,enrollment_challenge)
        AND v.credential_generation=generation AND v.state='PENDING' AND v.expires_at>clock_timestamp();
    RETURN jsonb_strip_nulls(jsonb_build_object('apiVersion','iam.matrix.xiak.com/v1','kind','NotificationContact','accountId',tenant,
        'userId',subject_id,'state','NONE','resourceVersion',0,'pendingVerificationId',pending));
END $function$;

DROP FUNCTION IF EXISTS iam.read_notification_contact(text,text,text);
CREATE OR REPLACE FUNCTION iam.read_notification_contact(tenant text,subject_id text,caller_id text,enrollment_challenge text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE generation bigint;
BEGIN
    generation:=iam.lock_notification_subject(tenant,subject_id,caller_id,enrollment_challenge);
    RETURN iam.notification_contact_snapshot(tenant,subject_id,caller_id,enrollment_challenge,generation);
END $function$;

DROP FUNCTION IF EXISTS iam.read_notification_verification(text,text,text,text);
CREATE OR REPLACE FUNCTION iam.read_notification_verification(tenant text,subject_id text,caller_id text,enrollment_challenge text,verification text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE generation bigint;
BEGIN
    generation:=iam.lock_notification_subject(tenant,subject_id,caller_id,enrollment_challenge);
    IF NOT EXISTS(SELECT 1 FROM iam.notification_contact_verifications v WHERE v.tenant_id=tenant AND v.id=verification
        AND v.user_id=subject_id AND (v.session_id,v.enrollment_challenge_id) IS NOT DISTINCT FROM (caller_id,enrollment_challenge)
        AND v.credential_generation=generation) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='notification verification unavailable';
    END IF;
    RETURN iam.notification_verification_snapshot(tenant,verification);
END $function$;

-- A notification worker has no user/service principal or reusable authority.
-- It can only consume these closed projections under its dedicated login.
CREATE OR REPLACE FUNCTION iam.assert_notification_worker()
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF session_user<>'matrix_iam_notification_worker_login'
        OR NOT pg_has_role(session_user,'matrix_iam_notification_worker','USAGE')
        OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname=session_user
            AND (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls))
        OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname NOT IN (session_user,'matrix_iam_notification_worker')
            AND pg_has_role(session_user,r.oid,'MEMBER'))
        OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relnamespace='iam'::regnamespace AND c.relkind IN ('r','p','v','m','f')
            AND has_table_privilege(session_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
        OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.pronamespace='iam'::regnamespace
            AND p.oid NOT IN (to_regprocedure('iam.read_email_verification_keyset()'),to_regprocedure('iam.claim_security_notification(text)'),
                to_regprocedure('iam.complete_security_notification(text,text,text,bigint,text,integer)'))
            AND has_function_privilege(session_user,p.oid,'EXECUTE')) THEN
        RAISE EXCEPTION USING ERRCODE='42501',MESSAGE='notification worker context is forbidden';
    END IF;
END $function$;

CREATE OR REPLACE FUNCTION iam.notification_retry_delay(attempt_count integer)
RETURNS interval LANGUAGE sql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT CASE attempt_count WHEN 1 THEN interval '30 seconds' WHEN 2 THEN interval '2 minutes'
        WHEN 3 THEN interval '5 minutes' ELSE interval '15 minutes' END
$function$;

CREATE OR REPLACE FUNCTION iam.claim_security_notification(worker text)
RETURNS TABLE(tenant_id text,notification_id text,user_id text,installation_id text,kind text,email text,created_at timestamptz,
    fence bigint,lease_expires_at timestamptz,verification_id text,bootstrap_digest text,credential_generation bigint,
    contact_revision bigint,issued_at timestamptz,expires_at timestamptz,key_id text,nonce bytea,ciphertext bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE candidate iam.security_notifications%ROWTYPE; original iam.notification_contact_verifications%ROWTYPE;
    registration jsonb; effective_now timestamptz(6); prior_scope text; prior_tenant text; eligible boolean;
BEGIN
    PERFORM iam.assert_notification_worker();
    IF COALESCE(worker,'') COLLATE "C" !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='notification worker is invalid';
    END IF;
    registration:=iam.read_email_verification_keyset();
    IF registration IS NULL THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='notification custody unavailable'; END IF;
    prior_scope:=current_setting('matrix.iam_notification_delivery',true);
    prior_tenant:=current_setting('matrix.iam_tenant_id',true);
    PERFORM set_config('matrix.iam_notification_delivery','trusted',true);
    -- At most sixteen expired/unavailable candidates per call. Network I/O
    -- happens only after this claim commits; no SMTP under an identity lock.
    FOR candidate IN SELECT n.* FROM iam.security_notifications n
        WHERE (n.state IN ('PENDING','RETRY_WAIT') AND n.next_attempt_at<=clock_timestamp())
            OR (n.state='IN_FLIGHT' AND n.lease_expires_at<=clock_timestamp())
        ORDER BY n.next_attempt_at,n.tenant_id,n.id LIMIT 16 FOR UPDATE SKIP LOCKED LOOP
        effective_now:=clock_timestamp();
        IF candidate.installation_id IS DISTINCT FROM registration#>>'{scope,installationId}' THEN
            RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='notification installation differs';
        END IF;
        PERFORM set_config('matrix.iam_tenant_id',candidate.tenant_id,true);
        SELECT * INTO original FROM iam.notification_contact_verifications v
            WHERE v.tenant_id=candidate.tenant_id AND v.id=candidate.verification_id AND v.user_id=candidate.user_id;
        IF NOT FOUND OR original.bootstrap_digest IS DISTINCT FROM registration#>>'{scope,bootstrapDigest}' THEN
            RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='notification origin unavailable';
        END IF;
        IF candidate.state='IN_FLIGHT' THEN
            -- Lease loss proves uncertainty, not an unsent message. Persist it
            -- before a later bounded retry; never reuse the old fence.
            UPDATE iam.security_notification_attempts a SET completed_at=effective_now,outcome='UNKNOWN',smtp_code=NULL
                WHERE a.tenant_id=candidate.tenant_id AND a.notification_id=candidate.id AND a.fence=candidate.fence AND a.outcome IS NULL;
            IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='notification lease history differs'; END IF;
            UPDATE iam.security_notifications n SET state=CASE WHEN candidate.attempts>=5 THEN 'FAILED'
                WHEN candidate.kind='ADDRESS_VERIFICATION' AND (original.state<>'PENDING' OR original.expires_at<=effective_now) THEN 'EXPIRED' ELSE 'RETRY_WAIT' END,
                worker_id=NULL,lease_expires_at=NULL,last_outcome='UNKNOWN',last_smtp_code=NULL,updated_at=effective_now,
                next_attempt_at=effective_now+iam.notification_retry_delay(candidate.attempts)
                WHERE n.tenant_id=candidate.tenant_id AND n.id=candidate.id;
            CONTINUE;
        END IF;
        eligible:=candidate.kind IN ('CONTACT_VERIFIED','AUTHENTICATOR_BOUND','AUTHENTICATOR_REPLACED','RECOVERY_STARTED','AUTHENTICATOR_RECOVERED','RECOVERY_CODES_REGENERATED','SECURITY_SETTINGS_CHANGED');
        IF candidate.kind='ADDRESS_VERIFICATION' THEN
            SELECT EXISTS(SELECT 1 FROM iam.accounts a JOIN iam.principals p ON p.tenant_id=a.id
                JOIN iam.user_credentials c ON (c.tenant_id,c.principal_id)=(p.tenant_id,p.id)
                WHERE a.id=candidate.tenant_id AND a.status='ACTIVE' AND p.id=candidate.user_id AND p.principal_type='USER'
                    AND p.status='ACTIVE' AND p.deleted_at IS NULL AND NOT p.must_change_password
                    AND c.credential_version=original.credential_generation
                    AND original.state='PENDING' AND original.expires_at>effective_now
                    AND ((original.enrollment_challenge_id IS NULL AND EXISTS(SELECT 1 FROM iam.sessions s
                        WHERE (s.tenant_id,s.principal_id,s.id)=(p.tenant_id,p.id,original.session_id)
                            AND s.status='ACTIVE' AND s.revoked_at IS NULL AND s.credential_version=c.credential_version
                            AND s.expires_at>effective_now AND iam.session_mfa_eligible(p.tenant_id,p.id,s.id)))
                        OR (original.session_id IS NULL AND iam.requires_initial_enrollment(p.tenant_id,p.id)
                            AND EXISTS(SELECT 1 FROM iam.authentication_challenges challenge
                                WHERE (challenge.tenant_id,challenge.user_id,challenge.id)=(p.tenant_id,p.id,original.enrollment_challenge_id)
                                    AND challenge.purpose='ENROLLMENT' AND challenge.next_step='ENROLLMENT' AND challenge.state='PENDING'
                                    AND challenge.credential_generation=c.credential_version AND challenge.expires_at>effective_now
                                    AND challenge.account_version=a.resource_version AND challenge.principal_version=p.resource_version
                                    AND challenge.security_settings_version=a.security_settings_version)))) INTO eligible;
        END IF;
        IF NOT eligible THEN
            UPDATE iam.security_notifications n SET state='EXPIRED',updated_at=effective_now
                WHERE n.tenant_id=candidate.tenant_id AND n.id=candidate.id;
            CONTINUE;
        END IF;
        IF candidate.attempts>=5 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='notification attempts exhausted'; END IF;
        UPDATE iam.security_notifications n SET state='IN_FLIGHT',attempts=n.attempts+1,fence=n.fence+1,
            worker_id=worker,lease_expires_at=effective_now+interval '45 seconds',updated_at=effective_now
            WHERE n.tenant_id=candidate.tenant_id AND n.id=candidate.id RETURNING n.* INTO candidate;
        INSERT INTO iam.security_notification_attempts(tenant_id,notification_id,fence,worker_id,claimed_at,lease_expires_at)
            VALUES(candidate.tenant_id,candidate.id,candidate.fence,worker,effective_now,candidate.lease_expires_at);
        -- A historical security notice does not disclose an old verification
        -- secret and is not reauthorized against today's USER/account state.
        RETURN QUERY SELECT candidate.tenant_id,candidate.id,candidate.user_id,candidate.installation_id,candidate.kind,candidate.email,
            candidate.created_at,candidate.fence,candidate.lease_expires_at,original.id,original.bootstrap_digest,
            original.credential_generation,original.contact_revision,original.issued_at,original.expires_at,
            CASE WHEN candidate.kind='ADDRESS_VERIFICATION' THEN original.key_id END,
            CASE WHEN candidate.kind='ADDRESS_VERIFICATION' THEN original.nonce END,
            CASE WHEN candidate.kind='ADDRESS_VERIFICATION' THEN original.ciphertext END;
        EXIT;
    END LOOP;
    PERFORM set_config('matrix.iam_notification_delivery',COALESCE(prior_scope,''),true);
    PERFORM set_config('matrix.iam_tenant_id',COALESCE(prior_tenant,''),true);
END $function$;

CREATE OR REPLACE FUNCTION iam.complete_security_notification(tenant text,notification text,worker text,lease_fence bigint,observed_outcome text,observed_code integer)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $function$
DECLARE original iam.security_notifications%ROWTYPE; verification_expiry timestamptz; verification_state text; effective_now timestamptz(6);
BEGIN
    PERFORM iam.assert_notification_worker();
    PERFORM set_config('matrix.iam_tenant_id',tenant,true);
    IF NOT ((observed_outcome='ACCEPTED' AND observed_code IS NOT NULL AND observed_code=250)
        OR (observed_outcome='REJECTED' AND observed_code IS NOT NULL AND observed_code BETWEEN 400 AND 599)
        OR (observed_outcome IN ('UNKNOWN','UNAVAILABLE') AND observed_code IS NULL)) OR observed_outcome IS NULL THEN
        RAISE EXCEPTION USING ERRCODE='22023',MESSAGE='notification observation is invalid';
    END IF;
    SELECT * INTO original FROM iam.security_notifications n WHERE n.tenant_id=tenant AND n.id=notification FOR UPDATE;
    effective_now:=clock_timestamp();
    IF NOT FOUND OR original.state<>'IN_FLIGHT' OR original.worker_id IS DISTINCT FROM worker
        OR original.fence IS DISTINCT FROM lease_fence OR original.lease_expires_at<=effective_now THEN
        RAISE EXCEPTION USING ERRCODE='P0002',MESSAGE='notification lease conflicts';
    END IF;
    SELECT v.expires_at,v.state INTO verification_expiry,verification_state FROM iam.notification_contact_verifications v
        WHERE v.tenant_id=tenant AND v.id=original.verification_id;
    UPDATE iam.security_notification_attempts a SET completed_at=effective_now,outcome=observed_outcome,smtp_code=observed_code
        WHERE a.tenant_id=tenant AND a.notification_id=notification AND a.fence=lease_fence AND a.worker_id=worker AND a.outcome IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='notification attempt history differs'; END IF;
    UPDATE iam.security_notifications n SET state=CASE WHEN observed_outcome='ACCEPTED' THEN 'ACCEPTED'
        WHEN (observed_outcome='REJECTED' AND observed_code>=500) OR original.attempts>=5 THEN 'FAILED'
        WHEN original.kind='ADDRESS_VERIFICATION' AND (verification_state<>'PENDING' OR verification_expiry<=effective_now) THEN 'EXPIRED'
        ELSE 'RETRY_WAIT' END,
        worker_id=NULL,lease_expires_at=NULL,last_outcome=observed_outcome,last_smtp_code=observed_code,updated_at=effective_now,
        next_attempt_at=effective_now+iam.notification_retry_delay(original.attempts) WHERE n.tenant_id=tenant AND n.id=notification;
END $function$;

CREATE OR REPLACE FUNCTION iam.guard_notification_history()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
BEGIN
    IF TG_OP<>'UPDATE' THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification history is immutable'; END IF;
    IF TG_TABLE_NAME='notification_contact_verifications' THEN
        IF OLD.state<>'PENDING' OR NEW.state NOT IN ('VERIFIED','CANCELLED','EXPIRED')
            OR (to_jsonb(NEW)-ARRAY['state','completed_at','confirmation_request_id','completion_event_id'])
                IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','completed_at','confirmation_request_id','completion_event_id']) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification verification identity is immutable';
        END IF;
    ELSIF TG_TABLE_NAME='security_notifications' THEN
        IF (to_jsonb(NEW)-ARRAY['state','attempts','fence','worker_id','lease_expires_at','next_attempt_at','last_outcome','last_smtp_code','updated_at'])
            IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','attempts','fence','worker_id','lease_expires_at','next_attempt_at','last_outcome','last_smtp_code','updated_at'])
            OR OLD.state IN ('ACCEPTED','FAILED','EXPIRED') OR NEW.updated_at<OLD.updated_at
            OR NOT ((OLD.state IN ('PENDING','RETRY_WAIT') AND NEW.state='IN_FLIGHT' AND NEW.attempts=OLD.attempts+1 AND NEW.fence=OLD.fence+1
                    AND NEW.last_outcome IS NOT DISTINCT FROM OLD.last_outcome AND NEW.last_smtp_code IS NOT DISTINCT FROM OLD.last_smtp_code)
                OR (OLD.state IN ('PENDING','RETRY_WAIT') AND NEW.state='EXPIRED' AND NEW.attempts=OLD.attempts AND NEW.fence=OLD.fence
                    AND NEW.last_outcome IS NOT DISTINCT FROM OLD.last_outcome AND NEW.last_smtp_code IS NOT DISTINCT FROM OLD.last_smtp_code)
                OR (OLD.state='IN_FLIGHT' AND NEW.state IN ('RETRY_WAIT','ACCEPTED','FAILED','EXPIRED') AND NEW.attempts=OLD.attempts AND NEW.fence=OLD.fence
                    AND NEW.last_outcome IS NOT NULL)) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification delivery transition is invalid';
        END IF;
    ELSIF TG_TABLE_NAME='security_notification_attempts' THEN
        IF OLD.outcome IS NOT NULL OR NEW.outcome IS NULL
            OR (to_jsonb(NEW)-ARRAY['completed_at','outcome','smtp_code']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['completed_at','outcome','smtp_code']) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification observation is immutable';
        END IF;
    ELSE RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification history relation is invalid';
    END IF;
    RETURN NEW;
END $function$;

-- Every successful fact has its original intent/contact and vice versa. This
-- constraint verifies committed history without consulting today's authority
-- or treating a newly generated USER decision as evidence of code possession.
CREATE OR REPLACE FUNCTION iam.verify_notification_facts()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE original iam.notification_contact_verifications%ROWTYPE; event jsonb; message iam.security_notifications%ROWTYPE;
    contact iam.notification_contacts%ROWTYPE; original_id text; candidate_tenant text;
BEGIN
    candidate_tenant:=NEW.tenant_id;
    PERFORM set_config('matrix.iam_tenant_id',candidate_tenant,true);
    IF TG_TABLE_NAME='audit_outbox' THEN
        IF NEW.event_document->>'action' NOT IN ('iam.notification-contact.verification-started','iam.notification-contact.verified') THEN RETURN NULL; END IF;
        SELECT v.id INTO original_id FROM iam.notification_contact_verifications v WHERE v.tenant_id=candidate_tenant
            AND (v.started_event_id=NEW.event_id OR v.completion_event_id=NEW.event_id);
    ELSIF TG_TABLE_NAME='notification_contact_verifications' THEN original_id:=NEW.id;
    ELSE original_id:=NEW.verification_id;
    END IF;
    SELECT * INTO original FROM iam.notification_contact_verifications v WHERE v.tenant_id=candidate_tenant AND v.id=original_id;
    IF NOT FOUND OR NOT ((original.enrollment_challenge_id IS NULL AND EXISTS(SELECT 1 FROM iam.sessions s
            WHERE s.tenant_id=candidate_tenant AND s.id=original.session_id AND s.principal_id=original.user_id))
        OR (original.session_id IS NULL AND EXISTS(SELECT 1 FROM iam.authentication_challenges c
            WHERE (c.tenant_id,c.user_id,c.id)=(candidate_tenant,original.user_id,original.enrollment_challenge_id)
                AND c.purpose='ENROLLMENT' AND c.next_step='ENROLLMENT' AND c.credential_generation=original.credential_generation
                AND c.created_at<=original.issued_at AND c.expires_at=original.expires_at)))
        OR NOT EXISTS(SELECT 1 FROM iam.principals p WHERE p.tenant_id=candidate_tenant AND p.id=original.user_id AND p.principal_type='USER')
        OR NOT EXISTS(SELECT 1 FROM iam.bootstrap_receipts r WHERE r.installation_id=original.installation_id AND r.content_digest=original.bootstrap_digest) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification origin is missing';
    END IF;
    SELECT o.event_document INTO event FROM iam.audit_outbox o WHERE o.tenant_id=candidate_tenant AND o.event_id=original.started_event_id;
    IF event IS NULL OR event->>'action' IS DISTINCT FROM 'iam.notification-contact.verification-started'
        OR event->'actor' IS DISTINCT FROM jsonb_build_object('type','USER','id',original.user_id)
        OR event->'target' IS DISTINCT FROM jsonb_build_object('kind','USER','id',original.user_id)
        OR event->>'tenantId' IS DISTINCT FROM candidate_tenant OR event->>'requestId' IS DISTINCT FROM original.request_id
        OR (event->>'occurredAt')::timestamptz IS DISTINCT FROM original.issued_at
        OR event->>'result' IS DISTINCT FROM 'SUCCEEDED' OR event ?| ARRAY['installationId','iamDecisionId','operationId'] THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification starting fact differs';
    END IF;
    SELECT * INTO message FROM iam.security_notifications n WHERE n.tenant_id=candidate_tenant AND n.id=original.notification_id;
    IF NOT FOUND OR (message.user_id,message.installation_id,message.verification_id,message.event_id,message.kind,message.email,message.contact_revision,message.created_at)
        IS DISTINCT FROM (original.user_id,original.installation_id,original.id,original.started_event_id,'ADDRESS_VERIFICATION'::text,original.email,0::bigint,original.issued_at) THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification verification delivery differs';
    END IF;
    IF original.state='VERIFIED' THEN
        SELECT * INTO contact FROM iam.notification_contacts c WHERE c.tenant_id=candidate_tenant AND c.user_id=original.user_id;
        IF NOT FOUND OR (contact.email,contact.resource_version,contact.verified_at,contact.verification_id)
            IS DISTINCT FROM (original.email,1::bigint,original.completed_at,original.id) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='verified notification contact differs';
        END IF;
        SELECT o.event_document INTO event FROM iam.audit_outbox o WHERE o.tenant_id=candidate_tenant AND o.event_id=original.completion_event_id;
        IF event IS NULL OR event->>'action' IS DISTINCT FROM 'iam.notification-contact.verified'
            OR event->'actor' IS DISTINCT FROM jsonb_build_object('type','USER','id',original.user_id)
            OR event->'target' IS DISTINCT FROM jsonb_build_object('kind','USER','id',original.user_id)
            OR event->>'tenantId' IS DISTINCT FROM candidate_tenant OR event->>'requestId' IS DISTINCT FROM original.confirmation_request_id
            OR (event->>'occurredAt')::timestamptz IS DISTINCT FROM original.completed_at
            OR event->>'result' IS DISTINCT FROM 'SUCCEEDED' OR event ?| ARRAY['installationId','iamDecisionId','operationId'] THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification confirmation fact differs';
        END IF;
        SELECT * INTO message FROM iam.security_notifications n WHERE n.tenant_id=candidate_tenant AND n.event_id=original.completion_event_id AND n.kind='CONTACT_VERIFIED';
        IF NOT FOUND OR (message.user_id,message.installation_id,message.verification_id,message.email,message.contact_revision,message.created_at)
            IS DISTINCT FROM (original.user_id,original.installation_id,original.id,original.email,1::bigint,original.completed_at) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='contact security notice differs';
        END IF;
    ELSIF EXISTS(SELECT 1 FROM iam.notification_contacts c WHERE c.tenant_id=candidate_tenant AND c.verification_id=original.id)
        OR EXISTS(SELECT 1 FROM iam.security_notifications n WHERE n.tenant_id=candidate_tenant AND n.verification_id=original.id AND n.kind='CONTACT_VERIFIED') THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='unverified contact has a completion';
    END IF;
    -- Reject extra counterfeit messages even if the genuine pair also exists.
    IF TG_TABLE_NAME='security_notifications' THEN
        IF (NEW.kind='ADDRESS_VERIFICATION' AND NEW.id<>original.notification_id)
            OR (NEW.kind='CONTACT_VERIFIED' AND NEW.event_id IS DISTINCT FROM original.completion_event_id) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification has no original fact';
        END IF;
    END IF;
    RETURN NULL;
END $function$;

CREATE OR REPLACE FUNCTION iam.verify_notification_delivery()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $function$
DECLARE message iam.security_notifications%ROWTYPE; latest iam.security_notification_attempts%ROWTYPE;
    prior iam.security_notification_attempts%ROWTYPE;
    notification text; total integer; completed integer; maximum_fence bigint;
BEGIN
    PERFORM set_config('matrix.iam_tenant_id',NEW.tenant_id,true);
    IF TG_TABLE_NAME='security_notifications' THEN notification:=NEW.id; ELSE notification:=NEW.notification_id; END IF;
    SELECT * INTO message FROM iam.security_notifications n WHERE n.tenant_id=NEW.tenant_id AND n.id=notification;
    IF NOT FOUND THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification delivery origin missing'; END IF;
    SELECT count(*),count(*) FILTER(WHERE a.outcome IS NOT NULL),COALESCE(max(a.fence),0) INTO total,completed,maximum_fence FROM iam.security_notification_attempts a
        WHERE a.tenant_id=NEW.tenant_id AND a.notification_id=notification;
    IF total<>message.attempts OR message.fence<>message.attempts OR maximum_fence<>message.fence THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification attempt count differs';
    END IF;
    IF total=0 THEN
        IF message.state NOT IN ('PENDING','EXPIRED') OR message.last_outcome IS NOT NULL THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification has no submission observation';
        END IF;
        RETURN NULL;
    END IF;
    SELECT * INTO latest FROM iam.security_notification_attempts a WHERE a.tenant_id=NEW.tenant_id AND a.notification_id=notification AND a.fence=message.fence;
    IF NOT FOUND OR latest.claimed_at<message.created_at OR latest.claimed_at>message.updated_at THEN
        RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification attempt identity differs';
    END IF;
    IF message.state='IN_FLIGHT' THEN
        IF completed<>total-1 OR latest.outcome IS NOT NULL OR latest.worker_id<>message.worker_id OR latest.lease_expires_at<>message.lease_expires_at THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification lease observation differs';
        END IF;
        SELECT * INTO prior FROM iam.security_notification_attempts a
            WHERE a.tenant_id=NEW.tenant_id AND a.notification_id=notification AND a.fence=message.fence-1;
        IF (message.last_outcome,message.last_smtp_code) IS DISTINCT FROM (prior.outcome,prior.smtp_code)
            OR (total>1 AND (prior.completed_at IS NULL OR latest.claimed_at<prior.completed_at+iam.notification_retry_delay(total-1))) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification retry observation differs';
        END IF;
    ELSE
        IF message.state='PENDING' OR completed<>total OR (message.last_outcome,message.last_smtp_code) IS DISTINCT FROM (latest.outcome,latest.smtp_code)
            OR latest.completed_at>message.updated_at OR (message.state='ACCEPTED' AND latest.outcome<>'ACCEPTED')
            OR (message.state='RETRY_WAIT' AND (total>=5 OR latest.outcome='ACCEPTED' OR latest.smtp_code>=500))
            OR (message.state='FAILED' AND (total=5 OR (latest.outcome='REJECTED' AND latest.smtp_code>=500)) IS DISTINCT FROM true)
            OR (message.state='RETRY_WAIT' AND message.next_attempt_at IS DISTINCT FROM latest.completed_at+iam.notification_retry_delay(total)) THEN
            RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='notification completion observation differs';
        END IF;
    END IF;
    RETURN NULL;
END $function$;

DO $mail_guards$
DECLARE relation_name text; operation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['email_verification_keys','email_verification_keysets','notification_contacts'] LOOP
        FOREACH operation_name IN ARRAY ARRAY['UPDATE','DELETE','TRUNCATE'] LOOP
            EXECUTE format('DROP TRIGGER IF EXISTS cannot_%s ON iam.%I',lower(operation_name),relation_name);
            EXECUTE format('CREATE TRIGGER cannot_%s BEFORE %s ON iam.%I FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change()',lower(operation_name),operation_name,relation_name);
            EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER cannot_%s',relation_name,lower(operation_name));
        END LOOP;
    END LOOP;
    FOREACH relation_name IN ARRAY ARRAY['notification_contact_verifications','security_notifications','security_notification_attempts'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS preserve_notification_history ON iam.%I',relation_name);
        EXECUTE format('CREATE TRIGGER preserve_notification_history BEFORE UPDATE OR DELETE ON iam.%I FOR EACH ROW EXECUTE FUNCTION iam.guard_notification_history()',relation_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER preserve_notification_history',relation_name);
        EXECUTE format('DROP TRIGGER IF EXISTS cannot_truncate ON iam.%I',relation_name);
        EXECUTE format('CREATE TRIGGER cannot_truncate BEFORE TRUNCATE ON iam.%I FOR EACH STATEMENT EXECUTE FUNCTION iam.reject_policy_history_change()',relation_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER cannot_truncate',relation_name);
    END LOOP;
    FOREACH relation_name IN ARRAY ARRAY['notification_contact_verifications','notification_contacts','security_notifications','audit_outbox'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS notification_fact_link ON iam.%I',relation_name);
        -- UPDATE on the outbox would needlessly recheck every delivery lease;
        -- its existing immutable-event trigger already protects later writes.
        IF relation_name='audit_outbox' THEN
            EXECUTE format('CREATE CONSTRAINT TRIGGER notification_fact_link AFTER INSERT ON iam.%I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.verify_notification_facts()',relation_name);
        ELSE
            EXECUTE format('CREATE CONSTRAINT TRIGGER notification_fact_link AFTER INSERT OR UPDATE ON iam.%I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.verify_notification_facts()',relation_name);
        END IF;
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER notification_fact_link',relation_name);
    END LOOP;
    FOREACH relation_name IN ARRAY ARRAY['security_notifications','security_notification_attempts'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS notification_delivery_link ON iam.%I',relation_name);
        EXECUTE format('CREATE CONSTRAINT TRIGGER notification_delivery_link AFTER INSERT OR UPDATE ON iam.%I DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION iam.verify_notification_delivery()',relation_name);
        EXECUTE format('ALTER TABLE iam.%I ENABLE ALWAYS TRIGGER notification_delivery_link',relation_name);
    END LOOP;
END $mail_guards$;

REVOKE ALL ON iam.email_verification_keys,iam.email_verification_keysets,iam.notification_contacts,iam.notification_contact_verifications,
    iam.notification_send_budgets,iam.notification_confirmation_attempts,iam.security_notifications,iam.security_notification_attempts
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker;
REVOKE ALL ON ALL TABLES IN SCHEMA iam FROM matrix_iam_notification_worker;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA iam FROM matrix_iam_notification_worker;
GRANT USAGE ON SCHEMA iam TO matrix_iam_notification_worker;
-- New internal functions are private by default; list them explicitly so no
-- global function revocation changes another owner's accepted runtime grants.
REVOKE ALL ON FUNCTION iam.valid_security_mail_address(text),iam.register_email_verification_keyset(jsonb),iam.read_email_verification_keyset(),
    iam.debit_notification_send_budget(text,text,integer,integer),iam.lock_notification_subject(text,text,text,text),iam.notification_verification_snapshot(text,text),
    iam.notification_contact_snapshot(text,text,text,text,bigint),
    iam.read_notification_contact(text,text,text,text),iam.read_notification_verification(text,text,text,text,text),
    iam.start_notification_verification(text,text,text,text,text,bigint,text,text,text,text,text,text,bigint,text,text,bytea,bytea,timestamptz,timestamptz,jsonb),
    iam.reserve_notification_confirmation(text,text,text,text,text,text),iam.reject_notification_confirmation(text,text,text,bigint),
    iam.confirm_notification_contact(text,text,text,text,text,text,bigint,text,jsonb),iam.assert_notification_worker(),iam.notification_retry_delay(integer),
    iam.claim_security_notification(text),iam.complete_security_notification(text,text,text,bigint,text,integer),
    iam.guard_notification_history(),iam.verify_notification_facts(),iam.verify_notification_delivery()
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker;
GRANT EXECUTE ON FUNCTION iam.register_email_verification_keyset(jsonb),iam.read_email_verification_keyset(),
    iam.read_notification_contact(text,text,text,text),iam.read_notification_verification(text,text,text,text,text),
    iam.start_notification_verification(text,text,text,text,text,bigint,text,text,text,text,text,text,bigint,text,text,bytea,bytea,timestamptz,timestamptz,jsonb),
    iam.reserve_notification_confirmation(text,text,text,text,text,text),iam.reject_notification_confirmation(text,text,text,bigint),
    iam.confirm_notification_contact(text,text,text,text,text,text,bigint,text,jsonb) TO matrix_iam_api;
GRANT EXECUTE ON FUNCTION iam.read_email_verification_keyset(),iam.claim_security_notification(text),
    iam.complete_security_notification(text,text,text,bigint,text,integer) TO matrix_iam_notification_worker;

CREATE OR REPLACE FUNCTION iam.notification_contract_ready()
RETURNS boolean LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $function$
    SELECT COALESCE(
        EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname='matrix_iam_notification_worker'
            AND NOT r.rolsuper AND NOT r.rolcanlogin AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls)
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname<>'matrix_iam_notification_worker'
            AND pg_has_role('matrix_iam_notification_worker',r.oid,'MEMBER'))
        AND has_schema_privilege('matrix_iam_notification_worker','iam','USAGE')
        AND NOT has_schema_privilege('matrix_iam_notification_worker','iam','CREATE')
        AND (SELECT count(*)=8 FROM pg_catalog.pg_class c WHERE c.oid IN (
            to_regclass('iam.email_verification_keys'),to_regclass('iam.email_verification_keysets'),to_regclass('iam.notification_contacts'),
            to_regclass('iam.notification_contact_verifications'),to_regclass('iam.notification_send_budgets'),to_regclass('iam.notification_confirmation_attempts'),
            to_regclass('iam.security_notifications'),to_regclass('iam.security_notification_attempts'))
            AND c.relowner='matrix_iam_owner'::regrole
            AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) p WHERE p.grantee<>c.relowner))
        AND (SELECT count(*)=5 FROM pg_catalog.pg_class c WHERE c.oid IN (
            to_regclass('iam.notification_contacts'),to_regclass('iam.notification_contact_verifications'),to_regclass('iam.notification_confirmation_attempts'),
            to_regclass('iam.security_notifications'),to_regclass('iam.security_notification_attempts')) AND c.relrowsecurity AND c.relforcerowsecurity)
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid IN (
            to_regclass('iam.notification_contacts'),to_regclass('iam.notification_contact_verifications'),to_regclass('iam.notification_confirmation_attempts'),
            to_regclass('iam.security_notifications'),to_regclass('iam.security_notification_attempts')) AND NOT c.convalidated)
        AND (SELECT count(*)=2 FROM pg_catalog.pg_attribute a WHERE a.attrelid=to_regclass('iam.notification_contact_verifications')
            AND a.attname IN ('session_id','enrollment_challenge_id') AND a.attnum>0 AND NOT a.attisdropped
            AND a.atttypid='text'::regtype AND a.attcollation='"C"'::regcollation AND NOT a.attnotnull AND NOT a.atthasdef)
        AND (SELECT count(*)=2 FROM pg_catalog.pg_constraint c WHERE c.conrelid=to_regclass('iam.notification_contact_verifications')
            AND c.conname IN ('notification_verification_origin','notification_verification_completion')
            AND c.contype='c' AND c.convalidated AND c.conenforced)
        AND EXISTS(SELECT 1 FROM pg_catalog.pg_constraint c WHERE c.conrelid=to_regclass('iam.notification_contact_verifications')
            AND c.conname='contact_initial_enrollment' AND c.contype='f' AND c.convalidated AND c.conenforced
            AND NOT c.condeferrable AND c.confrelid=to_regclass('iam.authentication_challenges')
            AND c.confupdtype='a' AND c.confdeltype='a' AND c.confmatchtype='s'
            AND ARRAY(SELECT a.attname::text FROM unnest(c.conkey) WITH ORDINALITY k(number,position)
                JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.number ORDER BY k.position)=ARRAY['tenant_id','enrollment_challenge_id']
            AND ARRAY(SELECT a.attname::text FROM unnest(c.confkey) WITH ORDINALITY k(number,position)
                JOIN pg_catalog.pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.number ORDER BY k.position)=ARRAY['tenant_id','id'])
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE r.rolname IN ('matrix_iam_api','matrix_iam_worker','matrix_iam_backup_custody','matrix_iam_credential_recovery')
            AND (pg_has_role(r.oid,'matrix_iam_notification_worker','MEMBER') OR pg_has_role('matrix_iam_notification_worker',r.oid,'MEMBER')))
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_class c WHERE c.relnamespace='iam'::regnamespace AND c.relkind IN ('r','p','v','m','f')
            AND has_table_privilege('matrix_iam_notification_worker',c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
        AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc p WHERE p.pronamespace='iam'::regnamespace
            AND p.oid NOT IN (to_regprocedure('iam.read_email_verification_keyset()'),to_regprocedure('iam.claim_security_notification(text)'),
                to_regprocedure('iam.complete_security_notification(text,text,text,bigint,text,integer)'))
            AND has_function_privilege('matrix_iam_notification_worker',p.oid,'EXECUTE'))
        AND (SELECT count(*)=10 FROM pg_catalog.pg_proc p WHERE p.oid IN (
            to_regprocedure('iam.register_email_verification_keyset(jsonb)'),to_regprocedure('iam.read_email_verification_keyset()'),
            to_regprocedure('iam.read_notification_contact(text,text,text,text)'),to_regprocedure('iam.read_notification_verification(text,text,text,text,text)'),
            to_regprocedure('iam.start_notification_verification(text,text,text,text,text,bigint,text,text,text,text,text,text,bigint,text,text,bytea,bytea,timestamptz,timestamptz,jsonb)'),
            to_regprocedure('iam.reserve_notification_confirmation(text,text,text,text,text,text)'),to_regprocedure('iam.reject_notification_confirmation(text,text,text,bigint)'),
            to_regprocedure('iam.confirm_notification_contact(text,text,text,text,text,text,bigint,text,jsonb)'),to_regprocedure('iam.claim_security_notification(text)'),
            to_regprocedure('iam.complete_security_notification(text,text,text,bigint,text,integer)'))
            AND p.proowner='matrix_iam_owner'::regrole AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
            AND NOT has_function_privilege('public',p.oid,'EXECUTE') AND NOT has_function_privilege('matrix_iam_worker',p.oid,'EXECUTE')
            AND NOT has_function_privilege('matrix_iam_credential_recovery',p.oid,'EXECUTE') AND NOT has_function_privilege('matrix_iam_backup_custody',p.oid,'EXECUTE')
            AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a
                WHERE a.grantee<>p.proowner AND (a.is_grantable OR
                    NOT (a.grantee='matrix_iam_api'::regrole AND p.proname NOT IN ('claim_security_notification','complete_security_notification')
                        OR a.grantee='matrix_iam_notification_worker'::regrole AND p.proname IN ('read_email_verification_keyset','claim_security_notification','complete_security_notification'))))
            AND has_function_privilege(CASE WHEN p.proname IN ('claim_security_notification','complete_security_notification')
                THEN 'matrix_iam_notification_worker' ELSE 'matrix_iam_api' END,p.oid,'EXECUTE'))
        AND (SELECT count(*)=10 FROM (VALUES
            ('iam.register_email_verification_keyset(jsonb)','void'),('iam.read_email_verification_keyset()','jsonb'),
            ('iam.read_notification_contact(text,text,text,text)','jsonb'),('iam.read_notification_verification(text,text,text,text,text)','jsonb'),
            ('iam.start_notification_verification(text,text,text,text,text,bigint,text,text,text,text,text,text,bigint,text,text,bytea,bytea,timestamptz,timestamptz,jsonb)','jsonb'),
            ('iam.reserve_notification_confirmation(text,text,text,text,text,text)',
                'TABLE(installation_id text, bootstrap_digest text, credential_generation bigint, contact_revision bigint, email text, issued_at timestamp with time zone, expires_at timestamp with time zone, key_id text, nonce bytea, ciphertext bytea, attempt_sequence bigint)'),
            ('iam.reject_notification_confirmation(text,text,text,bigint)','void'),
            ('iam.confirm_notification_contact(text,text,text,text,text,text,bigint,text,jsonb)','jsonb'),
            ('iam.claim_security_notification(text)',
                'TABLE(tenant_id text, notification_id text, user_id text, installation_id text, kind text, email text, created_at timestamp with time zone, fence bigint, lease_expires_at timestamp with time zone, verification_id text, bootstrap_digest text, credential_generation bigint, contact_revision bigint, issued_at timestamp with time zone, expires_at timestamp with time zone, key_id text, nonce bytea, ciphertext bytea)'),
            ('iam.complete_security_notification(text,text,text,bigint,text,integer)','void')) expected(signature,result)
            JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure(expected.signature)
            WHERE pg_get_function_result(p.oid)=expected.result AND p.proretset=(left(expected.result,6)='TABLE('))
        AND (SELECT count(*)=10 FROM pg_catalog.pg_proc p WHERE p.oid IN (
            to_regprocedure('iam.valid_security_mail_address(text)'),to_regprocedure('iam.debit_notification_send_budget(text,text,integer,integer)'),
            to_regprocedure('iam.lock_notification_subject(text,text,text,text)'),to_regprocedure('iam.notification_verification_snapshot(text,text)'),
            to_regprocedure('iam.notification_contact_snapshot(text,text,text,text,bigint)'),
            to_regprocedure('iam.assert_notification_worker()'),to_regprocedure('iam.notification_retry_delay(integer)'),
            to_regprocedure('iam.guard_notification_history()'),to_regprocedure('iam.verify_notification_facts()'),to_regprocedure('iam.verify_notification_delivery()'))
            AND p.proowner='matrix_iam_owner'::regrole AND NOT p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']
            AND NOT EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner))
        AND (SELECT count(*)=9 FROM pg_catalog.pg_trigger t WHERE t.tgrelid IN (
            to_regclass('iam.email_verification_keys'),to_regclass('iam.email_verification_keysets'),to_regclass('iam.notification_contacts'))
            AND t.tgname IN ('cannot_update','cannot_delete','cannot_truncate') AND t.tgenabled='A'
            AND t.tgfoid=to_regprocedure('iam.reject_policy_history_change()'))
        AND (SELECT count(*)=4 FROM pg_catalog.pg_trigger t WHERE t.tgname='notification_fact_link' AND t.tgenabled='A'
            AND t.tgfoid=to_regprocedure('iam.verify_notification_facts()') AND t.tgdeferrable AND t.tginitdeferred)
        AND (SELECT count(*)=3 FROM pg_catalog.pg_trigger t WHERE t.tgname='preserve_notification_history' AND t.tgenabled='A'
            AND t.tgfoid=to_regprocedure('iam.guard_notification_history()'))
        AND (SELECT count(*)=2 FROM pg_catalog.pg_trigger t WHERE t.tgname='notification_delivery_link' AND t.tgenabled='A'
            AND t.tgfoid=to_regprocedure('iam.verify_notification_delivery()') AND t.tgdeferrable AND t.tginitdeferred)
        AND has_function_privilege('matrix_iam_api','iam.start_notification_verification(text,text,text,text,text,bigint,text,text,text,text,text,text,bigint,text,text,bytea,bytea,timestamptz,timestamptz,jsonb)','EXECUTE')
        AND has_function_privilege('matrix_iam_notification_worker','iam.claim_security_notification(text)','EXECUTE')
        AND has_function_privilege('matrix_iam_notification_worker','iam.complete_security_notification(text,text,text,bigint,text,integer)','EXECUTE')
        AND has_function_privilege('matrix_iam_notification_worker','iam.read_email_verification_keyset()','EXECUTE')
        AND NOT has_function_privilege('matrix_iam_api','iam.claim_security_notification(text)','EXECUTE')
        AND NOT has_function_privilege('matrix_iam_api','iam.complete_security_notification(text,text,text,bigint,text,integer)','EXECUTE'),false)
$function$;
REVOKE ALL ON FUNCTION iam.notification_contract_ready()
    FROM PUBLIC,matrix_iam_api,matrix_iam_worker,matrix_iam_credential_recovery,matrix_iam_backup_custody,matrix_iam_notification_worker;
