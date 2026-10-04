-- Migration owner only. Existing DEV/PROD databases; no runtime owns these objects.
BEGIN;
CREATE SCHEMA IF NOT EXISTS uuid_audit;
REVOKE ALL ON SCHEMA uuid_audit FROM PUBLIC;
CREATE TABLE IF NOT EXISTS uuid_audit.operations (
 environment text NOT NULL CHECK(environment IN ('dev','prod')), caller text NOT NULL,
 operation_id uuid NOT NULL, provider_key uuid NOT NULL, context_hash text NOT NULL CHECK(context_hash ~ '^[a-f0-9]{64}$'),
 context jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(environment,caller,operation_id), UNIQUE(environment,caller,provider_key)
);
CREATE TABLE IF NOT EXISTS uuid_audit.issuances (
 environment text NOT NULL, caller text NOT NULL, request_id uuid NOT NULL, issuance_id uuid NOT NULL UNIQUE,
 operation_id uuid NOT NULL, receipt jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(environment,caller,request_id),
 FOREIGN KEY(environment,caller,operation_id) REFERENCES uuid_audit.operations(environment,caller,operation_id)
);
CREATE INDEX IF NOT EXISTS uuid_issuance_operation ON uuid_audit.issuances(environment,caller,operation_id,created_at);
CREATE TABLE IF NOT EXISTS uuid_audit.quotas (
 environment text NOT NULL, caller text NOT NULL, minute timestamptz NOT NULL, count integer NOT NULL,
 PRIMARY KEY(environment,caller,minute)
);
DO $$ BEGIN
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='sonoora_uuid_dev') THEN CREATE ROLE sonoora_uuid_dev NOLOGIN; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='sonoora_uuid_prod') THEN CREATE ROLE sonoora_uuid_prod NOLOGIN; END IF;
 IF NOT EXISTS(SELECT FROM pg_roles WHERE rolname='sonoora_uuid_audit_reader') THEN CREATE ROLE sonoora_uuid_audit_reader NOLOGIN; END IF;
END $$;
CREATE OR REPLACE FUNCTION uuid_audit.caller_environment() RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,uuid_audit AS $$
DECLARE d boolean; p boolean;
BEGIN
 d:=pg_has_role(session_user,'sonoora_uuid_dev','member'); p:=pg_has_role(session_user,'sonoora_uuid_prod','member');
 IF d=p THEN RAISE EXCEPTION 'caller role rejected' USING ERRCODE='42501'; END IF;
 RETURN CASE WHEN d THEN 'dev' ELSE 'prod' END;
END $$;
CREATE OR REPLACE FUNCTION uuid_audit.record_emission(ctx jsonb, receipt jsonb) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,uuid_audit AS $$
DECLARE e text; c text; existing uuid_audit.operations%ROWTYPE; hits integer;
BEGIN
 e:=uuid_audit.caller_environment(); c:='api-'||e;
 IF ctx->>'environment' IS DISTINCT FROM e OR receipt->>'environment' IS DISTINCT FROM e
  OR receipt->>'verifiedCaller' IS DISTINCT FROM c OR receipt->>'operationId' IS DISTINCT FROM ctx->>'operationId'
  OR receipt->>'providerIdempotencyKey' IS DISTINCT FROM ctx->>'providerIdempotencyKey'
  OR ctx ? 'entitySecretCiphertext' OR receipt ? 'entitySecretCiphertext' THEN
  RAISE EXCEPTION 'scope rejected' USING ERRCODE='42501';
 END IF;
 INSERT INTO uuid_audit.operations(environment,caller,operation_id,provider_key,context_hash,context)
  VALUES(e,c,(ctx->>'operationId')::uuid,(ctx->>'providerIdempotencyKey')::uuid,receipt->>'contextHash',ctx) ON CONFLICT DO NOTHING;
 SELECT * INTO existing FROM uuid_audit.operations WHERE environment=e AND caller=c AND operation_id=(ctx->>'operationId')::uuid FOR UPDATE;
 IF NOT FOUND OR existing.context IS DISTINCT FROM ctx OR existing.context_hash IS DISTINCT FROM receipt->>'contextHash'
  OR existing.provider_key IS DISTINCT FROM (ctx->>'providerIdempotencyKey')::uuid THEN
  RAISE EXCEPTION 'context conflict' USING ERRCODE='P0002';
 END IF;
 IF EXISTS(SELECT FROM uuid_audit.issuances WHERE environment=e AND caller=c AND request_id=(record_emission.receipt->>'requestId')::uuid) THEN
  RAISE EXCEPTION 'request replay' USING ERRCODE='P0002';
 END IF;
 INSERT INTO uuid_audit.quotas VALUES(e,c,date_trunc('minute',now()),1)
  ON CONFLICT(environment,caller,minute) DO UPDATE SET count=uuid_audit.quotas.count+1 RETURNING count INTO hits;
 IF hits>30 THEN RAISE EXCEPTION 'quota exceeded' USING ERRCODE='P0003'; END IF;
 INSERT INTO uuid_audit.issuances VALUES(e,c,(receipt->>'requestId')::uuid,(receipt->>'issuanceId')::uuid,(ctx->>'operationId')::uuid,receipt,now());
 RETURN true;
END $$;
CREATE OR REPLACE FUNCTION uuid_audit.read_receipt(request uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,uuid_audit AS $$
 SELECT receipt FROM uuid_audit.issuances WHERE environment=uuid_audit.caller_environment()
  AND caller='api-'||uuid_audit.caller_environment() AND request_id=request
$$;
REVOKE ALL ON ALL TABLES IN SCHEMA uuid_audit FROM PUBLIC,sonoora_uuid_dev,sonoora_uuid_prod;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA uuid_audit FROM PUBLIC;
GRANT USAGE ON SCHEMA uuid_audit TO sonoora_uuid_dev,sonoora_uuid_prod,sonoora_uuid_audit_reader;
GRANT EXECUTE ON FUNCTION uuid_audit.record_emission(jsonb,jsonb),uuid_audit.read_receipt(uuid) TO sonoora_uuid_dev,sonoora_uuid_prod;
GRANT SELECT ON uuid_audit.operations,uuid_audit.issuances TO sonoora_uuid_audit_reader;
COMMIT;
