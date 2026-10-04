-- Additive issuance-only journal. Standalone; does not require or erase 001.
BEGIN;
CREATE SCHEMA IF NOT EXISTS uuid_audit;
REVOKE ALL ON SCHEMA uuid_audit FROM PUBLIC;
CREATE TABLE IF NOT EXISTS uuid_audit.emission_requests (
 environment text NOT NULL CHECK(environment IN ('dev','prod')), request_id uuid NOT NULL,
 envelope jsonb NOT NULL, request_hash text NOT NULL, context_hash text NOT NULL,
 idempotency_key uuid NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(environment,request_id)
);
CREATE TABLE IF NOT EXISTS uuid_audit.emission_receipts (
 environment text NOT NULL, request_id uuid NOT NULL, issuance_id uuid PRIMARY KEY,
 receipt jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(environment,request_id) REFERENCES uuid_audit.emission_requests(environment,request_id)
);
CREATE INDEX IF NOT EXISTS emission_receipts_request ON uuid_audit.emission_receipts(environment,request_id,created_at DESC);
CREATE TABLE IF NOT EXISTS uuid_audit.emission_quotas (
 environment text NOT NULL, minute timestamptz NOT NULL, count integer NOT NULL,
 PRIMARY KEY(environment,minute)
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

CREATE OR REPLACE FUNCTION uuid_audit.prepare_request(req jsonb, req_hash text, ctx_hash text, proposed_key uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,uuid_audit AS $$
DECLARE e text; existing uuid_audit.emission_requests%ROWTYPE; hits integer;
BEGIN
 e:=uuid_audit.caller_environment();
 IF req->'context'->>'environment' IS DISTINCT FROM e OR req->>'schemaVersion' IS DISTINCT FROM 'uuid-audit-v1'
 OR req_hash !~ '^[a-f0-9]{64}$' OR ctx_hash !~ '^[a-f0-9]{64}$'
 OR (req->>'idempotencyKey' IS NOT NULL AND (req->>'idempotencyKey')::uuid IS DISTINCT FROM proposed_key) THEN
  RAISE EXCEPTION 'scope rejected' USING ERRCODE='42501';
 END IF;
 INSERT INTO uuid_audit.emission_requests(environment,request_id,envelope,request_hash,context_hash,idempotency_key)
 VALUES(e,(req->>'requestId')::uuid,req,req_hash,ctx_hash,proposed_key) ON CONFLICT DO NOTHING;
 SELECT * INTO existing FROM uuid_audit.emission_requests WHERE environment=e AND request_id=(req->>'requestId')::uuid FOR UPDATE;
 IF existing.envelope IS DISTINCT FROM req OR existing.request_hash IS DISTINCT FROM req_hash OR existing.context_hash IS DISTINCT FROM ctx_hash THEN
  RAISE EXCEPTION 'request conflict' USING ERRCODE='P0002';
 END IF;
 INSERT INTO uuid_audit.emission_quotas VALUES(e,date_trunc('minute',now()),1)
 ON CONFLICT(environment,minute) DO UPDATE SET count=uuid_audit.emission_quotas.count+1 RETURNING count INTO hits;
 IF hits>30 THEN RAISE EXCEPTION 'quota exceeded' USING ERRCODE='P0003'; END IF;
 RETURN existing.idempotency_key;
END $$;
CREATE OR REPLACE FUNCTION uuid_audit.record_receipt(rec jsonb) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,uuid_audit AS $$
DECLARE e text; existing uuid_audit.emission_requests%ROWTYPE;
BEGIN
 e:=uuid_audit.caller_environment();
 SELECT * INTO existing FROM uuid_audit.emission_requests WHERE environment=e AND request_id=(rec->>'requestId')::uuid;
 IF NOT FOUND OR rec->>'environment' IS DISTINCT FROM e OR rec->>'verifiedCaller' IS DISTINCT FROM 'api-'||e
 OR rec->>'schemaVersion' IS DISTINCT FROM 'uuid-audit-receipt-v1'
 OR rec->>'requestHash' IS DISTINCT FROM existing.request_hash OR rec->>'contextHash' IS DISTINCT FROM existing.context_hash
 OR (rec->>'idempotencyKey')::uuid IS DISTINCT FROM existing.idempotency_key
 OR (SELECT count(*) FROM jsonb_object_keys(rec)) <> 11
 OR NOT rec ?& ARRAY['schemaVersion','issuanceId','requestId','idempotencyKey','verifiedCaller','environment','issuedAt','contextHash','requestHash','ciphertextHash','issuanceHash'] THEN
  RAISE EXCEPTION 'scope rejected' USING ERRCODE='42501';
 END IF;
 INSERT INTO uuid_audit.emission_receipts VALUES(e,existing.request_id,(rec->>'issuanceId')::uuid,rec,clock_timestamp());
 RETURN true;
END $$;
CREATE OR REPLACE FUNCTION uuid_audit.read_emission_receipt(request uuid) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,uuid_audit AS $$
 SELECT receipt FROM uuid_audit.emission_receipts WHERE environment=uuid_audit.caller_environment() AND request_id=request ORDER BY created_at DESC,issuance_id DESC LIMIT 1
$$;
REVOKE ALL ON ALL TABLES IN SCHEMA uuid_audit FROM PUBLIC,sonoora_uuid_dev,sonoora_uuid_prod;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA uuid_audit FROM PUBLIC;
GRANT USAGE ON SCHEMA uuid_audit TO sonoora_uuid_dev,sonoora_uuid_prod,sonoora_uuid_audit_reader;
GRANT EXECUTE ON FUNCTION uuid_audit.prepare_request(jsonb,text,text,uuid),uuid_audit.record_receipt(jsonb),uuid_audit.read_emission_receipt(uuid) TO sonoora_uuid_dev,sonoora_uuid_prod;
GRANT SELECT ON uuid_audit.emission_requests,uuid_audit.emission_receipts TO sonoora_uuid_audit_reader;
-- Disable grants from the superseded candidate without dropping its evidence.
DO $$ BEGIN
 IF to_regprocedure('uuid_audit.record_emission(jsonb,jsonb)') IS NOT NULL THEN
   REVOKE EXECUTE ON FUNCTION uuid_audit.record_emission(jsonb,jsonb) FROM sonoora_uuid_dev,sonoora_uuid_prod;
 END IF;
 IF to_regprocedure('uuid_audit.read_receipt(uuid)') IS NOT NULL THEN
   REVOKE EXECUTE ON FUNCTION uuid_audit.read_receipt(uuid) FROM sonoora_uuid_dev,sonoora_uuid_prod;
 END IF;
END $$;
COMMIT;
