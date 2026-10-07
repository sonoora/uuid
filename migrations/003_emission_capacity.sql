-- Additive admission policy. Existing immutable requests/receipts remain intact.
BEGIN;
CREATE TABLE IF NOT EXISTS uuid_audit.emission_capacity_policy (
 environment text NOT NULL CHECK(environment IN ('dev','prod')),
 bucket text NOT NULL CHECK(bucket IN ('global','wallet_create','wallet_deploy','money_transfer','remediation','subject')),
 per_minute integer NOT NULL CHECK(per_minute BETWEEN 1 AND 10000),
 per_second integer NOT NULL CHECK(per_second BETWEEN 1 AND 100),
 PRIMARY KEY(environment,bucket)
);
INSERT INTO uuid_audit.emission_capacity_policy
 SELECT e,b,m,s FROM unnest(ARRAY['dev','prod']) e
 CROSS JOIN (VALUES('global',120,8),('wallet_create',60,4),('wallet_deploy',60,4),
 ('money_transfer',90,4),('remediation',12,1),('subject',30,8)) p(b,m,s)
 ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS uuid_audit.emission_capacity_counters (
 environment text NOT NULL, bucket text NOT NULL, window_seconds integer NOT NULL,
 window_start timestamptz NOT NULL, count integer NOT NULL,
 PRIMARY KEY(environment,bucket,window_seconds,window_start)
);
CREATE INDEX IF NOT EXISTS emission_capacity_counter_expiry ON uuid_audit.emission_capacity_counters(window_start);
CREATE OR REPLACE FUNCTION uuid_audit.prepare_request(req jsonb, req_hash text, ctx_hash text, proposed_key uuid) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,uuid_audit AS $$
DECLARE e text; existing uuid_audit.emission_requests%ROWTYPE; hits integer;
 purpose text; subject text; row record; bucket_key text; stamp timestamptz; lim integer; seconds integer;
BEGIN
 e:=uuid_audit.caller_environment();
 purpose:=req->'context'->>'purpose';
 subject:=COALESCE(req->'context'->'details'->>'userId',req->'context'->'actor'->>'reference');
 IF req->'context'->>'environment' IS DISTINCT FROM e OR req->>'schemaVersion' IS DISTINCT FROM 'uuid-audit-v1'
 OR req_hash IS NULL OR ctx_hash IS NULL OR req_hash !~ '^[a-f0-9]{64}$' OR ctx_hash !~ '^[a-f0-9]{64}$'
 OR purpose IS NULL OR purpose NOT IN ('wallet_create','wallet_deploy','money_transfer','remediation')
 OR subject IS NULL OR length(subject) NOT BETWEEN 1 AND 320
 OR (req->>'idempotencyKey' IS NOT NULL AND (req->>'idempotencyKey')::uuid IS DISTINCT FROM proposed_key) THEN
  RAISE EXCEPTION 'scope rejected' USING ERRCODE='42501';
 END IF;
 INSERT INTO uuid_audit.emission_requests(environment,request_id,envelope,request_hash,context_hash,idempotency_key)
 VALUES(e,(req->>'requestId')::uuid,req,req_hash,ctx_hash,proposed_key) ON CONFLICT DO NOTHING;
 SELECT * INTO existing FROM uuid_audit.emission_requests WHERE environment=e AND request_id=(req->>'requestId')::uuid FOR UPDATE;
 IF existing.envelope IS DISTINCT FROM req OR existing.request_hash IS DISTINCT FROM req_hash OR existing.context_hash IS DISTINCT FROM ctx_hash THEN
  RAISE EXCEPTION 'request conflict' USING ERRCODE='P0002';
 END IF;
 IF (SELECT count(*) FROM uuid_audit.emission_capacity_policy WHERE environment=e AND bucket IN ('global',purpose,'subject')) <> 3 THEN
  RAISE EXCEPTION 'policy unavailable' USING ERRCODE='42501';
 END IF;
 -- Identical lock order for every caller/purpose. Denied admission rolls back all counters.
 FOR row IN SELECT * FROM uuid_audit.emission_capacity_policy WHERE environment=e AND bucket IN ('global',purpose,'subject') ORDER BY bucket LOOP
  bucket_key:=CASE WHEN row.bucket='subject' THEN 'subject:'||md5(subject) ELSE row.bucket END;
  FOREACH seconds IN ARRAY ARRAY[1,60] LOOP
   stamp:=date_trunc(CASE WHEN seconds=1 THEN 'second' ELSE 'minute' END,now());
   lim:=CASE WHEN seconds=1 THEN row.per_second ELSE row.per_minute END;
   INSERT INTO uuid_audit.emission_capacity_counters VALUES(e,bucket_key,seconds,stamp,1)
   ON CONFLICT(environment,bucket,window_seconds,window_start) DO UPDATE
    SET count=uuid_audit.emission_capacity_counters.count+1 RETURNING count INTO hits;
   IF hits>lim THEN RAISE EXCEPTION 'quota exceeded' USING ERRCODE='P0003'; END IF;
  END LOOP;
 END LOOP;
 -- Disposable admission counters have bounded cleanup; immutable journals are untouched.
 DELETE FROM uuid_audit.emission_capacity_counters WHERE ctid IN (
  SELECT ctid FROM uuid_audit.emission_capacity_counters WHERE window_start<now()-interval '2 days'
  ORDER BY window_start LIMIT 64);
 RETURN existing.idempotency_key;
END $$;
REVOKE ALL ON uuid_audit.emission_capacity_policy,uuid_audit.emission_capacity_counters FROM PUBLIC,sonoora_uuid_dev,sonoora_uuid_prod;
REVOKE ALL ON FUNCTION uuid_audit.prepare_request(jsonb,text,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION uuid_audit.prepare_request(jsonb,text,text,uuid) TO sonoora_uuid_dev,sonoora_uuid_prod;
GRANT SELECT ON uuid_audit.emission_capacity_policy,uuid_audit.emission_capacity_counters TO sonoora_uuid_audit_reader;
COMMIT;
