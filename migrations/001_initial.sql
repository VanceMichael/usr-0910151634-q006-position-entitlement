-- 定位数据授权用量结算：初始结构
-- 所有时间戳均以 UTC 存储（连接层 SET TIME ZONE 'UTC'）。

CREATE TABLE IF NOT EXISTS organizations (
    id          TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    daily_quota BIGINT NOT NULL CHECK (daily_quota >= 0),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 合约参数：允许的时钟偏差等按机构在此读取，不允许硬编码到应用里。
CREATE TABLE IF NOT EXISTS contracts (
    organization_id              TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE RESTRICT,
    allowed_clock_skew_seconds   INTEGER NOT NULL CHECK (allowed_clock_skew_seconds BETWEEN 0 AND 86400),
    nonce_retention_seconds      INTEGER NOT NULL CHECK (nonce_retention_seconds >= 60),
    updated_at                   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 密钥永不物理删除：轮换只把旧 key 置为 rotated 并指向新 key，
-- 历史事件与审计中的 key_id 通过 ON DELETE RESTRICT 永久保留。
CREATE TABLE IF NOT EXISTS api_keys (
    key_id          TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    -- HMAC 共享密钥：演示环境明文保存；生产环境必须替换为 KMS/信封加密。
    shared_secret   TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'rotated', 'revoked')),
    superseded_by   TEXT REFERENCES api_keys(key_id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS api_keys_org_idx ON api_keys(organization_id);

CREATE TABLE IF NOT EXISTS key_scopes (
    key_id         TEXT NOT NULL REFERENCES api_keys(key_id) ON DELETE RESTRICT,
    resource_scope TEXT NOT NULL,
    granted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (key_id, resource_scope)
);

-- 防重放：同一 key_id 下 nonce 唯一；request_timestamp 供按合约保留期清理。
CREATE TABLE IF NOT EXISTS used_nonces (
    id                BIGSERIAL PRIMARY KEY,
    key_id            TEXT NOT NULL REFERENCES api_keys(key_id) ON DELETE RESTRICT,
    nonce             TEXT NOT NULL,
    request_timestamp TIMESTAMPTZ NOT NULL,
    seen_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (key_id, nonce)
);
CREATE INDEX IF NOT EXISTS used_nonces_ts_idx ON used_nonces(request_timestamp);

-- 按 UTC 账期累计的已用量；扣减在同一行上用谓词 UPDATE 串行化，杜绝超扣。
CREATE TABLE IF NOT EXISTS daily_quota_usage (
    organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    billing_day     DATE NOT NULL,
    consumed        BIGINT NOT NULL DEFAULT 0 CHECK (consumed >= 0),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, billing_day)
);

-- 只追加的消费流水（账底）。
CREATE TABLE IF NOT EXISTS consumption_events (
    id               BIGSERIAL PRIMARY KEY,
    organization_id  TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    key_id           TEXT NOT NULL,
    resource_scope   TEXT NOT NULL,
    units            BIGINT NOT NULL CHECK (units > 0),
    idempotency_key  TEXT NOT NULL,
    billing_day      DATE NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, idempotency_key),
    CONSTRAINT consumption_events_key_fk
        FOREIGN KEY (key_id) REFERENCES api_keys(key_id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS consumption_events_day_idx
    ON consumption_events(organization_id, billing_day);

-- 幂等记录保存“初次结果”（获准与被拒都保存），重试原样返回。
CREATE TABLE IF NOT EXISTS idempotency_records (
    organization_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE RESTRICT,
    idempotency_key       TEXT NOT NULL,
    key_id                TEXT NOT NULL,
    request_fingerprint   TEXT NOT NULL,
    outcome               TEXT NOT NULL CHECK (outcome IN ('approved', 'rejected')),
    reject_reason         TEXT,
    consumption_event_id  BIGINT REFERENCES consumption_events(id) ON DELETE RESTRICT,
    http_status           SMALLINT NOT NULL,
    response              JSONB NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, idempotency_key)
);

-- 只追加的审计日志；id 即连续审计游标。
-- organization_id 可空：无法识别 key_id 的请求挂在空机构下，仅运营方可见。
CREATE TABLE IF NOT EXISTS audit_log (
    id                   BIGSERIAL PRIMARY KEY,
    occurred_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    organization_id      TEXT REFERENCES organizations(id) ON DELETE RESTRICT,
    key_id               TEXT NOT NULL,
    resource_scope       TEXT,
    units                BIGINT,
    nonce                TEXT,
    request_timestamp    TIMESTAMPTZ,
    idempotency_key      TEXT,
    signature_valid      BOOLEAN NOT NULL,
    decision             TEXT NOT NULL CHECK (decision IN ('approved', 'rejected', 'admin')),
    reject_reason        TEXT,
    consumption_event_id BIGINT REFERENCES consumption_events(id) ON DELETE RESTRICT,
    -- 运营排障字段：机构调用方查询时裁剪，不返回。
    debug_info           JSONB
);
CREATE INDEX IF NOT EXISTS audit_org_occurred_idx
    ON audit_log(organization_id, occurred_at);

-- 只追加保护：禁止 UPDATE/DELETE（TRUNCATE 另需在生产角色上收回权限）。
CREATE OR REPLACE FUNCTION enforce_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'table %.% is append-only; % is forbidden',
        TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

DO $$
DECLARE t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['consumption_events', 'idempotency_records', 'audit_log']
    LOOP
        EXECUTE format(
            'DROP TRIGGER IF EXISTS %I_append_only ON %I;', t, t);
        EXECUTE format(
            'CREATE TRIGGER %I_append_only BEFORE UPDATE OR DELETE ON %I
             FOR EACH ROW EXECUTE FUNCTION enforce_append_only();', t, t);
    END LOOP;
END;
$$;

-- 按 nonce 保留期清理过期防重放记录（运营维护调用）。
CREATE OR REPLACE FUNCTION prune_expired_nonces() RETURNS integer
LANGUAGE sql AS $$
    WITH deleted AS (
        DELETE FROM used_nonces n
        USING api_keys k, contracts c
        WHERE n.key_id = k.key_id
          AND k.organization_id = c.organization_id
          AND n.request_timestamp < now() - make_interval(secs => c.nonce_retention_seconds)
        RETURNING 1
    )
    SELECT count(*)::integer FROM deleted;
$$;
