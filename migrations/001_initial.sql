-- 定位数据授权用量结算：初始 schema
-- 所有时间以 UTC 存储；账期 period_date 为 UTC 日期。
-- 本文件可重复执行（IF NOT EXISTS / OR REPLACE）。

CREATE TABLE IF NOT EXISTS organizations (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    daily_quota BIGINT NOT NULL CHECK (daily_quota >= 0),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 合同参数：允许的时钟偏差（秒）等均按机构从本表读取
CREATE TABLE IF NOT EXISTS contracts (
    organization_id       TEXT PRIMARY KEY REFERENCES organizations(id),
    clock_skew_seconds    INTEGER NOT NULL CHECK (clock_skew_seconds >= 0),
    max_units_per_request BIGINT CHECK (max_units_per_request IS NULL OR max_units_per_request > 0),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 密钥表只追加、不删除：轮换 = 插入新行并把旧行置为 rotated。
-- key_id 永不被抹除；历史事件另外保存 key_id 快照。
CREATE TABLE IF NOT EXISTS api_keys (
    key_id          TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    secret          TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active'
                      CHECK (status IN ('active', 'rotated', 'revoked')),
    superseded_by   TEXT REFERENCES api_keys(key_id),
    -- 查询审计时该调用方可见的字段白名单；'{}' 走默认裁剪，{'*'} 为全部
    view_fields     TEXT[] NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deactivated_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS api_keys_organization_idx ON api_keys(organization_id);

-- 机构获准的资源范围（权限判定依据）
CREATE TABLE IF NOT EXISTS scope_grants (
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    resource_scope  TEXT NOT NULL,
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    PRIMARY KEY (organization_id, resource_scope)
);

-- 每 UTC 账期一行；consumed 只在行锁内更新，CHECK 约束兜底不超扣
CREATE TABLE IF NOT EXISTS quota_periods (
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    period_date     DATE NOT NULL,
    quota           BIGINT NOT NULL CHECK (quota >= 0),
    consumed        BIGINT NOT NULL DEFAULT 0 CHECK (consumed >= 0 AND consumed <= quota),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, period_date)
);

-- 已见 nonce：仅签名与时戳校验通过的请求才登记
CREATE TABLE IF NOT EXISTS used_nonces (
    organization_id TEXT NOT NULL REFERENCES organizations(id),
    nonce           TEXT NOT NULL,
    first_key_id    TEXT NOT NULL,
    seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, nonce)
);

-- 获批消费台账（只增）。key_id 为不可变快照，与 api_keys 之间不设级联，
-- 密钥轮换/停用都不会影响历史行采用的 key_id。
CREATE TABLE IF NOT EXISTS consumption_events (
    id                BIGSERIAL PRIMARY KEY,
    organization_id   TEXT NOT NULL REFERENCES organizations(id),
    period_date       DATE NOT NULL,
    key_id            TEXT NOT NULL,
    idempotency_key   TEXT NOT NULL,
    nonce             TEXT NOT NULL,
    resource_scope    TEXT NOT NULL CHECK (resource_scope <> ''),
    units             BIGINT NOT NULL CHECK (units > 0),
    request_timestamp TIMESTAMPTZ NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (organization_id, idempotency_key),
    UNIQUE (organization_id, nonce)
);
CREATE INDEX IF NOT EXISTS consumption_events_period_idx
    ON consumption_events(organization_id, period_date);

-- 幂等结果：同 (机构, idempotency_key) 只有唯一结局，重试返回初次结果
CREATE TABLE IF NOT EXISTS idempotent_results (
    organization_id   TEXT NOT NULL,
    idempotency_key   TEXT NOT NULL,
    state             TEXT NOT NULL CHECK (state IN ('processing', 'final')),
    request_hash      TEXT NOT NULL,
    approved          BOOLEAN NOT NULL DEFAULT FALSE,
    http_status       INTEGER,
    reason            TEXT,
    response          JSONB NOT NULL DEFAULT '{}'::jsonb,
    key_id            TEXT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    finalized_at      TIMESTAMPTZ,
    PRIMARY KEY (organization_id, idempotency_key)
);

-- 只追加审计：每一次请求交付（含拒绝、幂等重试）都落一行
CREATE TABLE IF NOT EXISTS audit_log (
    id                   BIGSERIAL PRIMARY KEY,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    organization_id      TEXT,                       -- 无法归属（未知 key_id）时为空
    key_id               TEXT,                       -- 请求采用的 key_id 快照
    idempotency_key      TEXT,
    nonce                TEXT,
    resource_scope       TEXT,
    units                BIGINT,
    period_date          DATE,
    request_timestamp    TIMESTAMPTZ,
    signature            TEXT,
    request_hash         TEXT,
    result               TEXT NOT NULL
                           CHECK (result IN ('approved', 'rejected', 'idempotent_replay')),
    reason               TEXT,
    consumption_event_id BIGINT REFERENCES consumption_events(id),
    remaining_after      BIGINT
);
CREATE INDEX IF NOT EXISTS audit_org_cursor_idx
    ON audit_log(organization_id, id);
CREATE INDEX IF NOT EXISTS audit_org_period_idx
    ON audit_log(organization_id, period_date);

-- 审计表只追加：禁止 UPDATE / DELETE / TRUNCATE
CREATE OR REPLACE FUNCTION audit_log_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only; % is not permitted', TG_OP;
END;
$$;

DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

-- 迁移记账
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
