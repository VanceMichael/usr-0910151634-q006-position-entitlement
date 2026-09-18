-- 演示种子数据：机构 / 合约（时钟偏差）/ 密钥 / 授权范围 / 当日额度。
-- 示例密钥仅用于本地契约说明，不可用于其他环境。

INSERT INTO organizations (id, display_name, daily_quota) VALUES
    ('org-alpha', 'Alpha 定位机构', 100),
    ('org-beta',  'Beta 测绘机构', 20)
ON CONFLICT (id) DO NOTHING;

INSERT INTO contracts (organization_id, allowed_clock_skew_seconds, nonce_retention_seconds) VALUES
    ('org-alpha', 300, 86400),
    ('org-beta',  120, 86400)
ON CONFLICT (organization_id) DO NOTHING;

INSERT INTO api_keys (key_id, organization_id, shared_secret, status) VALUES
    ('demo-key-a',   'org-alpha', 'local-demo-secret-alpha',   'active'),
    ('demo-key-a-c', 'org-alpha', 'local-demo-secret-alpha-2', 'active'),
    ('demo-key-b',   'org-beta',  'local-demo-secret-beta',    'active')
ON CONFLICT (key_id) DO NOTHING;

INSERT INTO key_scopes (key_id, resource_scope) VALUES
    ('demo-key-a',   'correction/basic'),
    ('demo-key-a',   'correction/rtk'),
    ('demo-key-a',   'ephemeris/nav'),
    ('demo-key-a-c', 'correction/basic'),
    ('demo-key-a-c', 'correction/rtk'),
    ('demo-key-b',   'correction/basic')
ON CONFLICT DO NOTHING;
