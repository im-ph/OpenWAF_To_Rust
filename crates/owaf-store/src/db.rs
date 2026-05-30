//! 数据库连接与 schema 迁移（对齐 Go store.AutoMigrate 的子集）。
//! 采用 sqlx 运行时查询（非编译期宏），无需实时 PostgreSQL 即可编译。

use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::error::Result;

/// PostgreSQL 连接句柄。
#[derive(Clone)]
pub struct Db {
    pub pool: PgPool,
}

/// 已落地表的 schema（其余表按域在后续轮次追加）。
const MIGRATION_SQL: &str = "\
CREATE TABLE IF NOT EXISTS system_settings (
    id BIGSERIAL PRIMARY KEY,
key VARCHAR(128) UNIQUE NOT NULL,
    value TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS config_revisions (
    id BIGINT PRIMARY KEY,
    revision BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS certificates (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ,
    name VARCHAR(128) NOT NULL,
    cert_pem TEXT NOT NULL,
    key_pem TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS policies (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    name VARCHAR(128) NOT NULL
);
CREATE TABLE IF NOT EXISTS rules (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ,
    name VARCHAR(128) NOT NULL DEFAULT '',
    policy_id BIGINT NOT NULL,
    phase VARCHAR(32) NOT NULL,
    pattern TEXT NOT NULL,
    action VARCHAR(32) NOT NULL,
    priority INT NOT NULL DEFAULT 100,
    enabled BOOLEAN NOT NULL DEFAULT true,
 status_code INT NOT NULL DEFAULT 0,
  redirect_to VARCHAR(2048) NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS site_listeners (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    site_id BIGINT NOT NULL,
    bind VARCHAR(255) NOT NULL,
    network VARCHAR(16) NOT NULL DEFAULT 'tcp',
    tls_enabled BOOLEAN NOT NULL DEFAULT false,
    cert_id BIGINT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    note VARCHAR(255) NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS sites (
id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    host VARCHAR(255) NOT NULL,
    upstream_urls TEXT NOT NULL,
    bind VARCHAR(255) NOT NULL,
    network VARCHAR(16) NOT NULL DEFAULT 'tcp',
    enabled BOOLEAN NOT NULL DEFAULT true,
    tls_enabled BOOLEAN NOT NULL DEFAULT false,
    cert_id BIGINT,
    min_tls_version VARCHAR(32) NOT NULL DEFAULT 'TLS12',
    max_tls_version VARCHAR(32) NOT NULL DEFAULT 'TLS13',
    cipher_suites TEXT NOT NULL DEFAULT '',
 alpn VARCHAR(255) NOT NULL DEFAULT 'h2,http/1.1',
 policy_id BIGINT,
    bot_protection_enabled BOOLEAN NOT NULL DEFAULT false,
    bot_protection_level VARCHAR(16) NOT NULL DEFAULT 'medium',
    attack_protection_level VARCHAR(16) NOT NULL DEFAULT 'medium',
    anti_replay_enabled BOOLEAN NOT NULL DEFAULT false,
    anti_replay_ttl INT NOT NULL DEFAULT 300,
    anti_replay_action VARCHAR(64) NOT NULL DEFAULT 'shield_challenge',
    owasp_enabled BOOLEAN,
    owasp_sensitivity VARCHAR(16) NOT NULL DEFAULT '',
    owasp_action VARCHAR(32) NOT NULL DEFAULT '',
    cve_enabled BOOLEAN,
    cve_action VARCHAR(32) NOT NULL DEFAULT '',
    rate_limit_enabled BOOLEAN,
    rate_limit_window INT NOT NULL DEFAULT 0,
    rate_limit_max INT NOT NULL DEFAULT 0,
    rate_limit_action VARCHAR(32) NOT NULL DEFAULT '',
    xff_mode VARCHAR(64) NOT NULL DEFAULT 'strip_all_and_set_remote',
    trusted_cidr TEXT NOT NULL DEFAULT '',
 preserve_original_host BOOLEAN NOT NULL DEFAULT false,
    max_body_bytes BIGINT NOT NULL DEFAULT 10485760,
    upstream_tls_skip_verify BOOLEAN NOT NULL DEFAULT false,
    upstream_tls_server_name VARCHAR(255) NOT NULL DEFAULT '',
    cache_enabled BOOLEAN NOT NULL DEFAULT false,
    cache_default_ttl INT NOT NULL DEFAULT 0,
    cache_rules TEXT NOT NULL DEFAULT '',
    maintenance_enabled BOOLEAN NOT NULL DEFAULT false,
    maintenance_html TEXT NOT NULL DEFAULT '',
    maintenance_status INT NOT NULL DEFAULT 503,
    block_html TEXT NOT NULL DEFAULT '',
    block_status INT NOT NULL DEFAULT 403,
    custom_error_pages TEXT NOT NULL DEFAULT '{}',
    listener_id BIGINT NOT NULL DEFAULT 0,
    forwarding_profile_id BIGINT,
    inherit_listener_cert BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS admin_api_keys (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    name VARCHAR(128) NOT NULL DEFAULT '',
    token_hash VARCHAR(255) NOT NULL,
    last_used_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS admin_accounts (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    jti VARCHAR(128) UNIQUE NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    username VARCHAR(64) NOT NULL DEFAULT '',
    role VARCHAR(32) NOT NULL DEFAULT 'admin',
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    replaced_by VARCHAR(128) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS token_blacklist (
    id BIGSERIAL PRIMARY KEY,
    jti VARCHAR(64) UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason VARCHAR(128) NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    ip VARCHAR(45) NOT NULL DEFAULT '',
    success BOOLEAN NOT NULL DEFAULT false,
    user_agent VARCHAR(256) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS active_sessions (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    jti VARCHAR(64) UNIQUE,
    ip VARCHAR(45) NOT NULL DEFAULT '',
    user_agent VARCHAR(256) NOT NULL DEFAULT '',
    device_info VARCHAR(128) NOT NULL DEFAULT '',
    login_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS security_events (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    site_id BIGINT NOT NULL DEFAULT 0,
    request_id VARCHAR(64) NOT NULL DEFAULT '',
    client_ip VARCHAR(45) NOT NULL DEFAULT '',
    host VARCHAR(255) NOT NULL DEFAULT '',
    path VARCHAR(2048) NOT NULL DEFAULT '',
    method VARCHAR(16) NOT NULL DEFAULT '',
    user_agent VARCHAR(512) NOT NULL DEFAULT '',
    rule_id BIGINT NOT NULL DEFAULT 0,
  rule_id_str VARCHAR(64) NOT NULL DEFAULT '',
    phase VARCHAR(32) NOT NULL DEFAULT '',
  action VARCHAR(32) NOT NULL DEFAULT '',
    category VARCHAR(32) NOT NULL DEFAULT '',
    match_desc VARCHAR(512) NOT NULL DEFAULT '',
    geo_country VARCHAR(2) NOT NULL DEFAULT '',
    geo_city VARCHAR(128) NOT NULL DEFAULT '',
status_code INT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS access_logs (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    site_id BIGINT NOT NULL DEFAULT 0,
    request_id VARCHAR(64) NOT NULL DEFAULT '',
    client_ip VARCHAR(45) NOT NULL DEFAULT '',
    host VARCHAR(255) NOT NULL DEFAULT '',
    path VARCHAR(2048) NOT NULL DEFAULT '',
    query_string VARCHAR(2048) NOT NULL DEFAULT '',
    method VARCHAR(16) NOT NULL DEFAULT '',
    status_code INT NOT NULL DEFAULT 0,
    waf_action VARCHAR(32) NOT NULL DEFAULT '',
    cache_state VARCHAR(16) NOT NULL DEFAULT '',
    upstream VARCHAR(512) NOT NULL DEFAULT '',
 user_agent VARCHAR(512) NOT NULL DEFAULT '',
    upstream_latency_ms BIGINT NOT NULL DEFAULT 0,
    response_size BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS drop_events (
    id BIGSERIAL PRIMARY KEY,
    site_id BIGINT NOT NULL DEFAULT 0,
  client_ip VARCHAR(45) NOT NULL DEFAULT '',
    source VARCHAR(32) NOT NULL DEFAULT '',
    rule_id VARCHAR(64) NOT NULL DEFAULT '',
 detail VARCHAR(512) NOT NULL DEFAULT '',
    host VARCHAR(256) NOT NULL DEFAULT '',
    path VARCHAR(512) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS bot_score_logs (
    id BIGSERIAL PRIMARY KEY,
    client_ip VARCHAR(45) NOT NULL DEFAULT '',
    host VARCHAR(256) NOT NULL DEFAULT '',
    path VARCHAR(512) NOT NULL DEFAULT '',
    total_score INT NOT NULL DEFAULT 0,
 geoip_score INT NOT NULL DEFAULT 0,
 fingerprint_score INT NOT NULL DEFAULT 0,
    behavior_score INT NOT NULL DEFAULT 0,
    ip_rep_score INT NOT NULL DEFAULT 0,
 is_high_risk BOOLEAN NOT NULL DEFAULT false,
    action VARCHAR(32) NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS ip_list_entries (
    id BIGSERIAL PRIMARY KEY,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    kind VARCHAR(16) NOT NULL,
    value VARCHAR(64) NOT NULL,
    note VARCHAR(255) NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT true
);
CREATE TABLE IF NOT EXISTS cve_rules (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    cve_id VARCHAR(32) NOT NULL DEFAULT '',
    category VARCHAR(32) NOT NULL DEFAULT '',
    pattern TEXT NOT NULL DEFAULT '',
target VARCHAR(32) NOT NULL DEFAULT '',
    severity VARCHAR(16) NOT NULL DEFAULT '',
    action VARCHAR(16) NOT NULL DEFAULT 'drop',
    enabled BOOLEAN NOT NULL DEFAULT false,
    description TEXT NOT NULL DEFAULT '',
    source VARCHAR(32) NOT NULL DEFAULT '',
    approved BOOLEAN NOT NULL DEFAULT false,
    cvss_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    cwe_type VARCHAR(32) NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS cve_sync_logs (
    id BIGSERIAL PRIMARY KEY,
  source VARCHAR(32) NOT NULL DEFAULT '',
    status VARCHAR(16) NOT NULL DEFAULT '',
    rules_added INT NOT NULL DEFAULT 0,
    error VARCHAR(512) NOT NULL DEFAULT '',
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS fingerprint_records (
    id BIGSERIAL PRIMARY KEY,
    ja3_hash VARCHAR(64) NOT NULL DEFAULT '',
    browser VARCHAR(64) NOT NULL DEFAULT '',
    count BIGINT NOT NULL DEFAULT 0,
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    is_known_good BOOLEAN NOT NULL DEFAULT false
);";

impl Db {
    /// 建立连接池（对齐 Go open DB）。
    pub async fn connect(dsn: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(dsn)
            .await?;
        Ok(Self { pool })
    }

    /// 应用 schema（对齐 Go AutoMigrate）。
    pub async fn run_migrations(&self) -> Result<()> {
        sqlx::raw_sql(MIGRATION_SQL).execute(&self.pool).await?;
        Ok(())
    }
}
