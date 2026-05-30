//! 领域模型（对齐 Go internal/store 的 GORM 结构体）。
//! 软删除列 deleted_at 不进结构体，查询显式列且过滤 deleted_at IS NULL。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

/// 通用键值系统配置（对齐 Go SystemSettings）。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SystemSettings {
    pub id: i64,
    pub key: String,
    pub value: String,
}

/// 单调递增的快照修订号（对齐 Go ConfigRevision）。
#[derive(Debug, Clone, Copy, FromRow, Serialize, Deserialize)]
pub struct ConfigRevision {
    pub id: i64,
    pub revision: i64,
}

/// TLS 证书 + 私钥（对齐 Go Certificate）。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Certificate {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub name: String,
    pub cert_pem: String,
    pub key_pem: String,
}

/// 规则集合容器（对齐 Go Policy）。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Policy {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub name: String,
}

/// 单条规则（对齐 Go Rule）。phase/action 以字符串存储。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Rule {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub name: String,
    pub policy_id: i64,
    pub phase: String,
    pub pattern: String,
    pub action: String,
    pub priority: i32,
    pub enabled: bool,
    pub status_code: i32,
    pub redirect_to: String,
}

/// 站点网络监听端点（对齐 Go SiteListener）。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SiteListener {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub site_id: i64,
    pub bind: String,
    pub network: String,
    pub tls_enabled: bool,
    pub cert_id: Option<i64>,
    pub enabled: bool,
    pub note: String,
}

/// 虚拟主机配置（对齐 Go Site）：监听、TLS、防护、转发、缓存、维护、错误页。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Site {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    pub host: String,
    pub upstream_urls: String,

    pub bind: String,
    pub network: String,
    pub enabled: bool,

    pub tls_enabled: bool,
    pub cert_id: Option<i64>,
    pub min_tls_version: String,
    pub max_tls_version: String,
    pub cipher_suites: String,
    pub alpn: String,

    pub policy_id: Option<i64>,
    pub bot_protection_enabled: bool,
    pub bot_protection_level: String,
    pub attack_protection_level: String,

    pub anti_replay_enabled: bool,
    pub anti_replay_ttl: i32,
    pub anti_replay_action: String,

    pub owasp_enabled: Option<bool>,
    pub owasp_sensitivity: String,
    pub owasp_action: String,
    pub cve_enabled: Option<bool>,
    pub cve_action: String,
    pub rate_limit_enabled: Option<bool>,
    pub rate_limit_window: i32,
    pub rate_limit_max: i32,
    pub rate_limit_action: String,

    pub xff_mode: String,
    pub trusted_cidr: String,
    pub preserve_original_host: bool,

    pub max_body_bytes: i64,
    pub upstream_tls_skip_verify: bool,
    pub upstream_tls_server_name: String,

    pub cache_enabled: bool,
    pub cache_default_ttl: i32,
    pub cache_rules: String,

    pub maintenance_enabled: bool,
    pub maintenance_html: String,
    pub maintenance_status: i32,

    pub block_html: String,
    pub block_status: i32,

    pub custom_error_pages: String,

    pub listener_id: i64,
    pub forwarding_profile_id: Option<i64>,
    pub inherit_listener_cert: bool,
}

/// 管理 API 静态令牌（对齐 Go AdminAPIKey）。唯一带软删除的 auth 表。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AdminApiKey {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub name: String,
    pub token_hash: String,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// 管理账户（对齐 Go AdminAccount）：仅 username/password_hash/updated_at。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AdminAccount {
    pub id: i64,
    pub username: String,
    pub password_hash: String,
    pub updated_at: DateTime<Utc>,
}

/// 刷新令牌会话（对齐 Go RefreshToken）。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: i64,
    pub jti: String,
    pub token_hash: String,
    pub username: String,
    pub role: String,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
    pub replaced_by: String,
    pub created_at: DateTime<Utc>,
}

/// 令牌黑名单（对齐 Go TokenBlacklist）。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TokenBlacklist {
    pub id: i64,
    pub jti: String,
    pub expires_at: DateTime<Utc>,
    pub reason: String,
    pub created_at: DateTime<Utc>,
}

/// 登录尝试记录（对齐 Go LoginAttempt）。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct LoginAttempt {
    pub id: i64,
    pub username: String,
    pub ip: String,
    pub success: bool,
    pub user_agent: String,
    pub created_at: DateTime<Utc>,
}

/// 活跃会话（对齐 Go ActiveSession）。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct ActiveSession {
    pub id: i64,
    pub username: String,
    pub jti: String,
    pub ip: String,
    pub user_agent: String,
    pub device_info: String,
    pub login_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// 安全事件（对齐 Go SecurityEvent）：每次命中的 block/observe/challenge/drop。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub site_id: i64,
    pub request_id: String,
    pub client_ip: String,
    pub host: String,
    pub path: String,
    pub method: String,
    pub user_agent: String,
    pub rule_id: i64,
    pub rule_id_str: String,
    pub phase: String,
    pub action: String,
    pub category: String,
    pub match_desc: String,
    pub geo_country: String,
    pub geo_city: String,
    pub status_code: i32,
}

/// 访问日志（对齐 Go AccessLog）：每个入站请求结果。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct AccessLog {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub site_id: i64,
    pub request_id: String,
    pub client_ip: String,
    pub host: String,
    pub path: String,
    pub query_string: String,
    pub method: String,
    pub status_code: i32,
    pub waf_action: String,
    pub cache_state: String,
    pub upstream: String,
    pub user_agent: String,
    pub upstream_latency_ms: i64,
    pub response_size: i64,
}

/// TCP 连接 drop 事件（对齐 Go DropEvent）：无 HTTP 响应。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct DropEvent {
    pub id: i64,
    pub site_id: i64,
    pub client_ip: String,
    pub source: String,
    pub rule_id: String,
    pub detail: String,
    pub host: String,
    pub path: String,
    pub created_at: DateTime<Utc>,
}

/// Bot 评分日志（对齐 Go BotScoreLog）。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct BotScoreLog {
    pub id: i64,
    pub client_ip: String,
    pub host: String,
    pub path: String,
    pub total_score: i32,
    pub geoip_score: i32,
    pub fingerprint_score: i32,
    pub behavior_score: i32,
    pub ip_rep_score: i32,
    pub is_high_risk: bool,
    pub action: String,
    pub details: String,
    pub created_at: DateTime<Utc>,
}

/// 旧动作字符串归一（对齐 Go NormalizeAction）：block->intercept、log_only->observe。
/// 黑/白名单 IP 条目（对齐 Go IPListEntry）。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct IpListEntry {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub kind: String,
    pub value: String,
    pub note: String,
    pub enabled: bool,
}

/// CVE 检测规则（对齐 Go waf.CVERuleModel）。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct CveRule {
    pub id: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub cve_id: String,
    pub category: String,
    pub pattern: String,
    pub target: String,
    pub severity: String,
    pub action: String,
    pub enabled: bool,
    pub description: String,
    pub source: String,
    pub approved: bool,
    pub cvss_score: f64,
    pub cwe_type: String,
}

/// CVE 同步运行记录（对齐 Go CVESyncLog）。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct CveSyncLog {
    pub id: i64,
    pub source: String,
    pub status: String,
    pub rules_added: i32,
    pub error: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
}

/// 指纹聚合记录（对齐 Go FingerprintRecord）。
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct FingerprintRecord {
    pub id: i64,
    pub ja3_hash: String,
    pub browser: String,
    pub count: i64,
    pub last_seen: DateTime<Utc>,
    pub is_known_good: bool,
}

pub fn normalize_action(action: &str) -> &str {
    match action {
        "block" => "intercept",
        "log_only" => "observe",
        other => other,
    }
}
