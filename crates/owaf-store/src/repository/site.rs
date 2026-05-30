//! 站点仓库（对齐 Go SiteRepo）。Site 为 45 个业务列的大实体。

use sqlx::postgres::{PgArguments, PgPool};
use sqlx::query::QueryAs;
use sqlx::{Postgres, query_as};

use crate::error::Result;
use crate::models::Site;

const SITE_COLS: &str = "\
    id, created_at, updated_at, host, upstream_urls, bind, network, enabled, \
    tls_enabled, cert_id, min_tls_version, max_tls_version, cipher_suites, alpn, \
    policy_id, bot_protection_enabled, bot_protection_level, attack_protection_level, \
    anti_replay_enabled, anti_replay_ttl, anti_replay_action, \
    owasp_enabled, owasp_sensitivity, owasp_action, cve_enabled, cve_action, \
    rate_limit_enabled, rate_limit_window, rate_limit_max, rate_limit_action, \
    xff_mode, trusted_cidr, preserve_original_host, \
    max_body_bytes, upstream_tls_skip_verify, upstream_tls_server_name, \
    cache_enabled, cache_default_ttl, cache_rules, \
    maintenance_enabled, maintenance_html, maintenance_status, \
    block_html, block_status, custom_error_pages, \
    listener_id, forwarding_profile_id, inherit_listener_cert";

/// 45 个业务列（不含 id/created_at/updated_at/deleted_at），INSERT/UPDATE 共用。
const BIZ_COLS: &str = "\
 host, upstream_urls, bind, network, enabled, \
    tls_enabled, cert_id, min_tls_version, max_tls_version, cipher_suites, alpn, \
    policy_id, bot_protection_enabled, bot_protection_level, attack_protection_level, \
    anti_replay_enabled, anti_replay_ttl, anti_replay_action, \
    owasp_enabled, owasp_sensitivity, owasp_action, cve_enabled, cve_action, \
    rate_limit_enabled, rate_limit_window, rate_limit_max, rate_limit_action, \
    xff_mode, trusted_cidr, preserve_original_host, \
    max_body_bytes, upstream_tls_skip_verify, upstream_tls_server_name, \
    cache_enabled, cache_default_ttl, cache_rules, \
    maintenance_enabled, maintenance_html, maintenance_status, \
    block_html, block_status, custom_error_pages, \
    listener_id, forwarding_profile_id, inherit_listener_cert";

/// 按 BIZ_COLS 顺序绑定 45 个业务字段（INSERT/UPDATE 共用）。
fn bind_biz<'q, O>(
    q: QueryAs<'q, Postgres, O, PgArguments>,
    s: &'q Site,
) -> QueryAs<'q, Postgres, O, PgArguments> {
    q.bind(&s.host)
        .bind(&s.upstream_urls)
        .bind(&s.bind)
        .bind(&s.network)
        .bind(s.enabled)
        .bind(s.tls_enabled)
        .bind(s.cert_id)
        .bind(&s.min_tls_version)
        .bind(&s.max_tls_version)
        .bind(&s.cipher_suites)
        .bind(&s.alpn)
        .bind(s.policy_id)
        .bind(s.bot_protection_enabled)
        .bind(&s.bot_protection_level)
        .bind(&s.attack_protection_level)
        .bind(s.anti_replay_enabled)
        .bind(s.anti_replay_ttl)
        .bind(&s.anti_replay_action)
        .bind(s.owasp_enabled)
        .bind(&s.owasp_sensitivity)
        .bind(&s.owasp_action)
        .bind(s.cve_enabled)
        .bind(&s.cve_action)
        .bind(s.rate_limit_enabled)
        .bind(s.rate_limit_window)
        .bind(s.rate_limit_max)
        .bind(&s.rate_limit_action)
        .bind(&s.xff_mode)
        .bind(&s.trusted_cidr)
        .bind(s.preserve_original_host)
        .bind(s.max_body_bytes)
        .bind(s.upstream_tls_skip_verify)
        .bind(&s.upstream_tls_server_name)
        .bind(s.cache_enabled)
        .bind(s.cache_default_ttl)
        .bind(&s.cache_rules)
        .bind(s.maintenance_enabled)
        .bind(&s.maintenance_html)
        .bind(s.maintenance_status)
        .bind(&s.block_html)
        .bind(s.block_status)
        .bind(&s.custom_error_pages)
        .bind(s.listener_id)
        .bind(s.forwarding_profile_id)
        .bind(s.inherit_listener_cert)
}

pub struct SiteRepo {
    pool: PgPool,
}

impl SiteRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 全部站点（快照构建）：id 升序，排除软删除。
    pub async fn list_all(&self) -> Result<Vec<Site>> {
        let sql = format!("SELECT {SITE_COLS} FROM sites WHERE deleted_at IS NULL ORDER BY id ASC");
        Ok(query_as(&sql).fetch_all(&self.pool).await?)
    }

    /// 启用的站点（对齐 Go FindEnabled）。
    pub async fn find_enabled(&self) -> Result<Vec<Site>> {
        let sql = format!(
            "SELECT {SITE_COLS} FROM sites WHERE enabled = true AND deleted_at IS NULL \
             ORDER BY id ASC"
        );
        Ok(query_as(&sql).fetch_all(&self.pool).await?)
    }

    /// 指定 bind 的启用站点（对齐 Go FindByBind）。
    pub async fn find_by_bind(&self, bind: &str) -> Result<Vec<Site>> {
        let sql = format!(
            "SELECT {SITE_COLS} FROM sites WHERE bind = $1 AND enabled = true \
      AND deleted_at IS NULL ORDER BY id ASC"
        );
        Ok(query_as(&sql).bind(bind).fetch_all(&self.pool).await?)
    }

    pub async fn get(&self, id: i64) -> Result<Option<Site>> {
        let sql = format!("SELECT {SITE_COLS} FROM sites WHERE id = $1 AND deleted_at IS NULL");
        Ok(query_as(&sql).bind(id).fetch_optional(&self.pool).await?)
    }

    /// 新建，返回自增 id。占位符 $1..$45 与 bind_biz 顺序逐列对齐。
    pub async fn create(&self, s: &Site) -> Result<i64> {
        let sql = format!(
            "INSERT INTO sites ({BIZ_COLS}) VALUES (\
           $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
     $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, \
  $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, \
             $44, $45) RETURNING id"
        );
        let (id,): (i64,) = bind_biz(query_as(&sql), s).fetch_one(&self.pool).await?;
        Ok(id)
    }

    /// 全量更新（对齐 Go Save）：$1=id，$2..$46 为业务列。
    pub async fn update(&self, s: &Site) -> Result<()> {
        let sets: Vec<String> = BIZ_COLS
            .split(',')
            .map(str::trim)
            .enumerate()
            .map(|(i, col)| format!("{col} = ${}", i + 2))
            .collect();
        let sql = format!(
            "UPDATE sites SET {}, updated_at = now() WHERE id = $1 AND deleted_at IS NULL \
   RETURNING id",
            sets.join(", ")
        );
        let _: Option<(i64,)> = bind_biz(query_as(&sql).bind(s.id), s)
            .fetch_optional(&self.pool)
            .await?;
        Ok(())
    }

    /// 软删除。
    pub async fn delete(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE sites SET deleted_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 连同监听器一并软删除（对齐 Go DeleteWithListeners）：事务内执行。
    pub async fn delete_with_listeners(&self, id: i64) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE site_listeners SET deleted_at = now() WHERE site_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE sites SET deleted_at = now() WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}
