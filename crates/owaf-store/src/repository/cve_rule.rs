//! CVE 规则与同步日志仓库（对齐 Go CVERuleRepo / CVESyncLogRepo）。

use sqlx::postgres::PgPool;
use sqlx::{Postgres, QueryBuilder};

use crate::error::Result;
use crate::models::{CveRule, CveSyncLog};

const COLS: &str = "id, created_at, updated_at, cve_id, category, pattern, target, severity, \
     action, enabled, description, source, approved, cvss_score, cwe_type";

/// 列表过滤（对齐 Go CVERuleFilter）。
#[derive(Debug, Default, Clone)]
pub struct CveRuleFilter {
    pub category: Option<String>,
    pub severity: Option<String>,
    pub enabled: Option<bool>,
    pub source: Option<String>,
}

fn push_filters(qb: &mut QueryBuilder<Postgres>, f: &CveRuleFilter) {
    qb.push(" AND deleted_at IS NULL");
    if let Some(v) = &f.category {
        qb.push(" AND category = ").push_bind(v.clone());
    }
    if let Some(v) = &f.severity {
        qb.push(" AND severity = ").push_bind(v.clone());
    }
    if let Some(v) = f.enabled {
        qb.push(" AND enabled = ").push_bind(v);
    }
    if let Some(v) = &f.source {
        qb.push(" AND source = ").push_bind(v.clone());
    }
}

pub struct CveRuleRepo {
    pool: PgPool,
}

impl CveRuleRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list(
        &self,
        offset: i64,
        limit: i64,
        f: &CveRuleFilter,
    ) -> Result<(Vec<CveRule>, i64)> {
        let mut cq = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM cve_rules WHERE 1=1");
        push_filters(&mut cq, f);
        let total = cq.build_query_scalar::<i64>().fetch_one(&self.pool).await?;

        let mut qb =
            QueryBuilder::<Postgres>::new(format!("SELECT {COLS} FROM cve_rules WHERE 1=1"));
        push_filters(&mut qb, f);
        qb.push(" ORDER BY id DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        let items = qb.build_query_as::<CveRule>().fetch_all(&self.pool).await?;
        Ok((items, total))
    }

    pub async fn get(&self, id: i64) -> Result<Option<CveRule>> {
        Ok(sqlx::query_as::<_, CveRule>(&format!(
            "SELECT {COLS} FROM cve_rules WHERE id = $1 AND deleted_at IS NULL"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn create(&self, c: &CveRule) -> Result<i64> {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO cve_rules \
      (cve_id, category, pattern, target, severity, action, enabled, description, \
              source, approved, cvss_score, cwe_type) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING id",
        )
        .bind(&c.cve_id)
        .bind(&c.category)
        .bind(&c.pattern)
        .bind(&c.target)
        .bind(&c.severity)
        .bind(&c.action)
        .bind(c.enabled)
        .bind(&c.description)
        .bind(&c.source)
        .bind(c.approved)
        .bind(c.cvss_score)
        .bind(&c.cwe_type)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn update(&self, c: &CveRule) -> Result<()> {
        sqlx::query(
            "UPDATE cve_rules SET cve_id = $2, category = $3, pattern = $4, target = $5, \
             severity = $6, action = $7, enabled = $8, description = $9, source = $10, \
      approved = $11, cvss_score = $12, cwe_type = $13, updated_at = now() \
   WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(c.id)
        .bind(&c.cve_id)
        .bind(&c.category)
        .bind(&c.pattern)
        .bind(&c.target)
        .bind(&c.severity)
        .bind(&c.action)
        .bind(c.enabled)
        .bind(&c.description)
        .bind(&c.source)
        .bind(c.approved)
        .bind(c.cvss_score)
        .bind(&c.cwe_type)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE cve_rules SET deleted_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn toggle(&self, id: i64, enabled: bool) -> Result<()> {
        sqlx::query("UPDATE cve_rules SET enabled = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(enabled)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 未审批规则数（对齐 Go PendingApprovalCount）。
    pub async fn pending_approval_count(&self) -> Result<i64> {
        Ok(sqlx::query_scalar(
            "SELECT COUNT(*) FROM cve_rules WHERE deleted_at IS NULL AND approved = false",
        )
        .fetch_one(&self.pool)
        .await?)
    }
}

pub struct CveSyncLogRepo {
    pool: PgPool,
}

impl CveSyncLogRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, l: &CveSyncLog) -> Result<i64> {
        let (id,): (i64,) = sqlx::query_as(
 "INSERT INTO cve_sync_logs (source, status, rules_added, error, started_at, finished_at) \
             VALUES ($1,$2,$3,$4,$5,$6) RETURNING id",
        )
        .bind(&l.source)
        .bind(&l.status)
        .bind(l.rules_added)
        .bind(&l.error)
        .bind(l.started_at)
        .bind(l.finished_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn latest(&self, limit: i64) -> Result<Vec<CveSyncLog>> {
        Ok(sqlx::query_as::<_, CveSyncLog>(
            "SELECT id, source, status, rules_added, error, started_at, finished_at \
       FROM cve_sync_logs ORDER BY id DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?)
    }
}
