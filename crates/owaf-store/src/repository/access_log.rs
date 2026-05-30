//! 访问日志仓库（对齐 Go AccessLogRepo）。

use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use sqlx::{Postgres, QueryBuilder};

use crate::error::Result;
use crate::models::AccessLog;

const COLS: &str = "id, created_at, site_id, request_id, client_ip, host, path, query_string, \
     method, status_code, waf_action, cache_state, upstream, user_agent, \
     upstream_latency_ms, response_size";

/// 列表过滤（对齐 Go AccessLogFilter）。
#[derive(Debug, Default, Clone)]
pub struct AccessLogFilter {
    pub site_id: Option<i64>,
    pub client_ip: Option<String>,
    pub request_id: Option<String>,
    pub status_code: Option<i32>,
    pub waf_action: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

fn push_filters(qb: &mut QueryBuilder<Postgres>, f: &AccessLogFilter) {
    if let Some(v) = f.site_id {
        qb.push(" AND site_id = ").push_bind(v);
    }
    if let Some(v) = &f.client_ip {
        qb.push(" AND client_ip = ").push_bind(v.clone());
    }
    if let Some(v) = &f.request_id {
        qb.push(" AND request_id = ").push_bind(v.clone());
    }
    if let Some(v) = f.status_code {
        qb.push(" AND status_code = ").push_bind(v);
    }
    if let Some(v) = &f.waf_action {
        qb.push(" AND waf_action = ").push_bind(v.clone());
    }
    if let Some(v) = f.since {
        qb.push(" AND created_at >= ").push_bind(v);
    }
    if let Some(v) = f.until {
        qb.push(" AND created_at <= ").push_bind(v);
    }
}

pub struct AccessLogRepo {
    pool: PgPool,
}

impl AccessLogRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, a: &AccessLog) -> Result<i64> {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO access_logs \
             (site_id, request_id, client_ip, host, path, query_string, method, status_code, \
  waf_action, cache_state, upstream, user_agent, upstream_latency_ms, response_size) \
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id",
        )
        .bind(a.site_id)
        .bind(&a.request_id)
        .bind(&a.client_ip)
        .bind(&a.host)
        .bind(&a.path)
        .bind(&a.query_string)
        .bind(&a.method)
        .bind(a.status_code)
        .bind(&a.waf_action)
        .bind(&a.cache_state)
        .bind(&a.upstream)
        .bind(&a.user_agent)
        .bind(a.upstream_latency_ms)
        .bind(a.response_size)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn batch_create(&self, items: &[AccessLog]) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for a in items {
            sqlx::query(
                "INSERT INTO access_logs \
      (site_id, request_id, client_ip, host, path, query_string, method, status_code, \
             waf_action, cache_state, upstream, user_agent, upstream_latency_ms, response_size) \
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
            )
            .bind(a.site_id)
            .bind(&a.request_id)
            .bind(&a.client_ip)
            .bind(&a.host)
            .bind(&a.path)
            .bind(&a.query_string)
            .bind(&a.method)
            .bind(a.status_code)
            .bind(&a.waf_action)
            .bind(&a.cache_state)
            .bind(&a.upstream)
            .bind(&a.user_agent)
            .bind(a.upstream_latency_ms)
            .bind(a.response_size)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn list(
        &self,
        offset: i64,
        limit: i64,
        f: &AccessLogFilter,
    ) -> Result<(Vec<AccessLog>, i64)> {
        let mut cq = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM access_logs WHERE 1=1");
        push_filters(&mut cq, f);
        let total = cq.build_query_scalar::<i64>().fetch_one(&self.pool).await?;

        let mut qb =
            QueryBuilder::<Postgres>::new(format!("SELECT {COLS} FROM access_logs WHERE 1=1"));
        push_filters(&mut qb, f);
        qb.push(" ORDER BY id DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        let items = qb
            .build_query_as::<AccessLog>()
            .fetch_all(&self.pool)
            .await?;
        Ok((items, total))
    }

    pub async fn delete_older_than(&self, before: DateTime<Utc>) -> Result<u64> {
        let r = sqlx::query("DELETE FROM access_logs WHERE created_at < $1")
            .bind(before)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }
}
