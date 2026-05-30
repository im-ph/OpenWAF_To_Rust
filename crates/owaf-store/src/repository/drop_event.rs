//! Drop 事件仓库（对齐 Go DropEventRepo）。

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::postgres::PgPool;
use sqlx::{FromRow, Postgres, QueryBuilder};

use crate::error::Result;
use crate::models::DropEvent;

const COLS: &str = "id, site_id, client_ip, source, rule_id, detail, host, path, created_at";

/// 列表过滤（对齐 Go DropEventFilter）。
#[derive(Debug, Default, Clone)]
pub struct DropEventFilter {
    pub site_id: Option<i64>,
    pub client_ip: Option<String>,
    pub source: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

/// 24 小时聚合统计（对齐 Go DropStatsSummary）。
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct DropStatsSummary {
    pub total_24h: i64,
    pub by_bot: i64,
    pub by_cve: i64,
    pub by_rule: i64,
    pub by_ip_reputation: i64,
}

pub struct DropEventRepo {
    pool: PgPool,
}

impl DropEventRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, d: &DropEvent) -> Result<i64> {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO drop_events (site_id, client_ip, source, rule_id, detail, host, path) \
    VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id",
        )
        .bind(d.site_id)
        .bind(&d.client_ip)
        .bind(&d.source)
        .bind(&d.rule_id)
        .bind(&d.detail)
        .bind(&d.host)
        .bind(&d.path)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn batch_create(&self, items: &[DropEvent]) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for d in items {
            sqlx::query(
                "INSERT INTO drop_events (site_id, client_ip, source, rule_id, detail, host, path) \
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
            )
            .bind(d.site_id)
            .bind(&d.client_ip)
            .bind(&d.source)
            .bind(&d.rule_id)
            .bind(&d.detail)
            .bind(&d.host)
            .bind(&d.path)
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
        f: &DropEventFilter,
    ) -> Result<(Vec<DropEvent>, i64)> {
        let mut cq = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM drop_events WHERE 1=1");
        push_filters(&mut cq, f);
        let total = cq.build_query_scalar::<i64>().fetch_one(&self.pool).await?;

        let mut qb =
            QueryBuilder::<Postgres>::new(format!("SELECT {COLS} FROM drop_events WHERE 1=1"));
        push_filters(&mut qb, f);
        qb.push(" ORDER BY id DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        let items = qb
            .build_query_as::<DropEvent>()
            .fetch_all(&self.pool)
            .await?;
        Ok((items, total))
    }

    pub async fn delete_older_than(&self, before: DateTime<Utc>) -> Result<u64> {
        let r = sqlx::query("DELETE FROM drop_events WHERE created_at < $1")
            .bind(before)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    /// 近 24 小时按来源聚合（对齐 Go Stats24h[BySite]）。
    pub async fn stats_24h(&self, site_id: Option<i64>) -> Result<DropStatsSummary> {
        let since = Utc::now() - Duration::hours(24);
        let mut qb = QueryBuilder::<Postgres>::new(
            "SELECT COUNT(*) as total_24h, \
             COUNT(*) FILTER (WHERE source = 'bot') as by_bot, \
 COUNT(*) FILTER (WHERE source = 'cve') as by_cve, \
             COUNT(*) FILTER (WHERE source = 'rule') as by_rule, \
      COUNT(*) FILTER (WHERE source = 'ip_reputation') as by_ip_reputation \
     FROM drop_events WHERE created_at >= ",
        );
        qb.push_bind(since);
        if let Some(s) = site_id {
            qb.push(" AND site_id = ").push_bind(s);
        }
        Ok(qb
            .build_query_as::<DropStatsSummary>()
            .fetch_one(&self.pool)
            .await?)
    }
}

fn push_filters(qb: &mut QueryBuilder<Postgres>, f: &DropEventFilter) {
    if let Some(v) = f.site_id {
        qb.push(" AND site_id = ").push_bind(v);
    }
    if let Some(v) = &f.client_ip {
        qb.push(" AND client_ip = ").push_bind(v.clone());
    }
    if let Some(v) = &f.source {
        qb.push(" AND source = ").push_bind(v.clone());
    }
    if let Some(v) = f.since {
        qb.push(" AND created_at >= ").push_bind(v);
    }
    if let Some(v) = f.until {
        qb.push(" AND created_at <= ").push_bind(v);
    }
}
