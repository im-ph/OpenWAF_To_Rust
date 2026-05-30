//! 安全事件仓库（对齐 Go SecurityEventRepo）。*BySite 折叠为 site_id: Option。

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::postgres::PgPool;
use sqlx::{FromRow, Postgres, QueryBuilder};

use crate::error::Result;
use crate::models::SecurityEvent;

const COLS: &str = "id, created_at, site_id, request_id, client_ip, host, path, method, \
     user_agent, rule_id, rule_id_str, phase, action, category, match_desc, \
     geo_country, geo_city, status_code";

/// 列表过滤（对齐 Go SecurityEventFilter）。
#[derive(Debug, Default, Clone)]
pub struct SecurityEventFilter {
    pub site_id: Option<i64>,
    pub action: Option<String>,
    pub phase: Option<String>,
    pub category: Option<String>,
    pub client_ip: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub rule_id: Option<i64>,
    pub rule_id_str: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct CategoryStat {
    pub category: String,
    pub count: i64,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct IpStat {
    pub client_ip: String,
    pub count: i64,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct TimelineBucket {
    pub bucket: String,
    pub count: i64,
}

fn push_filters(qb: &mut QueryBuilder<Postgres>, f: &SecurityEventFilter) {
    if let Some(v) = f.site_id {
        qb.push(" AND site_id = ").push_bind(v);
    }
    if let Some(v) = &f.action {
        qb.push(" AND action = ").push_bind(v.clone());
    }
    if let Some(v) = &f.phase {
        qb.push(" AND phase = ").push_bind(v.clone());
    }
    if let Some(v) = &f.category {
        qb.push(" AND category = ").push_bind(v.clone());
    }
    if let Some(v) = &f.client_ip {
        qb.push(" AND client_ip = ").push_bind(v.clone());
    }
    if let Some(v) = &f.host {
        qb.push(" AND host = ").push_bind(v.clone());
    }
    if let Some(v) = &f.path {
        qb.push(" AND path LIKE ").push_bind(format!("%{v}%"));
    }
    if let Some(v) = f.rule_id {
        qb.push(" AND rule_id = ").push_bind(v);
    }
    if let Some(v) = &f.rule_id_str {
        qb.push(" AND rule_id_str = ").push_bind(v.clone());
    }
    if let Some(v) = f.since {
        qb.push(" AND created_at >= ").push_bind(v);
    }
    if let Some(v) = f.until {
        qb.push(" AND created_at <= ").push_bind(v);
    }
}

pub struct SecurityEventRepo {
    pool: PgPool,
}

impl SecurityEventRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 写入单条（对齐 Go Create 的直连 fallback）。
    pub async fn create(&self, e: &SecurityEvent) -> Result<i64> {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO security_events \
             (site_id, request_id, client_ip, host, path, method, user_agent, rule_id, \
              rule_id_str, phase, action, category, match_desc, geo_country, geo_city, status_code) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id",
        )
        .bind(e.site_id)
        .bind(&e.request_id)
        .bind(&e.client_ip)
        .bind(&e.host)
        .bind(&e.path)
        .bind(&e.method)
        .bind(&e.user_agent)
        .bind(e.rule_id)
        .bind(&e.rule_id_str)
        .bind(&e.phase)
        .bind(&e.action)
        .bind(&e.category)
        .bind(&e.match_desc)
        .bind(&e.geo_country)
        .bind(&e.geo_city)
        .bind(e.status_code)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    /// 批量写入（对齐 Go BatchCreate）：事务内逐条插入。
    pub async fn batch_create(&self, items: &[SecurityEvent]) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for e in items {
            sqlx::query(
                "INSERT INTO security_events \
                 (site_id, request_id, client_ip, host, path, method, user_agent, rule_id, \
                  rule_id_str, phase, action, category, match_desc, geo_country, geo_city, status_code) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
            )
            .bind(e.site_id)
            .bind(&e.request_id)
            .bind(&e.client_ip)
            .bind(&e.host)
            .bind(&e.path)
            .bind(&e.method)
            .bind(&e.user_agent)
            .bind(e.rule_id)
            .bind(&e.rule_id_str)
            .bind(&e.phase)
            .bind(&e.action)
            .bind(&e.category)
            .bind(&e.match_desc)
            .bind(&e.geo_country)
            .bind(&e.geo_city)
            .bind(e.status_code)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// 分页列表 + 总数（对齐 Go List）：id DESC。
    pub async fn list(
        &self,
        offset: i64,
        limit: i64,
        f: &SecurityEventFilter,
    ) -> Result<(Vec<SecurityEvent>, i64)> {
        let total = self.count(f).await?;
        let mut qb =
            QueryBuilder::<Postgres>::new(format!("SELECT {COLS} FROM security_events WHERE 1=1"));
        push_filters(&mut qb, f);
        qb.push(" ORDER BY id DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        let items = qb
            .build_query_as::<SecurityEvent>()
            .fetch_all(&self.pool)
            .await?;
        Ok((items, total))
    }

    pub async fn count(&self, f: &SecurityEventFilter) -> Result<i64> {
        let mut qb =
            QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM security_events WHERE 1=1");
        push_filters(&mut qb, f);
        Ok(qb.build_query_scalar::<i64>().fetch_one(&self.pool).await?)
    }

    pub async fn find_by_request_id(&self, request_id: &str) -> Result<Vec<SecurityEvent>> {
        let sql =
            format!("SELECT {COLS} FROM security_events WHERE request_id = $1 ORDER BY id ASC");
        Ok(sqlx::query_as(&sql)
            .bind(request_id)
            .fetch_all(&self.pool)
            .await?)
    }

    /// 删除早于 before 的事件（对齐 Go DeleteOlderThan），返回删除行数。
    pub async fn delete_older_than(&self, before: DateTime<Utc>) -> Result<u64> {
        let r = sqlx::query("DELETE FROM security_events WHERE created_at < $1")
            .bind(before)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }

    /// 分类统计（对齐 Go CategoryStats[BySite]）。
    pub async fn category_stats(
        &self,
        site_id: Option<i64>,
        since: DateTime<Utc>,
    ) -> Result<Vec<CategoryStat>> {
        let mut qb = QueryBuilder::<Postgres>::new(
            "SELECT category, COUNT(*) as count FROM security_events \
             WHERE created_at >= ",
        );
        qb.push_bind(since).push(" AND category <> ''");
        if let Some(s) = site_id {
            qb.push(" AND site_id = ").push_bind(s);
        }
        qb.push(" GROUP BY category ORDER BY count DESC");
        Ok(qb
            .build_query_as::<CategoryStat>()
            .fetch_all(&self.pool)
            .await?)
    }

    /// Top 客户端 IP（对齐 Go TopIPs[BySite]）。
    pub async fn top_ips(
        &self,
        site_id: Option<i64>,
        since: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<IpStat>> {
        let mut qb = QueryBuilder::<Postgres>::new(
            "SELECT client_ip, COUNT(*) as count FROM security_events WHERE created_at >= ",
        );
        qb.push_bind(since);
        if let Some(s) = site_id {
            qb.push(" AND site_id = ").push_bind(s);
        }
        qb.push(" GROUP BY client_ip ORDER BY count DESC LIMIT ")
            .push_bind(limit);
        Ok(qb.build_query_as::<IpStat>().fetch_all(&self.pool).await?)
    }

    /// 时间线按小时分桶（对齐 Go Timeline；sqlite strftime -> Postgres date_trunc）。
    pub async fn timeline(
        &self,
        site_id: Option<i64>,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> Result<Vec<TimelineBucket>> {
        let mut qb = QueryBuilder::<Postgres>::new(
            "SELECT to_char(date_trunc('hour', created_at), 'YYYY-MM-DD HH24:00') as bucket, \
             COUNT(*) as count FROM security_events WHERE created_at >= ",
        );
        qb.push_bind(since)
            .push(" AND created_at <= ")
            .push_bind(until);
        if let Some(s) = site_id {
            qb.push(" AND site_id = ").push_bind(s);
        }
        qb.push(" GROUP BY bucket ORDER BY bucket ASC");
        Ok(qb
            .build_query_as::<TimelineBucket>()
            .fetch_all(&self.pool)
            .await?)
    }
}
