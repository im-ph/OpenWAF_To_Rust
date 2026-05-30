//! Bot 评分日志仓库（对齐 Go BotScoreRepo）。

use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::postgres::PgPool;
use sqlx::{FromRow, Postgres, QueryBuilder};

use crate::error::Result;
use crate::models::BotScoreLog;

const COLS: &str = "id, client_ip, host, path, total_score, geoip_score, fingerprint_score, \
     behavior_score, ip_rep_score, is_high_risk, action, details, created_at";

/// 列表过滤（对齐 Go BotScoreFilter）。
#[derive(Debug, Default, Clone)]
pub struct BotScoreFilter {
    pub client_ip: Option<String>,
    pub min_score: Option<i32>,
    pub max_score: Option<i32>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
}

/// 24 小时聚合统计（对齐 Go BotScoreStats）。
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct BotScoreStats {
    pub total_24h: i64,
    pub blocked_24h: i64,
    pub high_risk_24h: i64,
}

fn push_filters(qb: &mut QueryBuilder<Postgres>, f: &BotScoreFilter) {
    if let Some(v) = &f.client_ip {
        qb.push(" AND client_ip = ").push_bind(v.clone());
    }
    if let Some(v) = f.min_score {
        qb.push(" AND total_score >= ").push_bind(v);
    }
    if let Some(v) = f.max_score {
        qb.push(" AND total_score <= ").push_bind(v);
    }
    if let Some(v) = f.since {
        qb.push(" AND created_at >= ").push_bind(v);
    }
    if let Some(v) = f.until {
        qb.push(" AND created_at <= ").push_bind(v);
    }
}

pub struct BotScoreRepo {
    pool: PgPool,
}

impl BotScoreRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, b: &BotScoreLog) -> Result<i64> {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO bot_score_logs \
   (client_ip, host, path, total_score, geoip_score, fingerprint_score, \
  behavior_score, ip_rep_score, is_high_risk, action, details) \
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id",
        )
        .bind(&b.client_ip)
        .bind(&b.host)
        .bind(&b.path)
        .bind(b.total_score)
        .bind(b.geoip_score)
        .bind(b.fingerprint_score)
        .bind(b.behavior_score)
        .bind(b.ip_rep_score)
        .bind(b.is_high_risk)
        .bind(&b.action)
        .bind(&b.details)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn batch_create(&self, items: &[BotScoreLog]) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let mut tx = self.pool.begin().await?;
        for b in items {
            sqlx::query(
                "INSERT INTO bot_score_logs \
            (client_ip, host, path, total_score, geoip_score, fingerprint_score, \
         behavior_score, ip_rep_score, is_high_risk, action, details) \
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            )
            .bind(&b.client_ip)
            .bind(&b.host)
            .bind(&b.path)
            .bind(b.total_score)
            .bind(b.geoip_score)
            .bind(b.fingerprint_score)
            .bind(b.behavior_score)
            .bind(b.ip_rep_score)
            .bind(b.is_high_risk)
            .bind(&b.action)
            .bind(&b.details)
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
        f: &BotScoreFilter,
    ) -> Result<(Vec<BotScoreLog>, i64)> {
        let mut cq = QueryBuilder::<Postgres>::new("SELECT COUNT(*) FROM bot_score_logs WHERE 1=1");
        push_filters(&mut cq, f);
        let total = cq.build_query_scalar::<i64>().fetch_one(&self.pool).await?;

        let mut qb =
            QueryBuilder::<Postgres>::new(format!("SELECT {COLS} FROM bot_score_logs WHERE 1=1"));
        push_filters(&mut qb, f);
        qb.push(" ORDER BY id DESC LIMIT ")
            .push_bind(limit)
            .push(" OFFSET ")
            .push_bind(offset);
        let items = qb
            .build_query_as::<BotScoreLog>()
            .fetch_all(&self.pool)
            .await?;
        Ok((items, total))
    }

    /// 近 24 小时统计（对齐 Go Stats24h）。
    pub async fn stats_24h(&self) -> Result<BotScoreStats> {
        let since = Utc::now() - Duration::hours(24);
        let stats = sqlx::query_as::<_, BotScoreStats>(
            "SELECT COUNT(*) as total_24h, \
      COUNT(*) FILTER (WHERE action IN ('block','drop')) as blocked_24h, \
     COUNT(*) FILTER (WHERE is_high_risk = true) as high_risk_24h \
      FROM bot_score_logs WHERE created_at >= $1",
        )
        .bind(since)
        .fetch_one(&self.pool)
        .await?;
        Ok(stats)
    }
}
