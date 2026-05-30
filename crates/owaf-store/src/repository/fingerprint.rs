//! 指纹统计仓库（对齐 Go FingerprintRepo）。

use serde::Serialize;
use sqlx::FromRow;
use sqlx::postgres::PgPool;

use crate::error::Result;

/// 指纹聚合统计（对齐 Go FingerprintStats）。
#[derive(Debug, Clone, Serialize)]
pub struct FingerprintStats {
    pub top_ja3: Vec<FingerprintEntry>,
    pub browser_distribution: Vec<BrowserDist>,
    pub total_count: i64,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct FingerprintEntry {
    pub ja3_hash: String,
    pub count: i64,
    pub is_known_good: bool,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct BrowserDist {
    pub browser: String,
    pub count: i64,
}

pub struct FingerprintRepo {
    pool: PgPool,
}

impl FingerprintRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 聚合统计（对齐 Go GetStats）。
    pub async fn get_stats(&self) -> Result<FingerprintStats> {
        let total_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fingerprint_records")
            .fetch_one(&self.pool)
            .await?;

        let top_ja3 = sqlx::query_as::<_, FingerprintEntry>(
            "SELECT ja3_hash, count, is_known_good FROM fingerprint_records \
             ORDER BY count DESC LIMIT 10",
        )
        .fetch_all(&self.pool)
        .await?;

        let browser_distribution = sqlx::query_as::<_, BrowserDist>(
            "SELECT browser, SUM(count)::bigint AS count FROM fingerprint_records \
 WHERE browser != '' GROUP BY browser ORDER BY count DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(FingerprintStats {
            top_ja3,
            browser_distribution,
            total_count,
        })
    }
}
