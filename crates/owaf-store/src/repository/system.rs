//! 系统设置 + 快照修订仓库（对齐 Go SystemSettingsRepo + store.BumpRevision/CurrentRevision）。

use sqlx::postgres::PgPool;

use crate::error::Result;

/// 系统设置与修订计数仓库。
pub struct SystemRepo {
    pool: PgPool,
}

impl SystemRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 读取键值（对齐 Go Get）：缺失返回 None。
    pub async fn get(&self, key: &str) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM system_settings WHERE key = $1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| r.0))
    }

    /// 写入/更新键值（对齐 Go Set）：UPSERT。
    pub async fn set(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            "INSERT INTO system_settings (key, value) VALUES ($1, $2) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 递增修订号并返回新值（对齐 Go BumpRevision）。
    pub async fn bump_revision(&self) -> Result<u64> {
        let (rev,): (i64,) = sqlx::query_as(
            "INSERT INTO config_revisions (id, revision) VALUES (1, 1) \
             ON CONFLICT (id) DO UPDATE SET revision = config_revisions.revision + 1 \
             RETURNING revision",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(rev.max(0) as u64)
    }

    /// 读取当前修订号（对齐 Go CurrentRevision）：缺失则初始化为 0。
    pub async fn current_revision(&self) -> Result<u64> {
        let (rev,): (i64,) = sqlx::query_as(
            "INSERT INTO config_revisions (id, revision) VALUES (1, 0) \
             ON CONFLICT (id) DO UPDATE SET revision = config_revisions.revision \
             RETURNING revision",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(rev.max(0) as u64)
    }
}
