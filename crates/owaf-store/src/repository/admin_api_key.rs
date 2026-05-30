//! 管理 API 令牌仓库（对齐 Go AdminAPIKeyRepo）。

use rand::RngCore;
use rand::rngs::OsRng;
use sqlx::postgres::PgPool;

use crate::error::Result;
use crate::models::AdminApiKey;

const COLS: &str = "id, created_at, updated_at, name, token_hash, last_used_at";

pub struct AdminApiKeyRepo {
    pool: PgPool,
}

impl AdminApiKeyRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list(&self) -> Result<Vec<AdminApiKey>> {
        let sql =
            format!("SELECT {COLS} FROM admin_api_keys WHERE deleted_at IS NULL ORDER BY id ASC");
        Ok(sqlx::query_as(&sql).fetch_all(&self.pool).await?)
    }

    pub async fn get(&self, id: i64) -> Result<Option<AdminApiKey>> {
        let sql = format!("SELECT {COLS} FROM admin_api_keys WHERE id = $1 AND deleted_at IS NULL");
        Ok(sqlx::query_as(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// 生成新令牌（对齐 Go Create）：32 随机字节 hex → bcrypt 存哈希 → 返回明文(仅此一次) + id。
    pub async fn create(&self, name: &str) -> Result<(String, i64)> {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let token = hex::encode(raw);
        let hash = bcrypt::hash(&token, bcrypt::DEFAULT_COST)?;
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO admin_api_keys (name, token_hash) VALUES ($1, $2) RETURNING id",
        )
        .bind(name)
        .bind(hash)
        .fetch_one(&self.pool)
        .await?;
        Ok((token, id))
    }

    /// 校验 bearer 令牌（对齐 Go Verify）：遍历比对，命中则更新 last_used_at。
    pub async fn verify(&self, token: &str) -> Result<Option<AdminApiKey>> {
        for k in self.list().await? {
            if bcrypt::verify(token, &k.token_hash).unwrap_or(false) {
                sqlx::query("UPDATE admin_api_keys SET last_used_at = now() WHERE id = $1")
                    .bind(k.id)
                    .execute(&self.pool)
                    .await?;
                return Ok(Some(k));
            }
        }
        Ok(None)
    }

    /// 软删除。
    pub async fn delete(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE admin_api_keys SET deleted_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
