//! 刷新令牌仓库（对齐 Go RefreshTokenRepo）。

use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;

use crate::error::Result;
use crate::models::RefreshToken;

const COLS: &str =
    "id, jti, token_hash, username, role, expires_at, revoked, replaced_by, created_at";

pub struct RefreshTokenRepo {
    pool: PgPool,
}

impl RefreshTokenRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn create(
        &self,
        jti: &str,
        token_hash: &str,
        username: &str,
        role: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<i64> {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO refresh_tokens (jti, token_hash, username, role, expires_at) \
    VALUES ($1, $2, $3, $4, $5) RETURNING id",
        )
        .bind(jti)
        .bind(token_hash)
        .bind(username)
        .bind(role)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    /// 查找有效令牌（对齐 Go FindByJTI）：未吊销且未过期。
    pub async fn find_by_jti(&self, jti: &str) -> Result<Option<RefreshToken>> {
        let sql = format!(
            "SELECT {COLS} FROM refresh_tokens \
        WHERE jti = $1 AND revoked = false AND expires_at > now()"
        );
        Ok(sqlx::query_as(&sql)
            .bind(jti)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// 吊销并记录替换者（对齐 Go Revoke）。
    pub async fn revoke(&self, jti: &str, replaced_by: &str) -> Result<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked = true, replaced_by = $2 WHERE jti = $1")
            .bind(jti)
            .bind(replaced_by)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 吊销全部未吊销令牌（对齐 Go RevokeAll）。
    pub async fn revoke_all(&self) -> Result<()> {
        sqlx::query("UPDATE refresh_tokens SET revoked = true WHERE revoked = false")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// 清理过期/已吊销令牌（对齐 Go CleanExpired）。
    pub async fn clean_expired(&self) -> Result<()> {
        sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < now() OR revoked = true")
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
