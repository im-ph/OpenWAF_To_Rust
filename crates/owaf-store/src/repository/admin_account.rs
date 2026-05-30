//! 管理账户仓库（对齐 Go AdminAccountRepo）。bcrypt 口令校验/改密。

use sqlx::postgres::PgPool;

use crate::error::Result;
use crate::models::AdminAccount;

const COLS: &str = "id, username, password_hash, updated_at";

pub struct AdminAccountRepo {
    pool: PgPool,
}

impl AdminAccountRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn get_by_username(&self, username: &str) -> Result<Option<AdminAccount>> {
        let sql = format!("SELECT {COLS} FROM admin_accounts WHERE username = $1");
        Ok(sqlx::query_as(&sql)
            .bind(username)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// 校验口令（对齐 Go VerifyPassword）：bcrypt 比对，失败返回 None。
    pub async fn verify_password(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<AdminAccount>> {
        let Some(acct) = self.get_by_username(username).await? else {
            return Ok(None);
        };
        if bcrypt::verify(password, &acct.password_hash).unwrap_or(false) {
            Ok(Some(acct))
        } else {
            Ok(None)
        }
    }

    /// 改密（对齐 Go UpdatePassword）：bcrypt 生成新哈希。
    pub async fn update_password(&self, username: &str, new_password: &str) -> Result<()> {
        let hash = bcrypt::hash(new_password, bcrypt::DEFAULT_COST)?;
        sqlx::query(
            "UPDATE admin_accounts SET password_hash = $2, updated_at = now() WHERE username = $1",
        )
        .bind(username)
        .bind(hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
