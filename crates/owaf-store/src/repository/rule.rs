//! 规则仓库（对齐 Go RuleRepo）。

use sqlx::postgres::PgPool;

use crate::error::Result;
use crate::models::Rule;

const COLS: &str = "id, created_at, updated_at, name, policy_id, phase, pattern, action, \
     priority, enabled, status_code, redirect_to";

pub struct RuleRepo {
    pool: PgPool,
}

impl RuleRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 全部规则（快照构建）：priority ASC, id ASC，排除软删除。
    pub async fn list_all(&self) -> Result<Vec<Rule>> {
        let sql = format!(
            "SELECT {COLS} FROM rules WHERE deleted_at IS NULL ORDER BY priority ASC, id ASC"
        );
        Ok(sqlx::query_as(&sql).fetch_all(&self.pool).await?)
    }

    /// 指定策略下的规则（priority ASC, id ASC）。
    pub async fn find_by_policy(&self, policy_id: i64) -> Result<Vec<Rule>> {
        let sql = format!(
            "SELECT {COLS} FROM rules WHERE policy_id = $1 AND deleted_at IS NULL \
             ORDER BY priority ASC, id ASC"
        );
        Ok(sqlx::query_as(&sql)
            .bind(policy_id)
            .fetch_all(&self.pool)
            .await?)
    }

    pub async fn get(&self, id: i64) -> Result<Option<Rule>> {
        let sql = format!("SELECT {COLS} FROM rules WHERE id = $1 AND deleted_at IS NULL");
        Ok(sqlx::query_as(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        name: &str,
        policy_id: i64,
        phase: &str,
        pattern: &str,
        action: &str,
        priority: i32,
        enabled: bool,
        status_code: i32,
        redirect_to: &str,
    ) -> Result<i64> {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO rules \
             (name, policy_id, phase, pattern, action, priority, enabled, status_code, redirect_to) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
        )
        .bind(name)
        .bind(policy_id)
        .bind(phase)
        .bind(pattern)
        .bind(action)
        .bind(priority)
        .bind(enabled)
        .bind(status_code)
        .bind(redirect_to)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn delete(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE rules SET deleted_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
