//! 策略仓库（对齐 Go PolicyRepo）。

use sqlx::postgres::PgPool;

use crate::error::Result;
use crate::models::Policy;

const COLS: &str = "id, created_at, updated_at, name";

pub struct PolicyRepo {
    pool: PgPool,
}

impl PolicyRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list_all(&self) -> Result<Vec<Policy>> {
        let sql = format!("SELECT {COLS} FROM policies WHERE deleted_at IS NULL ORDER BY id ASC");
        Ok(sqlx::query_as(&sql).fetch_all(&self.pool).await?)
    }

    pub async fn get(&self, id: i64) -> Result<Option<Policy>> {
        let sql = format!("SELECT {COLS} FROM policies WHERE id = $1 AND deleted_at IS NULL");
        Ok(sqlx::query_as(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    pub async fn create(&self, name: &str) -> Result<i64> {
        let (id,): (i64,) = sqlx::query_as("INSERT INTO policies (name) VALUES ($1) RETURNING id")
            .bind(name)
            .fetch_one(&self.pool)
            .await?;
        Ok(id)
    }

    pub async fn update(&self, id: i64, name: &str) -> Result<()> {
        sqlx::query(
            "UPDATE policies SET name = $2, updated_at = now() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE policies SET deleted_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
