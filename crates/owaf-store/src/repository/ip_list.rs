//! 黑/白名单 IP 仓库（对齐 Go IPListRepo）。

use sqlx::postgres::PgPool;

use crate::error::Result;
use crate::models::IpListEntry;

const COLS: &str = "id, created_at, updated_at, kind, value, note, enabled";

pub struct IpListRepo {
    pool: PgPool,
}

impl IpListRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list(
        &self,
        offset: i64,
        limit: i64,
        kind: Option<&str>,
    ) -> Result<(Vec<IpListEntry>, i64)> {
        let total: i64 = match kind {
            Some(k) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*) FROM ip_list_entries WHERE deleted_at IS NULL AND kind = $1",
                )
                .bind(k)
                .fetch_one(&self.pool)
                .await?
            }
            None => {
                sqlx::query_scalar("SELECT COUNT(*) FROM ip_list_entries WHERE deleted_at IS NULL")
                    .fetch_one(&self.pool)
                    .await?
            }
        };
        let sql = format!(
            "SELECT {COLS} FROM ip_list_entries WHERE deleted_at IS NULL {} ORDER BY id DESC LIMIT $1 OFFSET $2",
            if kind.is_some() { "AND kind = $3" } else { "" }
        );
        let mut q = sqlx::query_as::<_, IpListEntry>(&sql)
            .bind(limit)
            .bind(offset);
        if let Some(k) = kind {
            q = q.bind(k.to_string());
        }
        let items = q.fetch_all(&self.pool).await?;
        Ok((items, total))
    }

    pub async fn all_enabled(&self) -> Result<Vec<IpListEntry>> {
        Ok(sqlx::query_as::<_, IpListEntry>(&format!(
            "SELECT {COLS} FROM ip_list_entries WHERE deleted_at IS NULL AND enabled = true"
        ))
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn get(&self, id: i64) -> Result<Option<IpListEntry>> {
        Ok(sqlx::query_as::<_, IpListEntry>(&format!(
            "SELECT {COLS} FROM ip_list_entries WHERE id = $1 AND deleted_at IS NULL"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?)
    }

    pub async fn create(&self, e: &IpListEntry) -> Result<i64> {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO ip_list_entries (kind, value, note, enabled) \
         VALUES ($1,$2,$3,$4) RETURNING id",
        )
        .bind(&e.kind)
        .bind(&e.value)
        .bind(&e.note)
        .bind(e.enabled)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn update(&self, e: &IpListEntry) -> Result<()> {
        sqlx::query(
            "UPDATE ip_list_entries SET kind = $2, value = $3, note = $4, enabled = $5, \
         updated_at = now() WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(e.id)
        .bind(&e.kind)
        .bind(&e.value)
        .bind(&e.note)
        .bind(e.enabled)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn delete(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE ip_list_entries SET deleted_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
