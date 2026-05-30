//! 证书仓库（对齐 Go CertificateRepo）。

use sqlx::postgres::PgPool;

use crate::error::Result;
use crate::models::Certificate;

const COLS: &str = "id, created_at, updated_at, name, cert_pem, key_pem";

pub struct CertificateRepo {
    pool: PgPool,
}

impl CertificateRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 全部证书（对齐 Go List/快照构建）：按 id 升序，排除软删除。
    pub async fn list_all(&self) -> Result<Vec<Certificate>> {
        let sql =
            format!("SELECT {COLS} FROM certificates WHERE deleted_at IS NULL ORDER BY id ASC");
        Ok(sqlx::query_as(&sql).fetch_all(&self.pool).await?)
    }

    pub async fn get(&self, id: i64) -> Result<Option<Certificate>> {
        let sql = format!("SELECT {COLS} FROM certificates WHERE id = $1 AND deleted_at IS NULL");
        Ok(sqlx::query_as(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?)
    }

    /// 新建，返回自增 id。
    pub async fn create(&self, name: &str, cert_pem: &str, key_pem: &str) -> Result<i64> {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO certificates (name, cert_pem, key_pem) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(name)
        .bind(cert_pem)
        .bind(key_pem)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn update(&self, id: i64, name: &str, cert_pem: &str, key_pem: &str) -> Result<()> {
        sqlx::query(
            "UPDATE certificates SET name = $2, cert_pem = $3, key_pem = $4, updated_at = now() \
             WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(name)
        .bind(cert_pem)
        .bind(key_pem)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 软删除（对齐 GORM soft delete）。
    pub async fn delete(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE certificates SET deleted_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
