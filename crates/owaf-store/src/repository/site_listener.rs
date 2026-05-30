//! 站点监听器仓库（对齐 Go SiteListenerRepo）。

use sqlx::postgres::PgPool;

use crate::error::Result;
use crate::models::SiteListener;

const COLS: &str = "id, created_at, updated_at, site_id, bind, network, \
     tls_enabled, cert_id, enabled, note";

pub struct SiteListenerRepo {
    pool: PgPool,
}

impl SiteListenerRepo {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn list_all(&self) -> Result<Vec<SiteListener>> {
        let sql =
            format!("SELECT {COLS} FROM site_listeners WHERE deleted_at IS NULL ORDER BY id ASC");
        Ok(sqlx::query_as(&sql).fetch_all(&self.pool).await?)
    }

    pub async fn find_by_site(&self, site_id: i64) -> Result<Vec<SiteListener>> {
        let sql = format!(
            "SELECT {COLS} FROM site_listeners WHERE site_id = $1 AND deleted_at IS NULL \
             ORDER BY id ASC"
        );
        Ok(sqlx::query_as(&sql)
            .bind(site_id)
            .fetch_all(&self.pool)
            .await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        site_id: i64,
        bind: &str,
        network: &str,
        tls_enabled: bool,
        cert_id: Option<i64>,
        enabled: bool,
        note: &str,
    ) -> Result<i64> {
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO site_listeners \
             (site_id, bind, network, tls_enabled, cert_id, enabled, note) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(site_id)
        .bind(bind)
        .bind(network)
        .bind(tls_enabled)
        .bind(cert_id)
        .bind(enabled)
        .bind(note)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    pub async fn delete(&self, id: i64) -> Result<()> {
        sqlx::query("UPDATE site_listeners SET deleted_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
